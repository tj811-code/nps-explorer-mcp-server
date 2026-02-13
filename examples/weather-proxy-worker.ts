// Hardened Cloudflare Worker proxy for WeatherAPI.
// Deploy separately and set WEATHER_PROXY_BASE_URL in the MCP worker.

export interface Env {
  WEATHER_API_KEY: string;
  WEATHER_PROXY_BEARER_TOKEN: string;
  WEATHER_PROXY_SIGNING_SECRET?: string;
  ALLOWED_PROXY_CLIENT_ID?: string;
  REQUIRE_SIGNED_REQUESTS?: string; // "true" | "false"
  MAX_REQUESTS_PER_MINUTE?: string; // default 120
  RATE_LIMITER?: DurableObjectNamespace; // recommended for global limits
}

const ALLOWED_ENDPOINTS = new Set(["current.json", "forecast.json", "astronomy.json", "history.json", "future.json"]);
const rateBucket = new Map<string, { count: number; windowStart: number }>();
const nonceSeen = new Map<string, number>();
const encoder = new TextEncoder();

function toBool(v?: string): boolean {
  return (v || "").toLowerCase() === "true";
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function clientIp(request: Request): string {
  return request.headers.get("cf-connecting-ip") || "unknown";
}

function cleanNonceCache(nowSec: number) {
  for (const [k, exp] of nonceSeen.entries()) {
    if (exp <= nowSec) nonceSeen.delete(k);
  }
}

function unauthorized() {
  return new Response("Unauthorized", { status: 401 });
}
function badRequest(msg: string) {
  return new Response(msg, { status: 400 });
}
function tooManyRequests() {
  return new Response("Too Many Requests", { status: 429 });
}

function isRateLimitedInMemory(key: string, maxPerMinute: number): boolean {
  const now = Date.now();
  const windowMs = 60_000;
  const entry = rateBucket.get(key);
  if (!entry || now - entry.windowStart >= windowMs) {
    rateBucket.set(key, { count: 1, windowStart: now });
    return false;
  }
  entry.count += 1;
  return entry.count > maxPerMinute;
}

async function isRateLimitedGlobal(env: Env, key: string, limitPerMinute: number): Promise<boolean> {
  if (!env.RATE_LIMITER) {
    return isRateLimitedInMemory(key, limitPerMinute);
  }

  const id = env.RATE_LIMITER.idFromName(key);
  const stub = env.RATE_LIMITER.get(id);
  const resp = await stub.fetch("https://rate-limit/check", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ limitPerMinute }),
  });

  if (!resp.ok) return true;
  const data = (await resp.json()) as { allowed: boolean };
  return !data.allowed;
}

function validateQuery(endpoint: string, params: URLSearchParams): boolean {
  const q = params.get("q") || "";
  if (q.length > 120) return false;

  if (endpoint === "forecast.json") {
    const days = Number(params.get("days") || "1");
    if (!Number.isFinite(days) || days < 1 || days > 10) return false;
  }
  return true;
}

async function verifySignature(request: Request, env: Env, pathAndQuery: string): Promise<boolean> {
  if (!env.WEATHER_PROXY_SIGNING_SECRET) return false;

  const ts = request.headers.get("x-proxy-timestamp");
  const nonce = request.headers.get("x-proxy-nonce");
  const sig = request.headers.get("x-proxy-signature");
  const clientId = request.headers.get("x-proxy-client-id") || "default";
  if (!ts || !nonce || !sig) return false;

  if (env.ALLOWED_PROXY_CLIENT_ID && clientId !== env.ALLOWED_PROXY_CLIENT_ID) return false;

  const now = Math.floor(Date.now() / 1000);
  const tsNum = Number(ts);
  if (!Number.isFinite(tsNum)) return false;
  if (Math.abs(now - tsNum) > 90) return false;

  cleanNonceCache(now);
  const nonceKey = `${clientId}:${nonce}`;
  if (nonceSeen.has(nonceKey)) return false; // replay

  const payload = `${ts}.${nonce}.${clientId}.GET.${pathAndQuery}`;
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(env.WEATHER_PROXY_SIGNING_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const expected = await crypto.subtle.sign("HMAC", key, encoder.encode(payload));
  const expectedSig = toBase64Url(new Uint8Array(expected));
  const ok = sig === expectedSig;
  if (ok) nonceSeen.set(nonceKey, now + 120);
  return ok;
}

export class RateLimiterDO {
  constructor(private state: DurableObjectState) {}

  async fetch(request: Request): Promise<Response> {
    if (request.method !== "POST") return new Response("Method Not Allowed", { status: 405 });

    const { limitPerMinute } = (await request.json()) as { limitPerMinute: number };
    const now = Date.now();
    const windowMs = 60_000;

    const data = (await this.state.storage.get<{ count: number; windowStart: number }>("counter")) || {
      count: 0,
      windowStart: now,
    };

    let next = data;
    if (now - data.windowStart >= windowMs) {
      next = { count: 1, windowStart: now };
    } else {
      next = { count: data.count + 1, windowStart: data.windowStart };
    }

    await this.state.storage.put("counter", next);
    await this.state.storage.setAlarm(now + 2 * windowMs);

    const allowed = next.count <= Math.max(1, limitPerMinute || 1);
    return Response.json({ allowed });
  }

  async alarm(): Promise<void> {
    await this.state.storage.delete("counter");
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const auth = request.headers.get("authorization") || "";
    if (auth !== `Bearer ${env.WEATHER_PROXY_BEARER_TOKEN}`) return unauthorized();

    const url = new URL(request.url);
    const prefix = "/weatherapi/";
    if (!url.pathname.startsWith(prefix)) return badRequest("Invalid path");

    const endpoint = url.pathname.slice(prefix.length);
    if (!ALLOWED_ENDPOINTS.has(endpoint)) return badRequest("Endpoint not allowed");
    if (!validateQuery(endpoint, url.searchParams)) return badRequest("Query policy violation");

    if (toBool(env.REQUIRE_SIGNED_REQUESTS)) {
      const ok = await verifySignature(request, env, `${url.pathname}${url.search}`);
      if (!ok) return unauthorized();
    }

    const clientId = request.headers.get("x-proxy-client-id") || "default";
    const maxPerMinute = Math.max(10, Number(env.MAX_REQUESTS_PER_MINUTE || "120") || 120);
    if (await isRateLimitedGlobal(env, `ip:${clientIp(request)}`, maxPerMinute)) return tooManyRequests();
    if (await isRateLimitedGlobal(env, `client:${clientId}`, Math.max(10, Math.floor(maxPerMinute / 2)))) {
      return tooManyRequests();
    }

    const upstream = new URL(`https://api.weatherapi.com/v1/${endpoint}`);
    for (const [k, v] of url.searchParams.entries()) upstream.searchParams.set(k, v);
    upstream.searchParams.set("key", env.WEATHER_API_KEY);

    const resp = await fetch(upstream.toString(), { method: "GET", headers: { Accept: "application/json" } });
    return new Response(resp.body, {
      status: resp.status,
      headers: {
        "Content-Type": resp.headers.get("content-type") || "application/json",
        "Cache-Control": "no-store",
      },
    });
  },
};
