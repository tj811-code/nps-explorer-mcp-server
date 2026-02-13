// Hardened Cloudflare Worker proxy for WeatherAPI.
// Deploy separately and set WEATHER_PROXY_BASE_URL in the MCP worker.

export interface Env {
  WEATHER_API_KEY: string;
  WEATHER_PROXY_BEARER_TOKEN: string;
  // Optional shared secret for short-lived signed requests from MCP worker.
  WEATHER_PROXY_SIGNING_SECRET?: string;
  // Optional safety controls.
  REQUIRE_SIGNED_REQUESTS?: string; // "true" | "false" (default false)
  MAX_REQUESTS_PER_MINUTE?: string; // default 120
}

const ALLOWED_ENDPOINTS = new Set([
  "current.json",
  "forecast.json",
  "astronomy.json",
  "history.json",
  "future.json",
]);

const rateBucket = new Map<string, { count: number; windowStart: number }>();
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

function unauthorized() {
  return new Response("Unauthorized", { status: 401 });
}

function badRequest(msg: string) {
  return new Response(msg, { status: 400 });
}

function tooManyRequests() {
  return new Response("Too Many Requests", { status: 429 });
}

function isRateLimited(ip: string, maxPerMinute: number): boolean {
  const now = Date.now();
  const windowMs = 60_000;
  const entry = rateBucket.get(ip);

  if (!entry || now - entry.windowStart >= windowMs) {
    rateBucket.set(ip, { count: 1, windowStart: now });
    return false;
  }

  entry.count += 1;
  if (entry.count > maxPerMinute) return true;
  return false;
}

async function verifySignature(request: Request, env: Env, pathAndQuery: string): Promise<boolean> {
  if (!env.WEATHER_PROXY_SIGNING_SECRET) return false;

  const ts = request.headers.get("x-proxy-timestamp");
  const sig = request.headers.get("x-proxy-signature");
  if (!ts || !sig) return false;

  const now = Math.floor(Date.now() / 1000);
  const tsNum = Number(ts);
  if (!Number.isFinite(tsNum)) return false;
  if (Math.abs(now - tsNum) > 90) return false;

  const payload = `${ts}.GET.${pathAndQuery}`;
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(env.WEATHER_PROXY_SIGNING_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const expected = await crypto.subtle.sign("HMAC", key, encoder.encode(payload));
  const expectedSig = toBase64Url(new Uint8Array(expected));
  return sig === expectedSig;
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

    if (toBool(env.REQUIRE_SIGNED_REQUESTS)) {
      const ok = await verifySignature(request, env, `${url.pathname}${url.search}`);
      if (!ok) return unauthorized();
    }

    const maxPerMinute = Math.max(10, Number(env.MAX_REQUESTS_PER_MINUTE || "120") || 120);
    if (isRateLimited(clientIp(request), maxPerMinute)) return tooManyRequests();

    const upstream = new URL(`https://api.weatherapi.com/v1/${endpoint}`);
    for (const [k, v] of url.searchParams.entries()) {
      upstream.searchParams.set(k, v);
    }
    upstream.searchParams.set("key", env.WEATHER_API_KEY);

    // Never log full upstream URL here.
    const resp = await fetch(upstream.toString(), {
      method: "GET",
      headers: { "Accept": "application/json" },
    });

    return new Response(resp.body, {
      status: resp.status,
      headers: {
        "Content-Type": resp.headers.get("content-type") || "application/json",
        "Cache-Control": "no-store",
      },
    });
  },
};
