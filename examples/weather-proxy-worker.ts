// Minimal Cloudflare Worker proxy for WeatherAPI.
// Deploy separately and set WEATHER_PROXY_BASE_URL in the MCP worker.

export interface Env {
  WEATHER_API_KEY: string;
  WEATHER_PROXY_BEARER_TOKEN: string;
}

const ALLOWED_ENDPOINTS = new Set([
  "current.json",
  "forecast.json",
  "astronomy.json",
  "history.json",
  "future.json",
]);

function unauthorized() {
  return new Response("Unauthorized", { status: 401 });
}

function badRequest(msg: string) {
  return new Response(msg, { status: 400 });
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
