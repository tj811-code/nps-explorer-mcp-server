import type { AuthRequest, OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import { Hono } from "hono";
import { fetchUpstreamAuthToken, getUpstreamAuthorizeUrl } from "./utils";
import { type Env } from "./mcpServer";
import { Octokit } from "octokit";

const app = new Hono<{ Bindings: Env & { OAUTH_PROVIDER: OAuthHelpers } }>();

type SignedState = {
    payloadB64: string;
    sigB64: string;
};

const encoder = new TextEncoder();

function toBase64Url(bytes: Uint8Array): string {
    let binary = "";
    for (const b of bytes) binary += String.fromCharCode(b);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64Url(input: string): Uint8Array {
    const b64 = input.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((input.length + 3) % 4);
    const binary = atob(b64);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
}

async function importHmacKey(secret: string): Promise<CryptoKey> {
    return crypto.subtle.importKey(
        "raw",
        encoder.encode(secret),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign", "verify"]
    );
}

async function signStatePayload(payloadB64: string, secret: string): Promise<string> {
    const key = await importHmacKey(secret);
    const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(payloadB64));
    return toBase64Url(new Uint8Array(sig));
}

async function createSignedState(req: AuthRequest, secret: string): Promise<string> {
    const envelope = {
        iat: Math.floor(Date.now() / 1000),
        req,
    };
    const payloadB64 = toBase64Url(encoder.encode(JSON.stringify(envelope)));
    const sigB64 = await signStatePayload(payloadB64, secret);
    return toBase64Url(encoder.encode(JSON.stringify({ payloadB64, sigB64 } satisfies SignedState)));
}

async function parseAndVerifyState(state: string, secret: string): Promise<AuthRequest | null> {
    try {
        const outerJson = new TextDecoder().decode(fromBase64Url(state));
        const { payloadB64, sigB64 } = JSON.parse(outerJson) as SignedState;
        if (!payloadB64 || !sigB64) return null;

        const key = await importHmacKey(secret);
        const verified = await crypto.subtle.verify("HMAC", key, fromBase64Url(sigB64), encoder.encode(payloadB64));
        if (!verified) return null;

        const payloadJson = new TextDecoder().decode(fromBase64Url(payloadB64));
        const payload = JSON.parse(payloadJson) as { iat: number; req: AuthRequest };

        const maxAgeSeconds = 600;
        if (!payload?.iat || !payload?.req) return null;
        if (Math.floor(Date.now() / 1000) - payload.iat > maxAgeSeconds) return null;

        return payload.req;
    } catch {
        return null;
    }
}

// 1) Kick off the GitHub login
app.get("/authorize", async (c) => {
    const oauthReqInfo = await c.env.OAUTH_PROVIDER.parseAuthRequest(c.req.raw);
    const state = await createSignedState(oauthReqInfo, c.env.COOKIE_ENCRYPTION_KEY);

    return Response.redirect(
        getUpstreamAuthorizeUrl({
            upstream_url: "https://github.com/login/oauth/authorize",
            scope: "read:user",
            client_id: c.env.GITHUB_CLIENT_ID,
            redirect_uri: new URL("/callback", c.req.raw.url).href,
            state,
        })
    );
});

// 2) GitHub redirects back here with ?code=
app.get("/callback", async (c) => {
    const state = c.req.query("state");
    const code = c.req.query("code");

    if (!state || !code) {
        return new Response("Missing OAuth state or code", { status: 400 });
    }

    const oauthReqInfo = await parseAndVerifyState(state, c.env.COOKIE_ENCRYPTION_KEY);
    if (!oauthReqInfo) {
        return new Response("Invalid OAuth state", { status: 400 });
    }

    const [accessToken, err] = await fetchUpstreamAuthToken({
        upstream_url: "https://github.com/login/oauth/access_token",
        client_id: c.env.GITHUB_CLIENT_ID,
        client_secret: c.env.GITHUB_CLIENT_SECRET,
        code,
        redirect_uri: new URL("/callback", c.req.raw.url).href,
    });
    if (err) return err;

    const user = await new Octokit({ auth: accessToken }).rest.users.getAuthenticated();
    const { login, name, email } = user.data;

    const { redirectTo } = await c.env.OAUTH_PROVIDER.completeAuthorization({
        request: oauthReqInfo,
        userId: login,
        metadata: { label: name },
        scope: oauthReqInfo.scope,
        props: { login, name, email },
    });

    return Response.redirect(redirectTo);
});

export { app as GitHubHandler };
