function redactUrlSecrets(url: string): string {
    try {
        const u = new URL(url);
        const secretParams = ["key", "api_key", "apikey", "token", "access_token", "client_secret"];
        for (const p of secretParams) {
            if (u.searchParams.has(p)) u.searchParams.set(p, "[REDACTED]");
        }
        return u.toString();
    } catch {
        return "[invalid-url]";
    }
}

export class HttpClient {
    constructor(private readonly timeoutMs: number = 10000) {}

    async get<T>(url: string, init?: RequestInit): Promise<T> {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

        try {
            const res = await fetch(url, { ...init, signal: controller.signal });
            if (!res.ok) {
                throw new Error(`GET ${redactUrlSecrets(url)} failed: ${res.status}`);
            }
            return (await res.json()) as T;
        } catch (err) {
            if (err instanceof DOMException && err.name === "AbortError") {
                throw new Error(`GET ${redactUrlSecrets(url)} timed out after ${this.timeoutMs}ms`);
            }
            throw err;
        } finally {
            clearTimeout(timeout);
        }
    }
}
