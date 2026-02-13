function redactUrlSecrets(url: string): string {
    try {
        const u = new URL(url);
        const secretParams = ["key", "api_key", "apikey", "token", "access_token", "client_secret"];
        for (const p of secretParams) {
            if (u.searchParams.has(p)) u.searchParams.set(p, "[REDACTED]");
        }
        return u.toString();
    } catch {
        return url;
    }
}

export class HttpClient {
    async get<T>(url: string, init?: RequestInit): Promise<T> {
        const res = await fetch(url, init);
        if (!res.ok) {
            throw new Error(`GET ${redactUrlSecrets(url)} failed: ${res.status}`);
        }
        return (await res.json()) as T;
    }
}
