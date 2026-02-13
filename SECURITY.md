# Security Policy

## Reporting a Vulnerability

Please report vulnerabilities privately via GitHub Security Advisories for this repository.

- Do **not** open public issues for suspected vulnerabilities.
- Include reproduction steps, impact, and affected versions/commits.

## Security Notes

- OAuth `state` is signed (HMAC-SHA256) and expires after 10 minutes.
- Upstream GitHub access tokens are **not** persisted in authorization props.
- WeatherAPI requires API keys in query parameters; this project redacts secret-like query parameters from thrown HTTP errors.
- Optional proxy mode is supported (`WEATHER_PROXY_BASE_URL`) so this worker can avoid direct outbound weather requests with query-key auth.
- Startup performs fail-fast security config checks (cookie secret length, proxy var consistency, optional required proxy mode).
- Proxy supports optional short-lived signed request verification (timestamp + nonce), client-id allowlisting, and per-IP/per-client rate limiting (in-memory fallback or Durable Object-backed global counters).
- Outbound HTTP requests use hard timeouts to reduce hang/DoS amplification risk.
