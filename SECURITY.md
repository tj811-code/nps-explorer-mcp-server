# Security Policy

## Reporting a Vulnerability

Please report vulnerabilities privately via GitHub Security Advisories for this repository.

- Do **not** open public issues for suspected vulnerabilities.
- Include reproduction steps, impact, and affected versions/commits.

## Security Notes

- OAuth `state` is signed (HMAC-SHA256) and expires after 10 minutes.
- Upstream GitHub access tokens are **not** persisted in authorization props.
- WeatherAPI requires API keys in query parameters; this project redacts secret-like query parameters from thrown HTTP errors.
- Outbound HTTP requests use hard timeouts to reduce hang/DoS amplification risk.
