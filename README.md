# Digital Chakravyuha

A security-conscious, seven-stage signal intake reference implementation inspired by the [Digital Chakravyuha vision](https://digitalchakravyuha.wordpress.com/the-digital-chakravyuha-a-vision-by-abhishek-raj-creator-and-founder-of-the-worlds-first-seven-layer-ai-defense-system/).

This is a defensive software prototype. It is not an AI-powered detector, a firewall, quantum encryption, or an unbreakable system. The stages below are implemented as bounded request-processing controls and must be combined with deployment-specific security measures.

## Seven processing layers

1. **Detection** — constant-time token comparison, normalized IP allowlist, and per-source sliding-window rate limit.
2. **Absorption** — computes a one-way SHA-256 fingerprint; raw signals are not saved.
3. **Analysis** — checks JSON shape, empty input, length bounds, and control characters.
4. **Deception** — returns an opaque HMAC-authenticated event reference; it does not expose a honeypot or attack surface.
5. **Adaptation** — applies a short cooldown after repeated rejected requests. Policy does not self-modify.
6. **Resonance** — reports local aggregate counters only; no telemetry or external intelligence sharing is enabled.
7. **Core protection** — accepts a signal and grants no access to protected data or system commands.

## Requirements and local run

Python 3.10+ and Flask are required.

```sh
python -m pip install Flask
```

Set secrets in the environment. Use independent, randomly generated values of at least 32 characters and store them in a secrets manager in production.

PowerShell:

```powershell
$env:MFA_TOKEN = "replace-with-a-random-secret-of-at-least-32-characters"
$env:AUDIT_HMAC_KEY = "use-a-different-random-secret-of-at-least-32-characters"
python chakravyuha.py
```

POSIX shell:

```sh
export MFA_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export AUDIT_HMAC_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
python chakravyuha.py
```

The development server listens on `127.0.0.1:8080`. It deliberately fails to start when required secrets are missing.

Optional settings:

- `ALLOWED_IPS`: comma-separated exact IP addresses; defaults to loopback only.
- `MAX_SIGNAL_LENGTH`: 32–8192 characters; defaults to 512.
- `MAX_RPM`: 1–5000 requests per minute per source; defaults to 120.
- `COOLDOWN_SECONDS`: 1–3600 seconds after repeated rejected requests; defaults to 30.

## API

`POST /protect` requires `Content-Type: application/json`, the `X-MFA-Token` header, and an allowlisted source address.

```json
{"signal": "routine operational status"}
```

`GET /health` is a minimal liveness probe. It does not verify dependencies or disclose configuration.

## Deployment notes

- Run behind a maintained production WSGI server, TLS termination, network firewall, and secret manager.
- Do not trust forwarded IP headers unless a correctly configured trusted-proxy layer overwrites them.
- The in-memory rate limiter, cooldown, and counters reset on restart and are not shared between workers. Use a dedicated shared store and edge rate limiting for multi-process or distributed deployment.
- Keep the API isolated from privileged data and commands; perform threat review, dependency updates, monitoring, backups, and incident response separately.
- Never describe this prototype as unbreakable or as a substitute for a security assessment.
