# Digital Chakravyuha

A hardened defensive core for controlled signal intake.

## Security-first defaults

- Strict MFA check using constant-time comparison.
- IP allowlist enforcement via `ALLOWED_IPS`.
- Request-rate limiting per source IP.
- Signal schema + ethical content validation.
- Deterministic bounded scoring to prevent abuse.
- HMAC trap identifiers for tamper-evident audits.
- Thread-safe runtime state updates.

## API

### `POST /protect`

Header:
- `X-MFA-Token: <token>`

JSON body:
```json
{"signal": "normal operational signal"}
```

### `GET /health`

Health probe endpoint.

## Local run

```bash
python chakravyuha.py
```

Server starts on `127.0.0.1:8080`.

## Environment variables

- `MFA_TOKEN` (optional): fixed API token; generated at runtime if unset.
- `ALLOWED_IPS` (optional): comma-separated allowlist (`127.0.0.1,::1` by default).
- `MAX_SIGNAL_LENGTH` (optional): cap on signal size (default 512).
- `MAX_RPM` (optional): per-IP requests per minute (default 120).
