"""Digital Chakravyuha core.

Hardened request processing primitives and a small Flask API for protected signal
submission. The module avoids insecure cryptographic constructions and keeps
state mutations thread-safe.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

from flask import Flask, jsonify, request


LOGGER = logging.getLogger("digital_chakravyuha")
LOGGER.setLevel(logging.INFO)
if not LOGGER.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    LOGGER.addHandler(handler)


@dataclass(slots=True)
class SecurityConfig:
    """Runtime security settings with safe defaults."""

    allowed_ips: set[str] = field(default_factory=lambda: {"127.0.0.1", "::1"})
    max_signal_length: int = 512
    max_requests_per_minute: int = 120
    blocked_keywords: tuple[str, ...] = (
        "DESTROY",
        "HARM",
        "KILL",
        "ATTACK",
        "DELETE",
        "DROP",
    )

    @classmethod
    def from_env(cls) -> "SecurityConfig":
        allowed_ip_blob = os.getenv("ALLOWED_IPS", "127.0.0.1,::1")
        allowed_ips = {entry.strip() for entry in allowed_ip_blob.split(",") if entry.strip()}

        max_signal_length = int(os.getenv("MAX_SIGNAL_LENGTH", "512"))
        max_requests_per_minute = int(os.getenv("MAX_RPM", "120"))

        return cls(
            allowed_ips=allowed_ips or {"127.0.0.1", "::1"},
            max_signal_length=max(32, min(max_signal_length, 8192)),
            max_requests_per_minute=max(10, min(max_requests_per_minute, 5000)),
        )


class RateLimiter:
    """Simple fixed-window limiter with per-IP buckets."""

    def __init__(self, max_requests: int, interval_seconds: int = 60) -> None:
        self.max_requests = max_requests
        self.interval_seconds = interval_seconds
        self._lock = threading.Lock()
        self._events: defaultdict[str, deque[float]] = defaultdict(deque)

    def allow(self, client_ip: str) -> bool:
        now = time.time()
        with self._lock:
            bucket = self._events[client_ip]
            while bucket and now - bucket[0] > self.interval_seconds:
                bucket.popleft()

            if len(bucket) >= self.max_requests:
                return False

            bucket.append(now)
            return True


class IntegritySigner:
    """HMAC-based signer for audit-safe request fingerprints."""

    def __init__(self, key: bytes | None = None) -> None:
        self._key = key or secrets.token_bytes(32)

    def sign(self, message: str) -> str:
        digest = hmac.new(self._key, message.encode("utf-8"), hashlib.sha256)
        return digest.hexdigest()


@dataclass(slots=True)
class RuntimeState:
    absorbed_resources: int = 0
    threat_level: int = 0
    personas: list[str] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def absorb(self, score: int) -> int:
        with self._lock:
            self.absorbed_resources += score
            self.threat_level = min(100, self.threat_level + max(1, score // 100))
            return self.absorbed_resources

    def create_persona(self) -> str:
        with self._lock:
            persona_id = f"Persona-{len(self.personas) + 1}-{secrets.token_hex(4)}"
            self.personas.append(persona_id)
            return persona_id

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "absorbed": self.absorbed_resources,
                "threat_level": self.threat_level,
                "personas": self.personas[-5:],
            }


class DigitalChakravyuha:
    """Hardened core processing engine."""

    def __init__(self, config: SecurityConfig | None = None) -> None:
        self.config = config or SecurityConfig.from_env()
        self.state = RuntimeState()
        self.signer = IntegritySigner()
        self.rate_limiter = RateLimiter(self.config.max_requests_per_minute)
        self.mfa_token = os.getenv("MFA_TOKEN") or secrets.token_hex(32)

        LOGGER.info("Digital Chakravyuha initialized with hardened defaults")

    def _validate_ip(self, client_ip: str) -> bool:
        return client_ip in self.config.allowed_ips

    def _validate_signal(self, signal: str) -> tuple[bool, str | None]:
        if not isinstance(signal, str):
            return False, "Signal must be a string"

        normalized = signal.strip()
        if not normalized:
            return False, "Signal cannot be empty"

        if len(normalized) > self.config.max_signal_length:
            return False, "Signal too long"

        uppercase = normalized.upper()
        if any(token in uppercase for token in self.config.blocked_keywords):
            return False, "Ethical violation"

        return True, None

    def _compute_absorb_score(self, signal: str) -> int:
        # bounded deterministic score to avoid overflow/abuse
        digest = hashlib.blake2s(signal.encode("utf-8"), digest_size=16).digest()
        return 50 + (digest[0] % 151)  # 50..200

    def process(self, signal: str, mfa: str, client_ip: str) -> dict[str, Any]:
        if not hmac.compare_digest(mfa or "", self.mfa_token):
            return {"status": "rejected", "reason": "Invalid MFA"}

        if not self._validate_ip(client_ip):
            LOGGER.warning("Denied request from non-allowlisted IP: %s", client_ip)
            return {"status": "blocked", "reason": "IP denied"}

        if not self.rate_limiter.allow(client_ip):
            return {"status": "blocked", "reason": "Rate limit exceeded"}

        valid, reason = self._validate_signal(signal)
        if not valid:
            return {"status": "blocked", "reason": reason}

        score = self._compute_absorb_score(signal)
        total = self.state.absorb(score)
        trap_id = self.signer.sign(f"{client_ip}:{signal}:{total}")[:24]

        if total > 2000 and len(self.state.personas) < 100:
            self.state.create_persona()

        status = "secure" if self.state.threat_level >= 80 else "active"
        payload = {"status": status, "trap_id": trap_id}
        payload.update(self.state.snapshot())
        return payload


def create_app(core: DigitalChakravyuha | None = None) -> Flask:
    app = Flask(__name__)
    chakravyuha = core or DigitalChakravyuha()

    @app.post("/protect")
    def protect() -> Any:
        data = request.get_json(silent=True) or {}
        signal = data.get("signal", "")
        mfa = request.headers.get("X-MFA-Token", "")
        client_ip = request.remote_addr or ""

        result = chakravyuha.process(signal=signal, mfa=mfa, client_ip=client_ip)
        status_code = 200 if result.get("status") in {"active", "secure"} else 403
        return jsonify(result), status_code

    @app.get("/health")
    def health() -> Any:
        return jsonify({"status": "ok"})

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", port=8080)
