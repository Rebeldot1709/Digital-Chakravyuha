"""Seven-layer defensive intake service for Digital Chakravyuha.

This module is a bounded, local signal-ingestion example. It is not an AI
detector, a firewall, or a guarantee against compromise. Deploy behind a
properly configured reverse proxy and use independent operational controls.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
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
MAX_BODY_BYTES = 16 * 1024
MAX_TRACKED_CLIENTS = 10_000


@dataclass(frozen=True, slots=True)
class SecurityConfig:
    """Validated security settings. Secrets must be supplied by the operator."""

    mfa_token: str
    audit_key: bytes
    allowed_ips: frozenset[str] = frozenset({"127.0.0.1", "::1"})
    max_signal_length: int = 512
    max_requests_per_minute: int = 120
    cooldown_seconds: int = 30

    @classmethod
    def from_env(cls) -> "SecurityConfig":
        token = os.getenv("MFA_TOKEN", "")
        audit_secret = os.getenv("AUDIT_HMAC_KEY", "")
        if len(token) < 32:
            raise ValueError("MFA_TOKEN must contain at least 32 characters")
        if len(audit_secret) < 32:
            raise ValueError("AUDIT_HMAC_KEY must contain at least 32 characters")

        configured_ips = os.getenv("ALLOWED_IPS", "127.0.0.1,::1")
        try:
            allowed = frozenset(str(ipaddress.ip_address(item.strip()))
                                for item in configured_ips.split(",") if item.strip())
        except ValueError as exc:
            raise ValueError("ALLOWED_IPS must contain valid IP addresses") from exc
        if not allowed:
            raise ValueError("ALLOWED_IPS cannot be empty")

        def bounded_int(name: str, default: int, low: int, high: int) -> int:
            try:
                value = int(os.getenv(name, str(default)))
            except ValueError as exc:
                raise ValueError(f"{name} must be an integer") from exc
            if not low <= value <= high:
                raise ValueError(f"{name} must be between {low} and {high}")
            return value

        return cls(
            mfa_token=token,
            audit_key=audit_secret.encode("utf-8"),
            allowed_ips=allowed,
            max_signal_length=bounded_int("MAX_SIGNAL_LENGTH", 512, 32, 8192),
            max_requests_per_minute=bounded_int("MAX_RPM", 120, 1, 5000),
            cooldown_seconds=bounded_int("COOLDOWN_SECONDS", 30, 1, 3600),
        )


class RateLimiter:
    """Thread-safe sliding-window limiter with bounded client state."""

    def __init__(self, maximum: int, interval: float = 60.0) -> None:
        self.maximum = maximum
        self.interval = interval
        self._lock = threading.Lock()
        self._events: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, client: str, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        with self._lock:
            bucket = self._events.get(client)
            if bucket is None:
                if len(self._events) >= MAX_TRACKED_CLIENTS:
                    oldest = min(self._events, key=lambda key: self._events[key][-1]
                                 if self._events[key] else 0)
                    del self._events[oldest]
                bucket = self._events[client]
            while bucket and current - bucket[0] >= self.interval:
                bucket.popleft()
            if len(bucket) >= self.maximum:
                return False
            bucket.append(current)
            return True


class AdaptiveGuard:
    """Apply short, bounded cooldowns after repeated rejected requests."""

    def __init__(self, cooldown: int) -> None:
        self.cooldown = cooldown
        self._lock = threading.Lock()
        self._failures: dict[str, deque[float]] = defaultdict(deque)
        self._blocked_until: dict[str, float] = {}

    def blocked(self, client: str, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        with self._lock:
            return self._blocked_until.get(client, 0.0) > current

    def reject(self, client: str, now: float | None = None) -> None:
        current = time.monotonic() if now is None else now
        with self._lock:
            failures = self._failures[client]
            while failures and current - failures[0] > 60:
                failures.popleft()
            failures.append(current)
            if len(failures) >= 5:
                self._blocked_until[client] = current + self.cooldown
                failures.clear()


@dataclass(slots=True)
class RuntimeState:
    accepted: int = 0
    rejected: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record(self, accepted: bool) -> tuple[int, int]:
        with self._lock:
            if accepted:
                self.accepted += 1
            else:
                self.rejected += 1
            return self.accepted, self.rejected


class DigitalChakravyuha:
    """Orchestrate seven explicit, conservative defensive processing layers."""

    def __init__(self, config: SecurityConfig | None = None) -> None:
        self.config = config or SecurityConfig.from_env()
        self.rate_limiter = RateLimiter(self.config.max_requests_per_minute)
        self.adaptive_guard = AdaptiveGuard(self.config.cooldown_seconds)
        self.state = RuntimeState()

    def _audit_id(self, client: str, reason: str, digest: str = "") -> str:
        message = f"{client}|{reason}|{digest}|{int(time.time())}".encode()
        return hmac.new(self.config.audit_key, message, hashlib.sha256).hexdigest()[:24]

    def process(self, signal: Any, mfa: str, client_ip: str) -> tuple[dict[str, Any], int]:
        # Layer 1 — Detection: authenticate, normalize the source, and rate-limit.
        supplied = mfa if isinstance(mfa, str) else ""
        authenticated = hmac.compare_digest(supplied, self.config.mfa_token)
        try:
            client = str(ipaddress.ip_address(client_ip))
        except ValueError:
            client = ""
        if not authenticated:
            return self._deny(client, "authentication_failed", 401)
        if not client or client not in self.config.allowed_ips:
            return self._deny(client or "invalid", "source_denied", 403)
        if self.adaptive_guard.blocked(client):
            return self._deny(client, "temporary_cooldown", 429)
        if not self.rate_limiter.allow(client):
            return self._deny(client, "rate_limited", 429)

        # Layer 2 — Absorption: keep a one-way fingerprint; never retain the signal.
        if not isinstance(signal, str):
            return self._deny(client, "invalid_schema", 400)
        normalized = signal.strip()
        digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()

        # Layer 3 — Analysis: enforce strict bounds and reject control characters.
        if not normalized:
            return self._deny(client, "empty_signal", 400, digest)
        if len(normalized) > self.config.max_signal_length:
            return self._deny(client, "signal_too_long", 413, digest)
        if any(ord(char) < 32 and char not in "\t\n\r" for char in normalized):
            return self._deny(client, "invalid_characters", 400, digest)

        # Layer 4 — Deception: return an opaque, non-reversible event reference.
        event_id = self._audit_id(client, "accepted", digest)

        # Layer 5 — Adaptation: repeated rejected requests receive a short cooldown.
        # Successful traffic does not silently change policy or learn attacker rules.
        accepted, rejected = self.state.record(True)

        # Layer 6 — Resonance: expose only aggregate local counters; no network sharing.
        # Layer 7 — Core protection: this endpoint accepts a signal, grants no data access.
        return {
            "status": "accepted",
            "event_id": event_id,
            "layers": 7,
            "counters": {"accepted": accepted, "rejected": rejected},
        }, 200

    def _deny(self, client: str, reason: str, status: int,
              digest: str = "") -> tuple[dict[str, Any], int]:
        safe_client = client[:64] or "unknown"
        self.adaptive_guard.reject(safe_client)
        _, rejected = self.state.record(False)
        # Keep logs content-free: no credentials, IP addresses, or raw signal text.
        LOGGER.warning("request rejected reason=%s", reason)
        return {
            "status": "rejected",
            "reason": reason,
            "event_id": self._audit_id(safe_client, reason, digest),
            "counters": {"rejected": rejected},
        }, status


def create_app(core: DigitalChakravyuha | None = None) -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES
    chakravyuha = core or DigitalChakravyuha()

    @app.errorhandler(413)
    def request_too_large(_: Exception) -> Any:
        return jsonify({"status": "rejected", "reason": "request_too_large"}), 413

    @app.post("/protect")
    def protect() -> Any:
        if not request.is_json:
            return jsonify({"status": "rejected", "reason": "json_required"}), 415
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"status": "rejected", "reason": "invalid_json"}), 400
        result, status_code = chakravyuha.process(
            signal=data.get("signal"),
            mfa=request.headers.get("X-MFA-Token", ""),
            client_ip=request.remote_addr or "",
        )
        return jsonify(result), status_code

    @app.get("/health")
    def health() -> Any:
        # Liveness only; does not disclose keys, counters, or internal configuration.
        return jsonify({"status": "ok"})

    return app


if __name__ == "__main__":
    # Local-only development server. Use a production WSGI server for deployments.
    app = create_app()
    app.run(host="127.0.0.1", port=8080, debug=False)
