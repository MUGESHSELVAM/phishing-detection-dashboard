"""
rate_limiter.py — Sliding Window Rate Limiter
Phishing Detection Dashboard

Implements a true sliding window rate limit stored in-process (thread-safe).
Keyed by IP address. No external Redis dependency — uses collections.deque
per key with TTL-based pruning on each check.

Usage (as a Flask decorator):
    from rate_limiter import rate_limit

    @app.route("/api/scan", methods=["POST"])
    @rate_limit
    def scan_url():
        ...

A 429 response is returned with Retry-After header when the limit is exceeded.
"""
import time
import logging
import threading
from collections import defaultdict, deque
from functools import wraps

from flask import request, jsonify
from config import config

logger = logging.getLogger(__name__)


class SlidingWindowRateLimiter:
    """
    Thread-safe sliding window rate limiter.

    Each IP gets a deque of request timestamps. On every request:
      1. Drop timestamps older than `window_seconds`.
      2. If remaining count >= max_requests → reject.
      3. Otherwise append current timestamp and allow.

    Memory is bounded: each deque holds at most `max_requests` timestamps.
    """

    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests     = max_requests
        self.window_seconds   = window_seconds
        self._lock            = threading.Lock()
        self._windows: dict[str, deque] = defaultdict(deque)

    def is_allowed(self, key: str) -> tuple[bool, int]:
        """
        Check if `key` (IP address) is within rate limit.

        Returns
        -------
        (allowed: bool, retry_after_seconds: int)
        """
        now = time.monotonic()
        cutoff = now - self.window_seconds

        with self._lock:
            window = self._windows[key]

            # Evict expired timestamps
            while window and window[0] < cutoff:
                window.popleft()

            if len(window) >= self.max_requests:
                # Time until oldest request expires
                retry_after = int(window[0] - cutoff) + 1
                return False, retry_after

            window.append(now)
            return True, 0

    def remaining(self, key: str) -> int:
        """How many requests this key can still make in the current window."""
        now    = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            window = self._windows[key]
            while window and window[0] < cutoff:
                window.popleft()
            return max(0, self.max_requests - len(window))

    def reset(self, key: str):
        """Clear all timestamps for a key (useful for testing)."""
        with self._lock:
            self._windows.pop(key, None)

    def cleanup(self):
        """
        Remove keys with empty windows.
        Call this periodically (e.g. via a background thread) in long-running
        deployments to prevent unbounded memory growth.
        """
        now    = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            stale = [k for k, w in self._windows.items()
                     if not w or w[-1] < cutoff]
            for k in stale:
                del self._windows[k]
        if stale:
            logger.debug("Rate limiter: pruned %d stale keys", len(stale))


# ─── Singleton ────────────────────────────────────────────────────────────────

_limiter = SlidingWindowRateLimiter(
    max_requests=config.RATE_LIMIT_REQUESTS,
    window_seconds=config.RATE_LIMIT_WINDOW,
)


def get_client_ip() -> str:
    """
    Resolve the real client IP, respecting X-Forwarded-For if set by a
    trusted reverse proxy (nginx, cloudflare, etc.).
    """
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        # Take the first (leftmost) address — it is the original client
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


def rate_limit(f):
    """
    Decorator that applies the global sliding window rate limiter to a route.

    Adds response headers:
        X-RateLimit-Limit     : max requests allowed per window
        X-RateLimit-Remaining : requests remaining in current window
        X-RateLimit-Window    : window size in seconds
        Retry-After           : seconds to wait (only on 429)
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        ip = get_client_ip()
        allowed, retry_after = _limiter.is_allowed(ip)

        remaining = _limiter.remaining(ip)

        if not allowed:
            logger.warning("Rate limit exceeded for IP %s", ip)
            resp = jsonify({
                "success": False,
                "error":   "Rate limit exceeded. Please slow down.",
                "code":    "RATE_LIMIT_EXCEEDED",
                "retry_after_seconds": retry_after,
            })
            resp.status_code = 429
            resp.headers["Retry-After"]           = str(retry_after)
            resp.headers["X-RateLimit-Limit"]     = str(config.RATE_LIMIT_REQUESTS)
            resp.headers["X-RateLimit-Remaining"] = "0"
            resp.headers["X-RateLimit-Window"]    = str(config.RATE_LIMIT_WINDOW)
            return resp

        response = f(*args, **kwargs)

        # Attach rate limit headers to successful responses
        if hasattr(response, "headers"):
            response.headers["X-RateLimit-Limit"]     = str(config.RATE_LIMIT_REQUESTS)
            response.headers["X-RateLimit-Remaining"] = str(remaining)
            response.headers["X-RateLimit-Window"]    = str(config.RATE_LIMIT_WINDOW)

        return response

    return wrapper


# ─── Background cleanup thread ────────────────────────────────────────────────

def start_cleanup_thread(interval_seconds: int = 300):
    """
    Spawn a daemon thread that prunes stale rate-limit keys every
    `interval_seconds` seconds. Call once at app startup.
    """
    def _loop():
        while True:
            time.sleep(interval_seconds)
            _limiter.cleanup()

    t = threading.Thread(target=_loop, daemon=True, name="rate-limiter-cleanup")
    t.start()
    logger.info("Rate limiter cleanup thread started (interval=%ds)", interval_seconds)
