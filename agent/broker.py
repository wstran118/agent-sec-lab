"""Credential broker: tools (not the model) hold secrets and hand out short-lived, scoped tokens.

Tokens are `scope.expiry.signature` (HMAC-SHA256). Even if one leaks into a log it is narrow (one scope)
and short (TTL). Lab-grade: in production use your platform's secret manager / STS, not this.
"""
import hashlib
import hmac
import secrets as _secrets
import time


class Broker:
    def __init__(self, secrets: dict[str, str]):
        self._secrets = dict(secrets)
        self._key = _secrets.token_bytes(32)

    def values(self) -> list[str]:
        """Secret values, for redaction only. Never put these in model context."""
        return [v for v in self._secrets.values() if v]

    def get(self, name: str) -> str:
        return self._secrets[name]

    def _sig(self, scope: str, exp: int) -> str:
        return hmac.new(self._key, f"{scope}.{exp}".encode(), hashlib.sha256).hexdigest()[:32]

    def issue_token(self, scope: str, ttl: int = 60, now: float | None = None) -> str:
        exp = int((time.time() if now is None else now) + ttl)
        return f"{scope}.{exp}.{self._sig(scope, exp)}"

    def verify(self, token: str, scope: str, now: float | None = None) -> bool:
        try:
            tscope, exp_s, sig = token.rsplit(".", 2)
            exp = int(exp_s)
        except ValueError:
            return False
        ok = hmac.compare_digest(sig, self._sig(tscope, exp)) and tscope == scope
        return ok and (time.time() if now is None else now) < exp
