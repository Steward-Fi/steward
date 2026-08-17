from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
import warnings
from dataclasses import dataclass
from typing import Any, Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener


JsonObject = dict[str, Any]
Transport = Callable[[Request, bytes | None, float], tuple[int, Mapping[str, str], bytes]]


class StewardApiError(RuntimeError):
    def __init__(self, message: str, status: int = 0, data: Any | None = None):
        super().__init__(message)
        self.status = status
        self.data = data


@dataclass(frozen=True)
class StewardResponse:
    status: int
    data: Any
    headers: Mapping[str, str]


@dataclass(frozen=True)
class StewardClientConfig:
    base_url: str
    api_key: str | None = None
    bearer_token: str | None = None
    platform_key: str | None = None
    app_id: str | None = None
    app_secret: str | None = None
    tenant_id: str | None = None
    request_signing_secret: str | None = None
    request_signing_key_id: str | None = None
    timeout: float = 30.0
    transport: Transport | None = None
    # Appended to preserve the positional argument order of the published
    # config constructor. Permit plaintext non-loopback HTTP with a warning.
    allow_insecure_base_url: bool = False


# Keep in lockstep with the equivalent list in EVERY other SDK (sdk, go, java,
# ruby, rust, swift, csharp, flutter): mutations under these prefixes are
# HMAC-signed, and divergence silently downgrades integrity (SEC-049).
SENSITIVE_SIGNED_PREFIXES = (
    "/vault",
    "/agents",
    "/policies",
    "/secrets",
    "/trade",
    "/v1/trade",
    "/approvals",
    "/intents",
    "/user",
    "/webhooks",
    "/tenants",
    "/platform",
    "/condition-sets",
    "/condition_sets",
    "/v1/condition_sets",
    "/global-wallet",
    "/accounts",
)
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


# Headers that carry credentials or signing material. urllib capitalizes header
# names ("X-steward-key"), so comparisons must be case-insensitive.
_CREDENTIAL_HEADERS = frozenset(
    name.lower()
    for name in (
        "Authorization",
        "X-Steward-Key",
        "X-Steward-Platform-Key",
        "X-Steward-App-Id",
        "X-Steward-Signature",
        "X-Steward-Signing-Key-Id",
        "X-Steward-Request-Timestamp",
        "Idempotency-Key",
    )
)


class _StewardRedirectHandler(HTTPRedirectHandler):
    """Follow redirects, but never forward credential headers to a different
    host. urllib's default handler converts 301/302/303 POSTs to GET yet copies
    every header — including API keys and HMAC signatures — to the redirect
    target, so an open redirect or hostile proxy would exfiltrate them
    (SEC-125)."""

    def redirect_request(self, req: Request, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Request | None:
        new_req = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new_req is None:
            return None
        old_host = (urlparse(req.full_url).hostname or "").lower()
        new_host = (urlparse(new_req.full_url).hostname or "").lower()
        old_scheme = urlparse(req.full_url).scheme.lower()
        new_scheme = urlparse(new_req.full_url).scheme.lower()
        if new_host != old_host or (old_scheme == "https" and new_scheme != "https"):
            for store in (new_req.headers, new_req.unredirected_hdrs):
                for name in [key for key in store if key.lower() in _CREDENTIAL_HEADERS]:
                    del store[name]
        return new_req


_default_opener = build_opener(_StewardRedirectHandler())


def _default_transport(request: Request, body: bytes | None, timeout: float) -> tuple[int, Mapping[str, str], bytes]:
    try:
        with _default_opener.open(request, data=body, timeout=timeout) as response:
            return response.status, dict(response.headers.items()), response.read()
    except HTTPError as exc:
        return exc.code, dict(exc.headers.items()), exc.read()
    except URLError as exc:
        raise StewardApiError(str(exc.reason), 0) from exc


def _canonical_path(path: str) -> str:
    if path.startswith("/"):
        return path
    return f"/{path}"


def _json_body(body: Any | None) -> bytes | None:
    if body is None:
        return None
    return json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _is_sensitive_mutation(path: str, method: str) -> bool:
    return method.upper() in MUTATING_METHODS and any(path.startswith(prefix) for prefix in SENSITIVE_SIGNED_PREFIXES)


def _is_loopback_host(hostname: str) -> bool:
    return hostname in ("localhost", "127.0.0.1", "::1")


# Keep in lockstep with the equivalent check in EVERY other SDK (sdk, go,
# java, ruby, rust, swift, csharp, flutter): these clients transmit API keys,
# bearer tokens, and HMAC-signed credentials, none of which may travel to a
# plaintext non-loopback endpoint (SEC-200, mirroring SEC-048).
def _assert_secure_base_url(base_url: str, allow_insecure_base_url: bool) -> None:
    parsed = urlparse(base_url)
    if not parsed.scheme or not parsed.hostname:
        raise ValueError("base_url must be a valid absolute URL")
    if parsed.scheme not in ("http", "https"):
        raise ValueError("base_url must use HTTP or HTTPS")
    if parsed.scheme == "https" or (parsed.scheme == "http" and _is_loopback_host(parsed.hostname)):
        return
    if allow_insecure_base_url:
        warnings.warn(
            f"[steward-sdk] WARNING: base_url {base_url!r} is not HTTPS; credentials travel in "
            "cleartext. Use allow_insecure_base_url only on trusted private networks.",
            stacklevel=3,
        )
        return
    raise ValueError(
        "base_url must use HTTPS unless it targets loopback (http://localhost, http://127.0.0.1, "
        "http://[::1]). Set allow_insecure_base_url=True to override on trusted private networks."
    )


class StewardClient:
    def __init__(self, config: StewardClientConfig | None = None, **kwargs: Any):
        if config is None:
            config = StewardClientConfig(**kwargs)
        elif kwargs:
            raise TypeError("Pass either StewardClientConfig or keyword arguments, not both")
        self.config = config
        self.base_url = config.base_url.rstrip("/")
        _assert_secure_base_url(self.base_url, config.allow_insecure_base_url)
        self._transport = config.transport or _default_transport

    def request(
        self,
        method: str,
        path: str,
        *,
        body: Any | None = None,
        headers: Mapping[str, str] | None = None,
        query: Mapping[str, str | int | bool | None] | None = None,
        idempotency_key: str | None = None,
    ) -> StewardResponse:
        method = method.upper()
        path = _canonical_path(path)
        qs = ""
        if query:
            clean_query = {key: value for key, value in query.items() if value is not None}
            if clean_query:
                qs = f"?{urlencode(clean_query)}"
        request_body = _json_body(body)
        request_headers = self._headers(path, method, request_body, headers, idempotency_key)
        request = Request(
            f"{self.base_url}{path}{qs}",
            data=request_body,
            headers=request_headers,
            method=method,
        )
        status, response_headers, raw = self._transport(request, request_body, self.config.timeout)
        payload: Any = None
        if raw:
            try:
                payload = json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError as exc:
                raise StewardApiError("Received invalid JSON from Steward API", status) from exc
        if status >= 400 or (isinstance(payload, dict) and payload.get("ok") is False):
            message = payload.get("error") if isinstance(payload, dict) else None
            raise StewardApiError(message or f"Request failed with status {status}", status, payload)
        data = payload.get("data") if isinstance(payload, dict) and "data" in payload else payload
        return StewardResponse(status=status, data=data, headers=response_headers)

    def get(self, path: str, **kwargs: Any) -> Any:
        return self.request("GET", path, **kwargs).data

    def post(self, path: str, body: Any | None = None, **kwargs: Any) -> Any:
        return self.request("POST", path, body=body, **kwargs).data

    def patch(self, path: str, body: Any | None = None, **kwargs: Any) -> Any:
        return self.request("PATCH", path, body=body, **kwargs).data

    def delete(self, path: str, **kwargs: Any) -> Any:
        return self.request("DELETE", path, **kwargs).data

    def create_user(self, *, tenant_id: str, email: str | None = None, wallet_address: str | None = None, custom_metadata: JsonObject | None = None) -> JsonObject:
        return self.post(
            "/platform/users",
            {
                "tenantId": tenant_id,
                **({"email": email} if email else {}),
                **({"walletAddress": wallet_address} if wallet_address else {}),
                **({"customMetadata": custom_metadata} if custom_metadata is not None else {}),
            },
        )

    def get_user(self, user_id: str) -> JsonObject:
        return self.get(f"/platform/users/{quote(user_id, safe='')}")

    def lookup_user(self, **query: str) -> JsonObject:
        return self.get("/platform/users/lookup", query=query)

    def list_user_push_subscriptions(self) -> JsonObject:
        return self.get("/user/me/push-subscriptions")

    def register_user_push_subscription(self, subscription: JsonObject) -> JsonObject:
        return self.post("/user/me/push-subscriptions", subscription)

    def revoke_user_push_subscription(self, subscription_id: str) -> JsonObject:
        return self.delete(f"/user/me/push-subscriptions/{quote(subscription_id, safe='')}")

    def _headers(
        self,
        path: str,
        method: str,
        body: bytes | None,
        headers: Mapping[str, str] | None,
        idempotency_key: str | None,
    ) -> dict[str, str]:
        merged = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            **(dict(headers) if headers else {}),
        }
        if self.config.platform_key:
            merged["X-Steward-Platform-Key"] = self.config.platform_key
        elif self.config.bearer_token:
            merged["Authorization"] = f"Bearer {self.config.bearer_token}"
        elif self.config.app_id and self.config.app_secret:
            encoded = base64.b64encode(f"{self.config.app_id}:{self.config.app_secret}".encode("utf-8")).decode("ascii")
            merged["Authorization"] = f"Basic {encoded}"
            merged["X-Steward-App-Id"] = self.config.app_id
        elif self.config.api_key:
            merged["X-Steward-Key"] = self.config.api_key
        if self.config.tenant_id:
            merged["X-Steward-Tenant"] = self.config.tenant_id

        if self.config.request_signing_secret and _is_sensitive_mutation(path, method):
            timestamp = merged.setdefault("X-Steward-Request-Timestamp", str(int(time.time())))
            idem = merged.setdefault("Idempotency-Key", idempotency_key or str(uuid.uuid4()))
            if self.config.request_signing_key_id:
                merged.setdefault("X-Steward-Signing-Key-Id", self.config.request_signing_key_id)
            body_hash = hashlib.sha256(body or b"").hexdigest()
            canonical = "\n".join([method.upper(), path, timestamp, idem, body_hash])
            signature = hmac.new(
                self.config.request_signing_secret.encode("utf-8"),
                canonical.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            merged["X-Steward-Signature"] = f"v1={signature}"
        return merged
