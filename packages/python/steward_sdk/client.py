from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


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
)
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _default_transport(request: Request, body: bytes | None, timeout: float) -> tuple[int, Mapping[str, str], bytes]:
    try:
        with urlopen(request, data=body, timeout=timeout) as response:
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


class StewardClient:
    def __init__(self, config: StewardClientConfig | None = None, **kwargs: Any):
        if config is None:
            config = StewardClientConfig(**kwargs)
        elif kwargs:
            raise TypeError("Pass either StewardClientConfig or keyword arguments, not both")
        self.config = config
        self.base_url = config.base_url.rstrip("/")
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
        return self.get(f"/platform/users/{user_id}")

    def lookup_user(self, **query: str) -> JsonObject:
        return self.get("/platform/users/lookup", query=query)

    def list_user_push_subscriptions(self) -> JsonObject:
        return self.get("/user/me/push-subscriptions")

    def register_user_push_subscription(self, subscription: JsonObject) -> JsonObject:
        return self.post("/user/me/push-subscriptions", subscription)

    def revoke_user_push_subscription(self, subscription_id: str) -> JsonObject:
        return self.delete(f"/user/me/push-subscriptions/{subscription_id}")

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
