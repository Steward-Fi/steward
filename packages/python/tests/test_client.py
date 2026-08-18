import json
import re
import unittest
from urllib.request import Request

from steward_sdk import StewardApiError, StewardClient
from steward_sdk.client import _StewardRedirectHandler


class CaptureTransport:
    def __init__(self, status=200, payload=None):
        self.status = status
        self.payload = {"ok": True, "data": {"id": "ok"}} if payload is None else payload
        self.calls = []

    def __call__(self, request: Request, body: bytes | None, timeout: float):
        self.calls.append((request, body, timeout))
        return self.status, {"content-type": "application/json"}, json.dumps(self.payload).encode()


class StewardClientTests(unittest.TestCase):
    def test_platform_key_create_user_request(self):
        transport = CaptureTransport(payload={"ok": True, "data": {"id": "user-1"}})
        client = StewardClient(
            base_url="https://api.example.test/",
            platform_key="platform-key",
            transport=transport,
        )

        result = client.create_user(tenant_id="tenant-1", email="u@example.com")

        request, body, _ = transport.calls[0]
        self.assertEqual(result, {"id": "user-1"})
        self.assertEqual(request.full_url, "https://api.example.test/platform/users")
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.get_header("X-steward-platform-key"), "platform-key")
        self.assertEqual(json.loads(body.decode()), {"tenantId": "tenant-1", "email": "u@example.com"})

    def test_bearer_push_subscription_helpers(self):
        transport = CaptureTransport(payload={"ok": True, "data": {"subscription": {"id": "push-1"}}})
        client = StewardClient(
            base_url="https://api.example.test",
            bearer_token="user-token",
            transport=transport,
        )

        result = client.register_user_push_subscription(
            {"provider": "expo", "token": "ExpoPushToken[abc123abc123abc123]"}
        )

        request, body, _ = transport.calls[0]
        self.assertEqual(result["subscription"]["id"], "push-1")
        self.assertEqual(request.full_url, "https://api.example.test/user/me/push-subscriptions")
        self.assertEqual(request.get_header("Authorization"), "Bearer user-token")
        self.assertEqual(json.loads(body.decode())["provider"], "expo")

    def test_sensitive_mutations_are_signed_and_idempotent(self):
        transport = CaptureTransport()
        client = StewardClient(
            base_url="https://api.example.test",
            app_id="app-1",
            app_secret="secret-1",
            request_signing_secret="signing-secret",
            request_signing_key_id="key-1",
            transport=transport,
        )

        client.post("/user/me/push-subscriptions", {"provider": "fcm", "token": "fcm-token-123456"})

        request, _, _ = transport.calls[0]
        self.assertTrue(request.get_header("Authorization").startswith("Basic "))
        self.assertEqual(request.get_header("X-steward-app-id"), "app-1")
        self.assertEqual(request.get_header("X-steward-signing-key-id"), "key-1")
        self.assertRegex(request.get_header("X-steward-request-timestamp"), r"^\d+$")
        self.assertIsNotNone(request.get_header("Idempotency-key"))
        self.assertRegex(request.get_header("X-steward-signature"), r"^v1=[0-9a-f]{64}$")

    def test_api_errors_include_status_and_payload(self):
        transport = CaptureTransport(status=403, payload={"ok": False, "error": "denied"})
        client = StewardClient(
            base_url="https://api.example.test",
            api_key="tenant-key",
            transport=transport,
        )

        with self.assertRaises(StewardApiError) as caught:
            client.get("/platform/users/user-1")

        self.assertEqual(caught.exception.status, 403)
        self.assertEqual(str(caught.exception), "denied")

    def test_accounts_and_global_wallet_mutations_are_signed(self):
        # SEC-049: every SDK's signing-prefix list must cover wallet/account
        # mutations in lockstep (Flutter already signed these).
        transport = CaptureTransport()
        client = StewardClient(
            base_url="https://api.example.test",
            app_id="app-1",
            app_secret="secret-1",
            request_signing_secret="signing-secret",
            transport=transport,
        )

        for path in ("/accounts", "/global-wallet/consent/approve"):
            client.post(path, {})
            request, _, _ = transport.calls[-1]
            self.assertRegex(
                request.get_header("X-steward-signature") or "",
                r"^v1=[0-9a-f]{64}$",
                f"unsigned mutation: {path}",
            )

    def test_redirect_strips_credential_headers_cross_host(self):
        # SEC-125: urllib's default redirect handling copies every header to
        # the redirect target; an open redirect must not receive credentials.
        handler = _StewardRedirectHandler()
        original = Request(
            "https://api.example.test/accounts",
            headers={
                "Authorization": "Bearer user-token",
                "X-Steward-Key": "tenant-key",
                "X-Steward-Platform-Key": "platform-key",
                "X-Steward-Signature": "v1=deadbeef",
                "Content-Type": "application/json",
            },
        )

        cross = handler.redirect_request(original, None, 302, "Found", {}, "https://evil.example/harvest")
        self.assertIsNone(cross.get_header("Authorization"))
        self.assertIsNone(cross.get_header("X-steward-key"))
        self.assertIsNone(cross.get_header("X-steward-platform-key"))
        self.assertIsNone(cross.get_header("X-steward-signature"))

        same_host = handler.redirect_request(original, None, 302, "Found", {}, "https://api.example.test/other")
        self.assertEqual(same_host.get_header("Authorization"), "Bearer user-token")

        downgrade = handler.redirect_request(original, None, 302, "Found", {}, "http://api.example.test/other")
        self.assertIsNone(downgrade.get_header("Authorization"))
        self.assertIsNone(downgrade.get_header("X-steward-key"))
        self.assertIsNone(downgrade.get_header("X-steward-signature"))
        self.assertEqual(same_host.get_header("X-steward-key"), "tenant-key")

        different_port = handler.redirect_request(
            original, None, 302, "Found", {}, "https://api.example.test:444/harvest"
        )
        self.assertIsNone(different_port.get_header("Authorization"))
        self.assertIsNone(different_port.get_header("X-steward-key"))
        self.assertIsNone(different_port.get_header("X-steward-signature"))

    def test_path_parameters_are_url_encoded(self):
        # SEC-127: raw interpolation lets `/`, `?`, `#` in an id silently
        # alter the request path/query.
        transport = CaptureTransport()
        client = StewardClient(
            base_url="https://api.example.test",
            api_key="tenant-key",
            transport=transport,
        )

        client.get_user("user/evil?admin=true#frag")
        request, _, _ = transport.calls[-1]
        self.assertEqual(
            request.full_url,
            "https://api.example.test/platform/users/user%2Fevil%3Fadmin%3Dtrue%23frag",
        )

        client.revoke_user_push_subscription("sub/1")
        request, _, _ = transport.calls[-1]
        self.assertEqual(
            request.full_url,
            "https://api.example.test/user/me/push-subscriptions/sub%2F1",
        )

    def test_plaintext_non_loopback_base_url_rejected(self):
        # SEC-200: credentials must never travel to a plaintext non-loopback
        # endpoint unless the operator explicitly opts out.
        for base_url in ("http://api.example.test", "http://192.168.1.10:3200", "ftp://api.example.test", "not-a-url", "https://user:secret@api.example.test"):
            with self.assertRaises(ValueError, msg=base_url):
                StewardClient(base_url=base_url, api_key="tenant-key")

        for base_url in ("https://api.example.test", "http://localhost:3200", "http://127.0.0.1:3200", "http://[::1]:3200"):
            StewardClient(base_url=base_url, api_key="tenant-key")

    def test_allow_insecure_base_url_opts_out_with_warning(self):
        with self.assertWarns(UserWarning):
            StewardClient(
                base_url="http://api.example.test",
                api_key="tenant-key",
                allow_insecure_base_url=True,
            )


if __name__ == "__main__":
    unittest.main()
