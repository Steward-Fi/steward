import json
import re
import unittest
from urllib.request import Request

from steward_sdk import StewardApiError, StewardClient


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


if __name__ == "__main__":
    unittest.main()
