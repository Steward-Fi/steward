# steward-sdk

Python backend SDK for Steward API integrations.

```python
from steward_sdk import StewardClient

client = StewardClient(
    base_url="https://api.steward.fi",
    platform_key="steward_platform_...",
)

user = client.create_user(
    tenant_id="my-app",
    email="user@example.com",
)
```

For production mutating API calls, pass `request_signing_secret` so the SDK emits
Steward HMAC request signatures, freshness timestamps, and idempotency keys.

```python
client = StewardClient(
    base_url="https://api.steward.fi",
    app_id="app_...",
    app_secret="secret_...",
    request_signing_secret="stwd_req_...",
)
```
