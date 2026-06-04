# steward-swift

First-pass Swift SDK for Steward API integrations.

```swift
let client = try StewardClient(config: StewardConfig(
    baseURL: "https://api.steward.fi",
    platformKey: "steward_platform_..."
))

let user = try client.createUser(
    tenantID: "my-app",
    email: "user@example.com"
)
```

For production mutating calls, configure `requestSigningSecret`. The client
adds Steward request freshness, HMAC signature, and idempotency headers for
sensitive mutations.

