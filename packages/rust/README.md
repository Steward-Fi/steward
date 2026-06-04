# steward-sdk

First-pass Rust backend SDK for Steward API integrations.

```rust
use steward_sdk::{Client, Config, CreateUserInput};

let client = Client::new(Config {
    base_url: "https://api.steward.fi".to_string(),
    platform_key: Some("steward_platform_...".to_string()),
    ..Config::default()
})?;

let user = client.create_user(CreateUserInput {
    tenant_id: "my-app".to_string(),
    email: Some("user@example.com".to_string()),
    ..CreateUserInput::default()
})?;
# Ok::<(), steward_sdk::Error>(())
```

For production mutating calls, configure `request_signing_secret`. The client
adds Steward request freshness, HMAC signature, and idempotency headers for
sensitive mutations.
