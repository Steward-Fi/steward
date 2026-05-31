# steward-ruby

First-pass Ruby backend SDK for Steward API integrations.

```ruby
client = Steward::Client.new(
  base_url: "https://api.steward.fi",
  platform_key: "steward_platform_..."
)

user = client.create_user(
  tenant_id: "my-app",
  email: "user@example.com"
)
```

For production mutating calls, configure `request_signing_secret`. The client
adds Steward request freshness, HMAC signature, and idempotency headers for
sensitive mutations.

