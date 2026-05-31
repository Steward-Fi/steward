# steward-csharp

First-pass C#/.NET SDK for Steward API integrations, including Unity-oriented
runtime compatibility.

```csharp
var client = new StewardClient(new StewardClientConfig
{
    BaseUrl = "https://api.steward.fi",
    PlatformKey = "steward_platform_..."
});

var user = await client.CreateUserAsync(new CreateUserInput
{
    TenantId = "my-app",
    Email = "user@example.com"
});
```

For production mutating calls, configure `RequestSigningSecret`. The client
adds Steward request freshness, HMAC signature, and idempotency headers for
sensitive mutations.

