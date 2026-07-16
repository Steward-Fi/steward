# steward-go

First-pass Go backend SDK for Steward API integrations.

```go
client, err := steward.NewClient(steward.Config{
    BaseURL:     "http://localhost:3200",
    PlatformKey: "steward_platform_...",
})
if err != nil {
    panic(err)
}

user, err := client.CreateUser(context.Background(), steward.CreateUserInput{
    TenantID: "my-app",
    Email:    "user@example.com",
})
```

For production mutating calls, configure `RequestSigningSecret`. The client
adds Steward request freshness, HMAC signature, and idempotency headers for
sensitive mutations.
