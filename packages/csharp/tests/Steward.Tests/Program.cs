using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Steward;

namespace StewardTests
{
    internal static class Program
    {
        private static async Task Main()
        {
            await TestCreateUserUsesPlatformKey();
            await TestBearerPushSubscriptionHelper();
            await TestSensitiveMutationsAreSignedAndIdempotent();
            await TestApiErrorIncludesStatusAndPayload();
            Console.WriteLine("Steward C# tests passed");
        }

        private static async Task TestCreateUserUsesPlatformKey()
        {
            StewardTransportRequest? captured = null;
            var client = new StewardClient(new StewardClientConfig
            {
                BaseUrl = "https://api.example.test/",
                PlatformKey = "platform-key",
                Transport = (request, _) =>
                {
                    captured = request;
                    return Task.FromResult(new StewardTransportResponse { Status = 200, Body = "{\"ok\":true,\"data\":{\"id\":\"user-1\"}}" });
                }
            });

            var result = await client.CreateUserAsync(new CreateUserInput { TenantId = "tenant-1", Email = "u@example.com" });

            Assert(result!.Value.GetProperty("id").GetString() == "user-1", "unexpected user id");
            Assert(captured!.Method == "POST", "unexpected method");
            Assert(captured.Url.ToString() == "https://api.example.test/platform/users", "unexpected URL");
            Assert(captured.Headers["X-Steward-Platform-Key"] == "platform-key", "missing platform key");
            using var body = JsonDocument.Parse(captured.Body!);
            Assert(body.RootElement.GetProperty("tenantId").GetString() == "tenant-1", "unexpected tenant");
            Assert(body.RootElement.GetProperty("email").GetString() == "u@example.com", "unexpected email");
        }

        private static async Task TestBearerPushSubscriptionHelper()
        {
            StewardTransportRequest? captured = null;
            var client = new StewardClient(new StewardClientConfig
            {
                BaseUrl = "https://api.example.test",
                BearerToken = "user-token",
                Transport = (request, _) =>
                {
                    captured = request;
                    return Task.FromResult(new StewardTransportResponse { Status = 200, Body = "{\"ok\":true,\"data\":{\"subscription\":{\"id\":\"push-1\"}}}" });
                }
            });

            var result = await client.RegisterUserPushSubscriptionAsync(new PushSubscriptionInput
            {
                Provider = "expo",
                Token = "ExpoPushToken[abc123abc123abc123]"
            });

            Assert(result!.Value.GetProperty("subscription").GetProperty("id").GetString() == "push-1", "unexpected subscription id");
            Assert(captured!.Url.ToString() == "https://api.example.test/user/me/push-subscriptions", "unexpected push URL");
            Assert(captured.Headers["Authorization"] == "Bearer user-token", "missing bearer");
        }

        private static async Task TestSensitiveMutationsAreSignedAndIdempotent()
        {
            StewardTransportRequest? captured = null;
            var client = new StewardClient(new StewardClientConfig
            {
                BaseUrl = "https://api.example.test",
                AppId = "app-1",
                AppSecret = "secret-1",
                RequestSigningSecret = "signing-secret",
                RequestSigningKeyId = "key-1",
                Now = () => DateTimeOffset.FromUnixTimeSeconds(1_779_819_300),
                NewId = () => "idem-1",
                Transport = (request, _) =>
                {
                    captured = request;
                    return Task.FromResult(new StewardTransportResponse { Status = 200, Body = "{\"ok\":true,\"data\":{\"id\":\"ok\"}}" });
                }
            });

            await client.PostAsync("/user/me/push-subscriptions", new Dictionary<string, object>
            {
                ["provider"] = "fcm",
                ["token"] = "fcm-token-123456"
            });

            Assert(captured!.Headers["Authorization"] == "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("app-1:secret-1")), "missing basic auth");
            Assert(captured.Headers["X-Steward-App-Id"] == "app-1", "missing app id");
            Assert(captured.Headers["X-Steward-Request-Timestamp"] == "1779819300", "missing timestamp");
            Assert(captured.Headers["Idempotency-Key"] == "idem-1", "missing idempotency");
            Assert(captured.Headers["X-Steward-Signing-Key-Id"] == "key-1", "missing signing key id");
            Assert(captured.Headers["X-Steward-Signature"].StartsWith("v1=", StringComparison.Ordinal), "missing signature prefix");
            Assert(captured.Headers["X-Steward-Signature"].Length == 67, "bad signature length");
        }

        private static async Task TestApiErrorIncludesStatusAndPayload()
        {
            var client = new StewardClient(new StewardClientConfig
            {
                BaseUrl = "https://api.example.test",
                ApiKey = "tenant-key",
                Transport = (_, _) => Task.FromResult(new StewardTransportResponse { Status = 403, Body = "{\"ok\":false,\"error\":\"denied\"}" })
            });

            try
            {
                await client.GetAsync("/platform/users/user-1");
                throw new Exception("expected API error");
            }
            catch (StewardApiException error)
            {
                Assert(error.Status == 403, "unexpected error status");
                Assert(error.Message == "denied", "unexpected error message");
                Assert(error.ResponseData!.Value.GetProperty("ok").GetBoolean() == false, "unexpected error payload");
            }
        }

        private static void Assert(bool condition, string message)
        {
            if (!condition)
            {
                throw new Exception(message);
            }
        }
    }
}
