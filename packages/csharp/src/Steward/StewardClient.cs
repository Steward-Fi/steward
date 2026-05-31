using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace Steward
{
    public delegate Task<StewardTransportResponse> StewardTransport(StewardTransportRequest request, CancellationToken cancellationToken);

    public sealed class StewardClientConfig
    {
        public string BaseUrl { get; set; } = "";
        public string? ApiKey { get; set; }
        public string? BearerToken { get; set; }
        public string? PlatformKey { get; set; }
        public string? AppId { get; set; }
        public string? AppSecret { get; set; }
        public string? TenantId { get; set; }
        public string? RequestSigningSecret { get; set; }
        public string? RequestSigningKeyId { get; set; }
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);
        public StewardTransport? Transport { get; set; }
        public Func<DateTimeOffset> Now { get; set; } = () => DateTimeOffset.UtcNow;
        public Func<string> NewId { get; set; } = () => Guid.NewGuid().ToString();
    }

    public sealed class StewardTransportRequest
    {
        public string Method { get; set; } = "";
        public Uri Url { get; set; } = new Uri("http://localhost");
        public Dictionary<string, string> Headers { get; set; } = new Dictionary<string, string>();
        public string? Body { get; set; }
        public TimeSpan Timeout { get; set; }
    }

    public sealed class StewardTransportResponse
    {
        public int Status { get; set; }
        public Dictionary<string, string> Headers { get; set; } = new Dictionary<string, string>();
        public string Body { get; set; } = "";
    }

    public sealed class StewardApiException : Exception
    {
        public int Status { get; }
        public JsonElement? ResponseData { get; }

        public StewardApiException(string message, int status = 0, JsonElement? data = null) : base(message)
        {
            Status = status;
            ResponseData = data;
        }
    }

    public sealed class CreateUserInput
    {
        public string TenantId { get; set; } = "";
        public string? Email { get; set; }
        public string? WalletAddress { get; set; }
        public Dictionary<string, object>? CustomMetadata { get; set; }
    }

    public sealed class PushSubscriptionInput
    {
        public string Provider { get; set; } = "";
        public string Token { get; set; } = "";
        public string? Platform { get; set; }
        public string? TenantId { get; set; }
        public string? DeviceId { get; set; }
        public string? AppId { get; set; }
        public string? Locale { get; set; }
        public string? Timezone { get; set; }
        public Dictionary<string, object>? Metadata { get; set; }
    }

    public sealed class StewardClient
    {
        private static readonly string[] SensitivePrefixes = new[]
        {
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
            "/v1/condition_sets"
        };

        private readonly StewardClientConfig _config;
        private readonly StewardTransport _transport;

        public string BaseUrl { get; }

        public StewardClient(StewardClientConfig config)
        {
            if (string.IsNullOrWhiteSpace(config.BaseUrl))
            {
                throw new ArgumentException("BaseUrl is required", nameof(config));
            }

            _config = config;
            BaseUrl = config.BaseUrl.TrimEnd('/');
            _transport = config.Transport ?? DefaultTransportAsync;
        }

        public Task<JsonElement?> GetAsync(string path, Dictionary<string, string?>? query = null, Dictionary<string, string>? headers = null, CancellationToken cancellationToken = default)
        {
            return RequestAsync("GET", path, null, query, headers, null, cancellationToken);
        }

        public Task<JsonElement?> PostAsync(string path, object? body = null, Dictionary<string, string?>? query = null, Dictionary<string, string>? headers = null, string? idempotencyKey = null, CancellationToken cancellationToken = default)
        {
            return RequestAsync("POST", path, body, query, headers, idempotencyKey, cancellationToken);
        }

        public Task<JsonElement?> PatchAsync(string path, object? body = null, Dictionary<string, string?>? query = null, Dictionary<string, string>? headers = null, string? idempotencyKey = null, CancellationToken cancellationToken = default)
        {
            return RequestAsync("PATCH", path, body, query, headers, idempotencyKey, cancellationToken);
        }

        public Task<JsonElement?> DeleteAsync(string path, Dictionary<string, string?>? query = null, Dictionary<string, string>? headers = null, string? idempotencyKey = null, CancellationToken cancellationToken = default)
        {
            return RequestAsync("DELETE", path, null, query, headers, idempotencyKey, cancellationToken);
        }

        public async Task<JsonElement?> RequestAsync(string method, string path, object? body = null, Dictionary<string, string?>? query = null, Dictionary<string, string>? headers = null, string? idempotencyKey = null, CancellationToken cancellationToken = default)
        {
            var upperMethod = method.ToUpperInvariant();
            var canonicalPath = CanonicalPath(path);
            var url = new Uri(BaseUrl + canonicalPath + EncodeQuery(query));
            var bodyJson = body == null ? null : JsonSerializer.Serialize(body, JsonOptions());
            var requestHeaders = BuildHeaders(upperMethod, canonicalPath, bodyJson, headers, idempotencyKey);
            var response = await _transport(new StewardTransportRequest
            {
                Method = upperMethod,
                Url = url,
                Headers = requestHeaders,
                Body = bodyJson,
                Timeout = _config.Timeout
            }, cancellationToken).ConfigureAwait(false);

            return DecodeResponse(response.Status, response.Body);
        }

        public Task<JsonElement?> CreateUserAsync(CreateUserInput input, CancellationToken cancellationToken = default)
        {
            return PostAsync("/platform/users", input, cancellationToken: cancellationToken);
        }

        public Task<JsonElement?> GetUserAsync(string userId, CancellationToken cancellationToken = default)
        {
            return GetAsync("/platform/users/" + Uri.EscapeDataString(userId), cancellationToken: cancellationToken);
        }

        public Task<JsonElement?> LookupUserAsync(Dictionary<string, string?> query, CancellationToken cancellationToken = default)
        {
            return GetAsync("/platform/users/lookup", query, cancellationToken: cancellationToken);
        }

        public Task<JsonElement?> ListUserPushSubscriptionsAsync(CancellationToken cancellationToken = default)
        {
            return GetAsync("/user/me/push-subscriptions", cancellationToken: cancellationToken);
        }

        public Task<JsonElement?> RegisterUserPushSubscriptionAsync(PushSubscriptionInput input, CancellationToken cancellationToken = default)
        {
            return PostAsync("/user/me/push-subscriptions", input, cancellationToken: cancellationToken);
        }

        public Task<JsonElement?> RevokeUserPushSubscriptionAsync(string subscriptionId, CancellationToken cancellationToken = default)
        {
            return DeleteAsync("/user/me/push-subscriptions/" + Uri.EscapeDataString(subscriptionId), cancellationToken: cancellationToken);
        }

        private Dictionary<string, string> BuildHeaders(string method, string path, string? body, Dictionary<string, string>? headers, string? idempotencyKey)
        {
            var merged = new Dictionary<string, string>
            {
                ["Content-Type"] = "application/json",
                ["Accept"] = "application/json"
            };

            if (headers != null)
            {
                foreach (var pair in headers)
                {
                    merged[pair.Key] = pair.Value;
                }
            }

            if (!string.IsNullOrEmpty(_config.PlatformKey))
            {
                merged["X-Steward-Platform-Key"] = _config.PlatformKey!;
            }
            else if (!string.IsNullOrEmpty(_config.BearerToken))
            {
                merged["Authorization"] = "Bearer " + _config.BearerToken;
            }
            else if (!string.IsNullOrEmpty(_config.AppId) && !string.IsNullOrEmpty(_config.AppSecret))
            {
                merged["Authorization"] = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(_config.AppId + ":" + _config.AppSecret));
                merged["X-Steward-App-Id"] = _config.AppId!;
            }
            else if (!string.IsNullOrEmpty(_config.ApiKey))
            {
                merged["X-Steward-Key"] = _config.ApiKey!;
            }

            if (!string.IsNullOrEmpty(_config.TenantId))
            {
                merged["X-Steward-Tenant"] = _config.TenantId!;
            }

            if (!string.IsNullOrEmpty(_config.RequestSigningSecret) && IsSensitiveMutation(path, method))
            {
                if (!merged.TryGetValue("X-Steward-Request-Timestamp", out var timestamp))
                {
                    timestamp = _config.Now().ToUnixTimeSeconds().ToString();
                    merged["X-Steward-Request-Timestamp"] = timestamp;
                }

                if (!merged.TryGetValue("Idempotency-Key", out var idem))
                {
                    idem = idempotencyKey ?? _config.NewId();
                    merged["Idempotency-Key"] = idem;
                }

                if (!string.IsNullOrEmpty(_config.RequestSigningKeyId) && !merged.ContainsKey("X-Steward-Signing-Key-Id"))
                {
                    merged["X-Steward-Signing-Key-Id"] = _config.RequestSigningKeyId!;
                }

                using var sha256 = SHA256.Create();
                var bodyHash = Hex(sha256.ComputeHash(Encoding.UTF8.GetBytes(body ?? "")));
                var canonical = string.Join("\n", new[] { method, path, timestamp, idem, bodyHash });
                using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(_config.RequestSigningSecret!));
                merged["X-Steward-Signature"] = "v1=" + Hex(hmac.ComputeHash(Encoding.UTF8.GetBytes(canonical)));
            }

            return merged;
        }

        private static JsonElement? DecodeResponse(int status, string body)
        {
            JsonElement? payload = null;
            if (!string.IsNullOrEmpty(body))
            {
                using var document = JsonDocument.Parse(body);
                payload = document.RootElement.Clone();
            }

            if (status >= 400 || (payload.HasValue && payload.Value.TryGetProperty("ok", out var ok) && ok.ValueKind == JsonValueKind.False))
            {
                var message = payload.HasValue && payload.Value.TryGetProperty("error", out var error) ? error.GetString() : null;
                throw new StewardApiException(message ?? "Request failed with status " + status, status, payload);
            }

            if (payload.HasValue && payload.Value.TryGetProperty("data", out var data))
            {
                return data.Clone();
            }

            return payload;
        }

        private static async Task<StewardTransportResponse> DefaultTransportAsync(StewardTransportRequest request, CancellationToken cancellationToken)
        {
            using var http = new HttpClient { Timeout = request.Timeout };
            using var message = new HttpRequestMessage(new HttpMethod(request.Method), request.Url);
            foreach (var pair in request.Headers)
            {
                message.Headers.TryAddWithoutValidation(pair.Key, pair.Value);
            }
            if (request.Body != null)
            {
                message.Content = new StringContent(request.Body, Encoding.UTF8, "application/json");
            }
            using var response = await http.SendAsync(message, cancellationToken).ConfigureAwait(false);
            return new StewardTransportResponse
            {
                Status = (int)response.StatusCode,
                Body = await response.Content.ReadAsStringAsync().ConfigureAwait(false)
            };
        }

        private static string CanonicalPath(string path)
        {
            return path.StartsWith("/", StringComparison.Ordinal) ? path : "/" + path;
        }

        private static string EncodeQuery(Dictionary<string, string?>? query)
        {
            if (query == null || query.Count == 0)
            {
                return "";
            }

            var parts = new List<string>();
            foreach (var pair in query)
            {
                if (pair.Value == null)
                {
                    continue;
                }
                parts.Add(Uri.EscapeDataString(pair.Key) + "=" + Uri.EscapeDataString(pair.Value));
            }

            return parts.Count == 0 ? "" : "?" + string.Join("&", parts);
        }

        private static bool IsSensitiveMutation(string path, string method)
        {
            if (method != "POST" && method != "PUT" && method != "PATCH" && method != "DELETE")
            {
                return false;
            }

            foreach (var prefix in SensitivePrefixes)
            {
                if (path.StartsWith(prefix, StringComparison.Ordinal))
                {
                    return true;
                }
            }

            return false;
        }

        private static string Hex(byte[] bytes)
        {
            var builder = new StringBuilder(bytes.Length * 2);
            foreach (var b in bytes)
            {
                builder.Append(b.ToString("x2"));
            }
            return builder.ToString();
        }

        private static JsonSerializerOptions JsonOptions()
        {
            return new JsonSerializerOptions
            {
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            };
        }
    }
}
