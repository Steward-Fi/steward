# frozen_string_literal: true

require "base64"
require "json"
require "minitest/autorun"
require_relative "../lib/steward"

class StewardClientTest < Minitest::Test
  def test_create_user_uses_platform_key
    captured = {}
    client = Steward::Client.new(
      base_url: "https://api.example.test/",
      platform_key: "platform-key",
      transport: lambda do |method, uri, headers, body, _timeout|
        captured[:method] = method
        captured[:uri] = uri
        captured[:headers] = headers
        captured[:body] = JSON.parse(body)
        [200, {}, '{"ok":true,"data":{"id":"user-1"}}']
      end
    )

    user = client.create_user(tenant_id: "tenant-1", email: "u@example.com")

    assert_equal "user-1", user["id"]
    assert_equal "POST", captured[:method]
    assert_equal "https://api.example.test/platform/users", captured[:uri].to_s
    assert_equal "platform-key", captured[:headers]["X-Steward-Platform-Key"]
    assert_equal "tenant-1", captured[:body]["tenantId"]
    assert_equal "u@example.com", captured[:body]["email"]
  end

  def test_bearer_push_subscription_helper
    captured = {}
    client = Steward::Client.new(
      base_url: "https://api.example.test",
      bearer_token: "user-token",
      transport: lambda do |method, uri, headers, body, _timeout|
        captured[:method] = method
        captured[:uri] = uri
        captured[:headers] = headers
        captured[:body] = JSON.parse(body)
        [200, {}, '{"ok":true,"data":{"subscription":{"id":"push-1"}}}']
      end
    )

    result = client.register_user_push_subscription(provider: "expo", token: "ExpoPushToken[abc123abc123abc123]")

    assert_equal "push-1", result["subscription"]["id"]
    assert_equal "POST", captured[:method]
    assert_equal "https://api.example.test/user/me/push-subscriptions", captured[:uri].to_s
    assert_equal "Bearer user-token", captured[:headers]["Authorization"]
    assert_equal "expo", captured[:body]["provider"]
  end

  def test_sensitive_mutations_are_signed_and_idempotent
    captured = {}
    client = Steward::Client.new(
      base_url: "https://api.example.test",
      app_id: "app-1",
      app_secret: "secret-1",
      request_signing_secret: "signing-secret",
      request_signing_key_id: "key-1",
      now: -> { Time.at(1_779_819_300) },
      new_id: -> { "idem-1" },
      transport: lambda do |method, uri, headers, body, _timeout|
        captured[:method] = method
        captured[:uri] = uri
        captured[:headers] = headers
        captured[:body] = body
        [200, {}, '{"ok":true,"data":{"id":"ok"}}']
      end
    )

    client.post("/user/me/push-subscriptions", provider: "fcm", token: "fcm-token-123456")

    assert_equal "Basic #{Base64.strict_encode64("app-1:secret-1")}", captured[:headers]["Authorization"]
    assert_equal "app-1", captured[:headers]["X-Steward-App-Id"]
    assert_equal "1779819300", captured[:headers]["X-Steward-Request-Timestamp"]
    assert_equal "idem-1", captured[:headers]["Idempotency-Key"]
    assert_equal "key-1", captured[:headers]["X-Steward-Signing-Key-Id"]
    assert_match(/\Av1=[a-f0-9]{64}\z/, captured[:headers]["X-Steward-Signature"])
  end

  def test_api_error_includes_status_and_payload
    client = Steward::Client.new(
      base_url: "https://api.example.test",
      api_key: "tenant-key",
      transport: lambda do |_method, _uri, _headers, _body, _timeout|
        [403, {}, '{"ok":false,"error":"denied"}']
      end
    )

    error = assert_raises(Steward::APIError) do
      client.get("/platform/users/user-1")
    end

    assert_equal "denied", error.message
    assert_equal 403, error.status
    assert_equal false, error.data["ok"]
  end
end

