# frozen_string_literal: true

require "base64"
require "digest"
require "json"
require "net/http"
require "openssl"
require "securerandom"
require "time"
require "uri"

module Steward
  class APIError < StandardError
    attr_reader :status, :data

    def initialize(message, status: 0, data: nil)
      super(message)
      @status = status
      @data = data
    end
  end

  class Client
    SENSITIVE_PREFIXES = [
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
    ].freeze

    MUTATING_METHODS = %w[POST PUT PATCH DELETE].freeze

    attr_reader :base_url

    def initialize(
      base_url:,
      api_key: nil,
      bearer_token: nil,
      platform_key: nil,
      app_id: nil,
      app_secret: nil,
      tenant_id: nil,
      request_signing_secret: nil,
      request_signing_key_id: nil,
      timeout: 30,
      transport: nil,
      now: nil,
      new_id: nil
    )
      raise ArgumentError, "base_url is required" if base_url.to_s.strip.empty?

      @base_url = base_url.to_s.sub(%r{/+\z}, "")
      @api_key = api_key
      @bearer_token = bearer_token
      @platform_key = platform_key
      @app_id = app_id
      @app_secret = app_secret
      @tenant_id = tenant_id
      @request_signing_secret = request_signing_secret
      @request_signing_key_id = request_signing_key_id
      @timeout = timeout
      @transport = transport || method(:default_transport)
      @now = now || -> { Time.now }
      @new_id = new_id || -> { SecureRandom.uuid }
    end

    def get(path, options = {})
      query = options[:query]
      headers = options[:headers]
      request("GET", path, query: query, headers: headers)
    end

    def post(path, body = nil, options = {})
      query = options[:query]
      headers = options[:headers]
      idempotency_key = options[:idempotency_key]
      request("POST", path, body: body, query: query, headers: headers, idempotency_key: idempotency_key)
    end

    def patch(path, body = nil, options = {})
      query = options[:query]
      headers = options[:headers]
      idempotency_key = options[:idempotency_key]
      request("PATCH", path, body: body, query: query, headers: headers, idempotency_key: idempotency_key)
    end

    def delete(path, options = {})
      query = options[:query]
      headers = options[:headers]
      idempotency_key = options[:idempotency_key]
      request("DELETE", path, query: query, headers: headers, idempotency_key: idempotency_key)
    end

    def request(method, path, body: nil, query: nil, headers: nil, idempotency_key: nil)
      method = method.to_s.upcase
      path = canonical_path(path)
      encoded_query = encode_query(query)
      uri = URI.parse("#{@base_url}#{path}#{encoded_query}")
      raw_body = body.nil? ? nil : JSON.generate(body)
      request_headers = build_headers(method, path, raw_body, headers || {}, idempotency_key)
      status, response_headers, response_body = @transport.call(method, uri, request_headers, raw_body, @timeout)
      decode_response(status.to_i, response_headers, response_body)
    end

    def create_user(tenant_id:, email: nil, wallet_address: nil, custom_metadata: nil)
      body = { tenantId: tenant_id }
      body[:email] = email if email
      body[:walletAddress] = wallet_address if wallet_address
      body[:customMetadata] = custom_metadata unless custom_metadata.nil?
      post("/platform/users", body)
    end

    def get_user(user_id)
      get("/platform/users/#{escape_path(user_id)}")
    end

    def lookup_user(query = {})
      get("/platform/users/lookup", query: query)
    end

    def list_user_push_subscriptions
      get("/user/me/push-subscriptions")
    end

    def register_user_push_subscription(subscription)
      post("/user/me/push-subscriptions", subscription)
    end

    def revoke_user_push_subscription(subscription_id)
      delete("/user/me/push-subscriptions/#{escape_path(subscription_id)}")
    end

    private

    def default_transport(method, uri, headers, body, timeout)
      klass = Net::HTTP.const_get(method.capitalize)
      request = klass.new(uri)
      headers.each { |key, value| request[key] = value }
      request.body = body if body
      response = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == "https", read_timeout: timeout, open_timeout: timeout) do |http|
        http.request(request)
      end
      [response.code.to_i, response.each_header.to_h, response.body.to_s]
    rescue StandardError => e
      raise APIError.new(e.message)
    end

    def build_headers(method, path, body, headers, idempotency_key)
      merged = {
        "Content-Type" => "application/json",
        "Accept" => "application/json"
      }.merge(stringify_keys(headers))

      if present?(@platform_key)
        merged["X-Steward-Platform-Key"] = @platform_key
      elsif present?(@bearer_token)
        merged["Authorization"] = "Bearer #{@bearer_token}"
      elsif present?(@app_id) && present?(@app_secret)
        merged["Authorization"] = "Basic #{Base64.strict_encode64("#{@app_id}:#{@app_secret}")}"
        merged["X-Steward-App-Id"] = @app_id
      elsif present?(@api_key)
        merged["X-Steward-Key"] = @api_key
      end

      merged["X-Steward-Tenant"] = @tenant_id if present?(@tenant_id)

      if present?(@request_signing_secret) && sensitive_mutation?(path, method)
        timestamp = merged["X-Steward-Request-Timestamp"] ||= @now.call.to_i.to_s
        idem = merged["Idempotency-Key"] ||= idempotency_key || @new_id.call
        merged["X-Steward-Signing-Key-Id"] ||= @request_signing_key_id if present?(@request_signing_key_id)
        body_hash = Digest::SHA256.hexdigest(body.to_s)
        canonical = [method, path, timestamp, idem, body_hash].join("\n")
        signature = OpenSSL::HMAC.hexdigest("SHA256", @request_signing_secret, canonical)
        merged["X-Steward-Signature"] = "v1=#{signature}"
      end

      merged
    end

    def decode_response(status, _headers, body)
      payload = body.to_s.empty? ? nil : JSON.parse(body)
      if status >= 400 || (payload.is_a?(Hash) && payload["ok"] == false)
        message = payload.is_a?(Hash) ? payload["error"] : nil
        raise APIError.new(message || "Request failed with status #{status}", status: status, data: payload)
      end

      return nil if payload.nil?
      return payload["data"] if payload.is_a?(Hash) && payload.key?("data")

      payload
    rescue JSON::ParserError => e
      raise APIError.new("Received invalid JSON from Steward API", status: status, data: e.message)
    end

    def canonical_path(path)
      path = path.to_s
      path.start_with?("/") ? path : "/#{path}"
    end

    def encode_query(query)
      return "" if query.nil? || query.empty?

      clean = query.each_with_object({}) do |(key, value), memo|
        memo[key] = value unless value.nil?
      end
      clean.empty? ? "" : "?#{URI.encode_www_form(clean)}"
    end

    def escape_path(value)
      URI.encode_www_form_component(value.to_s)
    end

    def stringify_keys(hash)
      hash.each_with_object({}) { |(key, value), memo| memo[key.to_s] = value }
    end

    def present?(value)
      !value.nil? && value != ""
    end

    def sensitive_mutation?(path, method)
      MUTATING_METHODS.include?(method) && SENSITIVE_PREFIXES.any? { |prefix| path.start_with?(prefix) }
    end
  end
end
