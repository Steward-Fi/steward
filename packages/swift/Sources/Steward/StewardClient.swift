import CryptoKit
import Foundation

public typealias StewardJSON = [String: Any]
public typealias StewardTransport = (String, URL, [String: String], Data?, TimeInterval) throws -> (Int, [String: String], Data)

public struct StewardConfig {
    public var baseURL: String
    public var apiKey: String?
    public var bearerToken: String?
    public var platformKey: String?
    public var appID: String?
    public var appSecret: String?
    public var tenantID: String?
    public var requestSigningSecret: String?
    public var requestSigningKeyID: String?
    public var timeout: TimeInterval
    public var transport: StewardTransport?
    public var now: () -> Date
    public var newID: () -> String

    public init(
        baseURL: String,
        apiKey: String? = nil,
        bearerToken: String? = nil,
        platformKey: String? = nil,
        appID: String? = nil,
        appSecret: String? = nil,
        tenantID: String? = nil,
        requestSigningSecret: String? = nil,
        requestSigningKeyID: String? = nil,
        timeout: TimeInterval = 30,
        transport: StewardTransport? = nil,
        now: @escaping () -> Date = Date.init,
        newID: @escaping () -> String = { UUID().uuidString }
    ) {
        self.baseURL = baseURL
        self.apiKey = apiKey
        self.bearerToken = bearerToken
        self.platformKey = platformKey
        self.appID = appID
        self.appSecret = appSecret
        self.tenantID = tenantID
        self.requestSigningSecret = requestSigningSecret
        self.requestSigningKeyID = requestSigningKeyID
        self.timeout = timeout
        self.transport = transport
        self.now = now
        self.newID = newID
    }
}

public struct StewardAPIError: Error {
    public let status: Int
    public let message: String
    public let data: StewardJSON?
}

public final class StewardClient {
    private let config: StewardConfig
    public let baseURL: String

    private static let sensitivePrefixes = [
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
        "/v1/condition_sets",
    ]

    public init(config: StewardConfig) throws {
        let trimmed = config.baseURL.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw StewardAPIError(status: 0, message: "baseURL is required", data: nil)
        }
        self.config = config
        self.baseURL = String(trimmed.drop(whileTrailing: { $0 == "/" }))
    }

    public func get(_ path: String, query: [String: String?] = [:], headers: [String: String] = [:]) throws -> Any? {
        try request("GET", path, query: query, headers: headers)
    }

    public func post(_ path: String, body: Any? = nil, query: [String: String?] = [:], headers: [String: String] = [:], idempotencyKey: String? = nil) throws -> Any? {
        try request("POST", path, body: body, query: query, headers: headers, idempotencyKey: idempotencyKey)
    }

    public func patch(_ path: String, body: Any? = nil, query: [String: String?] = [:], headers: [String: String] = [:], idempotencyKey: String? = nil) throws -> Any? {
        try request("PATCH", path, body: body, query: query, headers: headers, idempotencyKey: idempotencyKey)
    }

    public func delete(_ path: String, query: [String: String?] = [:], headers: [String: String] = [:], idempotencyKey: String? = nil) throws -> Any? {
        try request("DELETE", path, query: query, headers: headers, idempotencyKey: idempotencyKey)
    }

    public func request(_ method: String, _ path: String, body: Any? = nil, query: [String: String?] = [:], headers: [String: String] = [:], idempotencyKey: String? = nil) throws -> Any? {
        let upperMethod = method.uppercased()
        let canonical = canonicalPath(path)
        guard var components = URLComponents(string: baseURL + canonical) else {
            throw StewardAPIError(status: 0, message: "invalid URL", data: nil)
        }
        let queryItems = query.compactMap { key, value -> URLQueryItem? in
            guard let value else { return nil }
            return URLQueryItem(name: key, value: value)
        }
        if !queryItems.isEmpty {
            components.queryItems = queryItems
        }
        guard let url = components.url else {
            throw StewardAPIError(status: 0, message: "invalid URL", data: nil)
        }
        let bodyData = try encodeBody(body)
        let requestHeaders = buildHeaders(method: upperMethod, path: canonical, body: bodyData, headers: headers, idempotencyKey: idempotencyKey)
        let transport = config.transport ?? defaultTransport
        let (status, responseHeaders, responseBody) = try transport(upperMethod, url, requestHeaders, bodyData, config.timeout)
        return try decodeResponse(status: status, headers: responseHeaders, body: responseBody)
    }

    public func createUser(tenantID: String, email: String? = nil, walletAddress: String? = nil, customMetadata: StewardJSON? = nil) throws -> StewardJSON {
        var body: StewardJSON = ["tenantId": tenantID]
        if let email { body["email"] = email }
        if let walletAddress { body["walletAddress"] = walletAddress }
        if let customMetadata { body["customMetadata"] = customMetadata }
        return try requireObject(post("/platform/users", body: body))
    }

    public func getUser(_ userID: String) throws -> StewardJSON {
        try requireObject(get("/platform/users/\(escapePath(userID))"))
    }

    public func lookupUser(query: [String: String?]) throws -> StewardJSON {
        try requireObject(get("/platform/users/lookup", query: query))
    }

    public func listUserPushSubscriptions() throws -> StewardJSON {
        try requireObject(get("/user/me/push-subscriptions"))
    }

    public func registerUserPushSubscription(_ subscription: StewardJSON) throws -> StewardJSON {
        try requireObject(post("/user/me/push-subscriptions", body: subscription))
    }

    public func revokeUserPushSubscription(_ subscriptionID: String) throws -> StewardJSON {
        try requireObject(delete("/user/me/push-subscriptions/\(escapePath(subscriptionID))"))
    }

    private func buildHeaders(method: String, path: String, body: Data?, headers: [String: String], idempotencyKey: String?) -> [String: String] {
        var merged = [
            "Content-Type": "application/json",
            "Accept": "application/json",
        ]
        headers.forEach { merged[$0.key] = $0.value }

        if let platformKey = nonEmpty(config.platformKey) {
            merged["X-Steward-Platform-Key"] = platformKey
        } else if let bearerToken = nonEmpty(config.bearerToken) {
            merged["Authorization"] = "Bearer \(bearerToken)"
        } else if let appID = nonEmpty(config.appID), let appSecret = nonEmpty(config.appSecret) {
            let encoded = Data("\(appID):\(appSecret)".utf8).base64EncodedString()
            merged["Authorization"] = "Basic \(encoded)"
            merged["X-Steward-App-Id"] = appID
        } else if let apiKey = nonEmpty(config.apiKey) {
            merged["X-Steward-Key"] = apiKey
        }
        if let tenantID = nonEmpty(config.tenantID) {
            merged["X-Steward-Tenant"] = tenantID
        }

        if let secret = nonEmpty(config.requestSigningSecret), isSensitiveMutation(path: path, method: method) {
            let timestamp = merged["X-Steward-Request-Timestamp"] ?? String(Int(config.now().timeIntervalSince1970))
            merged["X-Steward-Request-Timestamp"] = timestamp
            let idem = merged["Idempotency-Key"] ?? idempotencyKey ?? config.newID()
            merged["Idempotency-Key"] = idem
            if let keyID = nonEmpty(config.requestSigningKeyID), merged["X-Steward-Signing-Key-Id"] == nil {
                merged["X-Steward-Signing-Key-Id"] = keyID
            }
            let bodyHash = SHA256.hash(data: body ?? Data()).hexString
            let canonical = [method, path, timestamp, idem, bodyHash].joined(separator: "\n")
            let signature = HMAC<SHA256>.authenticationCode(for: Data(canonical.utf8), using: SymmetricKey(data: Data(secret.utf8))).hexString
            merged["X-Steward-Signature"] = "v1=\(signature)"
        }

        return merged
    }

    private func defaultTransport(method: String, url: URL, headers: [String: String], body: Data?, timeout: TimeInterval) throws -> (Int, [String: String], Data) {
        var request = URLRequest(url: url, timeoutInterval: timeout)
        request.httpMethod = method
        request.httpBody = body
        headers.forEach { request.setValue($0.value, forHTTPHeaderField: $0.key) }
        let semaphore = DispatchSemaphore(value: 0)
        var result: Result<(Int, [String: String], Data), Error>?
        URLSession.shared.dataTask(with: request) { data, response, error in
            defer { semaphore.signal() }
            if let error {
                result = .failure(error)
                return
            }
            let http = response as? HTTPURLResponse
            let responseHeaders = http?.allHeaderFields.reduce(into: [String: String]()) { memo, entry in
                memo[String(describing: entry.key)] = String(describing: entry.value)
            } ?? [:]
            result = .success((http?.statusCode ?? 0, responseHeaders, data ?? Data()))
        }.resume()
        semaphore.wait()
        return try result!.get()
    }

    private func decodeResponse(status: Int, headers _: [String: String], body: Data) throws -> Any? {
        let payload = body.isEmpty ? nil : try JSONSerialization.jsonObject(with: body)
        let object = payload as? StewardJSON
        if status >= 400 || object?["ok"] as? Bool == false {
            throw StewardAPIError(status: status, message: object?["error"] as? String ?? "Request failed with status \(status)", data: object)
        }
        if let object, let data = object["data"] {
            return data
        }
        return payload
    }

    private func encodeBody(_ body: Any?) throws -> Data? {
        guard let body else { return nil }
        return try JSONSerialization.data(withJSONObject: body)
    }

    private func requireObject(_ value: Any?) throws -> StewardJSON {
        guard let object = value as? StewardJSON else {
            throw StewardAPIError(status: 0, message: "Expected JSON object response", data: nil)
        }
        return object
    }

    private func canonicalPath(_ path: String) -> String {
        path.hasPrefix("/") ? path : "/\(path)"
    }

    private func escapePath(_ value: String) -> String {
        value.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? value
    }

    private func nonEmpty(_ value: String?) -> String? {
        guard let value, !value.isEmpty else { return nil }
        return value
    }

    private func isSensitiveMutation(path: String, method: String) -> Bool {
        ["POST", "PUT", "PATCH", "DELETE"].contains(method) && Self.sensitivePrefixes.contains { path.hasPrefix($0) }
    }
}

private extension String {
    func drop(whileTrailing shouldDrop: (Character) -> Bool) -> String {
        var result = self
        while let last = result.last, shouldDrop(last) {
            result.removeLast()
        }
        return result
    }
}

private extension Digest {
    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}

private extension HMAC<SHA256>.MAC {
    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
