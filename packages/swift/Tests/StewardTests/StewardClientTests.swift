import Foundation
import XCTest
@testable import Steward

final class StewardClientTests: XCTestCase {
    func testCreateUserUsesPlatformKey() throws {
        var capturedMethod = ""
        var capturedURL: URL?
        var capturedHeaders: [String: String] = [:]
        var capturedBody: StewardJSON = [:]
        let client = try StewardClient(config: StewardConfig(
            baseURL: "https://api.example.test/",
            platformKey: "platform-key",
            transport: { method, url, headers, body, _ in
                capturedMethod = method
                capturedURL = url
                capturedHeaders = headers
                capturedBody = try JSONSerialization.jsonObject(with: body ?? Data()) as! StewardJSON
                return (200, [:], Data(#"{"ok":true,"data":{"id":"user-1"}}"#.utf8))
            }
        ))

        let user = try client.createUser(tenantID: "tenant-1", email: "u@example.com")

        XCTAssertEqual(user["id"] as? String, "user-1")
        XCTAssertEqual(capturedMethod, "POST")
        XCTAssertEqual(capturedURL?.absoluteString, "https://api.example.test/platform/users")
        XCTAssertEqual(capturedHeaders["X-Steward-Platform-Key"], "platform-key")
        XCTAssertEqual(capturedBody["tenantId"] as? String, "tenant-1")
        XCTAssertEqual(capturedBody["email"] as? String, "u@example.com")
    }

    func testBearerPushSubscriptionHelper() throws {
        var capturedHeaders: [String: String] = [:]
        var capturedURL: URL?
        let client = try StewardClient(config: StewardConfig(
            baseURL: "https://api.example.test",
            bearerToken: "user-token",
            transport: { _, url, headers, _, _ in
                capturedURL = url
                capturedHeaders = headers
                return (200, [:], Data(#"{"ok":true,"data":{"subscription":{"id":"push-1"}}}"#.utf8))
            }
        ))

        let result = try client.registerUserPushSubscription([
            "provider": "expo",
            "token": "ExpoPushToken[abc123abc123abc123]",
        ])

        let subscription = result["subscription"] as? StewardJSON
        XCTAssertEqual(subscription?["id"] as? String, "push-1")
        XCTAssertEqual(capturedURL?.absoluteString, "https://api.example.test/user/me/push-subscriptions")
        XCTAssertEqual(capturedHeaders["Authorization"], "Bearer user-token")
    }

    func testSensitiveMutationsAreSignedAndIdempotent() throws {
        var capturedHeaders: [String: String] = [:]
        let client = try StewardClient(config: StewardConfig(
            baseURL: "https://api.example.test",
            appID: "app-1",
            appSecret: "secret-1",
            requestSigningSecret: "signing-secret",
            requestSigningKeyID: "key-1",
            transport: { _, _, headers, _, _ in
                capturedHeaders = headers
                return (200, [:], Data(#"{"ok":true,"data":{"id":"ok"}}"#.utf8))
            },
            now: { Date(timeIntervalSince1970: 1_779_819_300) },
            newID: { "idem-1" }
        ))

        _ = try client.post("/user/me/push-subscriptions", body: [
            "provider": "fcm",
            "token": "fcm-token-123456",
        ])

        XCTAssertEqual(capturedHeaders["Authorization"], "Basic \(Data("app-1:secret-1".utf8).base64EncodedString())")
        XCTAssertEqual(capturedHeaders["X-Steward-App-Id"], "app-1")
        XCTAssertEqual(capturedHeaders["X-Steward-Request-Timestamp"], "1779819300")
        XCTAssertEqual(capturedHeaders["Idempotency-Key"], "idem-1")
        XCTAssertEqual(capturedHeaders["X-Steward-Signing-Key-Id"], "key-1")
        XCTAssertEqual(capturedHeaders["X-Steward-Signature"]?.hasPrefix("v1="), true)
        XCTAssertEqual(capturedHeaders["X-Steward-Signature"]?.count, 67)
    }

    func testAPIErrorIncludesStatusAndPayload() throws {
        let client = try StewardClient(config: StewardConfig(
            baseURL: "https://api.example.test",
            apiKey: "tenant-key",
            transport: { _, _, _, _, _ in
                (403, [:], Data(#"{"ok":false,"error":"denied"}"#.utf8))
            }
        ))

        do {
            _ = try client.get("/platform/users/user-1")
            XCTFail("expected error")
        } catch let error as StewardAPIError {
            XCTAssertEqual(error.status, 403)
            XCTAssertEqual(error.message, "denied")
            XCTAssertEqual(error.data?["ok"] as? Bool, false)
        }
    }

    func testPlaintextNonLoopbackBaseURLRejected() throws {
        // SEC-200: credentials must never travel to a plaintext non-loopback
        // endpoint unless the operator explicitly opts out.
        for baseURL in ["http://api.example.test", "http://192.168.1.10:3200", "ftp://api.example.test", "not-a-url"] {
            XCTAssertThrowsError(try StewardClient(config: StewardConfig(baseURL: baseURL, apiKey: "tenant-key")), baseURL) { error in
                guard let apiError = error as? StewardAPIError else {
                    return XCTFail("expected StewardAPIError, got \(error)")
                }
                XCTAssertTrue(apiError.message.contains("HTTPS") || apiError.message.contains("absolute URL"), apiError.message)
            }
        }

        for baseURL in ["https://api.example.test", "http://localhost:3200", "http://127.0.0.1:3200", "http://[::1]:3200"] {
            XCTAssertNoThrow(try StewardClient(config: StewardConfig(baseURL: baseURL, apiKey: "tenant-key")), baseURL)
        }
    }

    func testAllowInsecureBaseURLOptsOut() throws {
        XCTAssertNoThrow(try StewardClient(config: StewardConfig(
            baseURL: "http://api.example.test",
            apiKey: "tenant-key",
            allowInsecureBaseURL: true
        )))
    }
}

