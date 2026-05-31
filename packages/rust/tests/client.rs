use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use serde_json::{json, Value};
use steward_sdk::{
    ApiError, Client, Config, CreateUserInput, Error, PushSubscriptionInput,
    PushSubscriptionResult, Request, Response, Transport,
};

#[derive(Clone)]
struct CaptureTransport {
    status: u16,
    payload: Value,
    requests: Arc<Mutex<Vec<Request>>>,
}

impl CaptureTransport {
    fn new(payload: Value) -> Self {
        Self {
            status: 200,
            payload,
            requests: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn with_status(status: u16, payload: Value) -> Self {
        Self {
            status,
            payload,
            requests: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn last_request(&self) -> Request {
        self.requests.lock().unwrap().last().unwrap().clone()
    }
}

impl Transport for CaptureTransport {
    fn send(&self, request: Request) -> Result<Response, Error> {
        self.requests.lock().unwrap().push(request);
        Ok(Response {
            status: self.status,
            headers: BTreeMap::from([("content-type".to_string(), "application/json".to_string())]),
            body: serde_json::to_vec(&self.payload).unwrap(),
        })
    }
}

#[test]
fn platform_key_create_user_request() {
    let transport = CaptureTransport::new(json!({"ok": true, "data": {"id": "user-1"}}));
    let client = Client::new(Config {
        base_url: "https://api.example.test/".to_string(),
        platform_key: Some("platform-key".to_string()),
        transport: Some(Arc::new(transport.clone())),
        ..Config::default()
    })
    .unwrap();

    let user = client
        .create_user(CreateUserInput {
            tenant_id: "tenant-1".to_string(),
            email: Some("u@example.com".to_string()),
            ..CreateUserInput::default()
        })
        .unwrap();

    let request = transport.last_request();
    let body: Value = serde_json::from_slice(request.body.as_ref().unwrap()).unwrap();
    assert_eq!(user.get("id").unwrap(), "user-1");
    assert_eq!(request.url, "https://api.example.test/platform/users");
    assert_eq!(request.method, "POST");
    assert_eq!(
        request.headers.get("X-Steward-Platform-Key").unwrap(),
        "platform-key"
    );
    assert_eq!(
        body,
        json!({"tenantId": "tenant-1", "email": "u@example.com"})
    );
}

#[test]
fn bearer_push_subscription_helper() {
    let transport = CaptureTransport::new(json!({
        "ok": true,
        "data": {"subscription": {"id": "push-1"}}
    }));
    let client = Client::new(Config {
        base_url: "https://api.example.test".to_string(),
        bearer_token: Some("user-token".to_string()),
        transport: Some(Arc::new(transport.clone())),
        ..Config::default()
    })
    .unwrap();

    let result: PushSubscriptionResult = client
        .register_user_push_subscription(PushSubscriptionInput {
            provider: "expo".to_string(),
            token: "ExpoPushToken[abc123abc123abc123]".to_string(),
            ..PushSubscriptionInput::default()
        })
        .unwrap();

    let request = transport.last_request();
    let body: Value = serde_json::from_slice(request.body.as_ref().unwrap()).unwrap();
    assert_eq!(result.subscription.get("id").unwrap(), "push-1");
    assert_eq!(
        request.url,
        "https://api.example.test/user/me/push-subscriptions"
    );
    assert_eq!(
        request.headers.get("Authorization").unwrap(),
        "Bearer user-token"
    );
    assert_eq!(body.get("provider").unwrap(), "expo");
}

#[test]
fn app_credentials_sensitive_mutations_are_signed_and_idempotent() {
    let transport = CaptureTransport::new(json!({
        "ok": true,
        "data": {"subscription": {"id": "ok"}}
    }));
    let client = Client::new(Config {
        base_url: "https://api.example.test".to_string(),
        app_id: Some("app-1".to_string()),
        app_secret: Some("secret-1".to_string()),
        request_signing_secret: Some("signing-secret".to_string()),
        request_signing_key_id: Some("key-1".to_string()),
        transport: Some(Arc::new(transport.clone())),
        now: Some(Arc::new(|| UNIX_EPOCH + Duration::from_secs(1_779_819_300))),
        new_id: Some(Arc::new(|| "idem-1".to_string())),
        ..Config::default()
    })
    .unwrap();

    client
        .register_user_push_subscription(PushSubscriptionInput {
            provider: "fcm".to_string(),
            token: "fcm-token-123456".to_string(),
            ..PushSubscriptionInput::default()
        })
        .unwrap();

    let request = transport.last_request();
    assert!(request
        .headers
        .get("Authorization")
        .unwrap()
        .starts_with("Basic "));
    assert_eq!(request.headers.get("X-Steward-App-Id").unwrap(), "app-1");
    assert_eq!(
        request.headers.get("X-Steward-Request-Timestamp").unwrap(),
        "1779819300"
    );
    assert_eq!(request.headers.get("Idempotency-Key").unwrap(), "idem-1");
    assert_eq!(
        request.headers.get("X-Steward-Signing-Key-Id").unwrap(),
        "key-1"
    );
    let signature = request.headers.get("X-Steward-Signature").unwrap();
    assert!(signature.starts_with("v1="));
    assert_eq!(signature.len(), 67);
}

#[test]
fn tenant_api_key_and_tenant_header_are_applied() {
    let transport = CaptureTransport::new(json!({"ok": true, "data": {"id": "user-1"}}));
    let client = Client::new(Config {
        base_url: "https://api.example.test".to_string(),
        api_key: Some("tenant-key".to_string()),
        tenant_id: Some("tenant-1".to_string()),
        transport: Some(Arc::new(transport.clone())),
        ..Config::default()
    })
    .unwrap();

    client.get_user("user 1").unwrap();

    let request = transport.last_request();
    assert_eq!(
        request.url,
        "https://api.example.test/platform/users/user%201"
    );
    assert_eq!(request.headers.get("X-Steward-Key").unwrap(), "tenant-key");
    assert_eq!(request.headers.get("X-Steward-Tenant").unwrap(), "tenant-1");
}

#[test]
fn api_errors_include_status_and_payload() {
    let transport = CaptureTransport::with_status(403, json!({"ok": false, "error": "denied"}));
    let client = Client::new(Config {
        base_url: "https://api.example.test".to_string(),
        api_key: Some("tenant-key".to_string()),
        transport: Some(Arc::new(transport)),
        ..Config::default()
    })
    .unwrap();

    let err = client.get_user("user-1").unwrap_err();
    match err {
        Error::Api(ApiError {
            status,
            message,
            data,
        }) => {
            assert_eq!(status, 403);
            assert_eq!(message, "denied");
            assert_eq!(data.unwrap(), json!({"ok": false, "error": "denied"}));
        }
        other => panic!("expected API error, got {other:?}"),
    }
}
