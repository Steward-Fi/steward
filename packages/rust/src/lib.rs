use std::collections::BTreeMap;
use std::fmt;
use std::io::Read;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use hmac::{Hmac, Mac};
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use url::form_urlencoded;

type HmacSha256 = Hmac<Sha256>;

const SENSITIVE_SIGNED_PREFIXES: &[&str] = &[
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
];

const MUTATING_METHODS: &[&str] = &["POST", "PUT", "PATCH", "DELETE"];
const PATH_SEGMENT_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'/');

#[derive(Clone, Default)]
pub struct Config {
    pub base_url: String,
    pub api_key: Option<String>,
    pub bearer_token: Option<String>,
    pub platform_key: Option<String>,
    pub app_id: Option<String>,
    pub app_secret: Option<String>,
    pub tenant_id: Option<String>,
    pub request_signing_secret: Option<String>,
    pub request_signing_key_id: Option<String>,
    pub timeout: Option<Duration>,
    pub transport: Option<Arc<dyn Transport>>,
    pub now: Option<Arc<dyn Fn() -> SystemTime + Send + Sync>>,
    pub new_id: Option<Arc<dyn Fn() -> String + Send + Sync>>,
}

pub struct Client {
    base_url: String,
    config: Config,
    transport: Arc<dyn Transport>,
    now: Arc<dyn Fn() -> SystemTime + Send + Sync>,
    new_id: Arc<dyn Fn() -> String + Send + Sync>,
}

#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub url: String,
    pub path: String,
    pub headers: BTreeMap<String, String>,
    pub body: Option<Vec<u8>>,
    pub timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

pub trait Transport: Send + Sync {
    fn send(&self, request: Request) -> Result<Response, Error>;
}

#[derive(Debug)]
pub enum Error {
    Config(String),
    Transport(String),
    Json(serde_json::Error),
    Api(ApiError),
}

#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: u16,
    pub data: Option<Value>,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct StewardResponse {
    pub status: u16,
    pub data: Value,
    pub headers: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default)]
pub struct RequestOptions {
    pub headers: BTreeMap<String, String>,
    pub query: BTreeMap<String, String>,
    pub idempotency_key: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateUserInput {
    pub tenant_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_metadata: Option<Value>,
}

pub type User = BTreeMap<String, Value>;

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PushSubscriptionInput {
    pub provider: String,
    pub token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct PushSubscriptionResult {
    pub subscription: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct PushSubscriptionList {
    pub subscriptions: Vec<BTreeMap<String, Value>>,
}

#[derive(Deserialize)]
struct ApiEnvelope {
    ok: Option<bool>,
    data: Option<Value>,
    error: Option<String>,
}

struct UreqTransport;

impl Client {
    pub fn new(config: Config) -> Result<Self, Error> {
        if config.base_url.trim().is_empty() {
            return Err(Error::Config("base URL is required".to_string()));
        }
        let parsed = url::Url::parse(&config.base_url)
            .map_err(|err| Error::Config(format!("invalid base URL: {err}")))?;
        if parsed.scheme() != "http" && parsed.scheme() != "https" {
            return Err(Error::Config("base URL must use http or https".to_string()));
        }
        let base_url = config.base_url.trim_end_matches('/').to_string();
        let transport = config
            .transport
            .clone()
            .unwrap_or_else(|| Arc::new(UreqTransport));
        let now = config
            .now
            .clone()
            .unwrap_or_else(|| Arc::new(SystemTime::now));
        let new_id = config
            .new_id
            .clone()
            .unwrap_or_else(|| Arc::new(|| uuid::Uuid::new_v4().to_string()));

        Ok(Self {
            base_url,
            config,
            transport,
            now,
            new_id,
        })
    }

    pub fn request<T: Serialize + ?Sized>(
        &self,
        method: &str,
        path: &str,
        body: Option<&T>,
        options: RequestOptions,
    ) -> Result<StewardResponse, Error> {
        let method = method.to_uppercase();
        let path = canonical_path(path);
        let raw_body = match body {
            Some(value) => Some(serde_json::to_vec(value).map_err(Error::Json)?),
            None => None,
        };
        let mut url = format!("{}{}", self.base_url, path);
        if !options.query.is_empty() {
            let query = form_urlencoded::Serializer::new(String::new())
                .extend_pairs(options.query.iter())
                .finish();
            url.push('?');
            url.push_str(&query);
        }
        let headers = self.headers(
            &path,
            &method,
            raw_body.as_deref(),
            options.headers,
            options.idempotency_key,
        )?;
        let request = Request {
            method,
            url,
            path,
            headers,
            body: raw_body,
            timeout: self.config.timeout.unwrap_or(Duration::from_secs(30)),
        };
        let response = self.transport.send(request)?;
        decode_response(response)
    }

    pub fn get(&self, path: &str, options: RequestOptions) -> Result<StewardResponse, Error> {
        self.request::<Value>("GET", path, None, options)
    }

    pub fn post<T: Serialize + ?Sized>(
        &self,
        path: &str,
        body: &T,
        options: RequestOptions,
    ) -> Result<StewardResponse, Error> {
        self.request("POST", path, Some(body), options)
    }

    pub fn patch<T: Serialize + ?Sized>(
        &self,
        path: &str,
        body: &T,
        options: RequestOptions,
    ) -> Result<StewardResponse, Error> {
        self.request("PATCH", path, Some(body), options)
    }

    pub fn delete(&self, path: &str, options: RequestOptions) -> Result<StewardResponse, Error> {
        self.request::<Value>("DELETE", path, None, options)
    }

    pub fn create_user(&self, input: CreateUserInput) -> Result<User, Error> {
        let response = self.post("/platform/users", &input, RequestOptions::default())?;
        value_to(response.data)
    }

    pub fn get_user(&self, user_id: &str) -> Result<User, Error> {
        let response = self.get(
            &format!("/platform/users/{}", urlencoding_path_segment(user_id)),
            RequestOptions::default(),
        )?;
        value_to(response.data)
    }

    pub fn lookup_user(&self, query: BTreeMap<String, String>) -> Result<User, Error> {
        let response = self.get(
            "/platform/users/lookup",
            RequestOptions {
                query,
                ..RequestOptions::default()
            },
        )?;
        value_to(response.data)
    }

    pub fn list_user_push_subscriptions(&self) -> Result<PushSubscriptionList, Error> {
        let response = self.get("/user/me/push-subscriptions", RequestOptions::default())?;
        value_to(response.data)
    }

    pub fn register_user_push_subscription(
        &self,
        input: PushSubscriptionInput,
    ) -> Result<PushSubscriptionResult, Error> {
        let response = self.post(
            "/user/me/push-subscriptions",
            &input,
            RequestOptions::default(),
        )?;
        value_to(response.data)
    }

    pub fn revoke_user_push_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<PushSubscriptionResult, Error> {
        let response = self.delete(
            &format!(
                "/user/me/push-subscriptions/{}",
                urlencoding_path_segment(subscription_id)
            ),
            RequestOptions::default(),
        )?;
        value_to(response.data)
    }

    fn headers(
        &self,
        path: &str,
        method: &str,
        body: Option<&[u8]>,
        extra_headers: BTreeMap<String, String>,
        idempotency_key: Option<String>,
    ) -> Result<BTreeMap<String, String>, Error> {
        let mut headers = BTreeMap::from([
            ("Accept".to_string(), "application/json".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ]);
        headers.extend(extra_headers);

        if let Some(platform_key) = &self.config.platform_key {
            headers.insert("X-Steward-Platform-Key".to_string(), platform_key.clone());
        } else if let Some(bearer_token) = &self.config.bearer_token {
            headers.insert(
                "Authorization".to_string(),
                format!("Bearer {bearer_token}"),
            );
        } else if let (Some(app_id), Some(app_secret)) =
            (&self.config.app_id, &self.config.app_secret)
        {
            let encoded =
                base64::engine::general_purpose::STANDARD.encode(format!("{app_id}:{app_secret}"));
            headers.insert("Authorization".to_string(), format!("Basic {encoded}"));
            headers.insert("X-Steward-App-Id".to_string(), app_id.clone());
        } else if let Some(api_key) = &self.config.api_key {
            headers.insert("X-Steward-Key".to_string(), api_key.clone());
        }

        if let Some(tenant_id) = &self.config.tenant_id {
            headers.insert("X-Steward-Tenant".to_string(), tenant_id.clone());
        }

        if let Some(secret) = &self.config.request_signing_secret {
            if is_sensitive_mutation(path, method) {
                let timestamp = match headers.get("X-Steward-Request-Timestamp") {
                    Some(value) => value.clone(),
                    None => {
                        let value = self
                            .now_seconds()
                            .map_err(|err| Error::Config(format!("invalid system time: {err}")))?
                            .to_string();
                        headers.insert("X-Steward-Request-Timestamp".to_string(), value.clone());
                        value
                    }
                };
                let idem = match headers.get("Idempotency-Key") {
                    Some(value) => value.clone(),
                    None => {
                        let value = idempotency_key.unwrap_or_else(|| (self.new_id)());
                        headers.insert("Idempotency-Key".to_string(), value.clone());
                        value
                    }
                };
                if let Some(key_id) = &self.config.request_signing_key_id {
                    headers
                        .entry("X-Steward-Signing-Key-Id".to_string())
                        .or_insert_with(|| key_id.clone());
                }

                let body_hash = hex::encode(Sha256::digest(body.unwrap_or(&[])));
                let canonical = [
                    method.to_uppercase(),
                    path.to_string(),
                    timestamp,
                    idem,
                    body_hash,
                ]
                .join("\n");
                let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
                    .map_err(|err| Error::Config(format!("invalid signing secret: {err}")))?;
                mac.update(canonical.as_bytes());
                headers.insert(
                    "X-Steward-Signature".to_string(),
                    format!("v1={}", hex::encode(mac.finalize().into_bytes())),
                );
            }
        }

        Ok(headers)
    }

    fn now_seconds(&self) -> Result<u64, std::time::SystemTimeError> {
        (self.now)().duration_since(UNIX_EPOCH).map(|d| d.as_secs())
    }
}

impl Transport for UreqTransport {
    fn send(&self, request: Request) -> Result<Response, Error> {
        let agent = ureq::AgentBuilder::new().timeout(request.timeout).build();
        let mut req = agent.request(&request.method, &request.url);
        for (key, value) in &request.headers {
            req = req.set(key, value);
        }
        let result = match &request.body {
            Some(body) => req.send_bytes(body),
            None => req.call(),
        };
        match result {
            Ok(res) => {
                let status = res.status();
                let headers = collect_headers(&res);
                let body = read_body(res)?;
                Ok(Response {
                    status,
                    headers,
                    body,
                })
            }
            Err(ureq::Error::Status(status, res)) => {
                let headers = collect_headers(&res);
                let body = read_body(res)?;
                Ok(Response {
                    status,
                    headers,
                    body,
                })
            }
            Err(err) => Err(Error::Transport(err.to_string())),
        }
    }
}

fn read_body(response: ureq::Response) -> Result<Vec<u8>, Error> {
    let mut reader = response.into_reader();
    let mut body = Vec::new();
    reader
        .read_to_end(&mut body)
        .map_err(|err| Error::Transport(err.to_string()))?;
    Ok(body)
}

fn decode_response(response: Response) -> Result<StewardResponse, Error> {
    if response.body.is_empty() {
        if response.status >= 400 {
            return Err(Error::Api(ApiError {
                status: response.status,
                data: None,
                message: format!("steward request failed with status {}", response.status),
            }));
        }
        return Ok(StewardResponse {
            status: response.status,
            data: Value::Null,
            headers: response.headers,
        });
    }

    let payload: Value = serde_json::from_slice(&response.body).map_err(Error::Json)?;
    let envelope: ApiEnvelope = serde_json::from_value(payload.clone()).map_err(Error::Json)?;
    if response.status >= 400 || envelope.ok == Some(false) {
        let message = envelope
            .error
            .unwrap_or_else(|| format!("steward request failed with status {}", response.status));
        return Err(Error::Api(ApiError {
            status: response.status,
            data: Some(payload),
            message,
        }));
    }
    Ok(StewardResponse {
        status: response.status,
        data: envelope.data.unwrap_or(payload),
        headers: response.headers,
    })
}

fn collect_headers(response: &ureq::Response) -> BTreeMap<String, String> {
    response
        .headers_names()
        .into_iter()
        .filter_map(|name| {
            response
                .header(&name)
                .map(|value| (name, value.to_string()))
        })
        .collect()
}

fn canonical_path(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

fn is_sensitive_mutation(path: &str, method: &str) -> bool {
    MUTATING_METHODS.contains(&method.to_uppercase().as_str())
        && SENSITIVE_SIGNED_PREFIXES
            .iter()
            .any(|prefix| path.starts_with(prefix))
}

fn value_to<T: for<'de> Deserialize<'de>>(value: Value) -> Result<T, Error> {
    serde_json::from_value(value).map_err(Error::Json)
}

fn urlencoding_path_segment(value: &str) -> String {
    utf8_percent_encode(value, PATH_SEGMENT_ENCODE_SET).to_string()
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Config(message) | Error::Transport(message) => f.write_str(message),
            Error::Json(err) => write!(f, "invalid steward JSON response: {err}"),
            Error::Api(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for Error {}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ApiError {}
