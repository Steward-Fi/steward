//! Steward D2 threshold-signing sidecar — FROST-secp256k1 (Zcash Foundation).
//!
//! PROTOTYPE. Dev/dummy keys only. Uses trusted-dealer keygen (labeled
//! honestly) rather than full DKG for the prototype; the SignerBackend
//! interface it sits behind is DKG-ready (see D1 §7 / THRESHOLD-SIGNING.md).
//!
//! Subcommands:
//!   keygen  --threshold T --participants N --out DIR [--scheme secp256k1|ed25519]
//!           Trusted-dealer keygen. Writes DIR/group.json (public) and
//!           DIR/share-<id>.json (secret share per participant).
//!
//!   share   --share-file FILE --port P
//!           Runs an HTTP service holding ONE secret share. Endpoints:
//!             GET  /health
//!             POST /commit  { }                      -> round1 commitments (public)
//!             POST /sign    { signing_package, nonces_id } -> round2 sig share
//!           The share never leaves this process.
//!           Every endpoint except GET /health requires
//!           `Authorization: Bearer TOKEN` (`FROST_SHARE_AUTH_TOKEN`);
//!           the service refuses to start without a strong token (SEC-025).
//!           Tokens are not accepted on the command line because process
//!           arguments are commonly visible to other local users. Shares must
//!           never share a network namespace with untrusted code.
//!
//!   aggregate (offline helper for tests) reads a signing package + shares from
//!           stdin — not needed in the HTTP flow; aggregation is done by whoever
//!           holds group.json since it only needs PUBLIC data.
//!
//! Aggregation uses only public data (commitments, signature shares, group
//! public-key package), so the TS coordinator posts to /commit and /sign on the
//! share services, then calls `frost-signer aggregate-http` — but to keep the
//! prototype self-contained the share service ALSO exposes POST /aggregate.

use std::collections::BTreeMap;
use std::io::Read;

use frost::{
    keys::{KeyPackage, PublicKeyPackage},
    Identifier,
};
use frost_secp256k1 as frost;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

// ----------------------------- persisted files -----------------------------

#[derive(Serialize, Deserialize)]
struct GroupFile {
    scheme: String,
    threshold: u16,
    participants: u16,
    /// Hex of the serialized PublicKeyPackage (public; contains group vk).
    pubkey_package_hex: String,
    /// Hex of the group verifying key (33-byte compressed secp256k1 point).
    group_public_key_hex: String,
}

#[derive(Serialize, Deserialize)]
struct ShareFile {
    scheme: String,
    identifier_hex: String,
    threshold: u16,
    participants: u16,
    /// Hex of the serialized KeyPackage (SECRET — this is one share).
    key_package_hex: String,
    /// Hex of the serialized PublicKeyPackage (public; for local aggregate).
    pubkey_package_hex: String,
}

// ------------------------------- keygen ------------------------------------

fn cmd_keygen(threshold: u16, participants: u16, out: &str, scheme: &str) {
    if scheme != "secp256k1" {
        eprintln!("prototype keygen currently wires secp256k1; ed25519 crate is pinned for the Solana follow-on but not exercised here");
        std::process::exit(2);
    }
    let rng = OsRng;
    let (shares, pubkey_package) = frost::keys::generate_with_dealer(
        participants,
        threshold,
        frost::keys::IdentifierList::Default,
        rng,
    )
    .expect("trusted-dealer keygen failed");

    std::fs::create_dir_all(out).expect("mkdir out");

    let pubkey_package_hex = hex::encode(pubkey_package.serialize().expect("ser pkp"));
    let group_public_key_hex =
        hex::encode(pubkey_package.verifying_key().serialize().expect("ser vk"));

    let group = GroupFile {
        scheme: scheme.to_string(),
        threshold,
        participants,
        pubkey_package_hex: pubkey_package_hex.clone(),
        group_public_key_hex: group_public_key_hex.clone(),
    };
    std::fs::write(
        format!("{out}/group.json"),
        serde_json::to_vec_pretty(&group).unwrap(),
    )
    .expect("write group.json");

    for (identifier, secret_share) in shares {
        // Verify + convert to KeyPackage, exactly as a participant would.
        let key_package = KeyPackage::try_from(secret_share).expect("verify share -> key package");
        let id_hex = hex::encode(identifier.serialize());
        let sf = ShareFile {
            scheme: scheme.to_string(),
            identifier_hex: id_hex.clone(),
            threshold,
            participants,
            key_package_hex: hex::encode(key_package.serialize().expect("ser kp")),
            pubkey_package_hex: pubkey_package_hex.clone(),
        };
        let share_path = format!("{out}/share-{id_hex}.json");
        std::fs::write(&share_path, serde_json::to_vec_pretty(&sf).unwrap())
            .expect("write share file");
        // SEC-083: share files hold secret key material — owner-only.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&share_path, std::fs::Permissions::from_mode(0o600))
                .expect("chmod share file 0600");
        }
    }

    // Emit machine-readable summary on stdout for the TS client.
    println!(
        "{}",
        serde_json::json!({
            "ok": true,
            "scheme": scheme,
            "threshold": threshold,
            "participants": participants,
            "group_public_key_hex": group_public_key_hex,
        })
    );
}

// --------------------------- share HTTP service ----------------------------

/// SEC-083: cap outstanding commit rounds so unbounded /commit calls cannot
/// grow the nonce map without limit.
const MAX_PENDING_NONCES: usize = 1024;
/// SEC-083: bound request bodies read from the socket.
const MAX_BODY_BYTES: u64 = 64 * 1024;

struct ShareState {
    key_package: KeyPackage,
    pubkey_package: PublicKeyPackage,
    identifier: Identifier,
    // Nonces are single-use and kept per commit round, keyed by the numeric
    // nonce counter (nonce ids on the wire are "n<counter>"). BTreeMap order
    // is ascending counter, so the front entry is the oldest parked round.
    nonces: BTreeMap<u64, frost::round1::SigningNonces>,
    next_nonce_id: u64,
    // SEC-025: per-share bearer token authenticating the coordinator.
    auth_token: String,
}

#[derive(Serialize)]
struct CommitResponse {
    identifier_hex: String,
    nonce_id: String,
    commitments_hex: String,
}

#[derive(Deserialize)]
struct SignRequest {
    /// Hex of serialized SigningPackage (built by the coordinator).
    signing_package_hex: String,
    /// The nonce id returned by /commit for this signing round.
    nonce_id: String,
}

#[derive(Serialize)]
struct SignResponse {
    identifier_hex: String,
    signature_share_hex: String,
}

#[derive(Deserialize)]
struct SigningPackageRequest {
    /// identifier_hex -> commitments_hex (from each participant's /commit).
    commitments: BTreeMap<String, String>,
    /// Hex of the message/digest to sign.
    message_hex: String,
}

#[derive(Serialize)]
struct SigningPackageResponse {
    signing_package_hex: String,
}

#[derive(Deserialize)]
struct AggregateRequest {
    signing_package_hex: String,
    /// identifier_hex -> signature_share_hex
    signature_shares: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct VerifyRequest {
    message_hex: String,
    signature_hex: String,
}

#[derive(Serialize)]
struct VerifyResponse {
    valid: bool,
    group_public_key_hex: String,
}

#[derive(Serialize)]
struct AggregateResponse {
    signature_hex: String,
    group_public_key_hex: String,
    valid: bool,
}

fn id_from_hex(s: &str) -> Identifier {
    let bytes = hex::decode(s).expect("id hex");
    Identifier::deserialize(&bytes).expect("id deser")
}

fn cmd_share(share_file: &str, port: u16, auth_token: String) {
    let raw = std::fs::read(share_file).expect("read share file");
    let sf: ShareFile = serde_json::from_slice(&raw).expect("parse share file");
    let key_package =
        KeyPackage::deserialize(&hex::decode(&sf.key_package_hex).unwrap()).expect("kp deser");
    let pubkey_package =
        PublicKeyPackage::deserialize(&hex::decode(&sf.pubkey_package_hex).unwrap())
            .expect("pkp deser");
    let identifier = id_from_hex(&sf.identifier_hex);

    let mut state = ShareState {
        key_package,
        pubkey_package,
        identifier,
        nonces: BTreeMap::new(),
        next_nonce_id: 0,
        auth_token,
    };

    let server = tiny_http::Server::http(("127.0.0.1", port))
        .unwrap_or_else(|e| panic!("bind 127.0.0.1:{port}: {e}"));
    eprintln!(
        "frost-signer share up on 127.0.0.1:{port} id={}",
        sf.identifier_hex
    );

    for mut request in server.incoming_requests() {
        let url = request.url().to_string();
        let method = request.method().as_str().to_string();

        // SEC-025: every endpoint except GET /health requires the per-share
        // bearer token. Without it any local process could drive /commit +
        // /sign and obtain signature shares over attacker-chosen messages.
        let is_health = method == "GET" && url == "/health";
        if !is_health {
            let expected = format!("Bearer {}", state.auth_token);
            let authorized = request
                .headers()
                .iter()
                .any(|h| h.field.equiv("authorization") && h.value.as_str() == expected);
            if !authorized {
                let response = tiny_http::Response::from_string(err_json("unauthorized"))
                    .with_status_code(401);
                let _ = request.respond(response);
                continue;
            }
        }

        // SEC-083: bound the request body read from the socket.
        let mut body = String::new();
        let _ = request
            .as_reader()
            .take(MAX_BODY_BYTES + 1)
            .read_to_string(&mut body);
        if body.len() as u64 > MAX_BODY_BYTES {
            let response = tiny_http::Response::from_string(err_json("request body too large"))
                .with_status_code(413);
            let _ = request.respond(response);
            continue;
        }

        let (code, payload) = handle(&mut state, &method, &url, &body);
        let response = tiny_http::Response::from_string(payload).with_status_code(code);
        let _ = request.respond(response);
    }
}

fn handle(state: &mut ShareState, method: &str, url: &str, body: &str) -> (u16, String) {
    match (method, url) {
        ("GET", "/health") => (
            200,
            serde_json::json!({ "ok": true, "id": hex::encode(state.identifier.serialize()) })
                .to_string(),
        ),
        ("POST", "/commit") => {
            // SEC-083 bounds the map. A hard refusal at the cap would let an
            // authenticated coordinator park 1024 rounds indefinitely and
            // wedge the signer. Evict the oldest parked round instead — its
            // /sign will fail closed with
            // "unknown or reused nonce_id", and an evicted unused nonce is
            // never signed with, so FROST nonce-reuse safety is preserved.
            // Never wrap the wire-id counter: wrapping could alias and
            // overwrite a still-parked nonce, violating single-use safety.
            let nonce_id = state.next_nonce_id;
            let Some(next_nonce_id) = nonce_id.checked_add(1) else {
                return (503, err_json("nonce id space exhausted"));
            };
            if state.nonces.len() >= MAX_PENDING_NONCES {
                state.nonces.pop_first();
            }
            let mut rng = OsRng;
            let (nonces, commitments) =
                frost::round1::commit(state.key_package.signing_share(), &mut rng);
            state.next_nonce_id = next_nonce_id;
            state.nonces.insert(nonce_id, nonces);
            let resp = CommitResponse {
                identifier_hex: hex::encode(state.identifier.serialize()),
                nonce_id: format!("n{nonce_id}"),
                commitments_hex: hex::encode(commitments.serialize().expect("ser commitments")),
            };
            (200, serde_json::to_string(&resp).unwrap())
        }
        ("POST", "/signing-package") => {
            // Pure PUBLIC-data operation: build a SigningPackage from the
            // participants' round1 commitments + the message. Any node can do
            // this; it holds no secret. The coordinator calls it once per round.
            let req: SigningPackageRequest = match serde_json::from_str(body) {
                Ok(r) => r,
                Err(e) => return (400, err_json(&format!("bad /signing-package body: {e}"))),
            };
            let message = match hex::decode(&req.message_hex) {
                Ok(m) => m,
                Err(_) => return (400, err_json("bad message_hex")),
            };
            let mut commitments_map = BTreeMap::new();
            for (id_hex, commit_hex) in &req.commitments {
                let id = id_from_hex(id_hex);
                let commit = match hex::decode(commit_hex)
                    .ok()
                    .and_then(|b| frost::round1::SigningCommitments::deserialize(&b).ok())
                {
                    Some(c) => c,
                    None => return (400, err_json("bad commitments_hex")),
                };
                commitments_map.insert(id, commit);
            }
            let sp = frost::SigningPackage::new(commitments_map, &message);
            let resp = SigningPackageResponse {
                signing_package_hex: hex::encode(sp.serialize().expect("ser signing package")),
            };
            (200, serde_json::to_string(&resp).unwrap())
        }
        ("POST", "/sign") => {
            let req: SignRequest = match serde_json::from_str(body) {
                Ok(r) => r,
                Err(e) => return (400, err_json(&format!("bad /sign body: {e}"))),
            };
            let nonce_key = req
                .nonce_id
                .strip_prefix('n')
                .and_then(|suffix| suffix.parse::<u64>().ok())
                // Preserve the original exact wire identity. Numeric aliases
                // such as n01 must not be able to consume the nonce named n1.
                .filter(|key| req.nonce_id == format!("n{key}"));
            let nonces = match nonce_key.and_then(|key| state.nonces.remove(&key)) {
                Some(n) => n,
                None => return (400, err_json("unknown or reused nonce_id")),
            };
            let signing_package = match hex::decode(&req.signing_package_hex)
                .ok()
                .and_then(|b| frost::SigningPackage::deserialize(&b).ok())
            {
                Some(sp) => sp,
                None => return (400, err_json("bad signing_package_hex")),
            };
            match frost::round2::sign(&signing_package, &nonces, &state.key_package) {
                Ok(share) => {
                    let resp = SignResponse {
                        identifier_hex: hex::encode(state.identifier.serialize()),
                        signature_share_hex: hex::encode(share.serialize()),
                    };
                    (200, serde_json::to_string(&resp).unwrap())
                }
                Err(e) => (400, err_json(&format!("round2 sign failed: {e}"))),
            }
        }
        ("POST", "/verify") => {
            // Genuine cryptographic verification of a PROVIDED signature against
            // this group's verifying key. Public-data operation. Not vacuous:
            // a wrong signature / wrong message returns valid=false.
            let req: VerifyRequest = match serde_json::from_str(body) {
                Ok(r) => r,
                Err(e) => return (400, err_json(&format!("bad /verify body: {e}"))),
            };
            let message = match hex::decode(&req.message_hex) {
                Ok(m) => m,
                Err(_) => return (400, err_json("bad message_hex")),
            };
            let vk = state.pubkey_package.verifying_key();
            let valid = hex::decode(&req.signature_hex)
                .ok()
                .and_then(|b| frost::Signature::deserialize(&b).ok())
                .map(|sig| vk.verify(&message, &sig).is_ok())
                .unwrap_or(false);
            let resp = VerifyResponse {
                valid,
                group_public_key_hex: hex::encode(vk.serialize().expect("ser vk")),
            };
            (200, serde_json::to_string(&resp).unwrap())
        }
        ("POST", "/aggregate") => {
            let req: AggregateRequest = match serde_json::from_str(body) {
                Ok(r) => r,
                Err(e) => return (400, err_json(&format!("bad /aggregate body: {e}"))),
            };
            let signing_package = match hex::decode(&req.signing_package_hex)
                .ok()
                .and_then(|b| frost::SigningPackage::deserialize(&b).ok())
            {
                Some(sp) => sp,
                None => return (400, err_json("bad signing_package_hex")),
            };
            let mut shares = BTreeMap::new();
            for (id_hex, share_hex) in &req.signature_shares {
                let id = id_from_hex(id_hex);
                let share = match hex::decode(share_hex)
                    .ok()
                    .and_then(|b| frost::round2::SignatureShare::deserialize(&b).ok())
                {
                    Some(s) => s,
                    None => return (400, err_json("bad signature_share_hex")),
                };
                shares.insert(id, share);
            }
            // Aggregate ALSO verifies each signature share internally, and the
            // final signature is verified against the group vk below. If fewer
            // than `threshold` shares are supplied, aggregation fails here —
            // this is the honest below-threshold failure path.
            match frost::aggregate(&signing_package, &shares, &state.pubkey_package) {
                Ok(group_sig) => {
                    let vk = state.pubkey_package.verifying_key();
                    let valid = vk.verify(signing_package.message(), &group_sig).is_ok();
                    let resp = AggregateResponse {
                        signature_hex: hex::encode(group_sig.serialize().expect("ser sig")),
                        group_public_key_hex: hex::encode(vk.serialize().expect("ser vk")),
                        valid,
                    };
                    (200, serde_json::to_string(&resp).unwrap())
                }
                Err(e) => (400, err_json(&format!("aggregate failed: {e}"))),
            }
        }
        _ => (404, err_json("not found")),
    }
}

fn err_json(msg: &str) -> String {
    serde_json::json!({ "ok": false, "error": msg }).to_string()
}

// --------------------------------- cli -------------------------------------

fn arg(args: &[String], key: &str) -> Option<String> {
    args.iter()
        .position(|a| a == key)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn validate_share_auth_token(token: String) -> Result<String, &'static str> {
    // SEC-025: an empty/short token turns the loopback bearer check into a
    // guessable credential. Require a 32-byte floor and instruct operators to
    // encode at least 32 random bytes (for example, as 64 hex characters).
    // Supply the token through the environment, never through argv.
    if token.len() < 32
        || token
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return Err("FROST_SHARE_AUTH_TOKEN must contain at least 32 non-whitespace bytes");
    }
    Ok(token)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("");
    match cmd {
        "keygen" => {
            let threshold: u16 = arg(&args, "--threshold")
                .unwrap_or_default()
                .parse()
                .unwrap_or(2);
            let participants: u16 = arg(&args, "--participants")
                .unwrap_or_default()
                .parse()
                .unwrap_or(3);
            let out = arg(&args, "--out").unwrap_or_else(|| "./shares".to_string());
            let scheme = arg(&args, "--scheme").unwrap_or_else(|| "secp256k1".to_string());
            cmd_keygen(threshold, participants, &out, &scheme);
        }
        "share" => {
            let share_file = arg(&args, "--share-file").expect("--share-file required");
            let port: u16 = arg(&args, "--port")
                .expect("--port required")
                .parse()
                .expect("port");
            // SEC-025: require a strong per-share bearer token via the
            // environment. Command-line tokens are intentionally unsupported:
            // argv is commonly exposed by process inspection tools.
            let auth_token = std::env::var("FROST_SHARE_AUTH_TOKEN")
                .map_err(|_| "FROST_SHARE_AUTH_TOKEN is required")
                .and_then(validate_share_auth_token)
                .unwrap_or_else(|message| {
                    eprintln!("{message}: the share service refuses to run unauthenticated");
                    std::process::exit(2);
                });
            cmd_share(&share_file, port, auth_token);
        }
        _ => {
            eprintln!("usage: frost-signer <keygen|share> ...");
            std::process::exit(2);
        }
    }
}

// --------------------------------- tests ------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state() -> ShareState {
        let rng = OsRng;
        let (shares, pubkey_package) =
            frost::keys::generate_with_dealer(2, 2, frost::keys::IdentifierList::Default, rng)
                .expect("trusted-dealer keygen");
        let (identifier, secret_share) = shares.into_iter().next().expect("one share");
        let key_package = KeyPackage::try_from(secret_share).expect("share -> key package");
        ShareState {
            key_package,
            pubkey_package,
            identifier,
            nonces: BTreeMap::new(),
            next_nonce_id: 0,
            auth_token: "test-token".to_string(),
        }
    }

    fn commit(state: &mut ShareState) -> (u16, String) {
        let (code, payload) = handle(state, "POST", "/commit", "");
        let nonce_id = serde_json::from_str::<serde_json::Value>(&payload)
            .expect("commit response json")["nonce_id"]
            .as_str()
            .expect("nonce_id string")
            .to_string();
        (code, nonce_id)
    }

    // An authenticated coordinator must not wedge the share service by parking
    // MAX_PENDING_NONCES rounds indefinitely. /commit evicts the oldest parked
    // round rather than refusing all new rounds.
    #[test]
    fn commit_evicts_oldest_parked_round_at_the_cap() {
        let mut state = test_state();
        for expected in 0..MAX_PENDING_NONCES {
            let (code, nonce_id) = commit(&mut state);
            assert_eq!(code, 200);
            assert_eq!(nonce_id, format!("n{expected}"));
        }
        assert_eq!(state.nonces.len(), MAX_PENDING_NONCES);

        // One more commit: succeeds, evicts the oldest round ("n0"), keeps the
        // map bounded at the cap.
        let (code, nonce_id) = commit(&mut state);
        assert_eq!(code, 200);
        assert_eq!(nonce_id, format!("n{}", MAX_PENDING_NONCES));
        assert_eq!(state.nonces.len(), MAX_PENDING_NONCES);
        assert!(!state.nonces.contains_key(&0));
        assert!(state.nonces.contains_key(&(MAX_PENDING_NONCES as u64)));

        // The evicted round fails closed if the coordinator tries to use it.
        let (code, payload) = handle(
            &mut state,
            "POST",
            "/sign",
            &serde_json::json!({ "signing_package_hex": "00", "nonce_id": "n0" }).to_string(),
        );
        assert_eq!(code, 400);
        assert!(payload.contains("unknown or reused nonce_id"));
    }

    // The nonce id wire format ("n<counter>") round-trips: a parked round is
    // consumed exactly once by /sign, and unknown or malformed ids fail closed.
    #[test]
    fn sign_consumes_a_parked_round_exactly_once() {
        let mut state = test_state();
        let (code, nonce_id) = commit(&mut state);
        assert_eq!(code, 200);
        assert_eq!(nonce_id, "n0");

        for bad_id in ["n9", "n00", "n01", "n+1", "garbage", ""] {
            let (code, payload) = handle(
                &mut state,
                "POST",
                "/sign",
                &serde_json::json!({ "signing_package_hex": "00", "nonce_id": bad_id }).to_string(),
            );
            assert_eq!(code, 400, "nonce id {bad_id:?} must fail closed");
            assert!(payload.contains("unknown or reused nonce_id"));
        }

        // The parked round is consumed on first use (here failing only on the
        // deliberately invalid package, AFTER the nonce lookup succeeded) and
        // cannot be replayed.
        let (code, payload) = handle(
            &mut state,
            "POST",
            "/sign",
            &serde_json::json!({ "signing_package_hex": "00", "nonce_id": "n0" }).to_string(),
        );
        assert_eq!(code, 400);
        assert!(payload.contains("bad signing_package_hex"));
        assert!(!state.nonces.contains_key(&0));

        let (code, payload) = handle(
            &mut state,
            "POST",
            "/sign",
            &serde_json::json!({ "signing_package_hex": "00", "nonce_id": "n0" }).to_string(),
        );
        assert_eq!(code, 400);
        assert!(payload.contains("unknown or reused nonce_id"));
    }

    #[test]
    fn commit_fails_closed_before_nonce_counter_overflow() {
        let mut state = test_state();
        state.next_nonce_id = u64::MAX;
        let before = state.nonces.len();

        let (code, payload) = handle(&mut state, "POST", "/commit", "");

        assert_eq!(code, 503);
        assert!(payload.contains("nonce id space exhausted"));
        assert_eq!(state.next_nonce_id, u64::MAX);
        assert_eq!(state.nonces.len(), before);
    }

    #[test]
    fn share_auth_token_rejects_missing_strength() {
        for weak in ["", "short", "                                "] {
            assert!(validate_share_auth_token(weak.to_string()).is_err());
        }
        let strong = "0123456789abcdef0123456789abcdef".to_string();
        assert_eq!(validate_share_auth_token(strong.clone()), Ok(strong));
    }
}
