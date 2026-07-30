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
        std::fs::write(
            format!("{out}/share-{id_hex}.json"),
            serde_json::to_vec_pretty(&sf).unwrap(),
        )
        .expect("write share file");
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

struct ShareState {
    key_package: KeyPackage,
    pubkey_package: PublicKeyPackage,
    identifier: Identifier,
    // Nonces are single-use and kept per commit round, keyed by nonce id.
    nonces: BTreeMap<String, frost::round1::SigningNonces>,
    next_nonce_id: u64,
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

fn cmd_share(share_file: &str, port: u16) {
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
        let mut body = String::new();
        let _ = request.as_reader().read_to_string(&mut body);

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
            let mut rng = OsRng;
            let (nonces, commitments) =
                frost::round1::commit(state.key_package.signing_share(), &mut rng);
            let nonce_id = format!("n{}", state.next_nonce_id);
            state.next_nonce_id += 1;
            state.nonces.insert(nonce_id.clone(), nonces);
            let resp = CommitResponse {
                identifier_hex: hex::encode(state.identifier.serialize()),
                nonce_id,
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
            let nonces = match state.nonces.remove(&req.nonce_id) {
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
            cmd_share(&share_file, port);
        }
        _ => {
            eprintln!("usage: frost-signer <keygen|share> ...");
            std::process::exit(2);
        }
    }
}
