/**
 * agent-client-mock-server.ts — a faithful in-process mock of the A1 capability
 * plane, wired as a `fetch` impl. It performs REAL P-256 verification of the
 * enrollment signature (so a wrong key / tampered signature genuinely fails) and
 * mints REAL signed JWTs with an `exp` claim (so the client's expiry/renewal
 * scheduling is exercised against real tokens, not stubs).
 *
 * It deliberately mirrors A1's exact wire contracts:
 *   POST /agent-enroll/challenge  → { ok, data:{ agentId, nonce, canonicalString, expiresAt } }
 *   POST /agent-enroll/verify     → { ok, data:{ token, agentId, tenantId, scope, scopes, expiresIn } }
 *   GET  /capabilities/manifest   → { ok, data:{ manifest:[...] } }
 *   POST /capabilities/manifest/:id/{issue,renew} → token|broker envelope
 *   POST /capabilities/:name/invoke → success | 202 pending | gate deny
 *
 * Only what the client depends on is modelled; it is not the real server.
 */

import { SignJWT } from "jose";

const AGENT_ENROLL_DOMAIN = "steward:agent-enroll:v1";
const JWT_SECRET = new TextEncoder().encode("mock-agent-client-jwt-secret-32chars-min!");

function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}
function bytesToB64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i += 1) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

export interface MockSignerRow {
  agentId: string;
  tenantId: string;
  /** raw uncompressed 04||X||Y base64 public key. */
  publicKeyRawBase64: string;
  status: "active" | "revoked";
}

export interface MockManifestEntry {
  manifest: string;
  provider: string;
  kind: string;
  capabilityName: string;
  capabilityId: string;
  grantExpiresAt: string | null;
  mode: "token" | "broker";
}

export interface MockServerOptions {
  signers: MockSignerRow[];
  manifest?: MockManifestEntry[];
  /** default seconds the enroll token lives (drives exp claim). default 300. */
  enrollTtlSeconds?: number;
  /** capability names whose invoke should return 202 pending. */
  approvalRequired?: Set<string>;
  /** capability names whose invoke should return a gate deny (status, message). */
  denies?: Map<string, { status: number; message: string }>;
  /** the (mock) upstream body a successful invoke returns. */
  invokeBody?: unknown;
  now?: () => number;
}

/** Generate a P-256 keypair; returns the private CryptoKey + raw-base64 pubkey. */
export async function generateMockKeyPair(): Promise<{
  privateKey: CryptoKey;
  publicKeyRawBase64: string;
  pkcs8Base64: string;
}> {
  const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  return {
    privateKey: pair.privateKey,
    publicKeyRawBase64: bytesToB64(raw),
    pkcs8Base64: bytesToB64(pkcs8),
  };
}

interface Challenge {
  agentId: string;
  nonce: string;
  issuedAt: number;
  canonicalString: string;
}

export class MockStewardServer {
  private readonly signers: MockSignerRow[];
  private manifestEntries: MockManifestEntry[];
  private readonly enrollTtlSeconds: number;
  private readonly approvalRequired: Set<string>;
  private readonly denies: Map<string, { status: number; message: string }>;
  private readonly invokeBody: unknown;
  private readonly now: () => number;

  private readonly challenges = new Map<string, Challenge>();
  /** revoked jti values (broker-token-level revocation simulation). */
  readonly revokedJti = new Set<string>();

  /** counters for assertions. */
  challengeCount = 0;
  verifyCount = 0;
  issueCount = 0;

  constructor(opts: MockServerOptions) {
    this.signers = opts.signers;
    this.manifestEntries = opts.manifest ?? [];
    this.enrollTtlSeconds = opts.enrollTtlSeconds ?? 300;
    this.approvalRequired = opts.approvalRequired ?? new Set();
    this.denies = opts.denies ?? new Map();
    this.invokeBody = opts.invokeBody ?? { ok: true };
    this.now = opts.now ?? (() => Date.now());
  }

  setManifest(entries: MockManifestEntry[]): void {
    this.manifestEntries = entries;
  }
  revokeSigner(agentId: string): void {
    for (const s of this.signers) if (s.agentId === agentId) s.status = "revoked";
  }
  activeSigner(agentId: string): MockSignerRow | undefined {
    return this.signers.find((s) => s.agentId === agentId && s.status === "active");
  }

  /** the fetch impl to hand the AgentClient. */
  fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input.toString();
    const path = new URL(url, "http://mock").pathname;
    const method = (init?.method ?? "GET").toUpperCase();
    const auth = new Headers(init?.headers).get("Authorization") ?? "";
    const body = init?.body ? JSON.parse(init.body as string) : {};

    if (path === "/agent-enroll/challenge" && method === "POST") {
      return this.handleChallenge(body);
    }
    if (path === "/agent-enroll/verify" && method === "POST") {
      return this.handleVerify(body);
    }
    if (path === "/capabilities/manifest" && method === "GET") {
      return this.handleManifest(auth);
    }
    const issueMatch = path.match(/^\/capabilities\/manifest\/([^/]+)\/(issue|renew)$/);
    if (issueMatch && method === "POST") {
      return this.handleIssue(auth, decodeURIComponent(issueMatch[1]), body);
    }
    const invokeMatch = path.match(/^\/capabilities\/([^/]+)\/invoke$/);
    if (invokeMatch && method === "POST") {
      return this.handleInvoke(auth, decodeURIComponent(invokeMatch[1]));
    }
    return this.json({ ok: false, error: "not found" }, 404);
  };

  private json(payload: unknown, status = 200): Response {
    return new Response(JSON.stringify(payload), {
      status,
      headers: { "Content-Type": "application/json" },
    });
  }

  private handleChallenge(body: { agentId?: string }): Response {
    this.challengeCount += 1;
    const agentId = String(body.agentId ?? "");
    if (!agentId) return this.json({ ok: false, error: "agentId required" }, 400);
    const nonce = crypto.randomUUID();
    const issuedAt = this.now();
    const canonicalString = [AGENT_ENROLL_DOMAIN, agentId, nonce, String(issuedAt)].join("\n");
    this.challenges.set(`${agentId}:${nonce}`, { agentId, nonce, issuedAt, canonicalString });
    return this.json({
      ok: true,
      data: { agentId, nonce, canonicalString, expiresAt: issuedAt + 120_000 },
    });
  }

  private async handleVerify(body: {
    agentId?: string;
    nonce?: string;
    signature?: string;
  }): Promise<Response> {
    this.verifyCount += 1;
    const agentId = String(body.agentId ?? "");
    const nonce = String(body.nonce ?? "");
    const signature = String(body.signature ?? "");
    const key = `${agentId}:${nonce}`;
    const challenge = this.challenges.get(key);
    // consume BEFORE verify (single-use), mirroring A1.
    this.challenges.delete(key);
    if (!challenge) return this.json({ ok: false, error: "enrollment denied" }, 401);

    const signer = this.activeSigner(agentId);
    if (!signer) return this.json({ ok: false, error: "enrollment denied" }, 401);

    const ok = await this.verifyP256(
      signer.publicKeyRawBase64,
      challenge.canonicalString,
      signature,
    );
    if (!ok) return this.json({ ok: false, error: "enrollment denied" }, 401);

    const token = await this.mintToken(agentId, signer.tenantId, ["agent"], this.enrollTtlSeconds);
    return this.json({
      ok: true,
      data: {
        token,
        agentId,
        tenantId: signer.tenantId,
        scope: "agent",
        scopes: ["agent"],
        expiresIn: `${this.enrollTtlSeconds}s`,
      },
    });
  }

  private async handleManifest(auth: string): Promise<Response> {
    const claims = await this.authAgent(auth);
    if (!claims) return this.json({ ok: false, error: "agent authentication required" }, 401);
    return this.json({
      ok: true,
      data: {
        manifest: this.manifestEntries.map(({ mode: _mode, ...rest }) => rest),
      },
    });
  }

  private async handleIssue(
    auth: string,
    manifestId: string,
    body: { ttlSeconds?: number },
  ): Promise<Response> {
    this.issueCount += 1;
    const claims = await this.authAgent(auth);
    if (!claims) return this.json({ ok: false, error: "agent authentication required" }, 401);
    const entry = this.manifestEntries.find((m) => m.manifest === manifestId);
    if (!entry) return this.json({ ok: false, error: "capability not granted to agent" }, 403);

    if (entry.mode === "broker") {
      return this.json({
        ok: true,
        mode: "broker",
        delegation: {
          capabilityName: entry.capabilityName,
          method: "POST",
          note: `broker mode: exercise via POST /capabilities/${entry.capabilityName}/invoke`,
        },
        manifest: entry.manifest,
        capabilityId: entry.capabilityId,
      });
    }
    const ttl = body.ttlSeconds ?? 120;
    if (ttl <= 0 || ttl > 300) {
      return this.json({ ok: false, error: "ttl must be 1-300 seconds" }, 400);
    }
    const scope = `cap:${entry.manifest}`;
    const jti = crypto.randomUUID();
    const token = await this.mintToken(claims.agentId, claims.tenantId, [scope], ttl, jti);
    return this.json({
      ok: true,
      mode: "token",
      token,
      jti,
      ttlSeconds: ttl,
      scopes: [scope],
      manifest: entry.manifest,
      capabilityId: entry.capabilityId,
    });
  }

  private async handleInvoke(auth: string, name: string): Promise<Response> {
    const claims = await this.authAgent(auth);
    if (!claims) return this.json({ ok: false, error: "agent authentication required" }, 401);
    const deny = this.denies.get(name);
    if (deny) return this.json({ ok: false, error: deny.message }, deny.status);
    if (this.approvalRequired.has(name)) {
      return this.json(
        { ok: true, data: { approvalId: crypto.randomUUID(), status: "pending" } },
        202,
      );
    }
    return this.json({ ok: true, data: this.invokeBody });
  }

  // ── crypto ────────────────────────────────────────────────────────────────
  private async verifyP256(
    publicKeyRawBase64: string,
    canonicalString: string,
    signatureBase64: string,
  ): Promise<boolean> {
    try {
      const key = await crypto.subtle.importKey(
        "raw",
        b64ToBytes(publicKeyRawBase64),
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["verify"],
      );
      return await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        key,
        b64ToBytes(signatureBase64),
        new TextEncoder().encode(canonicalString),
      );
    } catch {
      return false;
    }
  }

  private async mintToken(
    agentId: string,
    tenantId: string,
    scopes: string[],
    ttlSeconds: number,
    jti?: string,
  ): Promise<string> {
    const iat = Math.floor(this.now() / 1000);
    const builder = new SignJWT({ agentId, tenantId, scopes })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuedAt(iat)
      .setExpirationTime(iat + ttlSeconds);
    if (jti) builder.setJti(jti);
    return builder.sign(JWT_SECRET);
  }

  /** Verify a bearer agent token; returns claims or null. Honours revoked jti. */
  private async authAgent(
    auth: string,
  ): Promise<{ agentId: string; tenantId: string; scopes: string[]; jti?: string } | null> {
    const m = auth.match(/^Bearer (.+)$/);
    if (!m) return null;
    try {
      const { jwtVerify } = await import("jose");
      const { payload } = await jwtVerify(m[1], JWT_SECRET, {
        currentDate: new Date(this.now()),
      });
      if (payload.jti && this.revokedJti.has(payload.jti)) return null;
      return {
        agentId: String(payload.agentId),
        tenantId: String(payload.tenantId),
        scopes: (payload.scopes as string[]) ?? [],
        jti: payload.jti,
      };
    } catch {
      return null;
    }
  }
}
