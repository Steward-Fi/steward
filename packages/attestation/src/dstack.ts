import { request as httpRequest } from "node:http";
import { runtimeEnvironmentSnapshot } from "@stwd/shared/runtime-env";
import type {
  AttestationMeasurement,
  AttestationProvider,
  AttestationQuote,
  AttestationQuoteRequest,
  AttestationVerificationOptions,
} from "./types.js";

export interface DstackTdxProviderOptions {
  socketPath?: string;
  verifierUrl?: string;
  fetchImpl?: typeof fetch;
  now?: () => Date;
}

interface DstackInfoResponse {
  os_image_hash?: string;
  compose_hash?: string;
  mr_aggregated?: string;
  app_id?: string;
  instance_id?: string;
  vm_config?: string;
  [key: string]: unknown;
}

interface DstackQuoteResponse {
  quote?: string;
  event_log?: string;
  report_data?: string;
  vm_config?: string;
  attestation?: string;
  info?: DstackInfoResponse;
  [key: string]: unknown;
}

interface DstackVerifierResponse {
  is_valid?: boolean;
  details?: {
    quote_verified?: boolean;
    event_log_verified?: boolean;
    os_image_hash_verified?: boolean;
    tee_variant?: string;
    report_data?: string;
    app_info?: {
      os_image_hash?: string;
      compose_hash?: string;
      mr_aggregated?: string;
      [key: string]: unknown;
    };
    [key: string]: unknown;
  };
  reason?: string | null;
  [key: string]: unknown;
}

const DEFAULT_DSTACK_SOCKET = "/var/run/dstack.sock";
const ZERO_MEASUREMENT: AttestationMeasurement = { imageDigest: "unknown", configHash: "unknown" };

let warnedInsecureVerifier = false;

/**
 * SEC-165: the verifier verdict (`is_valid` etc.) is the entire trust
 * decision, and it transits a plain fetch. Warn loudly when the channel is
 * unauthenticated plain HTTP to anything but loopback — an on-path attacker
 * can flip verdicts. Deployments must use TLS (or mTLS) for the verifier.
 */
function warnIfVerifierChannelInsecure(verifierUrl?: string): void {
  if (!verifierUrl || warnedInsecureVerifier) return;
  try {
    const parsed = new URL(verifierUrl);
    if (parsed.protocol !== "http:") return;
    const host = parsed.hostname;
    if (host === "localhost" || host === "127.0.0.1" || host === "[::1]" || host === "::1") return;
    warnedInsecureVerifier = true;
    console.warn(
      `⚠️ STEWARD_DSTACK_VERIFIER_URL uses unauthenticated plain HTTP (${parsed.origin}): ` +
        "the attestation verdict channel is not integrity-protected. Use HTTPS (or mTLS) — " +
        "the verifier response is the entire trust decision.",
    );
  } catch {
    // Invalid URLs surface at verification time; nothing to warn about here.
  }
}

export class DstackTdxAttestationProvider implements AttestationProvider {
  readonly id = "dstack-tdx" as const;
  private readonly socketPath: string;
  private readonly verifierUrl?: string;
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => Date;

  constructor(options: DstackTdxProviderOptions = {}) {
    const env = runtimeEnvironmentSnapshot();
    this.socketPath = options.socketPath ?? env.DSTACK_SOCKET_PATH ?? DEFAULT_DSTACK_SOCKET;
    this.verifierUrl = options.verifierUrl ?? env.STEWARD_DSTACK_VERIFIER_URL;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.now = options.now ?? (() => new Date());
    warnIfVerifierChannelInsecure(this.verifierUrl);
  }

  async generateQuote(request: AttestationQuoteRequest = {}): Promise<AttestationQuote> {
    const reportData = normalizeReportData(request.nonce);
    const [info, quote] = await Promise.all([
      this.callGuestAgent<DstackInfoResponse>("/Info"),
      this.callGuestAgent<DstackQuoteResponse>("/GetQuote", { report_data: reportData }),
    ]);
    const raw: DstackQuoteResponse = {
      ...quote,
      info,
      vm_config: quote.vm_config ?? info.vm_config,
    };

    if (!this.verifierUrl) {
      return {
        provider: this.id,
        measurement: measurementFromInfo(info),
        timestamp: this.now().toISOString(),
        verified: false,
        raw: {
          ...raw,
          stewardVerification: {
            verified: false,
            reason:
              "STEWARD_DSTACK_VERIFIER_URL is not configured; hardware/DCAP verification was not performed",
          },
        },
      };
    }

    return this.verifyQuote(raw, { nonce: reportData, now: this.now() });
  }

  async verifyQuote(
    rawQuote: unknown,
    options: AttestationVerificationOptions = {},
  ): Promise<AttestationQuote> {
    const raw = asDstackQuote(rawQuote);
    if (!this.verifierUrl) {
      return {
        provider: this.id,
        measurement: measurementFromRaw(raw),
        timestamp: (options.now ?? this.now()).toISOString(),
        verified: false,
        raw: {
          ...raw,
          stewardVerification: {
            verified: false,
            reason: "No dstack verifier URL configured; refusing to mark quote verified",
          },
        },
      };
    }

    const verifier = await this.postVerifier(raw);
    // SEC-028: a nonce-less verification checked no freshness evidence, so it
    // must never report verified:true — captured once-valid quotes would be
    // replayable forever.
    const freshnessChecked = options.nonce !== undefined;
    const reportDataMatches = freshnessChecked
      ? verifier.details?.report_data === normalizeReportData(options.nonce)
      : false;
    // SEC-009: measurements must come from the authenticated verifier
    // response (details.app_info), never from the unauthenticated raw quote
    // info — a verifier that omits app_info cannot vouch for the measurement
    // binding, so fail closed instead of trusting attacker-supplied strings.
    const verifierMeasurement = measurementFromVerifier(verifier);
    const verified = Boolean(
      verifier.is_valid &&
        verifier.details?.quote_verified &&
        verifier.details?.event_log_verified &&
        verifier.details?.os_image_hash_verified &&
        verifier.details?.tee_variant?.startsWith("dstack-") &&
        reportDataMatches &&
        verifierMeasurement,
    );

    return {
      provider: this.id,
      measurement: verifierMeasurement ?? measurementFromRaw(raw),
      timestamp: (options.now ?? this.now()).toISOString(),
      verified,
      raw: {
        quote: raw,
        verifier,
        stewardVerification: {
          verified,
          reportDataMatches,
          freshnessChecked,
          measurementBound: Boolean(verifierMeasurement),
        },
      },
    };
  }

  private async callGuestAgent<T>(path: string, body?: unknown): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const payload = body ? JSON.stringify(body) : undefined;
      const req = httpRequest(
        {
          socketPath: this.socketPath,
          path,
          method: body ? "POST" : "GET",
          headers: payload
            ? { "content-type": "application/json", "content-length": Buffer.byteLength(payload) }
            : undefined,
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
          res.on("end", () => {
            const text = Buffer.concat(chunks).toString("utf8");
            if (!res.statusCode || res.statusCode >= 400) {
              reject(new Error(`dstack guest agent ${path} failed: ${res.statusCode} ${text}`));
              return;
            }
            try {
              resolve(JSON.parse(text) as T);
            } catch (error) {
              reject(error);
            }
          });
        },
      );
      req.on("error", reject);
      if (payload) req.write(payload);
      req.end();
    });
  }

  private async postVerifier(raw: DstackQuoteResponse): Promise<DstackVerifierResponse> {
    const response = await this.fetchImpl(new URL("/verify", this.verifierUrl).toString(), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(raw.attestation ? { attestation: raw.attestation } : raw),
    });
    if (!response.ok) {
      throw new Error(`dstack verifier failed: ${response.status} ${await response.text()}`);
    }
    return (await response.json()) as DstackVerifierResponse;
  }
}

export function createDstackTdxProvider(
  options?: DstackTdxProviderOptions,
): DstackTdxAttestationProvider {
  return new DstackTdxAttestationProvider(options);
}

function asDstackQuote(raw: unknown): DstackQuoteResponse {
  if (!raw || typeof raw !== "object") throw new Error("dstack quote must be an object");
  return raw as DstackQuoteResponse;
}

function measurementFromInfo(info?: DstackInfoResponse): AttestationMeasurement {
  return {
    imageDigest: info?.os_image_hash ?? "unknown",
    configHash: info?.compose_hash ?? "unknown",
  };
}

function measurementFromRaw(raw: DstackQuoteResponse): AttestationMeasurement {
  return measurementFromInfo(raw.info) ?? ZERO_MEASUREMENT;
}

function measurementFromVerifier(
  verifier: DstackVerifierResponse,
): AttestationMeasurement | undefined {
  const appInfo = verifier.details?.app_info;
  if (!appInfo?.os_image_hash || !appInfo.compose_hash) return undefined;
  return { imageDigest: appInfo.os_image_hash, configHash: appInfo.compose_hash };
}

export function normalizeReportData(nonce?: string): string {
  const bytes =
    nonce && nonce.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(nonce)
      ? Buffer.from(nonce, "hex")
      : Buffer.from(nonce ?? "", "utf8");
  if (bytes.length > 64) throw new Error("dstack report_data/nonce must be <= 64 bytes");
  return Buffer.concat([bytes, Buffer.alloc(64 - bytes.length)]).toString("hex");
}
