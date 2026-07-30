/**
 * Attestation boot gate — fail-closed startup enforcement.
 *
 * When `STEWARD_ATTESTATION_PROVIDER=dstack-tdx`, the API must prove it is
 * running inside an attested dstack TDX CVM BEFORE serving traffic: it
 * generates its own quote through the dstack guest agent and requires the
 * configured dstack verifier to return a fully verified result. If quote
 * generation or verification fails (guest agent socket missing, verifier
 * unreachable, DCAP failure, measurement rejection), boot ABORTS.
 *
 * There is deliberately NO fallback to `noop-dev` here: an operator who sets
 * the dstack provider gets attestation or gets no server. Downgrading requires
 * an explicit config change (visible in the measured compose file for dstack
 * deployments, since STEWARD_ATTESTATION_PROVIDER is hardcoded in
 * deploy/dstack/docker-compose.dstack.yml and any edit changes compose_hash).
 */

import {
  type AttestationProvider,
  type AttestationQuote,
  createDstackTdxProvider,
} from "@stwd/attestation";

export class AttestationBootGateError extends Error {
  constructor(
    message: string,
    readonly lastQuote?: AttestationQuote,
  ) {
    super(message);
    this.name = "AttestationBootGateError";
  }
}

export interface AttestationBootGateOptions {
  /** Injectable for tests; defaults to a real dstack-tdx provider. */
  provider?: AttestationProvider;
  env?: Record<string, string | undefined>;
  /** Total attempts before giving up. Default 20 (env: STEWARD_ATTESTATION_BOOT_ATTEMPTS). */
  attempts?: number;
  /** Delay between attempts in ms. Default 3000 (env: STEWARD_ATTESTATION_BOOT_DELAY_MS). */
  delayMs?: number;
  sleep?: (ms: number) => Promise<void>;
  log?: (message: string) => void;
}

export interface AttestationBootGateResult {
  /** True when the dstack gate was active and passed. False when not required. */
  enforced: boolean;
  quote?: AttestationQuote;
}

const KNOWN_PROVIDERS = new Set(["dstack-tdx", "noop-dev"]);

/**
 * Enforce the attestation boot gate. Resolves only when either:
 *  - no attestation provider (or the explicitly-labeled noop-dev provider) is
 *    configured, in which case nothing is enforced, or
 *  - the dstack-tdx provider produced a quote the verifier fully verified.
 *
 * Throws {@link AttestationBootGateError} otherwise. Callers on the production
 * boot path must treat a throw as fatal (exit non-zero).
 */
export async function enforceAttestationBootGate(
  options: AttestationBootGateOptions = {},
): Promise<AttestationBootGateResult> {
  const env = options.env ?? process.env;
  const configured = env.STEWARD_ATTESTATION_PROVIDER;

  if (!configured || configured === "noop-dev") {
    // noop-dev / unset: no runtime proof exists or is claimed. The /quote route
    // still reports verified:false unless explicitly allowed outside production.
    return { enforced: false };
  }

  if (!KNOWN_PROVIDERS.has(configured)) {
    throw new AttestationBootGateError(
      `Unsupported STEWARD_ATTESTATION_PROVIDER: ${configured}. Refusing to boot with an unknown attestation posture.`,
    );
  }

  if (configured === "dstack-tdx" && !options.provider && !env.STEWARD_DSTACK_VERIFIER_URL) {
    // Fail fast with a precise message instead of 20 doomed attempts: without a
    // verifier the dstack provider can never return verified:true.
    throw new AttestationBootGateError(
      "STEWARD_ATTESTATION_PROVIDER=dstack-tdx requires STEWARD_DSTACK_VERIFIER_URL; refusing to boot without hardware verification.",
    );
  }

  const provider = options.provider ?? createDstackTdxProvider();
  const attempts = clampPositiveInt(options.attempts ?? env.STEWARD_ATTESTATION_BOOT_ATTEMPTS, 20);
  const delayMs = clampPositiveInt(options.delayMs ?? env.STEWARD_ATTESTATION_BOOT_DELAY_MS, 3000);
  const sleep =
    options.sleep ?? ((ms: number) => new Promise((resolve) => setTimeout(resolve, ms)));
  const log = options.log ?? ((message: string) => console.log(message));

  let lastError: unknown;
  let lastQuote: AttestationQuote | undefined;

  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const quote = await provider.generateQuote({ nonce: crypto.randomUUID() });
      lastQuote = quote;
      if (quote.verified) {
        log(
          `[steward] attestation boot gate PASSED (provider=${quote.provider}, imageDigest=${quote.measurement.imageDigest}, configHash=${quote.measurement.configHash})`,
        );
        return { enforced: true, quote };
      }
      lastError = new Error("quote generated but not verified");
    } catch (error) {
      lastError = error;
    }
    if (attempt < attempts) {
      log(
        `[steward] attestation boot gate attempt ${attempt}/${attempts} failed (${describeError(lastError)}); retrying in ${delayMs}ms`,
      );
      await sleep(delayMs);
    }
  }

  throw new AttestationBootGateError(
    `Attestation boot gate FAILED after ${attempts} attempt(s): ${describeError(lastError)}. ` +
      "STEWARD_ATTESTATION_PROVIDER=dstack-tdx is fail-closed: fix the dstack guest agent socket / verifier and redeploy. There is no noop fallback.",
    lastQuote,
  );
}

function clampPositiveInt(value: string | number | undefined, fallback: number): number {
  const parsed = typeof value === "number" ? value : Number.parseInt(value ?? "", 10);
  if (!Number.isInteger(parsed) || parsed <= 0) return fallback;
  return parsed;
}

function describeError(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error ?? "unknown error");
}
