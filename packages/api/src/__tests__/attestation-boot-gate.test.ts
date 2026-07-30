import { describe, expect, test } from "bun:test";
import type { AttestationProvider, AttestationQuote } from "@stwd/attestation";
import {
  AttestationBootGateError,
  enforceAttestationBootGate,
} from "../services/attestation-boot-gate";

const verifiedQuote: AttestationQuote = {
  provider: "dstack-tdx",
  measurement: { imageDigest: "os-image-hash", configHash: "compose-hash" },
  timestamp: new Date().toISOString(),
  verified: true,
  raw: {},
};

const unverifiedQuote: AttestationQuote = { ...verifiedQuote, verified: false };

function stubProvider(overrides: Partial<AttestationProvider>): AttestationProvider {
  return {
    id: "dstack-tdx",
    generateQuote: async () => verifiedQuote,
    verifyQuote: async () => verifiedQuote,
    ...overrides,
  };
}

const noSleep = () => Promise.resolve();
const quietLog = () => {};

describe("attestation boot gate", () => {
  test("not enforced when no provider is configured", async () => {
    const result = await enforceAttestationBootGate({ env: {} });
    expect(result.enforced).toBe(false);
  });

  test("not enforced for explicitly-labeled noop-dev provider", async () => {
    const result = await enforceAttestationBootGate({
      env: { STEWARD_ATTESTATION_PROVIDER: "noop-dev" },
    });
    expect(result.enforced).toBe(false);
  });

  test("rejects unknown providers instead of silently continuing", async () => {
    await expect(
      enforceAttestationBootGate({
        env: { STEWARD_ATTESTATION_PROVIDER: "definitely-not-real" },
      }),
    ).rejects.toThrow(AttestationBootGateError);
  });

  test("dstack-tdx without a verifier URL fails closed immediately", async () => {
    await expect(
      enforceAttestationBootGate({
        env: { STEWARD_ATTESTATION_PROVIDER: "dstack-tdx" },
      }),
    ).rejects.toThrow(/requires STEWARD_DSTACK_VERIFIER_URL/);
  });

  test("passes when the provider returns a verified quote", async () => {
    const result = await enforceAttestationBootGate({
      env: { STEWARD_ATTESTATION_PROVIDER: "dstack-tdx" },
      provider: stubProvider({}),
      sleep: noSleep,
      log: quietLog,
    });
    expect(result.enforced).toBe(true);
    expect(result.quote?.verified).toBe(true);
  });

  test("FAILS CLOSED when the verifier is unreachable (quote generation throws)", async () => {
    let calls = 0;
    const provider = stubProvider({
      generateQuote: async () => {
        calls += 1;
        throw new Error("connect ECONNREFUSED dstack-verifier:8080");
      },
    });
    await expect(
      enforceAttestationBootGate({
        env: { STEWARD_ATTESTATION_PROVIDER: "dstack-tdx" },
        provider,
        attempts: 3,
        delayMs: 1,
        sleep: noSleep,
        log: quietLog,
      }),
    ).rejects.toThrow(/Attestation boot gate FAILED after 3 attempt\(s\)/);
    expect(calls).toBe(3);
  });

  test("FAILS CLOSED when quotes are generated but never verified (no noop fallback)", async () => {
    const provider = stubProvider({ generateQuote: async () => unverifiedQuote });
    const error = await enforceAttestationBootGate({
      env: { STEWARD_ATTESTATION_PROVIDER: "dstack-tdx" },
      provider,
      attempts: 2,
      delayMs: 1,
      sleep: noSleep,
      log: quietLog,
    }).then(
      () => undefined,
      (err: unknown) => err,
    );
    expect(error).toBeInstanceOf(AttestationBootGateError);
    expect((error as AttestationBootGateError).message).toContain("no noop fallback");
    expect((error as AttestationBootGateError).lastQuote?.verified).toBe(false);
  });

  test("recovers when the verifier becomes reachable within the retry budget", async () => {
    let calls = 0;
    const provider = stubProvider({
      generateQuote: async () => {
        calls += 1;
        if (calls < 3) throw new Error("verifier warming up");
        return verifiedQuote;
      },
    });
    const result = await enforceAttestationBootGate({
      env: { STEWARD_ATTESTATION_PROVIDER: "dstack-tdx" },
      provider,
      attempts: 5,
      delayMs: 1,
      sleep: noSleep,
      log: quietLog,
    });
    expect(result.enforced).toBe(true);
    expect(calls).toBe(3);
  });
});
