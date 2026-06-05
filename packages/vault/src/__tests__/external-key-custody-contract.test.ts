import { describe, expect, test } from "bun:test";
import {
  assertNoExternalPrivateKeyMaterial,
  type ExternalKeyHandleImportRequest,
  type ExternalKeyHandleRegistration,
  externalKeyPrivateExportUnavailableError,
  externalKeySigningUnavailableError,
  normalizeExternalKeyHandleRegistration,
} from "../external-key-custody";

const request: ExternalKeyHandleImportRequest = {
  tenantId: "tenant",
  agentId: "agent",
  chainFamily: "evm",
  address: "0x1111111111111111111111111111111111111111",
  handle: { providerId: "hsm", keyId: "key-1", version: "1", region: "us-east-1" },
  venue: "hsm-primary",
  purpose: "hsm",
  metadata: { label: "primary" },
};

function registration(
  overrides: Partial<ExternalKeyHandleRegistration> = {},
): ExternalKeyHandleRegistration {
  return {
    custody: "external",
    tenantId: "other-tenant",
    agentId: "other-agent",
    chainFamily: "solana",
    address: "old-address",
    handle: request.handle,
    venue: null,
    purpose: null,
    metadata: {},
    registeredAt: new Date("2026-06-05T00:00:00.000Z"),
    exportablePrivateKey: false,
    signingAvailability: "provider-signing",
    ...overrides,
  };
}

describe("external key custody contract", () => {
  test("normalizes provider-signing registrations without private-key exportability", () => {
    const normalized = normalizeExternalKeyHandleRegistration(request, registration());

    expect(normalized.tenantId).toBe("tenant");
    expect(normalized.agentId).toBe("agent");
    expect(normalized.chainFamily).toBe("evm");
    expect(normalized.address).toBe("0x1111111111111111111111111111111111111111");
    expect(normalized.venue).toBe("hsm-primary");
    expect(normalized.exportablePrivateKey).toBe(false);
    expect(normalized.signingAvailability).toBe("provider-signing");
  });

  test("rejects private material in nested provider values", () => {
    expect(() =>
      assertNoExternalPrivateKeyMaterial({
        handle: { providerId: "hsm", keyId: "key-1" },
        metadata: { nested: { secretKey: "not-allowed" } },
      }),
    ).toThrow("must not contain private key material");
  });

  test("keeps fail-closed error surfaces explicit", () => {
    expect(externalKeySigningUnavailableError().message).toContain(
      "signing provider is not configured",
    );
    expect(externalKeyPrivateExportUnavailableError().message).toContain("not exportable");
  });
});
