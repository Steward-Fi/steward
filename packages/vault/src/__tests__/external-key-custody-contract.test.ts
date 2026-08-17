import { describe, expect, test } from "bun:test";
import {
  assertExternalKeyCustodyProviderV1,
  assertNoExternalPrivateKeyMaterial,
  EXTERNAL_KEY_CUSTODY_CONTRACT_VERSION,
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
  test("publishes and enforces the v1 compatibility marker", () => {
    expect(EXTERNAL_KEY_CUSTODY_CONTRACT_VERSION).toBe(1);
    expect(() =>
      assertExternalKeyCustodyProviderV1({
        id: "provider-v1",
        contractVersion: 1,
        async registerKeyHandle(input) {
          return normalizeExternalKeyHandleRegistration(input, registration());
        },
      }),
    ).not.toThrow();
    expect(() =>
      assertExternalKeyCustodyProviderV1({
        id: "future-provider",
        contractVersion: 2 as 1,
        async registerKeyHandle(input) {
          return normalizeExternalKeyHandleRegistration(input, registration());
        },
      }),
    ).toThrow("Unsupported external key custody contract version");
  });

  test("normalizes provider-signing registrations without private-key exportability", () => {
    const normalized = normalizeExternalKeyHandleRegistration(
      request,
      registration({
        tenantId: request.tenantId,
        agentId: request.agentId,
        chainFamily: request.chainFamily,
        address: request.address,
      }),
    );

    expect(normalized.tenantId).toBe("tenant");
    expect(normalized.agentId).toBe("agent");
    expect(normalized.chainFamily).toBe("evm");
    expect(normalized.address).toBe("0x1111111111111111111111111111111111111111");
    expect(normalized.venue).toBe("hsm-primary");
    expect(normalized.exportablePrivateKey).toBe(false);
    expect(normalized.signingAvailability).toBe("provider-signing");
  });

  test("rejects provider responses that change the requested identity binding", () => {
    const bound = registration({
      tenantId: request.tenantId,
      agentId: request.agentId,
      chainFamily: request.chainFamily,
      address: request.address,
    });
    expect(() =>
      normalizeExternalKeyHandleRegistration(request, { ...bound, tenantId: "other-tenant" }),
    ).toThrow("did not preserve the requested identity binding");
    expect(() =>
      normalizeExternalKeyHandleRegistration(request, {
        ...bound,
        handle: { ...bound.handle, keyId: "different-key" },
      }),
    ).toThrow("did not preserve the requested identity binding");
    expect(() =>
      normalizeExternalKeyHandleRegistration(request, {
        ...bound,
        address: "0x2222222222222222222222222222222222222222",
      }),
    ).toThrow("did not preserve the requested identity binding");
  });

  test("rejects private material in nested provider values", () => {
    expect(() =>
      assertNoExternalPrivateKeyMaterial({
        handle: { providerId: "hsm", keyId: "key-1" },
        metadata: { nested: { secretKey: "not-allowed" } },
      }),
    ).toThrow("must not contain private key material");
    expect(() =>
      assertNoExternalPrivateKeyMaterial({ metadata: { nested: { private_key: "0xsecret" } } }),
    ).toThrow("must not contain private key material");
    expect(() =>
      assertNoExternalPrivateKeyMaterial({ metadata: { nested: { seedPhrase: "words" } } }),
    ).toThrow("must not contain private key material");
    expect(() =>
      assertNoExternalPrivateKeyMaterial({ metadata: { recoveryPhrase: "words" } }),
    ).toThrow("must not contain private key material");
  });

  test("rejects cyclic, accessor, and custom-prototype provider values", () => {
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(() => assertNoExternalPrivateKeyMaterial(cyclic)).toThrow("cyclic references");

    const accessor = Object.defineProperty({}, "privateKey", {
      enumerable: false,
      get: () => "must-not-run",
    });
    expect(() => assertNoExternalPrivateKeyMaterial(accessor)).toThrow(
      "must not contain private key material",
    );

    expect(() => assertNoExternalPrivateKeyMaterial(new Map([["label", "value"]]))).toThrow(
      "plain data only",
    );
  });

  test("keeps fail-closed error surfaces explicit", () => {
    expect(externalKeySigningUnavailableError().message).toContain(
      "signing provider is not configured",
    );
    expect(externalKeyPrivateExportUnavailableError().message).toContain("not exportable");
  });
});
