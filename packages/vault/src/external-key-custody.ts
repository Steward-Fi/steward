import type { ChainFamily } from "@stwd/shared";

export type ExternalKeySigningAvailability = "not-supported" | "provider-signing";

/** Public compatibility marker for operator-supplied custody providers. */
export const EXTERNAL_KEY_CUSTODY_CONTRACT_VERSION = 1 as const;

export interface ExternalKeyHandleDescriptor {
  providerId: string;
  keyId: string;
  version?: string;
  region?: string;
  metadata?: Record<string, unknown>;
}

export interface ExternalKeyHandleImportRequest {
  tenantId: string;
  agentId: string;
  chainFamily: ChainFamily;
  address: string;
  handle: ExternalKeyHandleDescriptor;
  venue?: string | null;
  purpose?: string | null;
  metadata?: Record<string, unknown>;
}

export interface ExternalKeyHandleExportRequest {
  tenantId: string;
  agentId: string;
  chainFamily: ChainFamily;
  venue?: string | null;
}

export interface ExternalKeySignTransactionRequest {
  tenantId: string;
  agentId: string;
  chainFamily: Extract<ChainFamily, "evm" | "solana">;
  address: string;
  handle: ExternalKeyHandleDescriptor;
  venue?: string | null;
  chainId: number;
  to: string;
  value: string;
  data?: string;
  gasLimit?: string;
  nonce?: number;
  broadcast: boolean;
  rpcUrl?: string;
}

export interface ExternalKeySignTransactionResult {
  result: string;
  broadcast: boolean;
}

export interface ExternalKeyHandleRegistration {
  custody: "external";
  tenantId: string;
  agentId: string;
  chainFamily: ChainFamily;
  address: string;
  handle: ExternalKeyHandleDescriptor;
  venue: string | null;
  purpose: string | null;
  metadata: Record<string, unknown>;
  registeredAt: Date;
  exportablePrivateKey: false;
  signingAvailability: ExternalKeySigningAvailability;
}

export interface ExternalKeyCustodyProvider {
  id: string;
  readonly contractVersion: typeof EXTERNAL_KEY_CUSTODY_CONTRACT_VERSION;
  registerKeyHandle(
    request: ExternalKeyHandleImportRequest,
  ): Promise<ExternalKeyHandleRegistration>;
  exportKeyHandle?(request: ExternalKeyHandleExportRequest): Promise<ExternalKeyHandleRegistration>;
  signTransaction?(
    request: ExternalKeySignTransactionRequest,
  ): Promise<ExternalKeySignTransactionResult>;
}

export function assertExternalKeyCustodyProviderV1(provider: ExternalKeyCustodyProvider): void {
  if (provider.contractVersion !== EXTERNAL_KEY_CUSTODY_CONTRACT_VERSION) {
    throw new Error(
      `Unsupported external key custody contract version: ${String(provider.contractVersion)}`,
    );
  }
  if (!provider.id?.trim() || typeof provider.registerKeyHandle !== "function") {
    throw new Error(
      "External key custody provider does not implement the v1 registration contract",
    );
  }
}

const PRIVATE_MATERIAL_FIELD_NAMES = new Set([
  "privatekey",
  "secretkey",
  "keymaterial",
  "plaintextkey",
  "mnemonic",
  "seed",
  "seedphrase",
]);

export function externalKeyCustodyUnavailableError(): Error {
  return new Error(
    "External key custody provider is not configured; hardware/HSM handle import is disabled",
  );
}

export function externalKeySigningUnavailableError(): Error {
  return new Error(
    "External key custody signing provider is not configured for this wallet; hardware/HSM signing is disabled",
  );
}

export function externalKeyPrivateExportUnavailableError(): Error {
  return new Error("External key custody private keys are not exportable");
}

export function assertNoExternalPrivateKeyMaterial(value: unknown, path = "request"): void {
  if (value === null || value === undefined) return;
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoExternalPrivateKeyMaterial(item, `${path}[${index}]`));
    return;
  }
  if (typeof value !== "object") return;

  for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
    // Normalize separators/casing so aliases such as private_key, private-key,
    // seedPhrase and KEY_MATERIAL cannot bypass the provider boundary.
    const normalizedKey = key.toLowerCase().replace(/[^a-z0-9]/g, "");
    if (PRIVATE_MATERIAL_FIELD_NAMES.has(normalizedKey)) {
      throw new Error(`External key custody ${path}.${key} must not contain private key material`);
    }
    assertNoExternalPrivateKeyMaterial(nested, `${path}.${key}`);
  }
}

export function normalizeExternalKeyHandleRegistration(
  request: ExternalKeyHandleImportRequest,
  registration: ExternalKeyHandleRegistration,
): ExternalKeyHandleRegistration {
  assertNoExternalPrivateKeyMaterial(registration, "registration");
  if (registration.exportablePrivateKey !== false) {
    throw new Error("External key custody registration must not be private-key exportable");
  }
  if (
    registration.signingAvailability !== "not-supported" &&
    registration.signingAvailability !== "provider-signing"
  ) {
    throw new Error("External key custody signingAvailability is not supported");
  }
  return {
    ...registration,
    custody: "external",
    tenantId: request.tenantId,
    agentId: request.agentId,
    chainFamily: request.chainFamily,
    address: request.address,
    venue: request.venue ?? null,
    purpose: request.purpose ?? null,
    exportablePrivateKey: false,
    signingAvailability: registration.signingAvailability,
  };
}

export class FailClosedExternalKeyCustodyProvider implements ExternalKeyCustodyProvider {
  id = "external-key-custody-disabled";
  readonly contractVersion = EXTERNAL_KEY_CUSTODY_CONTRACT_VERSION;

  async registerKeyHandle(): Promise<ExternalKeyHandleRegistration> {
    throw externalKeyCustodyUnavailableError();
  }

  async exportKeyHandle(): Promise<ExternalKeyHandleRegistration> {
    throw externalKeyCustodyUnavailableError();
  }
}

export class InMemoryExternalKeyCustodyProvider implements ExternalKeyCustodyProvider {
  id: string;
  readonly contractVersion = EXTERNAL_KEY_CUSTODY_CONTRACT_VERSION;
  private registrations = new Map<string, ExternalKeyHandleRegistration>();

  constructor(id = "in-memory-external-key-custody") {
    this.id = id;
  }

  async registerKeyHandle(
    request: ExternalKeyHandleImportRequest,
  ): Promise<ExternalKeyHandleRegistration> {
    assertNoExternalPrivateKeyMaterial(request);
    const registration: ExternalKeyHandleRegistration = {
      custody: "external",
      tenantId: request.tenantId,
      agentId: request.agentId,
      chainFamily: request.chainFamily,
      address: request.address,
      handle: request.handle,
      venue: request.venue ?? null,
      purpose: request.purpose ?? null,
      metadata: request.metadata ?? {},
      registeredAt: new Date(),
      exportablePrivateKey: false,
      signingAvailability: "not-supported",
    };
    this.registrations.set(this.registrationKey(request), registration);
    return registration;
  }

  async exportKeyHandle(
    request: ExternalKeyHandleExportRequest,
  ): Promise<ExternalKeyHandleRegistration> {
    const registration = this.registrations.get(this.registrationKey(request));
    if (!registration) {
      throw new Error("External key handle is not registered");
    }
    return registration;
  }

  private registrationKey(request: ExternalKeyHandleExportRequest): string {
    return [request.tenantId, request.agentId, request.chainFamily, request.venue ?? ""].join(":");
  }
}
