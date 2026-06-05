import type { ChainFamily } from "@stwd/shared";

export type ExternalKeySigningAvailability = "not-supported" | "provider-signing";

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
  registerKeyHandle(
    request: ExternalKeyHandleImportRequest,
  ): Promise<ExternalKeyHandleRegistration>;
  exportKeyHandle?(request: ExternalKeyHandleExportRequest): Promise<ExternalKeyHandleRegistration>;
  signTransaction?(
    request: ExternalKeySignTransactionRequest,
  ): Promise<ExternalKeySignTransactionResult>;
}

const PRIVATE_MATERIAL_FIELD_NAMES = new Set([
  "privatekey",
  "secretkey",
  "keymaterial",
  "plaintextkey",
  "mnemonic",
  "seed",
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
    if (PRIVATE_MATERIAL_FIELD_NAMES.has(key.toLowerCase())) {
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

  async registerKeyHandle(): Promise<ExternalKeyHandleRegistration> {
    throw externalKeyCustodyUnavailableError();
  }

  async exportKeyHandle(): Promise<ExternalKeyHandleRegistration> {
    throw externalKeyCustodyUnavailableError();
  }
}

export class InMemoryExternalKeyCustodyProvider implements ExternalKeyCustodyProvider {
  id: string;
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
