/**
 * KycAdapter — identity-verification seam.
 *
 * PRIVACY POSTURE: the mock NEVER persists raw document contents or PII. When a
 * document is submitted, only a SHA-256 hash + non-sensitive descriptor
 * (type/size) is retained, demonstrating the privacy-preserving seam a real KYC
 * provider integration must honor. Raw bytes are hashed and discarded.
 */

import { AdapterValidationError, type BaseAdapter } from "../types.js";
import { assertId } from "../validation.js";

export type KycStatus = "not_started" | "pending" | "verified" | "rejected";
export type KycLevel = "basic" | "standard" | "enhanced";

export interface StartVerificationRequest {
  userId: string;
  level: KycLevel;
}

export interface KycVerification {
  readonly id: string;
  readonly provider: string;
  readonly userId: string;
  readonly level: KycLevel;
  readonly status: KycStatus;
  /** Non-sensitive descriptors of submitted documents (NO raw contents). */
  readonly documents: ReadonlyArray<KycDocumentRecord>;
  readonly createdAt: number;
  readonly updatedAt: number;
}

export interface KycDocumentRecord {
  readonly documentType: string;
  /** SHA-256 hash of the document bytes. The raw bytes are NEVER stored. */
  readonly contentHash: string;
  readonly byteLength: number;
  readonly submittedAt: number;
}

export interface SubmitDocumentRequest {
  verificationId: string;
  documentType: string;
  /** Raw document bytes. Hashed immediately; never persisted. */
  content: Uint8Array;
}

export interface KycAdapter extends BaseAdapter {
  readonly category: "kyc";
  startVerification(request: StartVerificationRequest): Promise<KycVerification>;
  getStatus(verificationId: string): Promise<KycVerification | null>;
  submitDocument(request: SubmitDocumentRequest): Promise<KycVerification>;
}

const VALID_LEVELS: ReadonlySet<KycLevel> = new Set(["basic", "standard", "enhanced"]);
const MAX_DOCUMENT_BYTES = 10 * 1024 * 1024; // 10 MiB

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes as BufferSource);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

interface MutableVerification {
  id: string;
  userId: string;
  level: KycLevel;
  status: KycStatus;
  documents: KycDocumentRecord[];
  createdAt: number;
  updatedAt: number;
}

/**
 * Deterministic mock: a verification becomes `verified` once at least one
 * document has been submitted (the deterministic rule). No raw PII is retained.
 */
export class MockKycAdapter implements KycAdapter {
  readonly category = "kyc" as const;
  readonly provider = "mock";
  readonly enabled = true;

  private verifications = new Map<string, MutableVerification>();
  private now: () => number;

  constructor(options?: { now?: () => number }) {
    this.now = options?.now ?? (() => Date.now());
  }

  private toPublic(v: MutableVerification): KycVerification {
    return {
      id: v.id,
      provider: this.provider,
      userId: v.userId,
      level: v.level,
      status: v.status,
      documents: v.documents.map((doc) => ({ ...doc })),
      createdAt: v.createdAt,
      updatedAt: v.updatedAt,
    };
  }

  async startVerification(request: StartVerificationRequest): Promise<KycVerification> {
    const userId = assertId(request.userId, "userId", 128);
    if (!VALID_LEVELS.has(request.level)) {
      throw new AdapterValidationError("level must be basic, standard, or enhanced");
    }
    const ts = this.now();
    const verification: MutableVerification = {
      id: `kyc_${crypto.randomUUID()}`,
      userId,
      level: request.level,
      status: "pending",
      documents: [],
      createdAt: ts,
      updatedAt: ts,
    };
    this.verifications.set(verification.id, verification);
    return this.toPublic(verification);
  }

  async getStatus(verificationId: string): Promise<KycVerification | null> {
    const id = assertId(verificationId, "verificationId", 128);
    const existing = this.verifications.get(id);
    return existing ? this.toPublic(existing) : null;
  }

  async submitDocument(request: SubmitDocumentRequest): Promise<KycVerification> {
    const id = assertId(request.verificationId, "verificationId", 128);
    const documentType = assertId(request.documentType, "documentType", 64);
    if (!(request.content instanceof Uint8Array) || request.content.byteLength === 0) {
      throw new AdapterValidationError("content must be non-empty document bytes");
    }
    if (request.content.byteLength > MAX_DOCUMENT_BYTES) {
      throw new AdapterValidationError("document exceeds maximum size");
    }
    const existing = this.verifications.get(id);
    if (!existing) {
      throw new AdapterValidationError("unknown verificationId");
    }

    // Hash the bytes, retain only the hash + descriptor. Raw bytes go out of
    // scope here and are never persisted — the privacy-preserving seam.
    const contentHash = await sha256Hex(request.content);
    const byteLength = request.content.byteLength;

    existing.documents.push({
      documentType,
      contentHash,
      byteLength,
      submittedAt: this.now(),
    });
    // Deterministic rule: any submitted document marks the verification verified.
    existing.status = "verified";
    existing.updatedAt = this.now();
    return this.toPublic(existing);
  }
}
