import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";
import { request as httpRequest } from "node:http";
import type { AttestationMeasurement } from "@stwd/attestation";

const VERSION = 1 as const;
const AAD_DOMAIN = "steward.sealed-state.v1";

export interface SealedStateKeyProvider {
  readonly id: string;
  deriveKey(measurement: AttestationMeasurement, purpose: string): Promise<Uint8Array>;
}

export interface SealedStateEnvelope {
  version: typeof VERSION;
  provider: string;
  measurement: AttestationMeasurement;
  purpose: string;
  wrappedDek: string;
  wrapIv: string;
  wrapTag: string;
  ciphertext: string;
  iv: string;
  tag: string;
}

function aad(
  envelope: Pick<SealedStateEnvelope, "version" | "provider" | "measurement" | "purpose">,
): Buffer {
  return Buffer.from(
    JSON.stringify({
      domain: AAD_DOMAIN,
      version: envelope.version,
      provider: envelope.provider,
      measurement: envelope.measurement,
      purpose: envelope.purpose,
    }),
    "utf8",
  );
}

function encrypt(key: Uint8Array, plaintext: Uint8Array, associatedData: Buffer) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(associatedData);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    ciphertext: ciphertext.toString("base64"),
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
  };
}

function decrypt(
  key: Uint8Array,
  ciphertext: string,
  iv: string,
  tag: string,
  associatedData: Buffer,
): Buffer {
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(iv, "base64"));
    decipher.setAAD(associatedData);
    decipher.setAuthTag(Buffer.from(tag, "base64"));
    return Buffer.concat([decipher.update(Buffer.from(ciphertext, "base64")), decipher.final()]);
  } catch {
    throw new Error("sealed state authentication failed");
  }
}

export class SealedState {
  constructor(private readonly keys: SealedStateKeyProvider) {}

  async seal(
    state: Uint8Array,
    measurement: AttestationMeasurement,
    purpose = "agent-state",
  ): Promise<SealedStateEnvelope> {
    const header = { version: VERSION, provider: this.keys.id, measurement, purpose };
    const associatedData = aad(header);
    const kek = await this.keys.deriveKey(measurement, purpose);
    if (kek.byteLength !== 32) throw new Error("sealed-state key provider must return 32 bytes");
    const dek = randomBytes(32);
    const wrapped = encrypt(kek, dek, associatedData);
    const payload = encrypt(dek, state, associatedData);
    dek.fill(0);
    return {
      ...header,
      wrappedDek: wrapped.ciphertext,
      wrapIv: wrapped.iv,
      wrapTag: wrapped.tag,
      ciphertext: payload.ciphertext,
      iv: payload.iv,
      tag: payload.tag,
    };
  }

  async unseal(
    envelope: SealedStateEnvelope,
    currentMeasurement: AttestationMeasurement,
  ): Promise<Uint8Array> {
    if (envelope.version !== VERSION || envelope.provider !== this.keys.id)
      throw new Error("unsupported sealed state envelope");
    if (
      envelope.measurement.imageDigest !== currentMeasurement.imageDigest ||
      envelope.measurement.configHash !== currentMeasurement.configHash
    ) {
      throw new Error("sealed state measurement mismatch");
    }
    const associatedData = aad(envelope);
    const kek = await this.keys.deriveKey(currentMeasurement, envelope.purpose);
    const dek = decrypt(
      kek,
      envelope.wrappedDek,
      envelope.wrapIv,
      envelope.wrapTag,
      associatedData,
    );
    try {
      return decrypt(dek, envelope.ciphertext, envelope.iv, envelope.tag, associatedData);
    } finally {
      dek.fill(0);
    }
  }
}

export class DevMeasurementKeyProvider implements SealedStateKeyProvider {
  readonly id = "INSECURE-noop-dev";
  constructor(
    private readonly secret: string,
    environment = process.env.NODE_ENV ?? "development",
  ) {
    if (environment === "production")
      throw new Error("INSECURE noop-dev sealed-state backend is forbidden in production");
    if (secret.length < 16)
      throw new Error("noop-dev sealed-state secret must be at least 16 characters");
  }
  async deriveKey(measurement: AttestationMeasurement, purpose: string): Promise<Uint8Array> {
    const info = `${measurement.imageDigest}\0${measurement.configHash}\0${purpose}`;
    return new Uint8Array(hkdfSync("sha256", this.secret, AAD_DOMAIN, info, 32));
  }
}

export interface DstackSealedStateKeyProviderOptions {
  socketPath?: string;
}
export class DstackSealedStateKeyProvider implements SealedStateKeyProvider {
  readonly id = "dstack-tdx";
  private readonly socketPath: string;
  constructor(options: DstackSealedStateKeyProviderOptions = {}) {
    this.socketPath =
      options.socketPath ?? process.env.DSTACK_SOCKET_PATH ?? "/var/run/dstack.sock";
  }
  async currentMeasurement(): Promise<AttestationMeasurement> {
    const info = await this.call<{ os_image_hash?: string; compose_hash?: string }>("/Info");
    if (!info.os_image_hash || !info.compose_hash)
      throw new Error("dstack /Info omitted runtime measurement");
    return { imageDigest: info.os_image_hash, configHash: info.compose_hash };
  }
  async deriveKey(measurement: AttestationMeasurement, purpose: string): Promise<Uint8Array> {
    const info = await this.call<{ os_image_hash?: string; compose_hash?: string }>("/Info");
    if (
      info.os_image_hash !== measurement.imageDigest ||
      info.compose_hash !== measurement.configHash
    )
      throw new Error("dstack runtime measurement does not match sealed-state request");
    const path = `steward/sealed-state/v1/${measurement.imageDigest}/${measurement.configHash}/${purpose}`;
    const result = await this.call<{ key?: string }>("/GetKey", {
      path,
      purpose: "sealed-state-kek",
      algorithm: "ed25519",
    });
    if (!result.key || !/^[0-9a-fA-F]{64}$/.test(result.key))
      throw new Error("dstack /GetKey returned invalid key material");
    return Uint8Array.from(Buffer.from(result.key, "hex"));
  }
  private call<T>(path: string, body?: unknown): Promise<T> {
    return new Promise((resolve, reject) => {
      const payload = body ? JSON.stringify(body) : undefined;
      const req = httpRequest(
        {
          socketPath: this.socketPath,
          path,
          method: payload ? "POST" : "GET",
          headers: payload
            ? { "content-type": "application/json", "content-length": Buffer.byteLength(payload) }
            : undefined,
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
          res.on("end", () => {
            if ((res.statusCode ?? 500) >= 300)
              return reject(new Error(`dstack guest agent ${path} failed (${res.statusCode})`));
            try {
              resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")) as T);
            } catch {
              reject(new Error(`dstack guest agent ${path} returned invalid JSON`));
            }
          });
        },
      );
      req.on("error", () => reject(new Error(`dstack guest agent ${path} unavailable`)));
      if (payload) req.write(payload);
      req.end();
    });
  }
}
