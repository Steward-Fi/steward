# Keystore backends

`@stwd/vault` stores private signing keys as encrypted records. The vault accepts a `keystoreBackend` in `VaultConfig` so operators can choose where key wrapping happens.

## Default AES backend

If `keystoreBackend` is not set, the vault uses `KeyStore` with `masterPassword` exactly as before. This path derives an AES-256-GCM key from the master password with scrypt, then encrypts each private key locally.

Tradeoff: simple deployment and no network dependency. The application process can decrypt the raw private key during signing, so anyone with the master password and database contents can recover keys.

```ts
import { Vault } from "@stwd/vault";

const vault = new Vault({ masterPassword: process.env.STEWARD_MASTER_PASSWORD! });
```

## AWS KMS envelope backend

`KmsEnvelopeKeystore` creates a random 256-bit data key per record, encrypts the private key locally with AES-256-GCM, then asks AWS KMS to wrap the data key. The KMS root key never enters the application process. The plaintext data key is present only during encrypt or decrypt.

Tradeoff: the database alone is not enough to decrypt keys. The application still receives plaintext private keys at sign time, and availability depends on AWS KMS.

```ts
import { KmsEnvelopeKeystore, Vault } from "@stwd/vault";

const vault = new Vault({
  masterPassword: process.env.STEWARD_MASTER_PASSWORD!,
  keystoreBackend: new KmsEnvelopeKeystore({
    provider: "aws",
    keyId: process.env.STEWARD_AWS_KMS_KEY_ARN,
    region: process.env.STEWARD_AWS_REGION,
  }),
});
```

The AWS SDK is lazy loaded only when this backend is used. It is not required for default AES deployments.

Environment variables:

- `STEWARD_KMS_PROVIDER=aws`
- `STEWARD_KMS_KEY_ID` or `STEWARD_AWS_KMS_KEY_ARN`, the KMS key id or ARN
- `STEWARD_AWS_REGION`, the AWS region

You can also use `KmsEnvelopeKeystore.fromEnv()`.

## PKCS#11 backend

The PKCS#11 mode is for operators that use a hardware module or a PKCS#11 compatible service for wrapping data keys. The backend shape is present and accepts a `Pkcs11ClientLike` implementation with `wrapKey` and `unwrapKey` methods. This release does not include a full generic session manager for every PKCS#11 module.

Tradeoff: the wrapping root can live in hardware or a managed HSM. Operators must provide and test the module specific PKCS#11 adapter.

```ts
import { KmsEnvelopeKeystore } from "@stwd/vault";

const backend = new KmsEnvelopeKeystore({
  provider: "pkcs11",
  modulePath: process.env.STEWARD_PKCS11_MODULE,
  pin: process.env.STEWARD_PKCS11_PIN,
  keyLabel: process.env.STEWARD_PKCS11_KEY_LABEL,
  client: myPkcs11Client,
});
```

Environment variables:

- `STEWARD_KMS_PROVIDER=pkcs11`
- `STEWARD_PKCS11_MODULE`, path to the module
- `STEWARD_PKCS11_PIN`, user PIN or token PIN
- `STEWARD_PKCS11_KEY_LABEL`, label of the wrapping key

## SignerBackend — the threshold/MPC sibling (does NOT replace KeystoreBackend)

`KeystoreBackend` is built around `encrypt(privateKey) -> EncryptedKey` /
`decrypt(EncryptedKey) -> privateKey`. That shape assumes a raw private key
*exists* and can be handed back for an ephemeral signing operation. Threshold /
MPC signing (FROST, CGGMP21) breaks that assumption on purpose: the private key
never assembles in one place, so there is nothing to `encrypt` and nothing for
`decrypt` to return.

Rather than corrupt the `KeystoreBackend` contract, `@stwd/vault` ships a
**sibling** interface, `SignerBackend` (`src/signer-backend.ts`). The two are
independent and complementary:

| | `KeystoreBackend` | `SignerBackend` |
|---|---|---|
| Key material | raw private key, encrypted at rest | shares that never assemble |
| Core methods | `encrypt` / `decrypt` | `generate` (DKG/keygen ceremony) / `sign` / `verify` |
| Returns raw key? | yes (`decrypt`) | **never** — `capabilities.canReturnRawKey: false` (literal type) |
| Default? | yes (AES-256-GCM) | no — opt-in per wallet |
| Backends | AES, AWS KMS, PKCS#11 | FROST-secp256k1 (`@stwd/signer-frost`), later CGGMP21 |

The defining property of `SignerBackend` is `canReturnRawKey: false` as a
*literal type* — it is impossible to construct one that advertises a raw-key
export path, and `assertNoRawKeyExport()` enforces it at runtime for values that
slipped through via `any`/casts.

The classic path is untouched: existing call sites that `decrypt`-then-sign keep
working exactly as before. A wallet opts into threshold signing by carrying a
`ThresholdKeyRef` and routing to `signerBackend.sign(ref, digest)` instead of
touching `keystore.decrypt`. See `packages/signer-frost/THRESHOLD-SIGNING.md` for
the FROST prototype, ceremony/ops, and the EIP-1271/Safe verification path.

```ts
import type { SignerBackend, ThresholdKeyRef } from "@stwd/vault";
import { FrostSignerBackend } from "@stwd/signer-frost";

const signer: SignerBackend = new FrostSignerBackend({
  shareEndpoints: ["http://127.0.0.1:7401", "http://127.0.0.1:7402", "http://127.0.0.1:7403"],
  // per-share bearer tokens the sidecars require (single string = one shared token)
  shareAuthTokens: [
    process.env.STEWARD_FROST_TOKEN_1!,
    process.env.STEWARD_FROST_TOKEN_2!,
    process.env.STEWARD_FROST_TOKEN_3!,
  ],
  threshold: 2,
  groupPublicKeyHex: process.env.STEWARD_FROST_GROUP_PUBKEY!,
});
const ref: ThresholdKeyRef = signer.keyRef();
const { signature } = await signer.sign(ref, digest); // no private key ever exists
```

## Custom backend

Implement `KeystoreBackend` and pass it to the vault.

```ts
import type { EncryptedKey, KeystoreBackend } from "@stwd/vault";

const backend: KeystoreBackend = {
  id: "custom:v1",
  async encrypt(privateKey): Promise<EncryptedKey> {
    return encryptSomewhere(privateKey);
  },
  async decrypt(encrypted): Promise<string> {
    return decryptSomewhere(encrypted);
  },
};

const vault = new Vault({ masterPassword: "unused-by-custom", keystoreBackend: backend });
```

Backends should reject records produced by another backend. KMS envelope records include backend metadata so an AES backend cannot silently decrypt them and a PKCS#11 backend cannot silently decrypt AWS KMS records.
