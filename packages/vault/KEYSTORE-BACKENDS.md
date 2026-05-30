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
