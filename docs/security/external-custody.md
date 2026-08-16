# External signing custody v1

Steward's external-custody contract governs a signer without importing its
private key. Steward stores an opaque provider/key handle and a public EVM
address. At execution time it prepares a bounded transaction, sends only the
32-byte transaction digest to the signer, normalizes the returned signature,
and proves that the signature recovers to the registered address before it can
be returned or broadcast.

This is different from `STEWARD_KMS_PROVIDER=aws`:

| Configuration | AWS KMS use | Private key in Steward memory at sign time |
|---|---|---|
| `STEWARD_KMS_PROVIDER=aws` | Wrap/unwrap a per-record AES data key | **Yes** |
| `STEWARD_EXTERNAL_CUSTODY_PROVIDER=aws-kms` | Asymmetric secp256k1 signing | **No** |

The modes may coexist. External custody applies only to wallets registered with
an external handle; local/envelope wallets retain their configured posture.

## AWS prerequisites

Create an asymmetric KMS key with:

- key spec `ECC_SECG_P256K1`;
- key usage `SIGN_VERIFY`;
- signing algorithm `ECDSA_SHA_256`;
- an IAM policy granting only `kms:GetPublicKey` and `kms:Sign` for the exact
  key ARN. The reference adapter never calls `kms:Decrypt`, `kms:ExportKey`, or
  key-creation APIs.

Configure the deployment:

```bash
STEWARD_EXTERNAL_CUSTODY_PROVIDER=aws-kms
STEWARD_EXTERNAL_CUSTODY_AWS_REGION=us-east-1
```

`STEWARD_MASTER_PASSWORD` and the normal local-custody acknowledgement still
apply because a deployment can contain both external and server-managed
wallets. Selecting an external provider does not silently disable or relabel
the local keystore.

## Registering an EVM handle

Provisioning code registers the public identity once through the existing
`Vault.registerExternalKeyHandle` seam:

```ts
import { AwsKmsExternalKeyCustodyProvider, Vault } from "@stwd/vault";

const vault = new Vault({
  masterPassword: process.env.STEWARD_MASTER_PASSWORD!,
  externalKeyCustodyProvider: AwsKmsExternalKeyCustodyProvider.fromEnv(),
});

await vault.registerExternalKeyHandle({
  tenantId: "tenant-id",
  agentId: "agent-id",
  chainFamily: "evm",
  address: "0xExpectedAddressDerivedFromTheKmsPublicKey",
  handle: {
    providerId: "aws-kms",
    keyId: "arn:aws:kms:us-east-1:111122223333:key/key-id",
    region: "us-east-1",
  },
  venue: "aws-primary",
  purpose: "evm-signing",
});
```

Registration calls `GetPublicKey`, requires the exact key spec/usage/algorithm,
derives the Ethereum address from the returned SPKI key, and rejects an address
mismatch. Steward persists no public-key bytes, signature credentials, or
private material—only the provider handle and verified address. The same
binding is repeated immediately before every signature to detect a changed
alias or handle.

The reference provider supports EVM transaction signing only. Solana, Bitcoin,
messages, typed data, user operations, and arbitrary hashes fail closed rather
than being routed through an unreviewed translation.

## Signing and broadcast boundary

For an EVM transaction the provider:

1. validates chain, recipient, value, calldata, gas and nonce inputs;
2. resolves fees/nonce/gas from the operator-configured RPC;
3. rechecks that the prepared transaction still matches the semantic request;
4. hashes the canonical unsigned legacy transaction with Keccak-256;
5. calls KMS `Sign` with `MessageType=DIGEST` and `ECDSA_SHA_256`;
6. strictly decodes DER, validates scalar ranges, and normalizes high-s output;
7. derives `yParity` only by recovering the registered address;
8. broadcasts only after that recovery succeeds.

A malformed response, wrong key, wrong address, unsupported algorithm, mutated
RPC preparation, missing RPC, or KMS error fails closed before broadcast.

## Writing another provider

Implement `ExternalKeyCustodyProvider` with
`contractVersion = EXTERNAL_KEY_CUSTODY_CONTRACT_VERSION`. In the provider's
own test suite, run the framework-neutral conformance probe:

```ts
import { runExternalKeyCustodyV1Conformance } from "@stwd/vault";

await runExternalKeyCustodyV1Conformance({
  createProvider: () => new YourProvider(),
  validRegistrationRequest: testHandle,
});
```

The suite verifies contract versioning, identity binding, non-exportability,
signing declaration consistency, and direct rejection of nested private-key
material. Passing it does not certify a provider's HSM, IAM, availability, or
transport. Those remain operator responsibilities.

## Precise posture

The AWS KMS private key never leaves KMS unencrypted and never enters Steward
memory. This does **not** make signing operator-proof: a compromised Steward
process with valid `kms:Sign` permission can request signatures within whatever
IAM and Steward policy boundaries remain. Use narrow key policies, per-tenant or
per-agent keys where warranted, CloudTrail monitoring, key disable/revocation,
and the existing Steward policy/approval/audit controls.
