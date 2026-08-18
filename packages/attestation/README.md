# @stwd/attestation

Vendor-neutral runtime-attestation interfaces and measurement-registry
verification for Steward.

The package includes:

- the `dstack-tdx` provider for dstack Guest Agent quote generation and external
  verifier checks;
- the explicit `noop-dev` provider for local development;
- fail-closed unsupported-provider seams for AWS Nitro and AMD SEV-SNP; and
- signed measurement-registry verification with Ed25519 keys.

```ts
import {
  createDstackTdxProvider,
  createNoopDevProvider,
  verifyQuoteAgainstRegistry,
  verifyRegistrySignatures,
} from "@stwd/attestation";
```

See the [attestation guide](../../docs/ATTESTATION.md) for provider configuration,
trust boundaries, and registry operations. A generated quote is not trusted
unless provider verification succeeds and its measurement matches an active,
trusted registry entry.

## Validation

```bash
bun run build
bun test
```

## License

MIT
