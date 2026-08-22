export type SecuritySurfaceKind = "wallet-signing" | "key-material-export" | "credential-injection";

export type EnforcementBoundary =
  | "route-policy"
  | "gateway-authorized"
  | "route-policy-with-unsafe-flag"
  | "route-consent-with-unsafe-flag"
  | "route-mfa-break-glass"
  | "proxy-route-policy";

export interface SecuritySurfaceRoute {
  file: string;
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "ALL" | "HANDLER";
  path: string;
  notes?: string;
  /**
   * For wallet-signing surfaces: whether this specific route is bound to the
   * policy-bound execution gateway (GovernedVault mint and consume before raw
   * signing). `false`/undefined means the route still reaches the raw signer
   * through route-local policy only and is NOT yet gateway-migrated. This must
   * be honest per-route; do not claim product-wide enforcement.
   */
  gatewayMigrated?: boolean;
}

/**
 * A raw EVM `Vault.signTransaction` call site that is NOT yet routed through the
 * execution gateway. Enumerated explicitly so the security surface never
 * over-claims product-wide enforcement. These routes remain route-policy
 * boundaries until they are migrated to GovernedVault.
 */
export interface LegacyEvmSignCallSite {
  file: string;
  approxLine: number;
  path: string;
  reason: string;
}

export interface SecuritySurfaceOperation {
  id: string;
  kind: SecuritySurfaceKind;
  capability: string;
  vaultMethods: readonly string[];
  routes: readonly SecuritySurfaceRoute[];
  auth: readonly string[];
  policy: readonly string[];
  policyEngineGated: boolean | "mixed";
  legacy: boolean;
  custody: {
    localVault: boolean;
    externalCustody: "supported" | "unsupported" | "not-applicable";
    notes: string;
  };
  unsafeFlags: readonly string[];
  evidence: readonly string[];
  boundary: EnforcementBoundary;
  notes: string;
}

export const SECURITY_SURFACE_INVENTORY_VERSION = 1;

export const SECURITY_SURFACE_OPERATIONS = [
  {
    id: "wallet.evm_transaction.sign",
    kind: "wallet-signing",
    capability: "sign_transaction",
    vaultMethods: ["signTransaction"],
    routes: [
      {
        file: "packages/api/src/routes/vault.ts",
        method: "POST",
        path: "/:agentId/sign",
        gatewayMigrated: true,
        notes:
          "Primary EVM sign. Mints+consumes a policy-bound execution authorization via GovernedVault before raw signing; raw fallback is Solana-only with an invariant guard.",
      },
      {
        file: "packages/api/src/routes/vault.ts",
        method: "POST",
        path: "/:agentId/approve/:txId",
        gatewayMigrated: true,
        notes:
          "Approval replay for the primary EVM transaction surface. Fails closed unless the stored digest + policy-revision binding is present and matches; then mints+consumes an authorization via GovernedVault. Transfer/AA branches are separate and not gateway-migrated.",
      },
      {
        file: "packages/api/src/routes/vault.ts",
        method: "POST",
        path: "/:agentId/actions/transfer",
        gatewayMigrated: false,
        notes:
          "Transfer action surface. Route-local policy gated; NOT yet routed through the execution gateway.",
      },
      {
        file: "packages/api/src/routes/vault.ts",
        method: "POST",
        path: "/:agentId/actions/send-calls",
        gatewayMigrated: false,
        notes: "Batch-call action surface; approval replay hard-disabled; not gateway-migrated.",
      },
      {
        file: "packages/api/src/routes/vault.ts",
        method: "POST",
        path: "/:agentId/transactions/:txId/replace",
        gatewayMigrated: false,
        notes: "Replace/RBF surface; route-local policy only; not gateway-migrated.",
      },
      {
        file: "packages/api/src/routes/intents.ts",
        method: "POST",
        path: "/:intentId/execute",
        gatewayMigrated: false,
        notes: "Legacy intent execution EVM sign; not gateway-migrated.",
      },
      {
        file: "packages/api/src/routes/user.ts",
        method: "POST",
        path: "/me/wallet/sign",
        gatewayMigrated: false,
        notes: "Personal user-session EVM sign; not gateway-migrated.",
      },
      {
        file: "packages/api/src/routes/global-wallet.ts",
        method: "POST",
        path: "/rpc",
        notes: "eth_sendTransaction compatibility path; not gateway-migrated.",
        gatewayMigrated: false,
      },
    ],
    auth: [
      "agent access or tenant/user session as route-specific",
      "delegated signer permission sign_transaction where supported",
      "broadcast routes require idempotency",
    ],
    policy: ["PolicyEngine.evaluate", "rate limit policy", "spend lock before sign"],
    policyEngineGated: true,
    legacy: false,
    custody: {
      localVault: true,
      externalCustody: "supported",
      notes:
        "Vault.signTransaction can delegate only this operation to externalKeyCustodyProvider.signTransaction.",
    },
    unsafeFlags: ["STEWARD_ALLOW_UNSAFE_CONTRACT_CALL_SIGNING for unconstrained contract calls"],
    evidence: ["transactions row", "vault audit events", "webhook events"],
    boundary: "gateway-authorized",
    notes:
      "SCOPED CLAIM: only the primary EVM `/vault/:agentId/sign` route and its compatible approval replay (`/vault/:agentId/approve/:txId`, transaction action surface) are gateway-authorized — they mint+consume a policy-bound execution authorization immediately before raw Vault.signTransaction and fail closed otherwise. The remaining EVM sign call sites enumerated in LEGACY_EVM_SIGN_CALL_SITES are NOT yet gateway-migrated and remain route-local-policy only. This is intentionally NOT a product-wide enforcement claim; the remaining call sites are tracked as pending gateway convergence.",
  },
  {
    id: "wallet.message.sign",
    kind: "wallet-signing",
    capability: "sign_message",
    vaultMethods: ["signMessage"],
    routes: [
      { file: "packages/api/src/routes/vault.ts", method: "POST", path: "/:agentId/sign-message" },
      { file: "packages/api/src/routes/user.ts", method: "POST", path: "/me/wallet/sign-message" },
      {
        file: "packages/api/src/routes/global-wallet.ts",
        method: "POST",
        path: "/rpc",
        notes: "personal_sign compatibility path",
      },
    ],
    auth: ["owner/admin or user session with recent MFA", "delegated sign_message where supported"],
    policy: ["auth-message refusal only; no transaction policy model"],
    policyEngineGated: false,
    legacy: true,
    custody: {
      localVault: true,
      externalCustody: "unsupported",
      notes: "External custody provider currently exposes signTransaction only.",
    },
    unsafeFlags: [
      "STEWARD_ALLOW_UNSAFE_MESSAGE_SIGNING",
      "STEWARD_ALLOW_VAULT_UNSAFE_MESSAGE_SIGNING",
      "STEWARD_ALLOW_USER_UNSAFE_MESSAGE_SIGNING",
      "STEWARD_ALLOW_GLOBAL_WALLET_PERSONAL_SIGN",
    ],
    evidence: ["audit events"],
    boundary: "route-policy-with-unsafe-flag",
    notes:
      "Compatibility signing path intentionally fails closed unless explicit unsafe flags and MFA gates pass.",
  },
  {
    id: "wallet.raw_hash.sign",
    kind: "wallet-signing",
    capability: "sign_raw_hash",
    vaultMethods: ["signRawHash"],
    routes: [
      { file: "packages/api/src/routes/vault.ts", method: "POST", path: "/:agentId/sign-raw-hash" },
    ],
    auth: ["agent access", "owner/admin recent MFA", "delegated sign_raw_hash"],
    policy: ["no chain policy; compatibility path only"],
    policyEngineGated: false,
    legacy: true,
    custody: { localVault: true, externalCustody: "unsupported", notes: "Local EVM key only." },
    unsafeFlags: ["STEWARD_ALLOW_UNSAFE_RAW_SIGNING", "STEWARD_ALLOW_VAULT_UNSAFE_RAW_SIGNING"],
    evidence: ["vault audit events", "wallet.raw_signature.created webhook"],
    boundary: "route-policy-with-unsafe-flag",
    notes: "Raw secp256k1 digest signing bypasses transaction policy controls.",
  },
  {
    id: "wallet.raw_digest.sign",
    kind: "wallet-signing",
    capability: "sign_raw_digest",
    vaultMethods: ["signRawDigest"],
    routes: [
      {
        file: "packages/api/src/routes/vault.ts",
        method: "POST",
        path: "/:agentId/sign-raw-digest",
      },
    ],
    auth: ["agent access", "owner/admin recent MFA", "delegated sign_raw_digest"],
    policy: ["raw-signing-chain policy", "PolicyEngine.evaluate", "rate limit policy"],
    policyEngineGated: true,
    legacy: false,
    custody: {
      localVault: true,
      externalCustody: "unsupported",
      notes: "Local EVM/Solana keys only.",
    },
    unsafeFlags: ["STEWARD_ALLOW_UNSAFE_RAW_SIGNING", "STEWARD_ALLOW_VAULT_UNSAFE_RAW_SIGNING"],
    evidence: ["vault audit events", "wallet.raw_signature.created webhook"],
    boundary: "route-policy-with-unsafe-flag",
    notes:
      "Cross-curve raw digest signing is constrained by route policy before Vault.signRawDigest.",
  },
  {
    id: "wallet.bitcoin_psbt.sign",
    kind: "wallet-signing",
    capability: "sign_bitcoin_psbt",
    vaultMethods: ["signBitcoinPsbt"],
    routes: [
      {
        file: "packages/api/src/routes/vault.ts",
        method: "POST",
        path: "/:agentId/sign-bitcoin-psbt",
      },
    ],
    auth: ["agent access", "delegated sign_transaction"],
    policy: [
      "raw-signing-chain bitcoin/secp256k1",
      "destination and aggregate PolicyEngine.evaluate",
    ],
    policyEngineGated: true,
    legacy: false,
    custody: {
      localVault: true,
      externalCustody: "unsupported",
      notes: "Local Bitcoin keys only.",
    },
    unsafeFlags: [],
    evidence: ["transactions row", "vault audit events"],
    boundary: "route-policy",
    notes: "The route inspects PSBT outputs and fee before Vault.signBitcoinPsbt.",
  },
  {
    id: "wallet.monero_transfer.execute",
    kind: "wallet-signing",
    capability: "transfer_monero",
    vaultMethods: ["prepareMoneroTransfer", "relayMoneroTransfer"],
    routes: [
      {
        file: "packages/api/src/routes/vault.ts",
        method: "POST",
        path: "/:agentId/monero/transfer",
      },
    ],
    auth: ["agent access", "delegated sign_transaction"],
    policy: [
      "raw-signing-chain monero/ed25519",
      "destination and fee-inclusive aggregate PolicyEngine.evaluate",
    ],
    policyEngineGated: true,
    legacy: false,
    custody: {
      localVault: true,
      externalCustody: "unsupported",
      notes: "monero-wallet-rpc backend only.",
    },
    unsafeFlags: [],
    evidence: ["transactions row", "vault audit events", "wallet_action-style metadata"],
    boundary: "route-policy",
    notes:
      "The route prepares a signed but unrelayed transfer, re-evaluates fee-inclusive spend, then relays.",
  },
  {
    id: "wallet.typed_data.sign",
    kind: "wallet-signing",
    capability: "sign_typed_data",
    vaultMethods: ["signTypedData"],
    routes: [
      {
        file: "packages/api/src/routes/vault.ts",
        method: "POST",
        path: "/:agentId/sign-typed-data",
      },
      {
        file: "packages/api/src/routes/global-wallet.ts",
        method: "POST",
        path: "/rpc",
        notes: "eth_signTypedData_v4 compatibility path",
      },
    ],
    auth: ["agent access plus delegated sign_typed_data", "global wallet consent plus recent MFA"],
    policy: ["typed-data policy or explicit unsafe typed-data flags", "PolicyEngine.evaluate"],
    policyEngineGated: "mixed",
    legacy: true,
    custody: { localVault: true, externalCustody: "unsupported", notes: "Local EVM keys only." },
    unsafeFlags: [
      "STEWARD_ALLOW_UNSAFE_TYPED_DATA_SIGNING",
      "STEWARD_ALLOW_VAULT_UNSAFE_TYPED_DATA_SIGNING",
      "STEWARD_ALLOW_GLOBAL_WALLET_TYPED_DATA_SIGNING",
    ],
    evidence: ["transactions row", "vault/global-wallet audit events"],
    boundary: "route-policy-with-unsafe-flag",
    notes:
      "The vault route has policy evaluation; the global wallet compatibility route is consent/MFA gated.",
  },
  {
    id: "wallet.user_operation.sign",
    kind: "wallet-signing",
    capability: "sign_user_operation",
    vaultMethods: ["signUserOperation"],
    routes: [
      {
        file: "packages/api/src/routes/vault.ts",
        method: "POST",
        path: "/:agentId/sign-user-operation",
      },
    ],
    auth: ["agent access", "owner/admin recent MFA", "delegated sign_user_operation"],
    policy: ["PolicyEngine.evaluate after route-provided to/value/callData"],
    policyEngineGated: true,
    legacy: false,
    custody: { localVault: true, externalCustody: "unsupported", notes: "Local EVM keys only." },
    unsafeFlags: ["STEWARD_ALLOW_UNSAFE_USER_OPERATION_SIGNING"],
    evidence: ["transactions row", "vault audit events"],
    boundary: "route-policy-with-unsafe-flag",
    notes: "Disabled unless the unsafe flag and route policy-model gate pass.",
  },
  {
    id: "wallet.eip7702_authorization.sign",
    kind: "wallet-signing",
    capability: "sign_authorization",
    vaultMethods: ["signAuthorization"],
    routes: [
      {
        file: "packages/api/src/routes/vault.ts",
        method: "POST",
        path: "/:agentId/sign-authorization",
      },
    ],
    auth: ["agent access", "owner/admin recent MFA", "delegated sign_authorization"],
    policy: ["PolicyEngine.evaluate against delegation contract address"],
    policyEngineGated: true,
    legacy: false,
    custody: { localVault: true, externalCustody: "unsupported", notes: "Local EVM keys only." },
    unsafeFlags: ["STEWARD_ALLOW_UNSAFE_AUTHORIZATION_SIGNING"],
    evidence: ["transactions row", "vault audit events"],
    boundary: "route-policy-with-unsafe-flag",
    notes: "EIP-7702 delegation signing remains an unsafe break-glass route.",
  },
  {
    id: "wallet.solana_transaction.sign",
    kind: "wallet-signing",
    capability: "sign_solana_transaction",
    vaultMethods: ["signSolanaTransaction", "signTransaction"],
    routes: [
      {
        file: "packages/api/src/routes/vault.ts",
        method: "POST",
        path: "/:agentId/sign",
        notes:
          "Solana native branch consumes a durable execution claim through GovernedVault before raw signing",
      },
      { file: "packages/api/src/routes/vault.ts", method: "POST", path: "/:agentId/sign-solana" },
      {
        file: "packages/api/src/routes/vault.ts",
        method: "POST",
        path: "/:agentId/actions/transfer",
        notes: "Solana transfer action branch",
      },
      {
        file: "packages/api/src/routes/vault.ts",
        method: "POST",
        path: "/:agentId/approve/:txId",
        notes:
          "Solana approval execution branch; native transfers consume a durable execution claim through GovernedVault immediately before raw signing",
      },
    ],
    auth: ["agent access", "delegated sign_transaction"],
    policy: ["decoded transaction PolicyEngine.evaluate", "blind path requires unsafe flag"],
    policyEngineGated: true,
    legacy: false,
    custody: { localVault: true, externalCustody: "unsupported", notes: "Local Solana keys only." },
    unsafeFlags: ["STEWARD_ALLOW_UNSAFE_SOLANA_BLIND_SIGNING"],
    evidence: ["transactions row", "vault audit events"],
    boundary: "route-policy",
    notes:
      "Parsed Solana transactions are policy-derived from bytes; blind signing is explicit unsafe opt-in.",
  },
  {
    id: "wallet.private_key.export",
    kind: "key-material-export",
    capability: "export_private_key",
    vaultMethods: ["exportPrivateKey"],
    routes: [
      { file: "packages/api/src/routes/vault.ts", method: "POST", path: "/:agentId/export" },
      { file: "packages/api/src/routes/user.ts", method: "POST", path: "/me/wallet/export" },
      {
        file: "packages/api/src/routes/user.ts",
        method: "POST",
        path: "/me/wallet/claim-pregenerated",
        notes:
          "internal claim migration path exports from the pre-generated tenant wallet before import",
      },
    ],
    auth: [
      "tenant admin or personal user session",
      "recent MFA",
      "plaintext response acknowledgement",
    ],
    policy: ["tenant/user MFA export policy gate"],
    policyEngineGated: false,
    legacy: false,
    custody: {
      localVault: true,
      externalCustody: "not-applicable",
      notes: "External key handles cannot export private key material.",
    },
    unsafeFlags: [
      "STEWARD_ALLOW_KEY_EXPORT",
      "STEWARD_ALLOW_PRIVATE_KEY_EXPORT",
      "STEWARD_ALLOW_VAULT_PRIVATE_KEY_EXPORT",
      "STEWARD_ALLOW_USER_PRIVATE_KEY_EXPORT",
      "STEWARD_ALLOW_PLAINTEXT_KEY_EXPORT_IN_PRODUCTION",
    ],
    evidence: ["audit events", "private_key.exported webhook"],
    boundary: "route-mfa-break-glass",
    notes:
      "Break-glass plaintext export is not part of the signing path but is intentionally classified.",
  },
  {
    id: "credential.proxy.inject_http",
    kind: "credential-injection",
    capability: "credential_injection",
    vaultMethods: ["SecretVault.decryptSecret"],
    routes: [
      {
        file: "packages/proxy/src/handlers/proxy.ts",
        method: "HANDLER",
        path: "proxyHandler",
      },
      { file: "packages/api/src/routes/secrets.ts", method: "POST", path: "/routes" },
      { file: "packages/api/src/routes/secrets.ts", method: "PUT", path: "/routes/:id" },
    ],
    auth: [
      "proxy agent JWT with api:proxy scope",
      "secret route management requires owner/admin recent MFA",
    ],
    policy: ["route host/path/method/header validation", "proxy spend/rate/replay checks"],
    policyEngineGated: false,
    legacy: false,
    custody: {
      localVault: true,
      externalCustody: "not-applicable",
      notes: "SecretVault decrypts stored API credentials for outbound proxy injection.",
    },
    unsafeFlags: ["STEWARD_ALLOW_BROAD_SECRET_ROUTES", "STEWARD_ALLOW_COOKIE_INJECTION"],
    evidence: ["proxy audit events", "secret route audit events"],
    boundary: "proxy-route-policy",
    notes:
      "Credential injection happens only after proxy route matching, audit pre-write, replay protection, and secret route validation.",
  },
] as const satisfies readonly SecuritySurfaceOperation[];

/**
 * Explicit enumeration of raw EVM `Vault.signTransaction` call sites that are
 * not routed through the execution gateway. The migrated primary EVM
 * `/vault/:agentId/sign` route and its compatible approval replay are excluded
 * because they go through GovernedVault. The vault.ts entries below are
 * route-policy branches (transfer action surface); the intents, user, and
 * global-wallet entries remain separate route-policy boundaries.
 *
 * A CI guard (packages/api execution gateway guard test) asserts that the
 * primary EVM sign route + approval replay cannot reach the raw signer without
 * GovernedVault authorization, and that this list stays honest.
 */
export const LEGACY_EVM_SIGN_CALL_SITES = [
  {
    file: "packages/api/src/routes/vault.ts",
    approxLine: 3047,
    path: "POST /:agentId/actions/transfer",
    reason:
      "Transfer action EVM sign. Route-local policy gated, separate surface from primary sign; pending gateway convergence.",
  },
  {
    file: "packages/api/src/routes/vault.ts",
    approxLine: 3794,
    path: "POST /:agentId/approve/:txId (transfer branch)",
    reason:
      "Approval replay raw fallback for the TRANSFER surface only. An invariant guard throws if a primary-EVM raw-signing candidate reaches this branch; transfers remain pending gateway convergence.",
  },
  {
    file: "packages/api/src/routes/intents.ts",
    approxLine: 596,
    path: "POST /:intentId/execute",
    reason: "Legacy intent execution EVM sign; pending gateway convergence.",
  },
  {
    file: "packages/api/src/routes/intents.ts",
    approxLine: 715,
    path: "POST /:intentId/execute (secondary)",
    reason: "Legacy intent execution EVM sign; pending gateway convergence.",
  },
  {
    file: "packages/api/src/routes/user.ts",
    approxLine: 5138,
    path: "POST /me/wallet/sign",
    reason: "Personal user-session EVM sign; pending gateway convergence.",
  },
  {
    file: "packages/api/src/routes/global-wallet.ts",
    approxLine: 1540,
    path: "POST /rpc (eth_sendTransaction)",
    reason: "Global wallet compatibility EVM sign; pending gateway convergence.",
  },
] as const satisfies readonly LegacyEvmSignCallSite[];

/**
 * Classification of a single raw `Vault.signTransaction(` call site in the
 * production API source (packages/api/src, excluding __tests__).
 *
 *  - "migrated-invariant-guarded": a primary-EVM/approval site that is
 *    unreachable for EVM flows because a nearby invariant guard throws before
 *    it (the Solana primary-sign fallback and the transfer approval-replay
 *    fallback). These are inside the two gateway-migrated routes.
 *  - "legacy": a not-yet-gateway-migrated EVM sign surface, one-for-one with an
 *    entry in LEGACY_EVM_SIGN_CALL_SITES.
 */
export interface RawEvmSignCallSite {
  file: string;
  /** Stable nearby source marker (route/function/guard string) unique enough to
   *  anchor the call site without brittle line numbers. */
  marker: string;
  classification: "migrated-invariant-guarded" | "legacy";
  reason: string;
}

/**
 * COMPLETE inventory of every raw `Vault.signTransaction(` production call site
 * across packages/api/src. The CI guard (packages/api execution gateway guard
 * test) scans the production source repository-wide and asserts a one-for-one
 * match: exact per-file raw-call counts against this inventory's per-file
 * counts, AND that each occurrence anchors to a recognized marker here. Adding
 * a new raw signTransaction call anywhere (vault.ts / intents.ts / user.ts / a
 * NEW file) fails the guard until it is classified here; deleting an inventory
 * entry without removing the call also fails.
 */
export const RAW_EVM_SIGN_INVENTORY = [
  // ── packages/api/src/routes/vault.ts (2 raw calls) ──
  {
    file: "packages/api/src/routes/vault.ts",
    marker: "/:agentId/actions/transfer",
    classification: "legacy",
    reason:
      "Transfer action EVM sign; separate non-migrated surface. One-for-one with LEGACY_EVM_SIGN_CALL_SITES.",
  },
  {
    file: "packages/api/src/routes/vault.ts",
    marker: "invariant: primary EVM approval reached raw signer without gateway authorization",
    classification: "migrated-invariant-guarded",
    reason:
      "Approval replay TRANSFER fallback. An isRawEvmSigningCandidate invariant guard throws for any primary-EVM candidate before it.",
  },
  // ── packages/api/src/routes/intents.ts (2 raw calls) ──
  {
    file: "packages/api/src/routes/intents.ts",
    marker: "Transfer rejected by policy",
    classification: "legacy",
    reason:
      "Legacy intent execution EVM sign (single-transfer branch); pending gateway convergence. Anchored to its policy-rejection guard string.",
  },
  {
    file: "packages/api/src/routes/intents.ts",
    marker: "Batch calls rejected by policy",
    classification: "legacy",
    reason:
      "Legacy intent batch-call execution EVM sign; pending gateway convergence. Anchored to its batch policy-rejection guard string.",
  },
  // ── packages/api/src/routes/user.ts (1 raw call) ──
  {
    file: "packages/api/src/routes/user.ts",
    marker: "/me/wallet/sign",
    classification: "legacy",
    reason: "Personal user-session EVM sign; pending gateway convergence.",
  },
  // ── packages/api/src/routes/global-wallet.ts (1 raw call) ──
  {
    file: "packages/api/src/routes/global-wallet.ts",
    marker: "eth_sendTransaction",
    classification: "legacy",
    reason: "Global wallet compatibility EVM sign; pending gateway convergence.",
  },
] as const satisfies readonly RawEvmSignCallSite[];

/**
 * Exact expected raw `Vault.signTransaction(` call count per production source
 * file. Derived from RAW_EVM_SIGN_INVENTORY so the two never drift. The CI
 * scan asserts the actual per-file counts equal these.
 */
export const RAW_EVM_SIGN_EXPECTED_COUNTS: Readonly<Record<string, number>> =
  RAW_EVM_SIGN_INVENTORY.reduce<Record<string, number>>((acc, site) => {
    acc[site.file] = (acc[site.file] ?? 0) + 1;
    return acc;
  }, {});

export const SECURITY_SURFACE_VAULT_METHODS = [
  ...new Set(
    SECURITY_SURFACE_OPERATIONS.flatMap((operation) =>
      operation.vaultMethods.filter((method) => !method.startsWith("SecretVault.")),
    ),
  ),
].sort();

export const SECURITY_SURFACE_ROUTES = SECURITY_SURFACE_OPERATIONS.flatMap((operation) =>
  operation.routes.map((route) => ({ operationId: operation.id, ...route })),
);
