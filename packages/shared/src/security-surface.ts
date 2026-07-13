export type SecuritySurfaceKind = "wallet-signing" | "key-material-export" | "credential-injection";

export type EnforcementBoundary =
  | "route-policy"
  | "route-policy-with-unsafe-flag"
  | "route-consent-with-unsafe-flag"
  | "route-mfa-break-glass"
  | "proxy-route-policy";

export interface SecuritySurfaceRoute {
  file: string;
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "ALL" | "HANDLER";
  path: string;
  notes?: string;
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
      { file: "packages/api/src/routes/vault.ts", method: "POST", path: "/:agentId/sign" },
      {
        file: "packages/api/src/routes/vault.ts",
        method: "POST",
        path: "/:agentId/actions/transfer",
      },
      {
        file: "packages/api/src/routes/vault.ts",
        method: "POST",
        path: "/:agentId/actions/send-calls",
      },
      {
        file: "packages/api/src/routes/vault.ts",
        method: "POST",
        path: "/:agentId/approve/:txId",
      },
      {
        file: "packages/api/src/routes/vault.ts",
        method: "POST",
        path: "/:agentId/transactions/:txId/replace",
      },
      { file: "packages/api/src/routes/intents.ts", method: "POST", path: "/:intentId/execute" },
      { file: "packages/api/src/routes/user.ts", method: "POST", path: "/me/wallet/sign" },
      {
        file: "packages/api/src/routes/global-wallet.ts",
        method: "POST",
        path: "/rpc",
        notes: "eth_sendTransaction compatibility path",
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
    boundary: "route-policy",
    notes:
      "Policy is enforced in API routes before Vault.signTransaction; Vault.signTransaction itself does not verify gateway authorization.",
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
    vaultMethods: ["signSolanaTransaction"],
    routes: [
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
        notes: "Solana approval execution branch",
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
