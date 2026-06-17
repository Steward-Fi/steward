import { isSensitivePath, SENSITIVE_PATH_PREFIXES } from "./middleware/sensitive-paths";

type JsonSchema = Record<string, unknown>;
type OpenApiOperation = Record<string, unknown>;
type OpenApiPathItem = Record<string, unknown>;
type OpenApiSpec = {
  openapi: string;
  info: Record<string, unknown>;
  servers: Array<Record<string, unknown>>;
  tags: Array<Record<string, unknown>>;
  components: Record<string, unknown>;
  paths: Record<string, OpenApiPathItem>;
  "x-steward-sensitive-prefixes"?: readonly string[];
};

const stringSchema = { type: "string" };
const nullableStringSchema = { type: ["string", "null"] };
const dateTimeSchema = { type: "string", format: "date-time" };
const metadataSchema = { type: "object", additionalProperties: true };
const policyRuleSchema: JsonSchema = { type: "object", additionalProperties: true };
const digitalAssetAccountCapabilitiesSchema: JsonSchema = {
  type: "array",
  items: {
    type: "string",
    enum: [
      "sign_transaction",
      "sign_message",
      "sign_typed_data",
      "sign_user_operation",
      "sign_authorization",
      "send_calls",
      "transfer",
      "solana_transaction",
      "export_private_key",
    ],
  },
};
const intentStatusSchema: JsonSchema = {
  type: "string",
  enum: [
    "pending",
    "authorized",
    "executing",
    "executed",
    "failed",
    "rejected",
    "canceled",
    "expired",
  ],
};
const intentTypeSchema: JsonSchema = {
  type: "string",
  enum: [
    "rpc",
    "transfer",
    "wallet_update",
    "policy_update",
    "policy_rule_create",
    "policy_rule_delete",
    "policy_rule_update",
    "quorum_update",
    "wallet_action",
  ],
};
const intentSchema: JsonSchema = {
  type: "object",
  required: [
    "id",
    "intent_id",
    "intentType",
    "intent_type",
    "status",
    "payload",
    "createdAt",
    "updatedAt",
  ],
  properties: {
    id: stringSchema,
    intent_id: stringSchema,
    tenantId: stringSchema,
    agentId: nullableStringSchema,
    wallet_id: nullableStringSchema,
    intentType: intentTypeSchema,
    intent_type: intentTypeSchema,
    status: intentStatusSchema,
    resourceType: nullableStringSchema,
    resourceId: nullableStringSchema,
    resource_id: nullableStringSchema,
    createdByType: stringSchema,
    createdById: nullableStringSchema,
    created_by_id: nullableStringSchema,
    createdByDisplayName: nullableStringSchema,
    created_by_display_name: nullableStringSchema,
    authorizationDetails: { type: "array", items: metadataSchema },
    authorization_details: { type: "array", items: metadataSchema },
    payload: metadataSchema,
    executionResult: { type: ["object", "null"], additionalProperties: true },
    execution_result: { type: ["object", "null"], additionalProperties: true },
    expiresAt: { type: ["string", "null"], format: "date-time" },
    expires_at: { type: ["integer", "null"] },
    authorizedBy: nullableStringSchema,
    authorized_by: nullableStringSchema,
    authorizedAt: { type: ["string", "null"], format: "date-time" },
    executedAt: { type: ["string", "null"], format: "date-time" },
    createdAt: dateTimeSchema,
    created_at: { type: "integer" },
    updatedAt: dateTimeSchema,
  },
};

const paginationQueryParameters = [
  parameter("limit", "query", { type: "integer", minimum: 1, maximum: 200 }),
  parameter("offset", "query", { type: "integer", minimum: 0 }),
];

const MUTATING_METHODS = new Set(["post", "put", "patch", "delete"]);

const requestTimestampHeader = headerParameter(
  "X-Steward-Request-Timestamp",
  "Unix seconds, Unix milliseconds, or HTTP/ISO timestamp. Sensitive mutating routes require this or X-Steward-Request-Expires-At when request-expiry or request signatures are enforced.",
);
const requestExpiresAtHeader = headerParameter(
  "X-Steward-Request-Expires-At",
  "Unix seconds, Unix milliseconds, or HTTP/ISO expiry time. Sensitive mutating routes require this or X-Steward-Request-Timestamp when request-expiry or request signatures are enforced.",
);
const stewardSignatureHeader = headerParameter(
  "X-Steward-Signature",
  "Authorization signature for sensitive mutating routes when STEWARD_REQUIRE_AUTH_SIGNATURE=true or production enforcement is enabled. Use v1=<hmac-sha256> or p256=<signature>.",
);
const signingKeyIdHeader = headerParameter(
  "X-Steward-Signing-Key-Id",
  "Optional tenant request-signing key id used to select a managed HMAC signing key.",
);
const idempotencyKeyHeader = headerParameter(
  "Idempotency-Key",
  "Required for signed sensitive requests and recommended for all sensitive mutating requests. Replays are scoped to authenticated or explicitly signed contexts.",
);

function apiResponse(dataSchema: JsonSchema): JsonSchema {
  return {
    type: "object",
    required: ["ok", "data"],
    properties: {
      ok: { type: "boolean", const: true },
      data: dataSchema,
    },
  };
}

function errorResponse(): JsonSchema {
  return {
    type: "object",
    required: ["ok", "error"],
    properties: {
      ok: { type: "boolean", const: false },
      error: stringSchema,
    },
  };
}

function jsonResponse(schema: JsonSchema): JsonSchema {
  return {
    description: "JSON response",
    content: {
      "application/json": {
        schema,
      },
    },
  };
}

function errorResponses(): JsonSchema {
  return {
    "400": jsonResponse(errorResponse()),
    "401": jsonResponse(errorResponse()),
    "403": jsonResponse(errorResponse()),
    "404": jsonResponse(errorResponse()),
    "409": jsonResponse(errorResponse()),
  };
}

function parameter(name: string, location: "path" | "query", schema: JsonSchema = stringSchema) {
  return {
    name,
    in: location,
    required: location === "path",
    schema,
  };
}

function headerParameter(name: string, description: string, schema: JsonSchema = stringSchema) {
  return {
    name,
    in: "header",
    required: false,
    description,
    schema,
  };
}

function jsonRequestBody(schema: JsonSchema, required = true): JsonSchema {
  return {
    required,
    content: {
      "application/json": {
        schema,
      },
    },
  };
}

const authTokenResponseSchema: JsonSchema = {
  type: "object",
  required: ["ok", "token", "refreshToken", "expiresIn"],
  properties: {
    ok: { type: "boolean", const: true },
    token: stringSchema,
    refreshToken: stringSchema,
    expiresIn: { type: "integer", minimum: 1 },
    user: { type: "object", additionalProperties: true },
  },
};

const maskedMfaPhoneResponseSchema: JsonSchema = {
  type: "object",
  required: ["ok"],
  properties: {
    ok: { type: "boolean", const: true },
    enabled: { type: "boolean" },
    verified: { type: "boolean" },
    phone: stringSchema,
    expiresAt: dateTimeSchema,
  },
};

const mfaCodeBodySchema: JsonSchema = {
  type: "object",
  required: ["code"],
  properties: {
    code: { type: "string", pattern: "^\\d{6}$" },
  },
};

const mfaChallengeBodySchema: JsonSchema = {
  type: "object",
  required: ["challengeId"],
  properties: {
    challengeId: stringSchema,
    code: { type: "string", pattern: "^\\d{6}$" },
    recoveryCode: stringSchema,
  },
  oneOf: [{ required: ["code"] }, { required: ["recoveryCode"] }],
};

const digitalAssetAccountWalletSchema: JsonSchema = {
  type: "object",
  required: [
    "id",
    "walletId",
    "membershipId",
    "name",
    "chainType",
    "chainFamily",
    "address",
    "capabilities",
    "capabilityMetadata",
  ],
  properties: {
    id: stringSchema,
    walletId: stringSchema,
    membershipId: stringSchema,
    name: nullableStringSchema,
    ownerUserId: nullableStringSchema,
    owner_user_id: nullableStringSchema,
    walletType: nullableStringSchema,
    wallet_type: nullableStringSchema,
    custody: {
      type: "object",
      properties: {
        type: { type: "string", enum: ["server", "user_embedded"] },
        ownerUserId: nullableStringSchema,
        owner_user_id: nullableStringSchema,
      },
    },
    signing: {
      type: "object",
      properties: {
        signerCount: { type: "integer", minimum: 0 },
        activeSignerCount: { type: "integer", minimum: 0 },
        quorumCount: { type: "integer", minimum: 0 },
        activeQuorumCount: { type: "integer", minimum: 0 },
      },
    },
    capabilities: digitalAssetAccountCapabilitiesSchema,
    capabilityMetadata: { type: "object", additionalProperties: true },
    capability_metadata: { type: "object", additionalProperties: true },
    chainType: { type: "string", enum: ["ethereum", "solana", "bitcoin"] },
    chainFamily: { type: "string", enum: ["evm", "solana", "bitcoin"] },
    address: nullableStringSchema,
    purpose: nullableStringSchema,
    venue: nullableStringSchema,
    createdAt: { anyOf: [dateTimeSchema, { type: "null" }] },
  },
};

const digitalAssetAccountSchema: JsonSchema = {
  type: "object",
  required: [
    "id",
    "tenantId",
    "displayName",
    "metadata",
    "walletIds",
    "wallets",
    "capabilities",
    "capabilityMetadata",
    "createdAt",
    "updatedAt",
  ],
  properties: {
    id: stringSchema,
    tenantId: stringSchema,
    displayName: nullableStringSchema,
    display_name: nullableStringSchema,
    metadata: metadataSchema,
    ownerUserIds: { type: "array", items: stringSchema },
    owner_user_ids: { type: "array", items: stringSchema },
    additionalSignerIds: { type: "array", items: stringSchema },
    additional_signer_ids: { type: "array", items: stringSchema },
    signerPolicyIds: { type: "array", items: stringSchema },
    signer_policy_ids: { type: "array", items: stringSchema },
    walletIds: { type: "array", items: stringSchema },
    wallet_ids: { type: "array", items: stringSchema },
    wallets: { type: "array", items: digitalAssetAccountWalletSchema },
    capabilities: digitalAssetAccountCapabilitiesSchema,
    capabilityMetadata: { type: "object", additionalProperties: true },
    capability_metadata: { type: "object", additionalProperties: true },
    createdAt: dateTimeSchema,
    created_at: dateTimeSchema,
    updatedAt: dateTimeSchema,
    updated_at: dateTimeSchema,
  },
};

const digitalAssetAccountMutationSchema: JsonSchema = {
  type: "object",
  properties: {
    id: stringSchema,
    display_name: nullableStringSchema,
    displayName: nullableStringSchema,
    metadata: metadataSchema,
    owner_user_ids: { type: "array", maxItems: 32, items: stringSchema },
    ownerUserIds: { type: "array", maxItems: 32, items: stringSchema },
    additional_signer_ids: { type: "array", maxItems: 32, items: stringSchema },
    additionalSignerIds: { type: "array", maxItems: 32, items: stringSchema },
    signer_policy_ids: { type: "array", maxItems: 32, items: stringSchema },
    signerPolicyIds: { type: "array", maxItems: 32, items: stringSchema },
    wallet_ids: { type: "array", maxItems: 5, items: stringSchema },
    walletIds: { type: "array", maxItems: 5, items: stringSchema },
    user_wallet_ids: { type: "array", maxItems: 5, items: stringSchema },
    userWalletIds: { type: "array", maxItems: 5, items: stringSchema },
    wallets_configuration: {
      type: "array",
      maxItems: 5,
      items: {
        type: "object",
        properties: {
          chain_type: { type: "string", enum: ["ethereum", "evm", "solana", "bitcoin"] },
          chainType: { type: "string", enum: ["ethereum", "evm", "solana", "bitcoin"] },
          name: stringSchema,
          wallet_id: stringSchema,
          walletId: stringSchema,
        },
      },
    },
    walletsConfiguration: {
      type: "array",
      maxItems: 5,
      items: {
        type: "object",
        properties: {
          chainType: { type: "string", enum: ["ethereum", "evm", "solana", "bitcoin"] },
          name: stringSchema,
          walletId: stringSchema,
        },
      },
    },
  },
};

const digitalAssetAccountAggregationSchema: JsonSchema = {
  type: "object",
  required: [
    "id",
    "accountId",
    "tenantId",
    "displayName",
    "walletIds",
    "chainFamilies",
    "metadata",
    "createdAt",
    "updatedAt",
  ],
  properties: {
    id: stringSchema,
    accountId: stringSchema,
    account_id: stringSchema,
    tenantId: stringSchema,
    displayName: nullableStringSchema,
    display_name: nullableStringSchema,
    walletIds: { type: "array", items: stringSchema },
    wallet_ids: { type: "array", items: stringSchema },
    chainFamilies: { type: "array", items: { type: "string", enum: ["evm", "solana"] } },
    chain_families: { type: "array", items: { type: "string", enum: ["evm", "solana"] } },
    metadata: metadataSchema,
    createdAt: dateTimeSchema,
    created_at: dateTimeSchema,
    updatedAt: dateTimeSchema,
    updated_at: dateTimeSchema,
  },
};

const digitalAssetAccountBalanceRowSchema: JsonSchema = {
  type: "object",
  required: [
    "walletId",
    "chainFamily",
    "chainId",
    "symbol",
    "native",
    "nativeFormatted",
    "walletAddress",
  ],
  properties: {
    walletId: stringSchema,
    chainFamily: { type: "string", enum: ["evm", "solana", "bitcoin"] },
    chainId: { type: ["integer", "null"] },
    symbol: nullableStringSchema,
    native: nullableStringSchema,
    nativeFormatted: nullableStringSchema,
    walletAddress: nullableStringSchema,
    unavailableReason: stringSchema,
  },
};

const digitalAssetAccountTokenBalanceRowSchema: JsonSchema = {
  type: "object",
  required: ["walletId", "chainId", "token", "symbol", "balance", "formatted", "decimals"],
  properties: {
    walletId: stringSchema,
    chainId: { type: "integer" },
    token: stringSchema,
    symbol: stringSchema,
    balance: stringSchema,
    formatted: stringSchema,
    decimals: { type: "integer", minimum: 0 },
    unavailableReason: stringSchema,
  },
};

const walletExternalIdBodySchema: JsonSchema = {
  type: "object",
  required: ["tenantId"],
  properties: {
    tenantId: stringSchema,
    walletExternalId: stringSchema,
    externalId: stringSchema,
  },
  anyOf: [{ required: ["walletExternalId"] }, { required: ["externalId"] }],
};

const platformUserIdentitySchema: JsonSchema = {
  type: "object",
  additionalProperties: true,
  properties: {
    userId: stringSchema,
    email: nullableStringSchema,
    emailVerified: { type: ["boolean", "null"] },
    name: nullableStringSchema,
    image: nullableStringSchema,
    walletAddress: nullableStringSchema,
    walletChain: nullableStringSchema,
    customMetadata: metadataSchema,
    deactivatedAt: { anyOf: [dateTimeSchema, { type: "null" }] },
    createdAt: dateTimeSchema,
    updatedAt: dateTimeSchema,
    tenantIds: { type: "array", items: stringSchema },
    linkedAccounts: { type: "array", items: { type: "object", additionalProperties: true } },
    walletExternalIds: {
      type: "array",
      items: {
        type: "object",
        properties: {
          tenantId: stringSchema,
          walletExternalId: stringSchema,
          externalId: stringSchema,
        },
      },
    },
  },
};

const tenantMemberRoleSchema: JsonSchema = { type: "string", enum: ["owner", "admin", "member"] };

const platformTenantMemberSchema: JsonSchema = {
  type: "object",
  required: ["userId", "role", "email"],
  properties: {
    userId: stringSchema,
    tenantId: stringSchema,
    role: tenantMemberRoleSchema,
    email: nullableStringSchema,
    name: nullableStringSchema,
    joinedAt: { anyOf: [dateTimeSchema, { type: "null" }] },
  },
};

const platformTenantInvitationSchema: JsonSchema = {
  type: "object",
  required: ["id", "tenantId", "email", "role", "status", "expiresAt", "createdAt"],
  properties: {
    id: stringSchema,
    tenantId: stringSchema,
    email: { type: "string", format: "email" },
    role: tenantMemberRoleSchema,
    status: { type: "string", enum: ["pending", "accepted", "revoked", "expired"] },
    invitedByUserId: nullableStringSchema,
    acceptedByUserId: nullableStringSchema,
    acceptedAt: { anyOf: [dateTimeSchema, { type: "null" }] },
    revokedAt: { anyOf: [dateTimeSchema, { type: "null" }] },
    expiresAt: dateTimeSchema,
    createdAt: dateTimeSchema,
    updatedAt: dateTimeSchema,
  },
};

const tenantWalletPolicyViolationReportSchema: JsonSchema = {
  type: "object",
  required: ["tenantId", "policyEnabled", "violations", "total", "limit", "offset"],
  properties: {
    tenantId: stringSchema,
    policyEnabled: { type: "boolean" },
    violations: {
      type: "array",
      items: {
        type: "object",
        required: ["userId", "email", "name", "role", "walletCount", "wallets"],
        properties: {
          userId: stringSchema,
          email: nullableStringSchema,
          name: nullableStringSchema,
          role: stringSchema,
          walletCount: { type: "integer", minimum: 2 },
          wallets: {
            type: "array",
            minItems: 2,
            items: {
              type: "object",
              required: ["accountId", "provider", "providerAccountId"],
              properties: {
                accountId: stringSchema,
                provider: { type: "string", enum: ["wallet:ethereum", "wallet:solana"] },
                providerAccountId: stringSchema,
              },
            },
          },
        },
      },
    },
    total: { type: "integer", minimum: 0 },
    limit: { type: "integer", minimum: 1 },
    offset: { type: "integer", minimum: 0 },
  },
};

const tenantWalletPolicyRemediationSchema: JsonSchema = {
  type: "object",
  required: ["deleted", "accountId", "provider", "providerAccountId", "issuedBefore"],
  properties: {
    deleted: { type: "boolean", const: true },
    accountId: stringSchema,
    provider: { type: "string", enum: ["wallet:ethereum", "wallet:solana"] },
    providerAccountId: stringSchema,
    issuedBefore: { type: "integer", minimum: 0 },
  },
};

const agentSignerSchema: JsonSchema = {
  type: "object",
  required: [
    "id",
    "tenantId",
    "agentId",
    "signerType",
    "subjectType",
    "subjectId",
    "keyType",
    "publicKey",
    "permissions",
    "metadata",
    "status",
    "createdAt",
    "updatedAt",
  ],
  properties: {
    id: stringSchema,
    tenantId: stringSchema,
    agentId: stringSchema,
    signerType: { type: "string", enum: ["owner", "delegated", "service", "quorum_member"] },
    subjectType: { type: "string", enum: ["user", "wallet", "api_key", "external"] },
    subjectId: stringSchema,
    keyType: { type: "string", enum: ["hmac", "p256"] },
    publicKey: nullableStringSchema,
    address: nullableStringSchema,
    chainFamily: { type: ["string", "null"], enum: ["evm", "solana", null] },
    label: nullableStringSchema,
    permissions: { type: "array", items: stringSchema },
    policyIds: { type: "array", items: stringSchema },
    metadata: metadataSchema,
    hasCredential: { type: "boolean" },
    status: { type: "string", enum: ["active", "paused", "revoked"] },
    createdBy: nullableStringSchema,
    createdAt: dateTimeSchema,
    updatedAt: dateTimeSchema,
  },
};

const agentSignerMutationSchema: JsonSchema = {
  type: "object",
  properties: {
    signerType: { type: "string", enum: ["owner", "delegated", "service", "quorum_member"] },
    subjectType: { type: "string", enum: ["user", "wallet", "api_key", "external"] },
    subjectId: stringSchema,
    keyType: { type: "string", enum: ["hmac", "p256"] },
    publicKey: nullableStringSchema,
    address: nullableStringSchema,
    chainFamily: { type: ["string", "null"], enum: ["evm", "solana", null] },
    label: nullableStringSchema,
    permissions: { type: "array", items: stringSchema },
    policyIds: { type: "array", items: stringSchema },
    metadata: metadataSchema,
    issueCredential: { type: "boolean" },
    status: { type: "string", enum: ["active", "paused", "revoked"] },
  },
};

const userWalletSignerCreateSchema: JsonSchema = {
  type: "object",
  properties: {
    walletIndex: { type: "integer", minimum: 0, maximum: 255 },
    wallet_index: { type: "integer", minimum: 0, maximum: 255 },
    signerType: { type: "string", enum: ["delegated", "service"] },
    subjectType: { type: "string", enum: ["user", "wallet", "external"] },
    subjectId: stringSchema,
    keyType: { type: "string", enum: ["hmac"] },
    label: nullableStringSchema,
    permissions: { type: "array", items: stringSchema },
    metadata: metadataSchema,
  },
};

const agentKeyQuorumSchema: JsonSchema = {
  type: "object",
  required: [
    "id",
    "tenantId",
    "agentId",
    "name",
    "threshold",
    "memberSignerIds",
    "memberQuorumIds",
    "permissions",
    "metadata",
    "status",
    "createdAt",
    "updatedAt",
  ],
  properties: {
    id: stringSchema,
    tenantId: stringSchema,
    agentId: stringSchema,
    name: stringSchema,
    threshold: { type: "integer", minimum: 1 },
    memberSignerIds: { type: "array", items: stringSchema },
    memberQuorumIds: { type: "array", items: stringSchema },
    permissions: { type: "array", items: stringSchema },
    metadata: metadataSchema,
    status: { type: "string", enum: ["active", "paused", "revoked"] },
    createdBy: nullableStringSchema,
    createdAt: dateTimeSchema,
    updatedAt: dateTimeSchema,
  },
};

const agentKeyQuorumMutationSchema: JsonSchema = {
  type: "object",
  properties: {
    name: stringSchema,
    threshold: { type: "integer", minimum: 1 },
    memberSignerIds: { type: "array", items: stringSchema },
    memberQuorumIds: { type: "array", items: stringSchema },
    permissions: { type: "array", items: stringSchema },
    metadata: metadataSchema,
    status: { type: "string", enum: ["active", "paused", "revoked"] },
  },
};

const conditionSetSchema: JsonSchema = {
  type: "object",
  required: [
    "id",
    "tenantId",
    "name",
    "description",
    "ownerId",
    "metadata",
    "createdAt",
    "updatedAt",
  ],
  properties: {
    id: stringSchema,
    tenantId: stringSchema,
    name: stringSchema,
    description: nullableStringSchema,
    ownerId: nullableStringSchema,
    metadata: metadataSchema,
    createdAt: dateTimeSchema,
    updatedAt: dateTimeSchema,
  },
};

const conditionSetMutationSchema: JsonSchema = {
  type: "object",
  properties: {
    name: stringSchema,
    description: nullableStringSchema,
    ownerId: stringSchema,
    metadata: metadataSchema,
  },
};

const conditionSetCreateSchema: JsonSchema = {
  ...conditionSetMutationSchema,
  required: ["name", "ownerId"],
};

const conditionSetItemSchema: JsonSchema = {
  type: "object",
  required: [
    "id",
    "conditionSetId",
    "tenantId",
    "value",
    "label",
    "metadata",
    "createdAt",
    "updatedAt",
  ],
  properties: {
    id: stringSchema,
    conditionSetId: stringSchema,
    tenantId: stringSchema,
    value: stringSchema,
    label: nullableStringSchema,
    metadata: metadataSchema,
    createdAt: dateTimeSchema,
    updatedAt: dateTimeSchema,
  },
};

const conditionSetItemMutationSchema: JsonSchema = {
  type: "object",
  properties: {
    value: stringSchema,
    label: nullableStringSchema,
    metadata: metadataSchema,
  },
};

const conditionSetItemCreateSchema: JsonSchema = {
  ...conditionSetItemMutationSchema,
  required: ["value"],
};

const policyTemplateSchema: JsonSchema = {
  type: "object",
  required: [
    "id",
    "tenantId",
    "name",
    "description",
    "rules",
    "isDefault",
    "createdAt",
    "updatedAt",
  ],
  properties: {
    id: stringSchema,
    tenantId: stringSchema,
    name: stringSchema,
    description: nullableStringSchema,
    rules: { type: "array", items: policyRuleSchema },
    isDefault: { type: "boolean" },
    createdAt: dateTimeSchema,
    updatedAt: dateTimeSchema,
  },
};

const policyTemplateMutationSchema: JsonSchema = {
  type: "object",
  properties: {
    name: stringSchema,
    description: stringSchema,
    rules: { type: "array", items: policyRuleSchema },
    isDefault: { type: "boolean" },
  },
};

const policyTemplateCreateSchema: JsonSchema = {
  ...policyTemplateMutationSchema,
  required: ["name", "rules"],
};

const policySimulateRequestSchema: JsonSchema = {
  anyOf: [
    {
      type: "object",
      required: ["to", "value"],
      properties: {
        kind: { type: "string", const: "transaction" },
        to: stringSchema,
        value: stringSchema,
        data: stringSchema,
        chainId: { type: "integer", minimum: 1 },
      },
    },
    {
      type: "object",
      required: ["method", "url"],
      properties: {
        kind: { type: "string", const: "proxy" },
        method: { type: "string", enum: ["GET", "POST", "PUT", "PATCH", "DELETE"] },
        url: stringSchema,
        body: {},
        data: {},
        value: stringSchema,
        chainId: { type: "integer", minimum: 1 },
      },
    },
  ],
};

const policySimulateBodySchema: JsonSchema = {
  type: "object",
  properties: {
    policyId: stringSchema,
    agentId: stringSchema,
    rules: { type: "array", items: policyRuleSchema },
    request: policySimulateRequestSchema,
    kind: { type: "string", enum: ["transaction", "proxy"] },
    to: stringSchema,
    value: stringSchema,
    data: {},
    chainId: { type: "integer", minimum: 1 },
    method: { type: "string", enum: ["GET", "POST", "PUT", "PATCH", "DELETE"] },
    url: stringSchema,
    body: {},
  },
};

const policySimulateResultSchema: JsonSchema = {
  type: "object",
  required: ["approved", "requiresManualApproval", "results", "counters"],
  properties: {
    approved: { type: "boolean" },
    requiresManualApproval: { type: "boolean" },
    results: { type: "array", items: { type: "object", additionalProperties: true } },
    counters: { type: "object", additionalProperties: true },
  },
};

const agentIdentitySchema: JsonSchema = {
  type: "object",
  required: ["id", "tenantId", "name", "walletAddress", "createdAt"],
  properties: {
    id: stringSchema,
    tenantId: stringSchema,
    name: stringSchema,
    walletAddress: stringSchema,
    walletAddresses: {
      type: "object",
      properties: {
        evm: stringSchema,
        solana: stringSchema,
      },
    },
    platformId: nullableStringSchema,
    erc8004TokenId: nullableStringSchema,
    createdAt: dateTimeSchema,
  },
};

const walletBatchRequestSchema: JsonSchema = {
  type: "object",
  properties: {
    wallets: {
      type: "array",
      minItems: 1,
      maxItems: 25,
      items: {
        type: "object",
        required: ["name"],
        properties: {
          id: stringSchema,
          name: stringSchema,
          externalId: stringSchema,
          platformId: stringSchema,
        },
      },
    },
    applyPolicies: {
      type: "array",
      maxItems: 100,
      items: policyRuleSchema,
    },
  },
  required: ["wallets"],
};

const walletBatchResponseSchema: JsonSchema = apiResponse({
  type: "object",
  required: ["created", "errors"],
  properties: {
    created: { type: "array", items: agentIdentitySchema },
    errors: {
      type: "array",
      items: {
        type: "object",
        required: ["id", "error"],
        properties: {
          id: stringSchema,
          error: stringSchema,
        },
      },
    },
  },
});

const walletActionSponsorshipSchema: JsonSchema = {
  type: "object",
  properties: {
    requested: { type: "boolean" },
    sponsored: { type: "boolean" },
    provider: stringSchema,
    mode: stringSchema,
    estimatedUsd: { type: ["number", "null"] },
  },
};

const transferActionInputSchema: JsonSchema = {
  type: "object",
  required: ["to"],
  properties: {
    to: stringSchema,
    value: stringSchema,
    amountWei: stringSchema,
    token: stringSchema,
    chainId: { type: "integer", minimum: 1 },
    broadcast: { type: "boolean" },
    referenceId: stringSchema,
    sponsor: { type: "boolean" },
  },
  anyOf: [{ required: ["value"] }, { required: ["amountWei"] }],
};

const transferActionQuoteSchema: JsonSchema = {
  type: "object",
  required: ["quoteId", "type", "chainId", "from", "to", "value", "token", "expiresAt", "request"],
  properties: {
    quoteId: stringSchema,
    type: { type: "string", const: "transfer" },
    chainId: { type: "integer", minimum: 1 },
    from: stringSchema,
    to: stringSchema,
    value: stringSchema,
    token: stringSchema,
    expiresAt: dateTimeSchema,
    request: transferActionInputSchema,
  },
};

const transferActionSchema: JsonSchema = {
  type: "object",
  required: ["id", "type", "status", "chainId", "to", "value", "token"],
  properties: {
    id: stringSchema,
    type: { type: "string", const: "transfer" },
    status: {
      type: "string",
      enum: ["pending_approval", "rejected", "signed", "broadcast", "confirmed", "failed"],
    },
    chainId: { type: "integer", minimum: 1 },
    to: stringSchema,
    value: stringSchema,
    token: stringSchema,
    txHash: stringSchema,
    signedTx: stringSchema,
    sponsorship: walletActionSponsorshipSchema,
    policyResults: { type: "array", items: { type: "object", additionalProperties: true } },
    createdAt: dateTimeSchema,
    signedAt: dateTimeSchema,
    confirmedAt: dateTimeSchema,
  },
};

const encryptedKeyImportInitRequestSchema: JsonSchema = {
  type: "object",
  required: ["chain"],
  properties: {
    chain: { type: "string", enum: ["evm", "solana"] },
  },
};

const encryptedKeyImportInitResponseSchema: JsonSchema = {
  type: "object",
  required: ["importSessionId", "publicKey", "algorithm", "expiresAt", "aad"],
  properties: {
    importSessionId: stringSchema,
    publicKey: {
      type: "string",
      description: "Base64url DER-encoded X25519 SPKI public key for this one-time import session.",
    },
    algorithm: { type: "string", const: "X25519-HKDF-SHA256-AES-256-GCM" },
    expiresAt: dateTimeSchema,
    aad: {
      type: "object",
      required: ["importSessionId", "tenantId", "agentId", "chain"],
      properties: {
        importSessionId: stringSchema,
        tenantId: stringSchema,
        agentId: stringSchema,
        chain: { type: "string", enum: ["evm", "solana"] },
      },
    },
  },
};

const encryptedKeyImportSubmitRequestSchema: JsonSchema = {
  type: "object",
  required: ["importSessionId", "ephemeralPublicKey", "iv", "ciphertext", "tag"],
  properties: {
    importSessionId: stringSchema,
    ephemeralPublicKey: {
      type: "string",
      description: "Base64url DER-encoded X25519 SPKI public key generated by the client.",
    },
    iv: { type: "string", description: "Base64url AES-GCM nonce, 12 bytes before encoding." },
    ciphertext: {
      type: "string",
      description: "Base64url encrypted private key bytes. Plaintext privateKey is rejected.",
    },
    tag: { type: "string", description: "Base64url AES-GCM authentication tag." },
  },
};

const encryptedKeyImportResultSchema: JsonSchema = {
  type: "object",
  required: ["agentId", "walletAddress", "chain"],
  properties: {
    agentId: stringSchema,
    walletAddress: stringSchema,
    chain: { type: "string", enum: ["evm", "solana"] },
  },
};

const encryptedUserWalletKeyImportInitRequestSchema: JsonSchema = {
  type: "object",
  required: ["chain"],
  properties: {
    chain: { type: "string", enum: ["evm", "solana"] },
    walletIndex: { type: "integer", minimum: 0, maximum: 255 },
    wallet_index: { type: "integer", minimum: 0, maximum: 255 },
  },
};

const encryptedUserWalletKeyImportInitResponseSchema: JsonSchema = {
  type: "object",
  required: ["importSessionId", "publicKey", "algorithm", "expiresAt", "aad"],
  properties: {
    importSessionId: stringSchema,
    publicKey: {
      type: "string",
      description:
        "Base64url DER-encoded X25519 SPKI public key for this one-time user-wallet import session.",
    },
    algorithm: { type: "string", const: "X25519-HKDF-SHA256-AES-256-GCM" },
    expiresAt: dateTimeSchema,
    aad: {
      type: "object",
      required: ["importSessionId", "tenantId", "userId", "agentId", "chain", "walletIndex"],
      properties: {
        importSessionId: stringSchema,
        tenantId: stringSchema,
        userId: stringSchema,
        agentId: stringSchema,
        chain: { type: "string", enum: ["evm", "solana"] },
        walletIndex: { type: "integer", minimum: 0, maximum: 255 },
        appClientId: { type: ["string", "null"] },
      },
    },
  },
};

const encryptedUserWalletKeyImportSubmitRequestSchema: JsonSchema = {
  type: "object",
  required: ["importSessionId", "ephemeralPublicKey", "iv", "ciphertext", "tag"],
  properties: {
    importSessionId: stringSchema,
    ephemeralPublicKey: {
      type: "string",
      description: "Base64url DER-encoded X25519 SPKI public key generated by the client.",
    },
    iv: { type: "string", description: "Base64url AES-GCM nonce, 12 bytes before encoding." },
    ciphertext: {
      type: "string",
      description: "Base64url encrypted private key bytes. Plaintext privateKey is rejected.",
    },
    tag: { type: "string", description: "Base64url AES-GCM authentication tag." },
    walletIndex: { type: "integer", minimum: 0, maximum: 255 },
    wallet_index: { type: "integer", minimum: 0, maximum: 255 },
  },
};

const encryptedUserWalletKeyImportResultSchema: JsonSchema = {
  type: "object",
  required: ["agentId", "walletAddress", "chain", "walletIndex", "imported"],
  properties: {
    agentId: stringSchema,
    walletAddress: stringSchema,
    chain: { type: "string", enum: ["evm", "solana"] },
    walletIndex: { type: "integer", minimum: 0, maximum: 255 },
    imported: { type: "boolean", const: true },
  },
};

const sendCallsActionInputSchema: JsonSchema = {
  type: "object",
  required: ["calls"],
  properties: {
    calls: {
      type: "array",
      minItems: 1,
      maxItems: 25,
      items: {
        type: "object",
        required: ["to"],
        properties: {
          to: stringSchema,
          value: stringSchema,
          data: stringSchema,
        },
      },
    },
    chainId: { type: "integer", minimum: 1 },
    broadcast: { type: "boolean" },
    referenceId: stringSchema,
    sponsor: { type: "boolean" },
  },
};

const sendCallsActionSchema: JsonSchema = {
  type: "object",
  required: ["id", "type", "status", "chainId", "calls", "totalValue"],
  properties: {
    id: stringSchema,
    type: { type: "string", const: "send_calls" },
    status: { type: "string", enum: ["pending_approval", "rejected"] },
    chainId: { type: "integer", minimum: 1 },
    calls: {
      type: "array",
      items: {
        type: "object",
        required: ["to", "value"],
        properties: {
          to: stringSchema,
          value: stringSchema,
          data: stringSchema,
        },
      },
    },
    totalValue: stringSchema,
    sponsorship: walletActionSponsorshipSchema,
    policyResults: { type: "array", items: { type: "object", additionalProperties: true } },
  },
};

const auditEventSchema: JsonSchema = {
  type: "object",
  required: [
    "id",
    "seq",
    "actor_type",
    "actor_id",
    "action",
    "resource_type",
    "resource_id",
    "metadata",
    "created_at",
  ],
  properties: {
    id: stringSchema,
    seq: { type: "integer", minimum: 1 },
    actor_type: nullableStringSchema,
    actor_id: nullableStringSchema,
    action: stringSchema,
    resource_type: nullableStringSchema,
    resource_id: nullableStringSchema,
    metadata: metadataSchema,
    ip_address: nullableStringSchema,
    user_agent: nullableStringSchema,
    request_id: nullableStringSchema,
    created_at: dateTimeSchema,
  },
};

const auditEventsResponseSchema: JsonSchema = apiResponse({
  type: "object",
  required: ["data", "pagination"],
  properties: {
    data: { type: "array", items: auditEventSchema },
    pagination: {
      type: "object",
      required: ["page", "limit", "total", "totalPages"],
      properties: {
        page: { type: "integer", minimum: 1 },
        limit: { type: "integer", minimum: 1, maximum: 200 },
        total: { type: "integer", minimum: 0 },
        totalPages: { type: "integer", minimum: 0 },
      },
    },
  },
});

const auditPaginationSchema: JsonSchema = {
  type: "object",
  required: ["page", "limit", "total", "totalPages"],
  properties: {
    page: { type: "integer", minimum: 1 },
    limit: { type: "integer", minimum: 1, maximum: 200 },
    total: { type: "integer", minimum: 0 },
    totalPages: { type: "integer", minimum: 0 },
  },
};

const auditLogEntrySchema: JsonSchema = {
  type: "object",
  required: ["id", "timestamp", "agentId", "action", "status", "details"],
  properties: {
    id: stringSchema,
    timestamp: dateTimeSchema,
    agentId: stringSchema,
    action: { type: "string", enum: ["sign", "approve", "reject", "proxy"] },
    status: stringSchema,
    details: metadataSchema,
    policyResults: {},
    value: stringSchema,
    to: stringSchema,
  },
};

const auditLogResponseSchema: JsonSchema = apiResponse({
  type: "object",
  required: ["data", "pagination"],
  properties: {
    data: { type: "array", items: auditLogEntrySchema },
    pagination: auditPaginationSchema,
  },
});

const auditSummaryResponseSchema: JsonSchema = apiResponse({
  type: "object",
  required: [
    "totalTransactions",
    "totalApprovals",
    "totalRejections",
    "totalProxyRequests",
    "policyViolations",
    "topAgents",
    "dailyActivity",
  ],
  properties: {
    totalTransactions: { type: "integer", minimum: 0 },
    totalApprovals: { type: "integer", minimum: 0 },
    totalRejections: { type: "integer", minimum: 0 },
    totalProxyRequests: { type: "integer", minimum: 0 },
    policyViolations: { type: "integer", minimum: 0 },
    topAgents: {
      type: "array",
      items: {
        type: "object",
        required: ["agentId", "name", "txCount"],
        properties: {
          agentId: stringSchema,
          name: stringSchema,
          txCount: { type: "integer", minimum: 0 },
        },
      },
    },
    dailyActivity: {
      type: "array",
      items: {
        type: "object",
        required: ["date", "txCount"],
        properties: {
          date: { type: "string", format: "date" },
          txCount: { type: "integer", minimum: 0 },
        },
      },
    },
  },
});

const auditVerifyResponseSchema: JsonSchema = apiResponse({
  type: "object",
  required: ["valid", "anchored", "requireHead", "verifiedFromSeq", "verifiedToSeq"],
  anyOf: [{ required: ["valid", "count"] }, { required: ["valid", "brokenAt"] }],
  properties: {
    valid: { type: "boolean" },
    count: { type: "integer", minimum: 0 },
    brokenAt: { type: "integer", minimum: 1 },
    anchored: { type: "boolean" },
    requireHead: { type: "boolean" },
    verifiedFromSeq: { type: "integer", minimum: 1 },
    verifiedToSeq: { type: "integer", minimum: 0 },
    warning: stringSchema,
  },
});

const secretMetadataSchema: JsonSchema = {
  type: "object",
  required: ["id", "tenantId", "name", "version", "createdAt"],
  properties: {
    id: stringSchema,
    tenantId: stringSchema,
    name: stringSchema,
    description: nullableStringSchema,
    version: { type: "integer", minimum: 1 },
    expiresAt: { type: ["string", "null"], format: "date-time" },
    createdAt: dateTimeSchema,
    updatedAt: dateTimeSchema,
  },
  additionalProperties: true,
};

const secretCreateSchema: JsonSchema = {
  type: "object",
  required: ["name", "value"],
  properties: {
    name: stringSchema,
    value: {
      type: "string",
      description: "Secret value. Values are accepted for create/rotate only and never returned.",
    },
    description: stringSchema,
    expiresAt: dateTimeSchema,
  },
};

const secretRotateSchema: JsonSchema = {
  type: "object",
  required: ["value"],
  properties: {
    value: {
      type: "string",
      description:
        "Replacement secret value. Values are accepted for rotate only and never returned.",
    },
  },
};

const secretRouteSchema: JsonSchema = {
  type: "object",
  required: [
    "id",
    "tenantId",
    "agentId",
    "secretId",
    "hostPattern",
    "pathPattern",
    "method",
    "injectAs",
    "injectKey",
    "enabled",
  ],
  properties: {
    id: stringSchema,
    tenantId: stringSchema,
    agentId: stringSchema,
    secretId: stringSchema,
    hostPattern: stringSchema,
    pathPattern: stringSchema,
    method: {
      type: "string",
      enum: ["*", "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"],
    },
    injectAs: { type: "string", enum: ["header"] },
    injectKey: stringSchema,
    injectFormat: nullableStringSchema,
    priority: { type: "integer", minimum: 0, maximum: 1000000 },
    enabled: { type: "boolean" },
    createdAt: dateTimeSchema,
  },
  additionalProperties: true,
};

const secretRouteMutationProperties: Record<string, JsonSchema> = {
  agentId: stringSchema,
  hostPattern: stringSchema,
  pathPattern: stringSchema,
  method: {
    type: "string",
    enum: ["*", "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"],
  },
  injectAs: { type: "string", enum: ["header"] },
  injectKey: stringSchema,
  injectFormat: stringSchema,
  priority: { type: "integer", minimum: 0, maximum: 1000000 },
  enabled: { type: "boolean" },
};

const secretRouteMutationSchema: JsonSchema = {
  type: "object",
  properties: secretRouteMutationProperties,
};

const secretRouteCreateSchema: JsonSchema = {
  ...secretRouteMutationSchema,
  required: ["secretId", "agentId", "hostPattern", "injectAs", "injectKey"],
  properties: {
    ...secretRouteMutationProperties,
    secretId: stringSchema,
  },
};

const webhookEventTypeSchema: JsonSchema = {
  type: "string",
  enum: [
    "tx.pending",
    "tx.approved",
    "tx.denied",
    "tx.signed",
    "spend.threshold",
    "policy.violation",
    "wallet_action.transfer.failed",
    "wallet_action.transfer.succeeded",
    "wallet_action.send_calls.failed",
    "wallet_action.send_calls.succeeded",
    "wallet.raw_signature.created",
    "wallet.private_key_exported",
    "user.wallet.created",
    "intent.created",
    "intent.authorized",
    "intent.executed",
    "intent.failed",
    "intent.rejected",
    "intent.canceled",
    "intent.expired",
  ],
};

const webhookConfigProperties: Record<string, JsonSchema> = {
  id: stringSchema,
  tenantId: stringSchema,
  url: { type: "string", format: "uri" },
  events: { type: "array", items: webhookEventTypeSchema },
  enabled: { type: "boolean" },
  maxRetries: { type: "integer", minimum: 0, maximum: 10 },
  retryBackoffMs: { type: "integer", minimum: 1000, maximum: 3600000 },
  description: nullableStringSchema,
  createdAt: dateTimeSchema,
  updatedAt: dateTimeSchema,
};

const webhookConfigSchema: JsonSchema = {
  type: "object",
  required: [
    "id",
    "tenantId",
    "url",
    "events",
    "enabled",
    "maxRetries",
    "retryBackoffMs",
    "createdAt",
  ],
  properties: webhookConfigProperties,
  additionalProperties: true,
};

const webhookCreateResponseSchema: JsonSchema = {
  ...webhookConfigSchema,
  required: [...((webhookConfigSchema.required as string[]) ?? []), "secret"],
  properties: {
    ...webhookConfigProperties,
    secret: {
      type: "string",
      description: "One-time webhook signing secret. Returned only from create responses.",
    },
  },
};

const webhookMutationSchema: JsonSchema = {
  type: "object",
  properties: {
    url: { type: "string", format: "uri" },
    events: { type: "array", items: webhookEventTypeSchema },
    enabled: { type: "boolean" },
    description: stringSchema,
    maxRetries: { type: "integer", minimum: 0, maximum: 10 },
    retryBackoffMs: { type: "integer", minimum: 1000, maximum: 3600000 },
  },
};

const webhookCreateSchema: JsonSchema = {
  ...webhookMutationSchema,
  required: ["url"],
};

const webhookDeliverySchema: JsonSchema = {
  type: "object",
  required: ["id", "eventType", "status", "attempts", "maxAttempts", "hasError", "createdAt"],
  properties: {
    id: stringSchema,
    eventType: stringSchema,
    status: {
      type: "string",
      enum: ["pending", "processing", "delivered", "failed"],
    },
    attempts: { type: "integer", minimum: 0 },
    maxAttempts: { type: "integer", minimum: 0 },
    nextRetryAt: { type: ["string", "null"], format: "date-time" },
    replayedFromDeliveryId: nullableStringSchema,
    hasError: { type: "boolean" },
    createdAt: dateTimeSchema,
    deliveredAt: { type: ["string", "null"], format: "date-time" },
  },
};

const webhookDeliveryExportSchema: JsonSchema = {
  type: "object",
  required: ["webhookId", "exportedAt", "deliveries"],
  properties: {
    webhookId: stringSchema,
    exportedAt: dateTimeSchema,
    deliveries: { type: "array", items: webhookDeliverySchema },
  },
};

const approvalQueueEntrySchema: JsonSchema = {
  type: "object",
  required: ["id", "txId", "agentId", "status", "requestedAt"],
  properties: {
    id: stringSchema,
    txId: stringSchema,
    agentId: stringSchema,
    agentName: stringSchema,
    status: { type: "string", enum: ["pending", "approved", "rejected"] },
    requestedAt: dateTimeSchema,
    resolvedAt: { type: ["string", "null"], format: "date-time" },
    resolvedBy: nullableStringSchema,
    toAddress: nullableStringSchema,
    value: nullableStringSchema,
    chainId: { type: ["integer", "null"] },
    txStatus: nullableStringSchema,
    comment: stringSchema,
    reason: stringSchema,
  },
  additionalProperties: true,
};

const approvalStatsSchema: JsonSchema = {
  type: "object",
  required: ["pending", "approved", "rejected", "total", "avgWaitSeconds"],
  properties: {
    pending: { type: "integer", minimum: 0 },
    approved: { type: "integer", minimum: 0 },
    rejected: { type: "integer", minimum: 0 },
    total: { type: "integer", minimum: 0 },
    avgWaitSeconds: { type: "integer", minimum: 0 },
  },
};

const approvalCommentSchema: JsonSchema = {
  type: "object",
  properties: {
    comment: { type: "string", maxLength: 1000 },
    approvedBy: stringSchema,
  },
};

const approvalDenySchema: JsonSchema = {
  type: "object",
  required: ["reason"],
  properties: {
    reason: { type: "string", minLength: 1, maxLength: 1000 },
    deniedBy: stringSchema,
  },
};

const autoApprovalRuleSchema: JsonSchema = {
  type: "object",
  required: ["tenantId", "maxAmountWei", "enabled"],
  properties: {
    id: stringSchema,
    tenantId: stringSchema,
    maxAmountWei: { type: "string", pattern: "^\\d+$" },
    autoDenyAfterHours: { type: ["number", "null"], exclusiveMinimum: 0 },
    escalateAboveWei: { type: ["string", "null"], pattern: "^\\d+$" },
    enabled: { type: "boolean" },
    createdAt: dateTimeSchema,
    updatedAt: dateTimeSchema,
  },
  additionalProperties: true,
};

const autoApprovalRuleMutationSchema: JsonSchema = {
  type: "object",
  properties: {
    maxAmountWei: { type: "string", pattern: "^\\d+$" },
    autoDenyAfterHours: { type: ["number", "null"], exclusiveMinimum: 0 },
    escalateAboveWei: { type: ["string", "null"], pattern: "^\\d+$" },
    enabled: { type: "boolean" },
  },
};

const globalWalletScopeSchema: JsonSchema = {
  type: "string",
  enum: ["eth_accounts", "personal_sign", "eth_signTypedData_v4", "eth_sendTransaction"],
};

const globalWalletAppSchema: JsonSchema = {
  type: "object",
  required: ["id", "appId", "tenantId", "name", "origin"],
  properties: {
    id: stringSchema,
    appId: stringSchema,
    tenantId: stringSchema,
    name: stringSchema,
    environment: stringSchema,
    origin: stringSchema,
    redirectUri: nullableStringSchema,
  },
};

const globalWalletConsentSchema: JsonSchema = {
  type: "object",
  required: [
    "id",
    "tenantId",
    "clientId",
    "appId",
    "origin",
    "walletAgentId",
    "walletAddress",
    "scopes",
    "status",
  ],
  properties: {
    id: stringSchema,
    tenantId: stringSchema,
    clientId: stringSchema,
    appId: stringSchema,
    origin: stringSchema,
    redirectUri: nullableStringSchema,
    walletAgentId: stringSchema,
    walletAddress: stringSchema,
    walletIndex: { type: ["integer", "null"], minimum: 0, maximum: 255 },
    scopes: { type: "array", items: globalWalletScopeSchema },
    status: { type: "string", enum: ["active", "revoked"] },
    grantedAt: { type: ["string", "null"], format: "date-time" },
    lastUsedAt: { type: ["string", "null"], format: "date-time" },
    expiresAt: { type: ["string", "null"], format: "date-time" },
    revokedAt: { type: ["string", "null"], format: "date-time" },
    createdAt: dateTimeSchema,
    updatedAt: dateTimeSchema,
  },
  additionalProperties: true,
};

const globalWalletConsentRequestSchema: JsonSchema = {
  type: "object",
  required: ["app", "requestedScopes", "wallet", "consent"],
  properties: {
    app: globalWalletAppSchema,
    requestedScopes: { type: "array", items: globalWalletScopeSchema },
    wallet: {
      type: "object",
      required: ["agentId", "address", "walletIndex"],
      properties: {
        agentId: stringSchema,
        address: stringSchema,
        walletIndex: { type: "integer", minimum: 0, maximum: 255 },
      },
    },
    consent: { anyOf: [globalWalletConsentSchema, { type: "null" }] },
  },
};

const globalWalletConsentInputSchema: JsonSchema = {
  type: "object",
  required: ["app_id"],
  properties: {
    app_id: stringSchema,
    appId: stringSchema,
    origin: stringSchema,
    redirect_uri: stringSchema,
    redirectUri: stringSchema,
    wallet_index: { type: "integer", minimum: 0, maximum: 255 },
    walletIndex: { type: "integer", minimum: 0, maximum: 255 },
    scope: { anyOf: [globalWalletScopeSchema, { type: "array", items: globalWalletScopeSchema }] },
    scopes: { type: "array", items: globalWalletScopeSchema },
  },
};

const globalWalletRpcBodySchema: JsonSchema = {
  type: "object",
  required: ["app_id", "method"],
  properties: {
    app_id: stringSchema,
    appId: stringSchema,
    origin: stringSchema,
    method: globalWalletScopeSchema,
    params: {},
    wallet_index: { type: "integer", minimum: 0, maximum: 255 },
    walletIndex: { type: "integer", minimum: 0, maximum: 255 },
    confirmation_id: stringSchema,
    confirmationId: stringSchema,
    id: {},
    jsonrpc: stringSchema,
  },
};

const globalWalletActionConfirmationSchema: JsonSchema = {
  type: "object",
  required: ["confirmationId", "method", "expiresAt"],
  properties: {
    confirmationId: stringSchema,
    method: globalWalletScopeSchema,
    wallet: {
      type: "object",
      required: ["agentId", "address", "walletIndex"],
      properties: {
        agentId: stringSchema,
        address: stringSchema,
        walletIndex: { type: "integer", minimum: 0, maximum: 255 },
      },
    },
    expiresAt: dateTimeSchema,
  },
};

const globalWalletTransactionScanSchema: JsonSchema = {
  type: "object",
  required: [
    "method",
    "wallet",
    "transaction",
    "blocked",
    "riskLevel",
    "warnings",
    "confirmationRequired",
    "executionSupported",
  ],
  properties: {
    method: { type: "string", const: "eth_sendTransaction" },
    wallet: {
      type: "object",
      required: ["address", "agentId", "walletIndex"],
      properties: {
        address: stringSchema,
        agentId: stringSchema,
        walletIndex: { type: "integer", minimum: 0, maximum: 255 },
      },
    },
    transaction: {
      type: "object",
      required: ["to", "valueWei", "chainId"],
      properties: {
        from: stringSchema,
        to: stringSchema,
        valueWei: stringSchema,
        data: stringSchema,
        chainId: { type: "integer", minimum: 1 },
      },
    },
    blocked: { type: "boolean" },
    riskLevel: { type: "string", enum: ["low", "medium", "blocked"] },
    warnings: {
      type: "array",
      items: {
        type: "object",
        required: ["code", "severity", "message"],
        properties: {
          code: stringSchema,
          severity: { type: "string", enum: ["info", "warning", "error"] },
          message: stringSchema,
        },
      },
    },
    confirmationRequired: { type: "boolean", const: true },
    executionSupported: { type: "boolean" },
    unsupportedReason: nullableStringSchema,
  },
};

const globalWalletRpcResponseSchema: JsonSchema = {
  type: "object",
  required: ["jsonrpc", "id", "result"],
  properties: {
    jsonrpc: stringSchema,
    id: {},
    result: {},
  },
};

const tenantControlPlaneConfigSchema: JsonSchema = {
  type: "object",
  required: ["tenantId"],
  properties: {
    tenantId: stringSchema,
    displayName: stringSchema,
    policyExposure: metadataSchema,
    policyTemplates: { type: "array", items: metadataSchema },
    secretRoutePresets: { type: "array", items: metadataSchema },
    approvalConfig: metadataSchema,
    featureFlags: metadataSchema,
    theme: metadataSchema,
    allowedOrigins: { type: "array", items: stringSchema },
    allowedRedirectUrls: { type: "array", items: stringSchema },
    oidcProviders: { type: "array", items: metadataSchema },
    authAbuseConfig: metadataSchema,
    appClients: { type: "array", items: metadataSchema },
    testAccount: metadataSchema,
    gasSponsorshipConfig: metadataSchema,
    createdAt: dateTimeSchema,
    updatedAt: dateTimeSchema,
  },
  additionalProperties: true,
};

const tenantAuthAbuseConfigResponseSchema: JsonSchema = {
  type: "object",
  required: ["authAbuseConfig"],
  properties: {
    authAbuseConfig: metadataSchema,
  },
};

const tenantSecurityChecklistSchema: JsonSchema = {
  type: "object",
  required: ["tenantId", "generatedAt", "summary", "items"],
  properties: {
    tenantId: stringSchema,
    generatedAt: dateTimeSchema,
    summary: {
      type: "object",
      required: ["pass", "warning", "fail"],
      properties: {
        pass: { type: "integer", minimum: 0 },
        warning: { type: "integer", minimum: 0 },
        fail: { type: "integer", minimum: 0 },
      },
    },
    items: {
      type: "array",
      items: {
        type: "object",
        required: ["id", "label", "status", "description"],
        properties: {
          id: stringSchema,
          label: stringSchema,
          status: { type: "string", enum: ["pass", "warning", "fail"] },
          description: stringSchema,
          remediation: stringSchema,
        },
      },
    },
  },
};

const tenantIdempotencyMetricsSchema: JsonSchema = {
  type: "object",
  additionalProperties: true,
  description:
    "Privacy-preserving idempotency counters for the tenant. Shape can evolve with middleware storage backends.",
};

const tenantRequestSigningKeySchema: JsonSchema = {
  type: "object",
  required: ["id", "tenantId", "name", "secretPrefix", "status", "createdAt", "updatedAt"],
  properties: {
    id: stringSchema,
    tenantId: stringSchema,
    name: stringSchema,
    secretPrefix: stringSchema,
    status: { type: "string", enum: ["active", "retiring", "revoked"] },
    createdAt: dateTimeSchema,
    updatedAt: dateTimeSchema,
    expiresAt: { type: ["string", "null"], format: "date-time" },
    revokedAt: { type: ["string", "null"], format: "date-time" },
  },
};

const tenantRequestSigningKeyCreateSchema: JsonSchema = {
  type: "object",
  properties: {
    name: stringSchema,
  },
};

const tenantRequestSigningKeyCreateResultSchema: JsonSchema = {
  type: "object",
  required: ["key", "signingSecret"],
  properties: {
    key: tenantRequestSigningKeySchema,
    signingSecret: {
      type: "string",
      description:
        "One-time tenant request signing secret. It is returned only from key creation responses.",
    },
  },
};

const tenantPolicyTemplateApplySchema: JsonSchema = {
  type: "object",
  required: ["agentId"],
  properties: {
    agentId: stringSchema,
    overrides: metadataSchema,
  },
};

const tenantPolicyTemplateApplyResultSchema: JsonSchema = {
  type: "object",
  required: ["templateId", "templateName", "agentId", "policiesApplied", "policies"],
  properties: {
    templateId: stringSchema,
    templateName: stringSchema,
    agentId: stringSchema,
    policiesApplied: { type: "integer", minimum: 0 },
    policies: { type: "array", items: policyRuleSchema },
  },
};

function walletActionErrorResponses(): JsonSchema {
  return {
    ...errorResponses(),
    "429": jsonResponse(errorResponse()),
    "500": jsonResponse(errorResponse()),
    "501": jsonResponse(errorResponse()),
    "502": jsonResponse(errorResponse()),
    "503": jsonResponse(errorResponse()),
  };
}

function webhookPaths(prefix = ""): Record<string, unknown> {
  const webhookAdminDescription =
    "Requires an owner/admin browser session with recent MFA. Tenant API keys and agent tokens cannot manage webhook configuration or delivery controls.";
  const webhookRedactionDescription =
    "Responses redact webhook secrets, payloads, webhook URLs in delivery rows, and raw provider error text except for the one-time secret returned by create.";
  const deliveryParameters = [
    parameter("limit", "query", { type: "integer", minimum: 1, maximum: 200 }),
    parameter("offset", "query", { type: "integer", minimum: 0, maximum: 100000 }),
    parameter("status", "query", {
      type: "string",
      enum: ["pending", "processing", "delivered", "failed"],
    }),
    parameter("eventType", "query"),
    parameter("hasError", "query", { type: "boolean" }),
  ];

  return {
    [`${prefix}/webhooks`]: {
      get: {
        tags: ["Webhooks"],
        summary: "List webhook configurations",
        description: `${webhookAdminDescription} ${webhookRedactionDescription}`,
        security: [{ bearerAuth: [] }],
        responses: {
          "200": jsonResponse(apiResponse({ type: "array", items: webhookConfigSchema })),
          ...errorResponses(),
        },
      },
      post: {
        tags: ["Webhooks"],
        summary: "Create a webhook configuration",
        description: `${webhookAdminDescription} Returns the webhook signing secret exactly once in the create response.`,
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody(webhookCreateSchema),
        responses: {
          "201": jsonResponse(apiResponse(webhookCreateResponseSchema)),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/webhooks/{id}`]: {
      parameters: [parameter("id", "path")],
      put: {
        tags: ["Webhooks"],
        summary: "Update a webhook configuration",
        description: `${webhookAdminDescription} ${webhookRedactionDescription}`,
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody(webhookMutationSchema),
        responses: {
          "200": jsonResponse(apiResponse(webhookConfigSchema)),
          ...errorResponses(),
        },
      },
      delete: {
        tags: ["Webhooks"],
        summary: "Delete a webhook configuration",
        description: webhookAdminDescription,
        security: [{ bearerAuth: [] }],
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              required: ["deleted"],
              properties: { deleted: { type: "boolean", const: true } },
            }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/webhooks/{id}/test`]: {
      parameters: [parameter("id", "path")],
      post: {
        tags: ["Webhooks"],
        summary: "Send a diagnostic webhook test delivery",
        description:
          "Requires owner/admin session with recent MFA. Sends a signed webhook.test diagnostic delivery to an enabled endpoint; webhook.test is not a subscribable event type.",
        security: [{ bearerAuth: [] }],
        responses: {
          "202": jsonResponse(
            apiResponse({
              type: "object",
              required: ["eventType", "status"],
              properties: {
                eventType: { type: "string", const: "webhook.test" },
                status: { type: "string", const: "delivered" },
              },
            }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/webhooks/{id}/deliveries`]: {
      parameters: [parameter("id", "path")],
      get: {
        tags: ["Webhooks"],
        summary: "List redacted webhook delivery history",
        description: `${webhookAdminDescription} ${webhookRedactionDescription}`,
        security: [{ bearerAuth: [] }],
        parameters: deliveryParameters,
        responses: {
          "200": jsonResponse(apiResponse({ type: "array", items: webhookDeliverySchema })),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/webhooks/{id}/deliveries/export`]: {
      parameters: [parameter("id", "path")],
      get: {
        tags: ["Webhooks"],
        summary: "Export redacted webhook delivery history",
        description: `${webhookAdminDescription} Returns the same redacted delivery fields as the JSON history endpoint for offline review.`,
        security: [{ bearerAuth: [] }],
        parameters: deliveryParameters,
        responses: {
          "200": jsonResponse(apiResponse(webhookDeliveryExportSchema)),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/webhooks/deliveries/{id}/retry`]: {
      parameters: [parameter("id", "path")],
      post: {
        tags: ["Webhooks"],
        summary: "Retry a failed webhook delivery",
        description:
          "Requires owner/admin session with recent MFA. Re-queues an eligible failed delivery without resetting attempts or bypassing the configured retry budget.",
        security: [{ bearerAuth: [] }],
        responses: {
          "200": jsonResponse(apiResponse(webhookDeliverySchema)),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/webhooks/deliveries/{id}/replay`]: {
      parameters: [parameter("id", "path")],
      post: {
        tags: ["Webhooks"],
        summary: "Replay a historical webhook delivery",
        description:
          "Requires owner/admin session with recent MFA. Creates a new signed delivery with a new delivery ID when the original webhook still exists, is enabled, has the same URL, and still subscribes to the event type.",
        security: [{ bearerAuth: [] }],
        responses: {
          "200": jsonResponse(apiResponse(webhookDeliverySchema)),
          ...errorResponses(),
        },
      },
    },
  };
}

function approvalPaths(prefix = ""): Record<string, unknown> {
  const approvalDescription =
    "Requires an owner/admin browser session with recent MFA. Tenant API keys and agent tokens cannot review or mutate manual approvals.";
  const vaultExecutionDescription =
    "This generic approval route does not execute vault transactions; executable vault approvals must use POST /vault/{agentId}/approve/{txId} so signing, policy revalidation, audit rollback, and broadcast semantics stay on the vault path.";

  return {
    [`${prefix}/approvals`]: {
      get: {
        tags: ["Approvals"],
        summary: "List manual approval queue entries",
        description: `${approvalDescription} Supports status, limit, and offset filters.`,
        security: [{ bearerAuth: [] }],
        parameters: [
          parameter("status", "query", {
            type: "string",
            enum: ["pending", "approved", "rejected", "all"],
          }),
          parameter("limit", "query", { type: "integer", minimum: 1, maximum: 200 }),
          parameter("offset", "query", { type: "integer", minimum: 0, maximum: 10000 }),
        ],
        responses: {
          "200": jsonResponse(apiResponse({ type: "array", items: approvalQueueEntrySchema })),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/approvals/stats`]: {
      get: {
        tags: ["Approvals"],
        summary: "Get manual approval queue statistics",
        description: approvalDescription,
        security: [{ bearerAuth: [] }],
        responses: {
          "200": jsonResponse(apiResponse(approvalStatsSchema)),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/approvals/{txId}/approve`]: {
      parameters: [parameter("txId", "path")],
      post: {
        tags: ["Approvals"],
        summary: "Approve a non-vault manual approval entry",
        description: `${approvalDescription} ${vaultExecutionDescription}`,
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody(approvalCommentSchema, false),
        responses: {
          "200": jsonResponse(apiResponse(approvalQueueEntrySchema)),
          "409": jsonResponse(errorResponse()),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/approvals/{txId}/deny`]: {
      parameters: [parameter("txId", "path")],
      post: {
        tags: ["Approvals"],
        summary: "Deny a manual approval entry",
        description: `${approvalDescription} Denial updates the approval and transaction status in one transaction, writes audit events, and dispatches denial webhooks.`,
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody(approvalDenySchema),
        responses: {
          "200": jsonResponse(apiResponse(approvalQueueEntrySchema)),
          "409": jsonResponse(errorResponse()),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/approvals/rules`]: {
      get: {
        tags: ["Approvals"],
        summary: "Get tenant auto-approval rules",
        description: approvalDescription,
        security: [{ bearerAuth: [] }],
        responses: {
          "200": jsonResponse(apiResponse({ anyOf: [autoApprovalRuleSchema, { type: "null" }] })),
          ...errorResponses(),
        },
      },
      put: {
        tags: ["Approvals"],
        summary: "Create or update tenant auto-approval rules",
        description: `${approvalDescription} Rule writes are audited before persistence and rolled back if the final audit write fails.`,
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody(autoApprovalRuleMutationSchema),
        responses: {
          "200": jsonResponse(apiResponse(autoApprovalRuleSchema)),
          "201": jsonResponse(apiResponse(autoApprovalRuleSchema)),
          ...errorResponses(),
        },
      },
    },
  };
}

function globalWalletPaths(prefix = ""): Record<string, unknown> {
  const globalWalletDescription =
    "Requires an authenticated user session. App access is bound to an enabled tenant app client, allowed Origin/Referer, allowed redirect URI, and selected wallet index; responses are no-store.";
  const globalWalletWriteDescription =
    "Requires recent MFA. Write-capable global-wallet methods also require active consent for the exact origin/app, selected wallet index, wallet binding, explicit server-side enablement where applicable, and a one-time action confirmation.";
  const globalWalletRpcDescription =
    "Read-only eth_accounts/eth_chainId are allowed by active consent. personal_sign, eth_signTypedData_v4, and eth_sendTransaction fail closed unless explicitly enabled by server flags, recent MFA, matching scope, selected wallet index, wallet binding, and one-time action confirmation. Contract calldata transactions are blocked until selector-aware scanning is configured.";

  return {
    [`${prefix}/global-wallet/consent/request`]: {
      get: {
        tags: ["Global Wallet"],
        summary: "Preview a global wallet consent request",
        description: globalWalletDescription,
        security: [{ bearerAuth: [] }],
        parameters: [
          parameter("app_id", "query"),
          parameter("appId", "query"),
          parameter("origin", "query"),
          parameter("redirect_uri", "query"),
          parameter("redirectUri", "query"),
          parameter("scope", "query"),
          parameter("wallet_index", "query"),
          parameter("walletIndex", "query"),
        ],
        responses: {
          "200": jsonResponse(apiResponse(globalWalletConsentRequestSchema)),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/global-wallet/consent/approve`]: {
      post: {
        tags: ["Global Wallet"],
        summary: "Approve global wallet app access",
        description: `${globalWalletDescription} ${globalWalletWriteDescription} Existing active consent for the same user/app/origin is revoked before the new consent is inserted, and approval is rolled back if the final audit write fails.`,
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody(globalWalletConsentInputSchema),
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              required: ["consent", "wallet"],
              properties: {
                consent: globalWalletConsentSchema,
                wallet: {
                  type: "object",
                  required: ["agentId", "address", "walletIndex"],
                  properties: {
                    agentId: stringSchema,
                    address: stringSchema,
                    walletIndex: { type: "integer", minimum: 0, maximum: 255 },
                  },
                },
              },
            }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/global-wallet/consents`]: {
      get: {
        tags: ["Global Wallet"],
        summary: "List authenticated user's global wallet app consents",
        description: globalWalletDescription,
        security: [{ bearerAuth: [] }],
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              required: ["consents"],
              properties: { consents: { type: "array", items: globalWalletConsentSchema } },
            }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/global-wallet/consents/{consentId}/revoke`]: {
      parameters: [parameter("consentId", "path")],
      post: {
        tags: ["Global Wallet"],
        summary: "Revoke global wallet app access",
        description: globalWalletWriteDescription,
        security: [{ bearerAuth: [] }],
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              required: ["consent"],
              properties: { consent: globalWalletConsentSchema },
            }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/global-wallet/rpc/confirm`]: {
      post: {
        tags: ["Global Wallet"],
        summary: "Create a one-time global wallet action confirmation",
        description: `${globalWalletWriteDescription} Confirmations are bound to consent, user, tenant app, origin, method, request hash, wallet agent id, wallet address, and wallet index and expire after five minutes.`,
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody(globalWalletRpcBodySchema),
        responses: {
          "200": jsonResponse(apiResponse(globalWalletActionConfirmationSchema)),
          "409": jsonResponse(errorResponse()),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/global-wallet/rpc/scan`]: {
      post: {
        tags: ["Global Wallet"],
        summary: "Scan a global wallet transaction request",
        description:
          "Requires active consent for eth_sendTransaction and the selected wallet index. Native-transfer-shaped requests produce risk and confirmation metadata; contract calldata is blocked until selector-aware scanning is configured.",
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody(globalWalletRpcBodySchema),
        responses: {
          "200": jsonResponse(apiResponse(globalWalletTransactionScanSchema)),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/global-wallet/rpc`]: {
      post: {
        tags: ["Global Wallet"],
        summary: "Call the global wallet RPC bridge",
        description: globalWalletRpcDescription,
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody(globalWalletRpcBodySchema),
        responses: {
          "200": jsonResponse(apiResponse(globalWalletRpcResponseSchema)),
          ...errorResponses(),
        },
      },
    },
  };
}

function tenantConfigPaths(prefix = ""): Record<string, unknown> {
  const tenantConfigReadDescription =
    "Tenant control-plane configuration. Reads require tenant-level auth except /tenants/config, which is public default discovery for unauthenticated SDK bootstraps.";
  const tenantAdminDescription =
    "Requires an owner/admin browser session with recent MFA. Tenant API keys and agent tokens cannot mutate tenant security configuration.";

  return {
    [`${prefix}/tenants/config`]: {
      get: {
        tags: ["Tenant Config"],
        summary: "Get default public tenant config",
        description:
          "Public discovery endpoint used by SDKs before sign-in. Returns redacted default tenant config and never reads tenant PII.",
        security: [],
        responses: {
          "200": jsonResponse(apiResponse(tenantControlPlaneConfigSchema)),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/tenants/{id}/config`]: {
      parameters: [parameter("id", "path")],
      get: {
        tags: ["Tenant Config"],
        summary: "Get tenant control-plane config",
        description: tenantConfigReadDescription,
        security: [{ tenantApiKey: [] }, { bearerAuth: [] }],
        responses: {
          "200": jsonResponse(apiResponse(tenantControlPlaneConfigSchema)),
          ...errorResponses(),
        },
      },
      put: {
        tags: ["Tenant Config"],
        summary: "Update tenant control-plane config",
        description:
          "Requires owner/admin session with recent MFA. Updates policy exposure, policy templates, feature flags, app clients, allowed origins, redirect URLs, MFA/auth-abuse config, gas sponsorship config, and presentation settings.",
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody(tenantControlPlaneConfigSchema),
        responses: {
          "200": jsonResponse(apiResponse(tenantControlPlaneConfigSchema)),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/tenants/{id}/config/templates`]: {
      parameters: [parameter("id", "path")],
      get: {
        tags: ["Tenant Config"],
        summary: "List tenant policy templates",
        description:
          "Returns tenant policy templates. Non-admin tenant auth receives policy-exposure-redacted templates.",
        security: [{ tenantApiKey: [] }, { bearerAuth: [] }],
        responses: {
          "200": jsonResponse(apiResponse({ type: "array", items: metadataSchema })),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/tenants/{id}/config/templates/{name}/apply`]: {
      parameters: [parameter("id", "path"), parameter("name", "path")],
      post: {
        tags: ["Tenant Config"],
        summary: "Apply a tenant policy template to an agent",
        description: `${tenantAdminDescription} Applies a validated policy template to an agent, with optional per-field overrides restricted to template customizable fields.`,
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody(tenantPolicyTemplateApplySchema),
        responses: {
          "200": jsonResponse(apiResponse(tenantPolicyTemplateApplyResultSchema)),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/tenants/{id}/auth-abuse-config`]: {
      parameters: [parameter("id", "path")],
      get: {
        tags: ["Tenant Config"],
        summary: "Get tenant auth-abuse config",
        description: tenantAdminDescription,
        security: [{ bearerAuth: [] }],
        responses: {
          "200": jsonResponse(apiResponse(tenantAuthAbuseConfigResponseSchema)),
          ...errorResponses(),
        },
      },
      put: {
        tags: ["Tenant Config"],
        summary: "Update tenant auth-abuse config",
        description:
          "Requires owner/admin session with recent MFA. Updates CAPTCHA, allowlist/denylist, MFA, and wallet/phone/email abuse controls after server-side normalization.",
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody(tenantAuthAbuseConfigResponseSchema),
        responses: {
          "200": jsonResponse(apiResponse(tenantAuthAbuseConfigResponseSchema)),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/tenants/{id}/security-checklist`]: {
      parameters: [parameter("id", "path")],
      get: {
        tags: ["Tenant Config"],
        summary: "Get tenant security checklist",
        description:
          "Requires owner/admin session with recent MFA. Summarizes tenant origin, redirect, app-client, app-secret, and request-signing-key hardening status.",
        security: [{ bearerAuth: [] }],
        responses: {
          "200": jsonResponse(apiResponse(tenantSecurityChecklistSchema)),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/tenants/{id}/idempotency-metrics`]: {
      parameters: [parameter("id", "path")],
      get: {
        tags: ["Tenant Config"],
        summary: "Get tenant idempotency metrics",
        description:
          "Requires owner/admin session with recent MFA. Returns privacy-preserving idempotency counters for sensitive request replay diagnostics.",
        security: [{ bearerAuth: [] }],
        responses: {
          "200": jsonResponse(apiResponse(tenantIdempotencyMetricsSchema)),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/tenants/{id}/idempotency-metrics/export`]: {
      parameters: [parameter("id", "path")],
      get: {
        tags: ["Tenant Config"],
        summary: "Export tenant idempotency metrics",
        description:
          "Requires owner/admin session with recent MFA. Exports one privacy-preserving CSV snapshot of idempotency counters for sensitive request replay diagnostics. The export never includes idempotency keys, request bodies, stored response bodies, or credential material.",
        security: [{ bearerAuth: [] }],
        responses: {
          "200": {
            description: "CSV idempotency metrics snapshot",
            content: {
              "text/csv": {
                schema: { type: "string" },
              },
            },
          },
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/tenants/{id}/request-signing-keys`]: {
      parameters: [parameter("id", "path")],
      get: {
        tags: ["Tenant Config"],
        summary: "List tenant request-signing keys",
        description:
          "Requires owner/admin session with recent MFA. Returns metadata only; signing secrets are never returned by list responses.",
        security: [{ bearerAuth: [] }],
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              required: ["keys"],
              properties: { keys: { type: "array", items: tenantRequestSigningKeySchema } },
            }),
          ),
          ...errorResponses(),
        },
      },
      post: {
        tags: ["Tenant Config"],
        summary: "Create or rotate a tenant request-signing key",
        description:
          "Requires owner/admin session with recent MFA. Creates a new active request-signing key, retires currently active keys, and returns the signingSecret exactly once.",
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody(tenantRequestSigningKeyCreateSchema, false),
        responses: {
          "201": jsonResponse(apiResponse(tenantRequestSigningKeyCreateResultSchema)),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/tenants/{id}/request-signing-keys/{keyId}`]: {
      parameters: [parameter("id", "path"), parameter("keyId", "path")],
      delete: {
        tags: ["Tenant Config"],
        summary: "Revoke a tenant request-signing key",
        description: tenantAdminDescription,
        security: [{ bearerAuth: [] }],
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              required: ["key"],
              properties: { key: tenantRequestSigningKeySchema },
            }),
          ),
          ...errorResponses(),
        },
      },
    },
  };
}

function secretPaths(prefix = ""): Record<string, unknown> {
  const secretReadDescription =
    "Requires an owner/admin browser session with recent MFA. Returns metadata only; secret values are never included in responses. Tenant API keys and agent tokens cannot read this inventory.";
  const secretMutationDescription =
    "Requires an owner/admin browser session with recent MFA. Secret values are accepted only for create/rotate requests, never returned, and sensitive route hardening headers are advertised for mutation calls.";
  const secretRouteDescription =
    "Credential injection routes bind a secret to one tenant agent and an explicit allowlisted upstream host/path/method/header. Broad host, path, method, internal-host, line-break, and unsafe header injection patterns are rejected by the API.";

  return {
    [`${prefix}/secrets`]: {
      get: {
        tags: ["Secrets"],
        summary: "List tenant secret metadata",
        description: secretReadDescription,
        security: [{ bearerAuth: [] }],
        responses: {
          "200": jsonResponse(apiResponse({ type: "array", items: secretMetadataSchema })),
          ...errorResponses(),
        },
      },
      post: {
        tags: ["Secrets"],
        summary: "Create a tenant secret",
        description: secretMutationDescription,
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody(secretCreateSchema),
        responses: {
          "201": jsonResponse(apiResponse(secretMetadataSchema)),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/secrets/routes`]: {
      get: {
        tags: ["Secrets"],
        summary: "List credential injection routes",
        description: `${secretReadDescription} ${secretRouteDescription}`,
        security: [{ bearerAuth: [] }],
        parameters: [parameter("secretId", "query")],
        responses: {
          "200": jsonResponse(apiResponse({ type: "array", items: secretRouteSchema })),
          ...errorResponses(),
        },
      },
      post: {
        tags: ["Secrets"],
        summary: "Create a credential injection route",
        description: `${secretMutationDescription} ${secretRouteDescription}`,
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody(secretRouteCreateSchema),
        responses: {
          "201": jsonResponse(apiResponse(secretRouteSchema)),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/secrets/routes/{routeId}`]: {
      parameters: [parameter("routeId", "path")],
      put: {
        tags: ["Secrets"],
        summary: "Update a credential injection route",
        description: `${secretMutationDescription} ${secretRouteDescription}`,
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody(secretRouteMutationSchema),
        responses: {
          "200": jsonResponse(apiResponse(secretRouteSchema)),
          ...errorResponses(),
        },
      },
      delete: {
        tags: ["Secrets"],
        summary: "Delete a credential injection route",
        description: secretMutationDescription,
        security: [{ bearerAuth: [] }],
        responses: {
          "200": jsonResponse(
            apiResponse({ type: "object", properties: { deleted: stringSchema } }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/secrets/{secretId}`]: {
      parameters: [parameter("secretId", "path")],
      get: {
        tags: ["Secrets"],
        summary: "Get tenant secret metadata",
        description: secretReadDescription,
        security: [{ bearerAuth: [] }],
        responses: {
          "200": jsonResponse(apiResponse(secretMetadataSchema)),
          ...errorResponses(),
        },
      },
      put: {
        tags: ["Secrets"],
        summary: "Rotate a tenant secret value",
        description: secretMutationDescription,
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody(secretRotateSchema),
        responses: {
          "200": jsonResponse(apiResponse(secretMetadataSchema)),
          ...errorResponses(),
        },
      },
      delete: {
        tags: ["Secrets"],
        summary: "Delete a tenant secret",
        description: secretMutationDescription,
        security: [{ bearerAuth: [] }],
        responses: {
          "200": jsonResponse(
            apiResponse({ type: "object", properties: { deleted: stringSchema } }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/secrets/{secretId}/rotate`]: {
      parameters: [parameter("secretId", "path")],
      post: {
        tags: ["Secrets"],
        summary: "Rotate a tenant secret value",
        description: secretMutationDescription,
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody(secretRotateSchema),
        responses: {
          "200": jsonResponse(apiResponse(secretMetadataSchema)),
          ...errorResponses(),
        },
      },
    },
  };
}

function auditPaths(prefix = ""): Record<string, unknown> {
  const auditReadDescription =
    "Requires an owner/admin browser session with recent MFA. Returns tenant-scoped, no-store audit data; agent tokens and tenant API keys are not sufficient.";
  const auditFilterParameters = [
    parameter("agentId", "query"),
    parameter("action", "query", {
      type: "string",
      enum: ["sign", "approve", "reject", "proxy"],
    }),
    parameter("status", "query"),
    parameter("dateFrom", "query", dateTimeSchema),
    parameter("dateTo", "query", dateTimeSchema),
  ];

  return {
    [`${prefix}/audit/log`]: {
      get: {
        tags: ["Audits"],
        summary: "List tenant transaction and proxy audit log entries",
        description: `${auditReadDescription} Supports agent, action, status, date range, and page/limit filters across transaction approvals/signatures plus proxy audit rows.`,
        security: [{ bearerAuth: [] }],
        parameters: [
          ...auditFilterParameters,
          parameter("page", "query", { type: "integer", minimum: 1, maximum: 5000 }),
          parameter("limit", "query", { type: "integer", minimum: 1, maximum: 200 }),
        ],
        responses: {
          "200": jsonResponse(auditLogResponseSchema),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/audit/summary`]: {
      get: {
        tags: ["Audits"],
        summary: "Summarize tenant audit activity",
        description: `${auditReadDescription} Summarizes transaction, approval, rejection, proxy, policy-violation, top-agent, and daily activity counts for 24h, 7d, 30d, or all when explicitly enabled by server configuration.`,
        security: [{ bearerAuth: [] }],
        parameters: [
          parameter("range", "query", {
            type: "string",
            enum: ["24h", "7d", "30d", "all"],
            default: "30d",
          }),
        ],
        responses: {
          "200": jsonResponse(auditSummaryResponseSchema),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/audit/export`]: {
      get: {
        tags: ["Audits"],
        summary: "Export tenant audit log rows as CSV",
        description: `${auditReadDescription} Requires dateFrom and dateTo and rejects ranges over 31 days. The CSV columns are id,timestamp,agentId,action,status,to,value,details.`,
        security: [{ bearerAuth: [] }],
        parameters: auditFilterParameters.map((param) =>
          param.name === "dateFrom" || param.name === "dateTo"
            ? { ...param, required: true }
            : param,
        ),
        responses: {
          "200": {
            description: "CSV audit export",
            content: {
              "text/csv": {
                schema: { type: "string" },
              },
            },
          },
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/audit/events`]: {
      get: {
        tags: ["Audits"],
        summary: "List tenant audit events",
        description:
          "Requires an owner/admin browser session with recent MFA. Supports exact action filters, action-prefix filters for wallet/action history views, exact actor/resource/request filters, date ranges, pagination, and up to five exact metadata filters using dot-path query keys such as `metadata.adapter.kind=swap`.",
        security: [{ bearerAuth: [] }],
        parameters: [
          parameter("action", "query", {
            type: "string",
            pattern: "^[A-Za-z0-9_.:-]{1,128}$",
          }),
          parameter("actionPrefix", "query", {
            type: "string",
            pattern: "^[A-Za-z0-9_.:-]{1,128}$",
          }),
          parameter("actorType", "query"),
          parameter("actorId", "query"),
          parameter("resourceType", "query"),
          parameter("resourceId", "query"),
          parameter("requestId", "query"),
          parameter("metadata.<path>", "query", {
            type: "string",
            minLength: 1,
            maxLength: 256,
            description:
              "Exact metadata filter. Replace <path> with a dot-separated JSON metadata path, for example metadata.adapter.kind=swap. Up to five filters are accepted.",
          }),
          parameter("dateFrom", "query", dateTimeSchema),
          parameter("dateTo", "query", dateTimeSchema),
          parameter("page", "query", { type: "integer", minimum: 1, maximum: 5000 }),
          parameter("limit", "query", { type: "integer", minimum: 1, maximum: 200 }),
        ],
        responses: {
          "200": jsonResponse(auditEventsResponseSchema),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/audit/verify`]: {
      post: {
        tags: ["Audits"],
        summary: "Verify tenant audit chain integrity",
        description: `${auditReadDescription} Walks the tenant audit chain and verifies HMAC continuity over at most 10,000 rows. Partial verification starts at fromSeq and is anchored to the stored predecessor hash; use requireHead=true to require the current chain head.`,
        security: [{ bearerAuth: [] }],
        parameters: [
          parameter("fromSeq", "query", { type: "integer", minimum: 1, default: 1 }),
          parameter("toSeq", "query", { type: "integer", minimum: 1 }),
          parameter("requireHead", "query", { type: "boolean", default: false }),
        ],
        responses: {
          "200": jsonResponse(auditVerifyResponseSchema),
          ...errorResponses(),
        },
      },
    },
  };
}

function intentPaths(prefix = ""): Record<string, unknown> {
  const intentListSchema: JsonSchema = {
    type: "object",
    required: ["intents", "limit", "offset"],
    properties: {
      intents: { type: "array", items: intentSchema },
      limit: { type: "integer" },
      offset: { type: "integer" },
    },
  };
  const intentBodySchema: JsonSchema = {
    type: "object",
    additionalProperties: true,
    properties: {
      intentType: intentTypeSchema,
      intent_type: intentTypeSchema,
      agentId: nullableStringSchema,
      wallet_id: nullableStringSchema,
      resourceType: nullableStringSchema,
      resource_type: nullableStringSchema,
      resourceId: nullableStringSchema,
      resource_id: nullableStringSchema,
      authorizationDetails: { type: "array", items: metadataSchema },
      authorization_details: { type: "array", items: metadataSchema },
      payload: metadataSchema,
      createdByDisplayName: nullableStringSchema,
      created_by_display_name: nullableStringSchema,
      expiresAt: { type: ["string", "null"], format: "date-time" },
      expires_at: { type: ["string", "null"], format: "date-time" },
      ttlSeconds: { type: "integer", minimum: 1 },
      ttl_seconds: { type: "integer", minimum: 1 },
    },
    anyOf: [{ required: ["intentType"] }, { required: ["intent_type"] }],
  };
  const lifecycleBodySchema: JsonSchema = {
    type: "object",
    additionalProperties: true,
    properties: {
      reason: stringSchema,
      executionResult: metadataSchema,
      execution_result: metadataSchema,
    },
  };

  const paths: Record<string, unknown> = {
    [`${prefix}/intents`]: {
      get: {
        tags: ["Intents"],
        summary: "List intents",
        security: [{ tenantApiKey: [] }, { bearerAuth: [] }],
        parameters: [
          parameter("status", "query", intentStatusSchema),
          parameter("intentType", "query", intentTypeSchema),
          parameter("intent_type", "query", intentTypeSchema),
          parameter("type", "query", intentTypeSchema),
          parameter("agentId", "query"),
          parameter("wallet_id", "query"),
          parameter("limit", "query", { type: "integer", minimum: 1, maximum: 200 }),
          parameter("offset", "query", { type: "integer", minimum: 0 }),
        ],
        responses: { "200": jsonResponse(apiResponse(intentListSchema)), ...errorResponses() },
      },
      post: {
        tags: ["Intents"],
        summary: "Create an intent",
        description:
          "Creates a tenant-scoped intent. Privy-style snake_case aliases are accepted for intent_type, wallet_id, resource_type, resource_id, authorization_details, created_by_display_name, expires_at, and ttl_seconds.",
        security: [{ tenantApiKey: [] }, { bearerAuth: [] }],
        requestBody: jsonRequestBody(intentBodySchema),
        responses: {
          "201": jsonResponse(apiResponse(intentSchema)),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/intents/{intentId}`]: {
      parameters: [parameter("intentId", "path")],
      get: {
        tags: ["Intents"],
        summary: "Get an intent",
        security: [{ tenantApiKey: [] }, { bearerAuth: [] }],
        responses: { "200": jsonResponse(apiResponse(intentSchema)), ...errorResponses() },
      },
    },
  };

  for (const action of ["authorize", "approve", "reject", "execute", "fail", "cancel", "expire"]) {
    paths[`${prefix}/intents/{intentId}/${action}`] = {
      parameters: [parameter("intentId", "path")],
      post: {
        tags: ["Intents"],
        summary: `${action[0].toUpperCase()}${action.slice(1)} an intent`,
        description: action === "approve" ? "Alias for /intents/{intentId}/authorize." : undefined,
        security: [{ tenantApiKey: [] }, { bearerAuth: [] }],
        requestBody: jsonRequestBody(lifecycleBodySchema, false),
        responses: { "200": jsonResponse(apiResponse(intentSchema)), ...errorResponses() },
      },
    };
  }

  return paths;
}

function walletBatchPaths(prefix = ""): Record<string, unknown> {
  return {
    [`${prefix}/wallets/batch`]: {
      post: {
        tags: ["Wallets"],
        summary: "Create multiple server wallets",
        description:
          "Privy-style batch wallet alias. `externalId` maps to Steward's immutable per-tenant wallet platform ID.",
        security: [{ tenantApiKey: [] }, { bearerAuth: [] }],
        requestBody: jsonRequestBody(walletBatchRequestSchema),
        responses: {
          "200": jsonResponse(walletBatchResponseSchema),
          ...errorResponses(),
        },
      },
    },
  };
}

function platformTenantManagementPaths(): Record<string, unknown> {
  const tenantPathParameters = [parameter("tenantId", "path")];
  return {
    "/platform/tenants/{tenantId}/members": {
      parameters: tenantPathParameters,
      get: {
        tags: ["Platform Tenants"],
        summary: "List tenant members",
        description:
          "Requires a platform key with platform:tenant-member:read. Returns tenant-scoped membership rows without global user secrets.",
        security: [{ platformKey: [] }],
        parameters: paginationQueryParameters,
        responses: {
          "200": jsonResponse(apiResponse({ type: "array", items: platformTenantMemberSchema })),
          ...errorResponses(),
        },
      },
      post: {
        tags: ["Platform Tenants"],
        summary: "Add a tenant member by email",
        description:
          "Requires a platform key with platform:tenant-member:write. Creates the user if needed, audits the membership add before mutating identity state, and preserves existing memberships idempotently.",
        security: [{ platformKey: [] }],
        requestBody: jsonRequestBody({
          type: "object",
          required: ["email"],
          properties: {
            email: { type: "string", format: "email" },
            role: tenantMemberRoleSchema,
          },
        }),
        responses: {
          "201": jsonResponse(apiResponse(platformTenantMemberSchema)),
          ...errorResponses(),
        },
      },
    },
    "/platform/tenants/{tenantId}/members/{userId}": {
      parameters: [...tenantPathParameters, parameter("userId", "path")],
      patch: {
        tags: ["Platform Tenants"],
        summary: "Update a tenant member role",
        description:
          "Requires platform:tenant-member:write. Role changes revoke the member's tenant refresh tokens, audit the previous role, and fail closed when they would downgrade the sole active owner.",
        security: [{ platformKey: [] }],
        requestBody: jsonRequestBody({
          type: "object",
          required: ["role"],
          properties: { role: tenantMemberRoleSchema },
        }),
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              required: ["userId", "tenantId", "role"],
              properties: {
                userId: stringSchema,
                tenantId: stringSchema,
                role: tenantMemberRoleSchema,
              },
            }),
          ),
          ...errorResponses(),
        },
      },
      delete: {
        tags: ["Platform Tenants"],
        summary: "Remove a tenant member",
        description:
          "Requires platform:tenant-member:write. Removal revokes user tokens and refuses to remove the sole active tenant owner.",
        security: [{ platformKey: [] }],
        responses: { "200": jsonResponse(apiResponse({ type: "object" })), ...errorResponses() },
      },
    },
    "/platform/tenants/{tenantId}/invitations": {
      parameters: tenantPathParameters,
      get: {
        tags: ["Platform Tenants"],
        summary: "List tenant invitations",
        description:
          "Requires platform:tenant-member:read. Invitation tokens and token hashes are never returned by list responses.",
        security: [{ platformKey: [] }],
        parameters: [
          parameter("status", "query", {
            type: "string",
            enum: ["pending", "accepted", "revoked", "expired", "all"],
          }),
          ...paginationQueryParameters,
        ],
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              required: ["invitations"],
              properties: {
                invitations: { type: "array", items: platformTenantInvitationSchema },
              },
            }),
          ),
          ...errorResponses(),
        },
      },
      post: {
        tags: ["Platform Tenants"],
        summary: "Create a tenant invitation",
        description:
          "Requires platform:tenant-member:write. Returns the single-use invitation token exactly once, stores only its hash, sets no-store response headers at runtime, and audits create/rollback behavior around pending invitation replacement.",
        security: [{ platformKey: [] }],
        requestBody: jsonRequestBody({
          type: "object",
          required: ["email"],
          properties: {
            email: { type: "string", format: "email" },
            role: tenantMemberRoleSchema,
            expiresInSeconds: { type: "integer", minimum: 60, maximum: 2592000 },
            invitedByUserId: stringSchema,
            sendEmail: { type: "boolean" },
          },
        }),
        responses: {
          "201": jsonResponse(
            apiResponse({
              type: "object",
              required: ["invitation", "token", "emailSent"],
              properties: {
                invitation: platformTenantInvitationSchema,
                token: stringSchema,
                emailSent: { type: "boolean" },
              },
            }),
          ),
          ...errorResponses(),
        },
      },
    },
    "/platform/tenants/{tenantId}/invitations/{invitationId}": {
      parameters: [...tenantPathParameters, parameter("invitationId", "path")],
      delete: {
        tags: ["Platform Tenants"],
        summary: "Revoke a pending tenant invitation",
        description:
          "Requires platform:tenant-member:write. Revokes only pending invitations in the addressed tenant and rolls the status back if the final audit event fails.",
        security: [{ platformKey: [] }],
        responses: { "200": jsonResponse(apiResponse({ type: "object" })), ...errorResponses() },
      },
    },
  };
}

function authPaths(): Record<string, unknown> {
  const sessionDescription =
    "Sensitive authentication session mutation. Responses that issue or rotate tokens are no-store; refresh tokens are single-use and reuse detection revokes the user's refresh-token family.";
  const mfaManagementDescription =
    "Requires an authenticated user session. MFA factor enrollment and unenrollment require recent step-up where configured, write audit events, and revoke refresh sessions after factor state changes.";
  const mfaChallengeDescription =
    "Consumes a pending MFA challenge atomically, rate-limits invalid attempts, re-checks active tenant membership before session issuance, and returns no-store session tokens only after verification.";

  return {
    "/auth/mfa/totp/enroll": {
      post: {
        tags: ["Auth"],
        summary: "Start TOTP MFA enrollment",
        description:
          "Requires an authenticated user session and recent factor-enrollment step-up. Returns a one-time TOTP secret and otpauth URI for pending enrollment; clients must not persist the secret beyond setup.",
        security: [{ bearerAuth: [] }],
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              required: ["secret", "otpauthUri", "expiresAt"],
              properties: {
                secret: stringSchema,
                otpauthUri: stringSchema,
                expiresAt: dateTimeSchema,
              },
            }),
          ),
          ...errorResponses(),
        },
      },
    },
    "/auth/mfa/totp/verify": {
      post: {
        tags: ["Auth"],
        summary: "Verify TOTP code or complete pending TOTP enrollment",
        description: `${mfaManagementDescription} Pending enrollment verification returns one-time recovery codes and dispatches non-secret MFA/recovery webhooks.`,
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody(mfaCodeBodySchema),
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              properties: {
                enabled: { type: "boolean" },
                verified: { type: "boolean" },
                recoveryCodes: { type: "array", items: stringSchema },
              },
            }),
          ),
          "429": jsonResponse(errorResponse()),
          ...errorResponses(),
        },
      },
    },
    "/auth/mfa/totp/complete": {
      post: {
        tags: ["Auth"],
        summary: "Complete a TOTP MFA login challenge",
        description:
          "Consumes exactly one pending TOTP MFA challenge using either a six-digit TOTP code or a recovery code. " +
          mfaChallengeDescription,
        security: [],
        requestBody: jsonRequestBody(mfaChallengeBodySchema),
        responses: {
          "200": jsonResponse(authTokenResponseSchema),
          "429": jsonResponse(errorResponse()),
          ...errorResponses(),
        },
      },
    },
    "/auth/mfa/totp/step-up": {
      post: {
        tags: ["Auth"],
        summary: "Step up the current session with TOTP or a recovery code",
        description:
          "Requires an authenticated user session and verifies either a six-digit TOTP code or one recovery code before issuing refreshed no-store session tokens with current MFA freshness claims.",
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody({
          type: "object",
          properties: {
            code: { type: "string", pattern: "^\\d{6}$" },
            recoveryCode: stringSchema,
          },
          oneOf: [{ required: ["code"] }, { required: ["recoveryCode"] }],
        }),
        responses: {
          "200": jsonResponse(authTokenResponseSchema),
          "429": jsonResponse(errorResponse()),
          ...errorResponses(),
        },
      },
    },
    "/auth/mfa/recovery-codes/regenerate": {
      post: {
        tags: ["Auth"],
        summary: "Regenerate MFA recovery codes",
        description:
          "Requires an authenticated user session plus a valid current TOTP code. Returns replacement recovery codes exactly once, writes audit events, and dispatches a non-secret recovery-setup webhook.",
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody(mfaCodeBodySchema),
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              required: ["recoveryCodes"],
              properties: { recoveryCodes: { type: "array", items: stringSchema } },
            }),
          ),
          "429": jsonResponse(errorResponse()),
          ...errorResponses(),
        },
      },
    },
    "/auth/mfa/sms/enroll": {
      post: {
        tags: ["Auth"],
        summary: "Start SMS MFA enrollment",
        description: `${mfaManagementDescription} Sends an OTP to an E.164 phone number and stores only pending masked-phone state.`,
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody({
          type: "object",
          required: ["phone"],
          properties: { phone: { type: "string", pattern: "^\\+[1-9]\\d{1,14}$" } },
        }),
        responses: {
          "200": jsonResponse(maskedMfaPhoneResponseSchema),
          "429": jsonResponse(errorResponse()),
          "503": jsonResponse(errorResponse()),
          ...errorResponses(),
        },
      },
    },
    "/auth/mfa/sms/verify": {
      post: {
        tags: ["Auth"],
        summary: "Verify pending SMS MFA enrollment",
        description: `${mfaManagementDescription} Enforces bounded failed-attempt counters, stores only the phone needed for MFA, and returns a masked phone value.`,
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody(mfaCodeBodySchema),
        responses: {
          "200": jsonResponse(maskedMfaPhoneResponseSchema),
          "429": jsonResponse(errorResponse()),
          ...errorResponses(),
        },
      },
    },
    "/auth/mfa/sms/send": {
      post: {
        tags: ["Auth"],
        summary: "Send an SMS MFA management OTP",
        description:
          "Requires an authenticated user session with SMS MFA already enabled. Sends a bounded management OTP and returns only the masked phone and expiry.",
        security: [{ bearerAuth: [] }],
        responses: {
          "200": jsonResponse(maskedMfaPhoneResponseSchema),
          "429": jsonResponse(errorResponse()),
          "503": jsonResponse(errorResponse()),
          ...errorResponses(),
        },
      },
    },
    "/auth/mfa/sms/complete": {
      post: {
        tags: ["Auth"],
        summary: "Complete an SMS MFA login challenge",
        description: mfaChallengeDescription,
        security: [],
        requestBody: jsonRequestBody({
          type: "object",
          required: ["challengeId", "code"],
          properties: {
            challengeId: stringSchema,
            code: { type: "string", pattern: "^\\d{6}$" },
          },
        }),
        responses: {
          "200": jsonResponse(authTokenResponseSchema),
          "429": jsonResponse(errorResponse()),
          ...errorResponses(),
        },
      },
    },
    "/auth/mfa/sms/step-up": {
      post: {
        tags: ["Auth"],
        summary: "Step up the current session with SMS MFA",
        description:
          "Requires an authenticated user session plus an SMS management OTP from /auth/mfa/sms/send before issuing refreshed no-store session tokens with current MFA freshness claims.",
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody(mfaCodeBodySchema),
        responses: {
          "200": jsonResponse(authTokenResponseSchema),
          "429": jsonResponse(errorResponse()),
          ...errorResponses(),
        },
      },
    },
    "/auth/mfa/sms/unenroll": {
      post: {
        tags: ["Auth"],
        summary: "Unenroll SMS MFA",
        description:
          "Requires an authenticated user session plus valid SMS management OTP. Writes audit events, dispatches mfa.disabled, and revokes refresh sessions after factor removal.",
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody(mfaCodeBodySchema),
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              properties: { enabled: { type: "boolean", const: false } },
            }),
          ),
          "429": jsonResponse(errorResponse()),
          ...errorResponses(),
        },
      },
    },
    "/auth/mfa/passkey/options": {
      post: {
        tags: ["Auth"],
        summary: "Create passkey MFA authentication options",
        description:
          "Requires an authenticated user session, tenant passkey login-method allowlist, and a registered passkey. The returned challenge is stored server-side for one-time verification.",
        security: [{ bearerAuth: [] }],
        responses: {
          "200": jsonResponse({
            type: "object",
            properties: {
              challengeId: stringSchema,
              challenge: stringSchema,
            },
            additionalProperties: true,
          }),
          "429": jsonResponse(errorResponse()),
          ...errorResponses(),
        },
      },
    },
    "/auth/mfa/passkey/complete": {
      post: {
        tags: ["Auth"],
        summary: "Complete a passkey MFA step-up",
        description:
          "Requires an authenticated user session and consumes a one-time WebAuthn challenge before issuing fresh no-store session tokens with recent-MFA claims.",
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody({
          type: "object",
          required: ["challengeId", "response"],
          properties: {
            challengeId: stringSchema,
            response: { type: "object", required: ["id"], additionalProperties: true },
          },
        }),
        responses: {
          "200": jsonResponse(authTokenResponseSchema),
          "429": jsonResponse(errorResponse()),
          ...errorResponses(),
        },
      },
    },
    "/auth/mfa/passkey/verify": {
      post: {
        tags: ["Auth"],
        summary: "Verify a passkey MFA step-up",
        description: "Alias for /auth/mfa/passkey/complete with the same one-time challenge rules.",
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody({
          type: "object",
          required: ["challengeId", "response"],
          properties: {
            challengeId: stringSchema,
            response: { type: "object", required: ["id"], additionalProperties: true },
          },
        }),
        responses: {
          "200": jsonResponse(authTokenResponseSchema),
          "429": jsonResponse(errorResponse()),
          ...errorResponses(),
        },
      },
    },
    "/auth/logout": {
      post: {
        tags: ["Auth"],
        summary: "Log out and optionally revoke a refresh token",
        description:
          "Idempotently revokes the presented access token JTI and optional refresh token, writes logout audit events when token context is available, and never returns session secrets.",
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody(
          {
            type: "object",
            properties: { refreshToken: stringSchema },
          },
          false,
        ),
        responses: {
          "200": jsonResponse(apiResponse({ type: "object", additionalProperties: false })),
          ...errorResponses(),
        },
      },
    },
    "/auth/refresh": {
      post: {
        tags: ["Auth"],
        summary: "Rotate a refresh token",
        description: sessionDescription,
        security: [],
        requestBody: jsonRequestBody({
          type: "object",
          required: ["refreshToken"],
          properties: { refreshToken: stringSchema },
        }),
        responses: {
          "200": jsonResponse(authTokenResponseSchema),
          "429": jsonResponse(errorResponse()),
          ...errorResponses(),
        },
      },
    },
    "/auth/revoke": {
      post: {
        tags: ["Auth"],
        summary: "Revoke a refresh token",
        description:
          "Revokes a single refresh token by hash, writes audit events when the token exists, and remains idempotent for already-absent tokens.",
        security: [],
        requestBody: jsonRequestBody({
          type: "object",
          required: ["refreshToken"],
          properties: { refreshToken: stringSchema },
        }),
        responses: {
          "200": jsonResponse(apiResponse({ type: "object", additionalProperties: false })),
          ...errorResponses(),
        },
      },
    },
  };
}

function accountPaths(prefix = ""): Record<string, unknown> {
  return {
    [`${prefix}/accounts`]: {
      get: {
        tags: ["Digital Asset Accounts"],
        summary: "List digital asset accounts",
        security: [{ tenantApiKey: [] }],
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              properties: { accounts: { type: "array", items: digitalAssetAccountSchema } },
            }),
          ),
          ...errorResponses(),
        },
      },
      post: {
        tags: ["Digital Asset Accounts"],
        summary: "Create a digital asset account",
        security: [{ tenantApiKey: [] }],
        requestBody: jsonRequestBody(digitalAssetAccountMutationSchema),
        responses: {
          "201": jsonResponse(apiResponse(digitalAssetAccountSchema)),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/accounts/{accountId}`]: {
      parameters: [parameter("accountId", "path")],
      get: {
        tags: ["Digital Asset Accounts"],
        summary: "Get a digital asset account",
        security: [{ tenantApiKey: [] }],
        responses: {
          "200": jsonResponse(apiResponse(digitalAssetAccountSchema)),
          ...errorResponses(),
        },
      },
      patch: {
        tags: ["Digital Asset Accounts"],
        summary: "Update a digital asset account",
        security: [{ tenantApiKey: [] }],
        requestBody: jsonRequestBody(digitalAssetAccountMutationSchema),
        responses: {
          "200": jsonResponse(apiResponse(digitalAssetAccountSchema)),
          ...errorResponses(),
        },
      },
      delete: {
        tags: ["Digital Asset Accounts"],
        summary: "Delete a digital asset account",
        security: [{ tenantApiKey: [] }],
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              properties: { id: stringSchema, deleted: { type: "boolean" } },
            }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/accounts/{accountId}/balance`]: {
      parameters: [
        parameter("accountId", "path"),
        parameter("chainId", "query", { type: "integer", minimum: 1 }),
        parameter("tokens", "query"),
      ],
      get: {
        tags: ["Digital Asset Accounts"],
        summary: "Get grouped wallet membership and native/token balance rollups for an account",
        security: [{ tenantApiKey: [] }],
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              properties: {
                id: stringSchema,
                accountId: stringSchema,
                account_id: stringSchema,
                wallets: { type: "array", items: digitalAssetAccountWalletSchema },
                capabilities: digitalAssetAccountCapabilitiesSchema,
                capabilityMetadata: { type: "object", additionalProperties: true },
                capability_metadata: { type: "object", additionalProperties: true },
                balances: { type: "array", items: digitalAssetAccountBalanceRowSchema },
                tokenBalances: {
                  type: "array",
                  items: digitalAssetAccountTokenBalanceRowSchema,
                },
                rollups: {
                  type: "object",
                  properties: {
                    native: {
                      type: "array",
                      items: {
                        type: "object",
                        properties: {
                          chainId: { type: "integer" },
                          symbol: stringSchema,
                          native: stringSchema,
                        },
                      },
                    },
                    tokens: {
                      type: "array",
                      items: {
                        type: "object",
                        properties: {
                          chainId: { type: "integer" },
                          token: stringSchema,
                          symbol: stringSchema,
                          balance: stringSchema,
                          decimals: { type: "integer", minimum: 0 },
                        },
                      },
                    },
                  },
                },
              },
            }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/accounts/{accountId}/aggregations`]: {
      parameters: [parameter("accountId", "path")],
      get: {
        tags: ["Digital Asset Accounts"],
        summary: "List account aggregation snapshots",
        security: [{ tenantApiKey: [] }],
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              properties: {
                aggregations: { type: "array", items: digitalAssetAccountAggregationSchema },
              },
            }),
          ),
          ...errorResponses(),
        },
      },
      post: {
        tags: ["Digital Asset Accounts"],
        summary: "Create an account aggregation snapshot",
        security: [{ tenantApiKey: [] }],
        requestBody: jsonRequestBody({
          type: "object",
          properties: {
            id: stringSchema,
            display_name: nullableStringSchema,
            displayName: nullableStringSchema,
            metadata: metadataSchema,
          },
        }),
        responses: {
          "201": jsonResponse(apiResponse(digitalAssetAccountAggregationSchema)),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/accounts/{accountId}/aggregations/{aggregationId}`]: {
      parameters: [parameter("accountId", "path"), parameter("aggregationId", "path")],
      get: {
        tags: ["Digital Asset Accounts"],
        summary: "Get an account aggregation snapshot",
        security: [{ tenantApiKey: [] }],
        responses: {
          "200": jsonResponse(apiResponse(digitalAssetAccountAggregationSchema)),
          ...errorResponses(),
        },
      },
      delete: {
        tags: ["Digital Asset Accounts"],
        summary: "Delete an account aggregation snapshot",
        security: [{ tenantApiKey: [] }],
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              properties: { id: stringSchema, deleted: { type: "boolean" } },
            }),
          ),
          ...errorResponses(),
        },
      },
    },
  };
}

function agentAuthorizationPaths(prefix = ""): Record<string, unknown> {
  return {
    [`${prefix}/agents/{agentId}/signers`]: {
      parameters: [parameter("agentId", "path")],
      get: {
        tags: ["Agent Authorization"],
        summary: "List agent signers and authorization keys",
        description:
          "Owner/admin session endpoint for signer inventory. P-256 signers are Privy-style asymmetric authorization keys; HMAC signers use server-issued delegated credentials.",
        security: [{ bearerAuth: [] }],
        parameters: [
          parameter("status", "query", { type: "string", enum: ["active", "paused", "revoked"] }),
        ],
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              properties: { signers: { type: "array", items: agentSignerSchema } },
            }),
          ),
          ...errorResponses(),
        },
      },
      post: {
        tags: ["Agent Authorization"],
        summary: "Create an agent signer or authorization key",
        description:
          'Requires owner/admin session with recent MFA. Use `keyType: "p256"` plus `publicKey` to register an asymmetric authorization key; use `issueCredential: true` for a one-time HMAC delegated signer secret.',
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody(agentSignerMutationSchema),
        responses: {
          "201": jsonResponse(
            apiResponse({
              anyOf: [
                agentSignerSchema,
                {
                  allOf: [
                    agentSignerSchema,
                    {
                      type: "object",
                      properties: { credentialSecret: stringSchema },
                    },
                  ],
                },
              ],
            }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/agents/{agentId}/signers/{signerId}`]: {
      parameters: [parameter("agentId", "path"), parameter("signerId", "path")],
      patch: {
        tags: ["Agent Authorization"],
        summary: "Update an agent signer or authorization key",
        description:
          "Authority-changing updates such as key type, public key, permissions, metadata, address, chain family, signer type, or status require recent MFA.",
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody(agentSignerMutationSchema),
        responses: { "200": jsonResponse(apiResponse(agentSignerSchema)), ...errorResponses() },
      },
      delete: {
        tags: ["Agent Authorization"],
        summary: "Revoke an agent signer or authorization key",
        security: [{ bearerAuth: [] }],
        responses: { "200": jsonResponse(apiResponse(agentSignerSchema)), ...errorResponses() },
      },
    },
    [`${prefix}/agents/{agentId}/key-quorums`]: {
      parameters: [parameter("agentId", "path")],
      get: {
        tags: ["Agent Authorization"],
        summary: "List agent key quorums",
        security: [{ bearerAuth: [] }],
        parameters: [
          parameter("status", "query", { type: "string", enum: ["active", "paused", "revoked"] }),
        ],
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              properties: { quorums: { type: "array", items: agentKeyQuorumSchema } },
            }),
          ),
          ...errorResponses(),
        },
      },
      post: {
        tags: ["Agent Authorization"],
        summary: "Create an agent key quorum",
        description:
          "Requires owner/admin session with recent MFA. Quorums can include signer members and child quorum members through `memberSignerIds` and `memberQuorumIds`.",
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody(agentKeyQuorumMutationSchema),
        responses: {
          "201": jsonResponse(apiResponse(agentKeyQuorumSchema)),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/agents/{agentId}/key-quorums/{quorumId}`]: {
      parameters: [parameter("agentId", "path"), parameter("quorumId", "path")],
      patch: {
        tags: ["Agent Authorization"],
        summary: "Update an agent key quorum",
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody(agentKeyQuorumMutationSchema),
        responses: { "200": jsonResponse(apiResponse(agentKeyQuorumSchema)), ...errorResponses() },
      },
      delete: {
        tags: ["Agent Authorization"],
        summary: "Revoke an agent key quorum",
        security: [{ bearerAuth: [] }],
        responses: { "200": jsonResponse(apiResponse(agentKeyQuorumSchema)), ...errorResponses() },
      },
    },
  };
}

function userWalletSignerPaths(prefix = ""): Record<string, unknown> {
  return {
    [`${prefix}/user/me/wallet/import/init`]: {
      post: {
        tags: ["Wallets"],
        summary: "Initialize encrypted authenticated user-wallet key import",
        description:
          "Requires a personal authenticated user session with recent MFA plus audited user-wallet import feature flags. Returns a short-lived X25519 public key and tenant/app/user/wallet AAD for a one-time encrypted private-key import session. Responses are no-store and do not contain private-key material.",
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody(encryptedUserWalletKeyImportInitRequestSchema),
        responses: {
          "200": jsonResponse(apiResponse(encryptedUserWalletKeyImportInitResponseSchema)),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/user/me/wallet/import/submit`]: {
      post: {
        tags: ["Wallets"],
        summary: "Submit encrypted authenticated user-wallet key import",
        description:
          "Consumes a one-time user-wallet import session bound to the authenticated user, personal tenant, walletIndex, and app client when present. Plaintext `privateKey` fields are rejected; audit and webhook metadata record only chain/session/address metadata.",
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody(encryptedUserWalletKeyImportSubmitRequestSchema),
        responses: {
          "200": jsonResponse(apiResponse(encryptedUserWalletKeyImportResultSchema)),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/user/me/wallet/signers`]: {
      get: {
        tags: ["Wallets"],
        summary: "List authenticated user wallet signers",
        description:
          "Requires a personal authenticated user session with recent MFA. Supports walletIndex/wallet_index selectors for indexed embedded wallets. Credential secrets are never returned by list responses.",
        security: [{ bearerAuth: [] }],
        parameters: [
          parameter("walletIndex", "query", { type: "integer", minimum: 0, maximum: 255 }),
          parameter("wallet_index", "query", { type: "integer", minimum: 0, maximum: 255 }),
          parameter("status", "query", { type: "string", enum: ["active", "paused", "revoked"] }),
        ],
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              properties: { signers: { type: "array", items: agentSignerSchema } },
            }),
          ),
          ...errorResponses(),
        },
      },
      post: {
        tags: ["Wallets"],
        summary: "Create an authenticated user wallet signer credential",
        description:
          "Requires a personal authenticated user session with recent MFA. Creates a bounded HMAC signer credential for signing-only permissions on the selected embedded wallet. The one-time credentialSecret is returned only in this create response.",
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody(userWalletSignerCreateSchema),
        responses: {
          "201": jsonResponse(
            apiResponse({
              allOf: [
                agentSignerSchema,
                {
                  type: "object",
                  properties: { credentialSecret: stringSchema },
                },
              ],
            }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/user/me/wallet/signers/{signerId}`]: {
      parameters: [parameter("signerId", "path")],
      delete: {
        tags: ["Wallets"],
        summary: "Revoke an authenticated user wallet signer",
        description:
          "Requires a personal authenticated user session with recent MFA and a matching walletIndex/wallet_index selector when revoking a signer on an indexed embedded wallet.",
        security: [{ bearerAuth: [] }],
        parameters: [
          parameter("walletIndex", "query", { type: "integer", minimum: 0, maximum: 255 }),
          parameter("wallet_index", "query", { type: "integer", minimum: 0, maximum: 255 }),
        ],
        responses: { "200": jsonResponse(apiResponse(agentSignerSchema)), ...errorResponses() },
      },
    },
  };
}

function conditionSetPaths(prefix = ""): Record<string, unknown> {
  return {
    [`${prefix}/condition-sets`]: {
      get: {
        tags: ["Condition Sets"],
        summary: "List condition sets",
        security: [{ bearerAuth: [] }],
        parameters: paginationQueryParameters,
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              required: ["conditionSets", "limit", "offset"],
              properties: {
                conditionSets: { type: "array", items: conditionSetSchema },
                limit: { type: "integer" },
                offset: { type: "integer" },
              },
            }),
          ),
          ...errorResponses(),
        },
      },
      post: {
        tags: ["Condition Sets"],
        summary: "Create a condition set",
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody(conditionSetCreateSchema),
        responses: {
          "201": jsonResponse(apiResponse(conditionSetSchema)),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/condition-sets/{conditionSetId}`]: {
      parameters: [parameter("conditionSetId", "path")],
      get: {
        tags: ["Condition Sets"],
        summary: "Get a condition set",
        security: [{ bearerAuth: [] }],
        responses: {
          "200": jsonResponse(apiResponse(conditionSetSchema)),
          ...errorResponses(),
        },
      },
      patch: {
        tags: ["Condition Sets"],
        summary: "Update a condition set",
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody(conditionSetMutationSchema),
        responses: {
          "200": jsonResponse(apiResponse(conditionSetSchema)),
          ...errorResponses(),
        },
      },
      delete: {
        tags: ["Condition Sets"],
        summary: "Delete a condition set",
        security: [{ bearerAuth: [] }],
        responses: {
          "200": jsonResponse(apiResponse({ type: "object", properties: {} })),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/condition-sets/{conditionSetId}/items`]: {
      parameters: [parameter("conditionSetId", "path")],
      get: {
        tags: ["Condition Sets"],
        summary: "List condition set items",
        security: [{ bearerAuth: [] }],
        parameters: paginationQueryParameters,
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              required: ["items", "limit", "offset"],
              properties: {
                items: { type: "array", items: conditionSetItemSchema },
                limit: { type: "integer" },
                offset: { type: "integer" },
              },
            }),
          ),
          ...errorResponses(),
        },
      },
      post: {
        tags: ["Condition Sets"],
        summary: "Create or upsert a condition set item",
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody(conditionSetItemCreateSchema),
        responses: {
          "201": jsonResponse(apiResponse(conditionSetItemSchema)),
          ...errorResponses(),
        },
      },
      put: {
        tags: ["Condition Sets"],
        summary: "Replace condition set items",
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody({
          type: "object",
          required: ["items"],
          properties: {
            items: { type: "array", items: conditionSetItemCreateSchema },
          },
        }),
        responses: {
          "200": jsonResponse(apiResponse({ type: "array", items: conditionSetItemSchema })),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/condition-sets/{conditionSetId}/items/{itemId}`]: {
      parameters: [parameter("conditionSetId", "path"), parameter("itemId", "path")],
      get: {
        tags: ["Condition Sets"],
        summary: "Get a condition set item",
        security: [{ bearerAuth: [] }],
        responses: {
          "200": jsonResponse(apiResponse(conditionSetItemSchema)),
          ...errorResponses(),
        },
      },
      patch: {
        tags: ["Condition Sets"],
        summary: "Update a condition set item",
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody(conditionSetItemMutationSchema),
        responses: {
          "200": jsonResponse(apiResponse(conditionSetItemSchema)),
          ...errorResponses(),
        },
      },
      delete: {
        tags: ["Condition Sets"],
        summary: "Delete a condition set item",
        security: [{ bearerAuth: [] }],
        responses: {
          "200": jsonResponse(apiResponse({ type: "object", properties: {} })),
          ...errorResponses(),
        },
      },
    },
  };
}

function policyPaths(prefix = ""): Record<string, unknown> {
  return {
    [`${prefix}/policies`]: {
      get: {
        tags: ["Policy Templates"],
        summary: "List policy templates",
        security: [{ bearerAuth: [] }],
        parameters: [
          parameter("limit", "query", { type: "integer", minimum: 1, maximum: 100 }),
          parameter("offset", "query", { type: "integer", minimum: 0, maximum: 10000 }),
        ],
        responses: {
          "200": jsonResponse(apiResponse({ type: "array", items: policyTemplateSchema })),
          ...errorResponses(),
        },
      },
      post: {
        tags: ["Policy Templates"],
        summary: "Create a policy template",
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody(policyTemplateCreateSchema),
        responses: {
          "201": jsonResponse(apiResponse(policyTemplateSchema)),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/policies/simulate`]: {
      post: {
        tags: ["Policy Templates"],
        summary: "Simulate policy evaluation",
        security: [{ bearerAuth: [] }, { tenantApiKey: [] }],
        requestBody: jsonRequestBody(policySimulateBodySchema),
        responses: {
          "200": jsonResponse(apiResponse(policySimulateResultSchema)),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/policies/{templateId}`]: {
      parameters: [parameter("templateId", "path")],
      get: {
        tags: ["Policy Templates"],
        summary: "Get a policy template",
        security: [{ bearerAuth: [] }],
        responses: {
          "200": jsonResponse(apiResponse(policyTemplateSchema)),
          ...errorResponses(),
        },
      },
      put: {
        tags: ["Policy Templates"],
        summary: "Update a policy template",
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody(policyTemplateMutationSchema),
        responses: {
          "200": jsonResponse(apiResponse(policyTemplateSchema)),
          ...errorResponses(),
        },
      },
      delete: {
        tags: ["Policy Templates"],
        summary: "Delete a policy template",
        security: [{ bearerAuth: [] }],
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              properties: { deleted: { type: "boolean" } },
            }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/policies/{templateId}/assign`]: {
      parameters: [parameter("templateId", "path")],
      post: {
        tags: ["Policy Templates"],
        summary: "Assign a policy template to agents",
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody({
          type: "object",
          required: ["agentIds"],
          properties: { agentIds: { type: "array", items: stringSchema, minItems: 1 } },
        }),
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              required: ["templateId", "assignedAgents", "rulesApplied"],
              properties: {
                templateId: stringSchema,
                assignedAgents: { type: "array", items: stringSchema },
                rulesApplied: { type: "integer", minimum: 0 },
              },
            }),
          ),
          ...errorResponses(),
        },
      },
    },
  };
}

function userLookupResponse(): JsonSchema {
  return apiResponse({
    type: "object",
    properties: { user: { anyOf: [platformUserIdentitySchema, { type: "null" }] } },
  });
}

function adapterPaths(prefix = ""): Record<string, unknown> {
  const adapterTokenSchema = {
    type: "object",
    required: ["address"],
    properties: {
      address: stringSchema,
      symbol: stringSchema,
      decimals: { type: "integer", minimum: 0, maximum: 36 },
    },
  };
  const adapterUnsignedIntentSchema = {
    type: "object",
    required: ["signed", "kind", "chainId", "to", "value", "owner", "category", "provider"],
    properties: {
      signed: { type: "boolean", const: false },
      kind: { type: "string", enum: ["evm-tx", "evm-typed-data", "abstract-intent"] },
      chainId: { type: "integer" },
      to: stringSchema,
      value: stringSchema,
      data: stringSchema,
      owner: stringSchema,
      category: stringSchema,
      provider: stringSchema,
      metadata: metadataSchema,
    },
  };
  const swapQuoteInputSchema = {
    type: "object",
    required: ["fromToken", "toToken", "amount", "chainId"],
    properties: {
      agentId: stringSchema,
      fromToken: adapterTokenSchema,
      toToken: adapterTokenSchema,
      amount: stringSchema,
      chainId: { type: "integer", minimum: 1 },
      slippageBps: { type: "integer", minimum: 0, maximum: 10000 },
      estimatedUsd: { type: "number", minimum: 0 },
    },
  };
  const swapQuoteSchema = {
    type: "object",
    required: ["provider", "quoteId", "fromToken", "toToken", "amountIn", "amountOut", "chainId"],
    properties: {
      provider: stringSchema,
      quoteId: stringSchema,
      fromToken: adapterTokenSchema,
      toToken: adapterTokenSchema,
      amountIn: stringSchema,
      amountOut: stringSchema,
      minAmountOut: stringSchema,
      feeAmount: stringSchema,
      chainId: { type: "integer" },
      slippageBps: { type: "integer" },
      expiresAt: { type: "integer" },
      route: { type: "array", items: metadataSchema },
    },
  };
  const earnVaultSchema = {
    type: "object",
    required: ["id"],
    properties: {
      id: stringSchema,
      provider: stringSchema,
      chainId: { type: "integer" },
      asset: adapterTokenSchema,
      shareToken: adapterTokenSchema,
      apy: { type: "number" },
      metadata: metadataSchema,
    },
  };
  const earnPositionSchema = {
    type: "object",
    required: ["vault", "owner", "assets", "shares"],
    properties: {
      vault: stringSchema,
      owner: stringSchema,
      assets: stringSchema,
      shares: stringSchema,
      metadata: metadataSchema,
    },
  };
  const bridgeQuoteInputSchema = {
    type: "object",
    required: ["fromChainId", "toChainId", "fromToken", "toToken", "amount", "recipient"],
    properties: {
      agentId: stringSchema,
      fromChainId: { type: "integer", minimum: 1 },
      toChainId: { type: "integer", minimum: 1 },
      fromToken: adapterTokenSchema,
      toToken: adapterTokenSchema,
      amount: stringSchema,
      recipient: stringSchema,
      slippageBps: { type: "integer", minimum: 0, maximum: 10000 },
      estimatedUsd: { type: "number", minimum: 0 },
    },
  };
  const bridgeQuoteSchema = {
    type: "object",
    required: ["provider", "quoteId", "fromChainId", "toChainId", "amountIn", "amountOut"],
    properties: {
      provider: stringSchema,
      quoteId: stringSchema,
      fromChainId: { type: "integer" },
      toChainId: { type: "integer" },
      fromToken: adapterTokenSchema,
      toToken: adapterTokenSchema,
      amountIn: stringSchema,
      amountOut: stringSchema,
      minAmountOut: stringSchema,
      feeAmount: stringSchema,
      recipient: stringSchema,
      route: { type: "array", items: metadataSchema },
      slippageBps: { type: "integer" },
      expiresAt: { type: "integer" },
    },
  };
  const bridgeSessionSchema = {
    type: "object",
    required: ["id", "provider", "quoteId", "status"],
    properties: {
      id: stringSchema,
      provider: stringSchema,
      quoteId: stringSchema,
      status: stringSchema,
      fromChainId: { type: "integer" },
      toChainId: { type: "integer" },
      recipient: stringSchema,
      createdAt: { type: "integer" },
    },
  };
  const sparkWalletSchema = {
    type: "object",
    required: [
      "id",
      "provider",
      "userId",
      "network",
      "status",
      "sparkAddress",
      "identityPublicKey",
      "createdAt",
    ],
    properties: {
      id: stringSchema,
      provider: stringSchema,
      userId: stringSchema,
      network: { type: "string", enum: ["mainnet", "testnet", "signet"] },
      status: { type: "string", enum: ["created", "active", "disabled"] },
      sparkAddress: stringSchema,
      identityPublicKey: stringSchema,
      createdAt: { type: "integer" },
    },
  };
  const sparkBalanceSchema = {
    type: "object",
    required: ["walletId", "provider", "network", "btcSats", "lightningSats", "updatedAt"],
    properties: {
      walletId: stringSchema,
      provider: stringSchema,
      network: { type: "string", enum: ["mainnet", "testnet", "signet"] },
      btcSats: stringSchema,
      lightningSats: stringSchema,
      sparkTokenBalances: {
        type: "array",
        items: {
          type: "object",
          required: ["tokenId", "amount"],
          properties: { tokenId: stringSchema, amount: stringSchema },
        },
      },
      updatedAt: { type: "integer" },
    },
  };
  const sparkStaticBtcDepositQuoteSchema = {
    type: "object",
    required: [
      "id",
      "provider",
      "walletId",
      "network",
      "depositAddress",
      "status",
      "expiresAt",
      "createdAt",
    ],
    properties: {
      id: stringSchema,
      provider: stringSchema,
      walletId: stringSchema,
      network: { type: "string", enum: ["mainnet", "testnet", "signet"] },
      depositAddress: stringSchema,
      amountSats: stringSchema,
      status: { type: "string", enum: ["created", "funded", "claimed", "expired"] },
      expiresAt: { type: "integer" },
      createdAt: { type: "integer" },
    },
  };
  const sparkLightningInvoiceSchema = {
    type: "object",
    required: [
      "id",
      "provider",
      "walletId",
      "amountSats",
      "paymentRequest",
      "status",
      "createdAt",
      "expiresAt",
    ],
    properties: {
      id: stringSchema,
      provider: stringSchema,
      walletId: stringSchema,
      amountSats: stringSchema,
      memo: stringSchema,
      paymentRequest: stringSchema,
      status: { type: "string", enum: ["created", "paid", "expired", "canceled"] },
      createdAt: { type: "integer" },
      expiresAt: { type: "integer" },
    },
  };
  const exchangeSessionSchema = {
    type: "object",
    required: ["id", "provider", "userId", "tenantId", "status", "url"],
    properties: {
      id: stringSchema,
      provider: stringSchema,
      userId: stringSchema,
      tenantId: stringSchema,
      status: stringSchema,
      url: stringSchema,
      scopes: { type: "array", items: stringSchema },
      createdAt: { type: "integer" },
      expiresAt: { type: "integer" },
    },
  };
  const exchangeAccountSchema = {
    type: "object",
    required: ["id", "provider", "userId", "status"],
    properties: {
      id: stringSchema,
      provider: stringSchema,
      userId: stringSchema,
      externalAccountId: stringSchema,
      status: stringSchema,
      createdAt: { type: "integer" },
    },
  };
  const adapterDiscoverySchema = {
    type: "object",
    required: ["adapters"],
    properties: {
      adapters: {
        type: "object",
        description:
          "Provider-neutral adapter registry for swap, earn, bridge, Spark BTC/Lightning, exchange, fiat, KYC/TOS, and custodial seams. Production provider availability depends on tenant configuration.",
        additionalProperties: true,
      },
    },
  };
  return {
    [`${prefix}/adapters`]: {
      get: {
        tags: ["Adapters"],
        summary: "Discover configured financial-service adapters",
        description:
          "Returns the tenant-visible adapter registry. Adapter routes are tenant-authenticated, no-store, and fund-moving build endpoints return unsigned intents gated by policy/spend checks before anything signable is exposed.",
        security: [{ tenantApiKey: [] }, { bearerAuth: [] }],
        responses: {
          "200": jsonResponse(apiResponse(adapterDiscoverySchema)),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/adapters/swap/quote`]: {
      post: {
        tags: ["Adapters"],
        summary: "Quote a swap through the configured adapter",
        security: [{ tenantApiKey: [] }, { bearerAuth: [] }],
        requestBody: jsonRequestBody(swapQuoteInputSchema),
        responses: {
          "200": jsonResponse(
            apiResponse({ type: "object", properties: { quote: swapQuoteSchema } }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/adapters/swap/build`]: {
      post: {
        tags: ["Adapters"],
        summary: "Build an unsigned swap intent after policy/spend checks",
        description:
          "Returns an unsigned intent only. The caller must still route the artifact through the vault signing path before funds move.",
        security: [{ tenantApiKey: [] }, { bearerAuth: [] }],
        requestBody: jsonRequestBody({
          type: "object",
          required: ["quote"],
          properties: {
            agentId: stringSchema,
            quote: swapQuoteSchema,
            estimatedUsd: { type: "number", minimum: 0 },
          },
        }),
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              properties: { unsignedIntent: adapterUnsignedIntentSchema },
            }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/adapters/earn/vaults`]: {
      get: {
        tags: ["Adapters"],
        summary: "List earn vaults",
        security: [{ tenantApiKey: [] }, { bearerAuth: [] }],
        parameters: [parameter("chainId", "query", { type: "integer", minimum: 1 })],
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              properties: { vaults: { type: "array", items: earnVaultSchema } },
            }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/adapters/earn/vaults/{vault}/position`]: {
      parameters: [parameter("vault", "path"), parameter("owner", "query")],
      get: {
        tags: ["Adapters"],
        summary: "Get an earn vault position",
        security: [{ tenantApiKey: [] }, { bearerAuth: [] }],
        responses: {
          "200": jsonResponse(
            apiResponse({ type: "object", properties: { position: earnPositionSchema } }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/adapters/earn/deposit`]: {
      post: {
        tags: ["Adapters"],
        summary: "Build an unsigned earn deposit intent after policy/spend checks",
        security: [{ tenantApiKey: [] }, { bearerAuth: [] }],
        requestBody: jsonRequestBody({
          type: "object",
          required: ["vault", "assets"],
          properties: {
            agentId: stringSchema,
            vault: stringSchema,
            assets: stringSchema,
            estimatedUsd: { type: "number", minimum: 0 },
          },
        }),
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              properties: { unsignedIntent: adapterUnsignedIntentSchema },
            }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/adapters/earn/withdraw`]: {
      post: {
        tags: ["Adapters"],
        summary: "Build an unsigned earn withdraw intent after policy/spend checks",
        security: [{ tenantApiKey: [] }, { bearerAuth: [] }],
        requestBody: jsonRequestBody({
          type: "object",
          required: ["vault", "shares"],
          properties: {
            agentId: stringSchema,
            vault: stringSchema,
            shares: stringSchema,
            estimatedUsd: { type: "number", minimum: 0 },
          },
        }),
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              properties: { unsignedIntent: adapterUnsignedIntentSchema },
            }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/adapters/bridge/quote`]: {
      post: {
        tags: ["Adapters"],
        summary: "Quote a bridge transfer",
        security: [{ tenantApiKey: [] }, { bearerAuth: [] }],
        requestBody: jsonRequestBody(bridgeQuoteInputSchema),
        responses: {
          "200": jsonResponse(
            apiResponse({ type: "object", properties: { quote: bridgeQuoteSchema } }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/adapters/bridge/build`]: {
      post: {
        tags: ["Adapters"],
        summary: "Build an unsigned bridge intent after policy/spend checks",
        security: [{ tenantApiKey: [] }, { bearerAuth: [] }],
        requestBody: jsonRequestBody({
          type: "object",
          required: ["owner", "quote"],
          properties: {
            agentId: stringSchema,
            owner: stringSchema,
            quote: bridgeQuoteSchema,
            estimatedUsd: { type: "number", minimum: 0 },
          },
        }),
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              properties: { unsignedIntent: adapterUnsignedIntentSchema },
            }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/adapters/bridge/sessions`]: {
      post: {
        tags: ["Adapters"],
        summary: "Create a bridge session",
        security: [{ tenantApiKey: [] }, { bearerAuth: [] }],
        requestBody: jsonRequestBody({
          type: "object",
          required: ["quote"],
          properties: { userId: stringSchema, quote: bridgeQuoteSchema },
        }),
        responses: {
          "201": jsonResponse(
            apiResponse({ type: "object", properties: { session: bridgeSessionSchema } }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/adapters/bridge/sessions/{sessionId}`]: {
      parameters: [parameter("sessionId", "path")],
      get: {
        tags: ["Adapters"],
        summary: "Get a bridge session",
        security: [{ tenantApiKey: [] }, { bearerAuth: [] }],
        responses: {
          "200": jsonResponse(
            apiResponse({ type: "object", properties: { session: bridgeSessionSchema } }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/adapters/spark/wallets`]: {
      post: {
        tags: ["Adapters"],
        summary: "Create a mock Spark wallet DTO",
        description:
          "Creates provider-neutral Spark wallet metadata. The mock never creates or stores key material.",
        security: [{ tenantApiKey: [] }, { bearerAuth: [] }],
        requestBody: jsonRequestBody({
          type: "object",
          properties: {
            userId: stringSchema,
            network: { type: "string", enum: ["mainnet", "testnet", "signet"] },
            label: stringSchema,
          },
        }),
        responses: {
          "201": jsonResponse(
            apiResponse({ type: "object", properties: { wallet: sparkWalletSchema } }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/adapters/spark/wallets/{walletId}`]: {
      parameters: [parameter("walletId", "path")],
      get: {
        tags: ["Adapters"],
        summary: "Get a Spark wallet DTO",
        security: [{ tenantApiKey: [] }, { bearerAuth: [] }],
        responses: {
          "200": jsonResponse(
            apiResponse({ type: "object", properties: { wallet: sparkWalletSchema } }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/adapters/spark/wallets/{walletId}/balance`]: {
      parameters: [parameter("walletId", "path")],
      get: {
        tags: ["Adapters"],
        summary: "Read Spark BTC/Lightning balances",
        security: [{ tenantApiKey: [] }, { bearerAuth: [] }],
        responses: {
          "200": jsonResponse(
            apiResponse({ type: "object", properties: { balance: sparkBalanceSchema } }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/adapters/spark/static-btc-deposits`]: {
      post: {
        tags: ["Adapters"],
        summary: "Create a static BTC deposit quote",
        security: [{ tenantApiKey: [] }, { bearerAuth: [] }],
        requestBody: jsonRequestBody({
          type: "object",
          required: ["walletId"],
          properties: { walletId: stringSchema, amountSats: stringSchema },
        }),
        responses: {
          "201": jsonResponse(
            apiResponse({
              type: "object",
              properties: { quote: sparkStaticBtcDepositQuoteSchema },
            }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/adapters/spark/static-btc-deposits/claim`]: {
      post: {
        tags: ["Adapters"],
        summary: "Build an unsigned static BTC deposit claim intent after policy/spend checks",
        security: [{ tenantApiKey: [] }, { bearerAuth: [] }],
        requestBody: jsonRequestBody({
          type: "object",
          required: ["walletId", "quoteId"],
          properties: {
            agentId: stringSchema,
            walletId: stringSchema,
            quoteId: stringSchema,
            estimatedUsd: { type: "number", minimum: 0 },
          },
        }),
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              properties: { unsignedIntent: adapterUnsignedIntentSchema },
            }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/adapters/spark/lightning/invoices`]: {
      post: {
        tags: ["Adapters"],
        summary: "Create a Lightning invoice DTO",
        security: [{ tenantApiKey: [] }, { bearerAuth: [] }],
        requestBody: jsonRequestBody({
          type: "object",
          required: ["walletId", "amountSats"],
          properties: {
            walletId: stringSchema,
            amountSats: stringSchema,
            memo: stringSchema,
            expiresInSeconds: { type: "integer", minimum: 60, maximum: 86400 },
          },
        }),
        responses: {
          "201": jsonResponse(
            apiResponse({ type: "object", properties: { invoice: sparkLightningInvoiceSchema } }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/adapters/spark/lightning/invoices/{invoiceId}`]: {
      parameters: [parameter("invoiceId", "path")],
      get: {
        tags: ["Adapters"],
        summary: "Get a Lightning invoice DTO",
        security: [{ tenantApiKey: [] }, { bearerAuth: [] }],
        responses: {
          "200": jsonResponse(
            apiResponse({ type: "object", properties: { invoice: sparkLightningInvoiceSchema } }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/adapters/spark/lightning/pay`]: {
      post: {
        tags: ["Adapters"],
        summary: "Build an unsigned Lightning payment intent after policy/spend checks",
        security: [{ tenantApiKey: [] }, { bearerAuth: [] }],
        requestBody: jsonRequestBody({
          type: "object",
          required: ["walletId", "paymentRequest"],
          properties: {
            agentId: stringSchema,
            walletId: stringSchema,
            paymentRequest: stringSchema,
            maxFeeSats: stringSchema,
            estimatedUsd: { type: "number", minimum: 0 },
          },
        }),
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              properties: { unsignedIntent: adapterUnsignedIntentSchema },
            }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/adapters/spark/transfers`]: {
      post: {
        tags: ["Adapters"],
        summary: "Build an unsigned Spark BTC transfer intent after policy/spend checks",
        security: [{ tenantApiKey: [] }, { bearerAuth: [] }],
        requestBody: jsonRequestBody({
          type: "object",
          required: ["walletId", "recipient", "amountSats"],
          properties: {
            agentId: stringSchema,
            walletId: stringSchema,
            recipient: stringSchema,
            amountSats: stringSchema,
            memo: stringSchema,
            estimatedUsd: { type: "number", minimum: 0 },
          },
        }),
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              properties: { unsignedIntent: adapterUnsignedIntentSchema },
            }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/adapters/spark/token-transfers`]: {
      post: {
        tags: ["Adapters"],
        summary: "Build an unsigned Spark token transfer intent after policy/spend checks",
        security: [{ tenantApiKey: [] }, { bearerAuth: [] }],
        requestBody: jsonRequestBody({
          type: "object",
          required: ["walletId", "recipient", "tokenId", "amount"],
          properties: {
            agentId: stringSchema,
            walletId: stringSchema,
            recipient: stringSchema,
            tokenId: stringSchema,
            amount: stringSchema,
            memo: stringSchema,
            estimatedUsd: { type: "number", minimum: 0 },
          },
        }),
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              properties: { unsignedIntent: adapterUnsignedIntentSchema },
            }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/adapters/spark/identity/sign`]: {
      post: {
        tags: ["Adapters"],
        summary: "Request Spark identity-key signing",
        description:
          "The mock Spark adapter fails closed with 501 and never fabricates signatures. A real provider must be configured before this can return a signature.",
        security: [{ tenantApiKey: [] }, { bearerAuth: [] }],
        requestBody: jsonRequestBody({
          type: "object",
          required: ["walletId", "payload"],
          properties: { walletId: stringSchema, payload: stringSchema },
        }),
        responses: {
          "501": jsonResponse(apiResponse({ type: "object", properties: { error: stringSchema } })),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/adapters/exchange/sessions`]: {
      post: {
        tags: ["Adapters"],
        summary: "Create an exchange embed session",
        security: [{ tenantApiKey: [] }, { bearerAuth: [] }],
        requestBody: jsonRequestBody({
          type: "object",
          required: ["provider", "returnUrl"],
          properties: {
            userId: stringSchema,
            provider: { type: "string", enum: ["kraken", "coinbase", "binance", "mock"] },
            returnUrl: stringSchema,
            scopes: { type: "array", items: stringSchema },
            locale: stringSchema,
          },
        }),
        responses: {
          "201": jsonResponse(
            apiResponse({ type: "object", properties: { session: exchangeSessionSchema } }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/adapters/exchange/sessions/{sessionId}`]: {
      parameters: [parameter("sessionId", "path")],
      get: {
        tags: ["Adapters"],
        summary: "Get an exchange embed session",
        security: [{ tenantApiKey: [] }, { bearerAuth: [] }],
        responses: {
          "200": jsonResponse(
            apiResponse({ type: "object", properties: { session: exchangeSessionSchema } }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/adapters/exchange/accounts`]: {
      get: {
        tags: ["Adapters"],
        summary: "List linked exchange accounts",
        security: [{ tenantApiKey: [] }, { bearerAuth: [] }],
        parameters: [parameter("userId", "query")],
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              properties: { accounts: { type: "array", items: exchangeAccountSchema } },
            }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/adapters/exchange/accounts/{accountId}`]: {
      parameters: [parameter("accountId", "path")],
      delete: {
        tags: ["Adapters"],
        summary: "Revoke a linked exchange account",
        security: [{ tenantApiKey: [] }, { bearerAuth: [] }],
        responses: {
          "200": jsonResponse(
            apiResponse({ type: "object", properties: { account: exchangeAccountSchema } }),
          ),
          ...errorResponses(),
        },
      },
    },
  };
}

function fiatPaths(prefix = ""): Record<string, unknown> {
  const userIdParam = parameter("userId", "path", {
    type: "string",
    description:
      "Tenant user id. Tenant-authenticated callers may act only for users in their tenant.",
  });
  const fiatAccountSchema = {
    type: "object",
    required: ["id", "provider", "status"],
    properties: {
      id: stringSchema,
      provider: stringSchema,
      status: stringSchema,
      fiatCurrency: stringSchema,
      createdAt: { type: "integer" },
    },
  };
  const kycVerificationSchema = {
    type: "object",
    required: ["id", "provider", "userId", "level", "status"],
    properties: {
      id: stringSchema,
      provider: stringSchema,
      userId: stringSchema,
      level: { type: "string", enum: ["basic", "standard", "enhanced"] },
      status: { type: "string", enum: ["not_started", "pending", "verified", "rejected"] },
      documents: { type: "array", items: metadataSchema },
      createdAt: { type: "integer" },
      updatedAt: { type: "integer" },
    },
  };
  const kycStartInputSchema = {
    type: "object",
    required: ["level"],
    properties: {
      level: { type: "string", enum: ["basic", "standard", "enhanced"] },
      returnUrl: { type: "string", format: "uri" },
    },
  };
  const kycDocumentInputSchema = {
    type: "object",
    required: ["verificationId", "documentType", "contentBase64"],
    properties: {
      verificationId: stringSchema,
      documentType: stringSchema,
      contentBase64: {
        type: "string",
        description:
          "Base64 document bytes. The adapter hashes and discards raw bytes; responses and audits expose only non-secret document descriptors.",
      },
    },
  };
  const onrampInputSchema = {
    type: "object",
    required: ["fiatCurrency", "fiatAmount", "cryptoAsset", "chainId", "destinationAddress"],
    properties: {
      fiatCurrency: stringSchema,
      fiatAmount: { type: "number", minimum: 0 },
      cryptoAsset: stringSchema,
      chainId: { type: "integer", minimum: 1 },
      destinationAddress: stringSchema,
    },
  };
  const offrampInputSchema = {
    type: "object",
    required: ["cryptoAsset", "cryptoAmount", "chainId", "fiatCurrency", "payoutMethodId"],
    properties: {
      cryptoAsset: stringSchema,
      cryptoAmount: stringSchema,
      chainId: { type: "integer", minimum: 1 },
      fiatCurrency: stringSchema,
      payoutMethodId: stringSchema,
    },
  };
  const onrampSessionSchema = {
    type: "object",
    required: ["id", "provider", "tenantId", "userId", "status"],
    properties: {
      id: stringSchema,
      provider: stringSchema,
      tenantId: stringSchema,
      userId: stringSchema,
      status: stringSchema,
      fiatCurrency: stringSchema,
      fiatAmount: { type: "number" },
      cryptoAsset: stringSchema,
      chainId: { type: "integer" },
      cryptoAmount: stringSchema,
      destinationAddress: stringSchema,
      createdAt: { type: "integer" },
      updatedAt: { type: "integer" },
    },
  };
  const offrampSessionSchema = {
    type: "object",
    required: ["id", "provider", "tenantId", "userId", "status"],
    properties: {
      id: stringSchema,
      provider: stringSchema,
      tenantId: stringSchema,
      userId: stringSchema,
      status: stringSchema,
      cryptoAsset: stringSchema,
      cryptoAmount: stringSchema,
      chainId: { type: "integer" },
      fiatCurrency: stringSchema,
      fiatAmount: { type: "number" },
      depositAddress: stringSchema,
      payoutMethodId: stringSchema,
      createdAt: { type: "integer" },
      updatedAt: { type: "integer" },
    },
  };
  const security = [{ tenantApiKey: [] }, { bearerAuth: [] }];
  return {
    [`${prefix}/apps/{appId}/fiat`]: {
      parameters: [parameter("appId", "path")],
      post: {
        tags: ["Fiat"],
        summary: "Configure app-level fiat provider settings",
        description:
          "Privy-compatible route placeholder. Steward exposes the OSS route surface but fails closed until a real fiat provider integration is configured.",
        security,
        requestBody: jsonRequestBody({ type: "object", additionalProperties: true }),
        responses: {
          "501": jsonResponse(errorResponse()),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/users/{userId}/fiat/accounts`]: {
      parameters: [userIdParam],
      get: {
        tags: ["Fiat"],
        summary: "List a user's fiat accounts",
        security,
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              properties: { accounts: { type: "array", items: fiatAccountSchema } },
            }),
          ),
          ...errorResponses(),
        },
      },
      post: {
        tags: ["Fiat"],
        summary: "Create a user's fiat account",
        description: "Fails closed with 501 unless a real banking/onramp provider is configured.",
        security,
        requestBody: jsonRequestBody({ type: "object", additionalProperties: true }),
        responses: {
          "501": jsonResponse(errorResponse()),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/users/{userId}/fiat/kyc_link`]: {
      parameters: [userIdParam],
      post: {
        tags: ["Fiat"],
        summary: "Create a KYC link for a user",
        security,
        requestBody: jsonRequestBody(kycStartInputSchema),
        responses: {
          "201": jsonResponse(
            apiResponse({
              type: "object",
              properties: {
                verification: kycVerificationSchema,
                kycLink: stringSchema,
                kyc_link: stringSchema,
              },
            }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/users/{userId}/fiat/kyc`]: {
      parameters: [userIdParam],
      get: {
        tags: ["Fiat"],
        summary: "Get fiat KYC status",
        security,
        parameters: [parameter("verificationId", "query")],
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              properties: { status: stringSchema, verification: kycVerificationSchema },
            }),
          ),
          ...errorResponses(),
        },
      },
      post: {
        tags: ["Fiat"],
        summary: "Start fiat KYC verification",
        security,
        requestBody: jsonRequestBody(kycStartInputSchema),
        responses: {
          "201": jsonResponse(
            apiResponse({
              type: "object",
              properties: { status: stringSchema, verification: kycVerificationSchema },
            }),
          ),
          ...errorResponses(),
        },
      },
      patch: {
        tags: ["Fiat"],
        summary: "Submit fiat KYC document bytes",
        description:
          "Raw document bytes are accepted only as request input, then hashed and discarded by the adapter. Responses and audit metadata expose only the hash and non-secret descriptors.",
        security,
        requestBody: jsonRequestBody(kycDocumentInputSchema),
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              properties: { status: stringSchema, verification: kycVerificationSchema },
            }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/users/{userId}/fiat/onramp`]: {
      parameters: [userIdParam],
      post: {
        tags: ["Fiat"],
        summary: "Create a fiat onramp session",
        security,
        requestBody: jsonRequestBody(onrampInputSchema),
        responses: {
          "201": jsonResponse(
            apiResponse({
              type: "object",
              properties: { quote: metadataSchema, session: onrampSessionSchema },
            }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/users/{userId}/fiat/onramp/{sessionId}`]: {
      parameters: [userIdParam, parameter("sessionId", "path")],
      get: {
        tags: ["Fiat"],
        summary: "Get a fiat onramp session",
        security,
        responses: {
          "200": jsonResponse(
            apiResponse({ type: "object", properties: { session: onrampSessionSchema } }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/users/{userId}/fiat/offramp`]: {
      parameters: [userIdParam],
      post: {
        tags: ["Fiat"],
        summary: "Create a fiat offramp session",
        security,
        requestBody: jsonRequestBody(offrampInputSchema),
        responses: {
          "201": jsonResponse(
            apiResponse({
              type: "object",
              properties: { quote: metadataSchema, session: offrampSessionSchema },
            }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/users/{userId}/fiat/offramp/{sessionId}`]: {
      parameters: [userIdParam, parameter("sessionId", "path")],
      get: {
        tags: ["Fiat"],
        summary: "Get a fiat offramp session",
        security,
        responses: {
          "200": jsonResponse(
            apiResponse({ type: "object", properties: { session: offrampSessionSchema } }),
          ),
          ...errorResponses(),
        },
      },
    },
  };
}

function tradePaths(prefix = ""): Record<string, unknown> {
  const hyperliquidAssetSchema: JsonSchema = {
    anyOf: [
      {
        type: "string",
        enum: ["BTC", "ETH", "BNB", "SOL", "AVAX", "ARB", "OP", "NEAR", "HYPE", "ZEC", "XMR"],
      },
      { type: "string", pattern: "^[a-z0-9]+:[A-Z0-9]+$", examples: ["xyz:SPCX"] },
    ],
  };
  const tradeSessionSchema: JsonSchema = {
    type: "object",
    required: [
      "id",
      "agentId",
      "tenantId",
      "venue",
      "walletId",
      "dailyCapUsd",
      "perOrderCapUsd",
      "leverageCap",
      "allowedAssets",
      "dailySpendUsd",
      "expiresAt",
      "remainingCapUsd",
    ],
    properties: {
      id: stringSchema,
      agentId: stringSchema,
      tenantId: stringSchema,
      venue: { type: "string", const: "hyperliquid" },
      walletId: stringSchema,
      dailyCapUsd: { type: "number", minimum: 0 },
      perOrderCapUsd: { type: "number", minimum: 0 },
      leverageCap: { type: "number", minimum: 0 },
      allowedAssets: { type: "array", items: hyperliquidAssetSchema },
      dailySpendUsd: { type: "number", minimum: 0 },
      createdAt: dateTimeSchema,
      expiresAt: dateTimeSchema,
      revokedAt: { anyOf: [dateTimeSchema, { type: "null" }] },
      remainingCapUsd: { type: "number", minimum: 0 },
    },
  };
  const tradeSessionCreateSchema: JsonSchema = {
    type: "object",
    required: ["venue"],
    properties: {
      agentId: stringSchema,
      venue: { type: "string", const: "hyperliquid" },
      walletAddress: stringSchema,
      dailyCap: { type: "number", minimum: 0, maximum: 50_000, default: 300 },
      perOrderCap: { type: "number", minimum: 0, maximum: 10_000, default: 100 },
      leverageCap: { type: "number", minimum: 0, maximum: 50, default: 5 },
      allowedAssets: {
        type: "array",
        minItems: 1,
        items: hyperliquidAssetSchema,
        default: ["BTC", "ETH", "BNB"],
      },
      ttlSeconds: { type: "integer", minimum: 1, maximum: 86_400, default: 3_600 },
    },
  };
  const orderInputSchema: JsonSchema = {
    type: "object",
    required: ["sessionId", "side", "size"],
    properties: {
      sessionId: stringSchema,
      coin: hyperliquidAssetSchema,
      asset: hyperliquidAssetSchema,
      side: { type: "string", enum: ["buy", "sell"] },
      size: { type: "number", minimum: 0 },
      limitPx: { anyOf: [{ type: "string" }, { type: "number" }] },
      limitPrice: { anyOf: [{ type: "string" }, { type: "number" }] },
      leverage: { type: "number", minimum: 0, default: 1 },
      reduceOnly: { type: "boolean", default: false },
      idempotencyKey: stringSchema,
    },
    anyOf: [{ required: ["coin"] }, { required: ["asset"] }],
  };
  const orderResultSchema: JsonSchema = {
    type: "object",
    required: ["orderId", "status", "filledQty", "avgPrice", "txHash"],
    properties: {
      orderId: stringSchema,
      status: stringSchema,
      filledQty: { type: "number" },
      avgPrice: { type: "number" },
      txHash: nullableStringSchema,
      builderPerp: { type: "boolean" },
    },
  };
  const recoveryInputProperties: Record<string, JsonSchema> = {
    agentId: stringSchema,
    idempotencyKey: stringSchema,
  };
  const tradeRecoveryDescription =
    "Operator recovery endpoint. Auth deliberately accepts platform operators or tenant admins and must not require an agent JWT, so humans can recover funds when the agent token is expired. Raw signing keys never leave the vault; all recovery actions are audited and idempotency-protected.";

  return {
    [`${prefix}/trade/token-status`]: {
      get: {
        tags: ["Trading"],
        summary: "Get last observed agent trade-token expiry",
        description:
          "Tenant-authenticated diagnostic endpoint for observing agent JWT expiry without granting trading authority.",
        security: [{ tenantApiKey: [] }, { bearerAuth: [] }],
        parameters: [parameter("agentId", "query")],
        responses: {
          "200": jsonResponse(
            apiResponse({
              $ref: "#/components/schemas/TradeTokenStatus",
            }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/trade/sessions`]: {
      post: {
        tags: ["Trading"],
        summary: "Create a policy-bounded Hyperliquid trading session",
        description:
          "Creates a venue-scoped session after tenant authentication, agent-tenant ownership checks, optional agent-token scoping, wallet resolution, policy cap intersection, venue allowlist checks, and asset allowlist checks.",
        security: [{ tenantApiKey: [] }, { bearerAuth: [] }],
        requestBody: jsonRequestBody(tradeSessionCreateSchema),
        responses: {
          "201": jsonResponse(
            apiResponse({
              type: "object",
              required: ["sessionId", "expiresAt"],
              properties: { sessionId: stringSchema, expiresAt: dateTimeSchema },
            }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/trade/sessions/{id}`]: {
      parameters: [parameter("id", "path")],
      get: {
        tags: ["Trading"],
        summary: "Get a policy-bounded trading session",
        description:
          "Tenant-authenticated session lookup. Agent-scoped callers can only access their own sessions.",
        security: [{ tenantApiKey: [] }, { bearerAuth: [] }],
        responses: { "200": jsonResponse(apiResponse(tradeSessionSchema)), ...errorResponses() },
      },
    },
    [`${prefix}/trade/sessions/{id}/revoke`]: {
      parameters: [parameter("id", "path")],
      post: {
        tags: ["Trading"],
        summary: "Revoke a trading session",
        description:
          "Revokes a policy-bounded trading session and writes an audit event. Agent-scoped callers can only revoke their own sessions.",
        security: [{ tenantApiKey: [] }, { bearerAuth: [] }],
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              required: ["sessionId", "revokedAt"],
              properties: { sessionId: stringSchema, revokedAt: dateTimeSchema },
            }),
          ),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/trade/hyperliquid/order`]: {
      post: {
        tags: ["Trading"],
        summary: "Submit a Hyperliquid order through an active agent session",
        description:
          "Requires an agent JWT for the calling agent. Orders are rate-limited, idempotency-protected, scoped to an active Hyperliquid session, rechecked against adapter asset support, evaluated against leverage/per-order/daily-spend policy before signing, and audited on both success and policy rejection.",
        security: [{ bearerAuth: [] }],
        requestBody: jsonRequestBody(orderInputSchema),
        responses: {
          "200": jsonResponse(apiResponse(orderResultSchema)),
          "429": jsonResponse(errorResponse()),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/trade/{venue}/deposit`]: {
      parameters: [parameter("venue", "path", { type: "string", enum: ["hyperliquid"] })],
      post: {
        tags: ["Trading"],
        summary: "Operator deposit recovery funds to a venue account",
        description: `${tradeRecoveryDescription} Hyperliquid deposits sign a bounded Arbitrum native-USDC transfer from the agent's venue wallet to the Hyperliquid bridge; amount must be 5-2000 USDC with at most six decimals.`,
        security: [{ platformKey: [] }, { tenantApiKey: [] }, { bearerAuth: [] }],
        requestBody: jsonRequestBody({
          type: "object",
          required: ["agentId", "amount"],
          properties: {
            ...recoveryInputProperties,
            amount: { anyOf: [{ type: "string" }, { type: "number" }] },
          },
        }),
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              properties: {
                venue: { type: "string", const: "hyperliquid" },
                walletAddress: stringSchema,
                bridge: stringSchema,
                amountUsdc: { type: "number" },
                amountBaseUnits: stringSchema,
                txHash: stringSchema,
              },
            }),
          ),
          "502": jsonResponse(errorResponse()),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/trade/{venue}/close-all`]: {
      parameters: [parameter("venue", "path", { type: "string", enum: ["hyperliquid"] })],
      post: {
        tags: ["Trading"],
        summary: "Operator close all venue positions for an agent",
        description: `${tradeRecoveryDescription} Every per-coin close result is audited so the recovery action remains traceable.`,
        security: [{ platformKey: [] }, { tenantApiKey: [] }, { bearerAuth: [] }],
        requestBody: jsonRequestBody({
          type: "object",
          required: ["agentId"],
          properties: recoveryInputProperties,
        }),
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              properties: {
                venue: { type: "string", const: "hyperliquid" },
                walletAddress: stringSchema,
                closed: { type: "array", items: { type: "object", additionalProperties: true } },
              },
            }),
          ),
          "502": jsonResponse(errorResponse()),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/trade/{venue}/leverage`]: {
      parameters: [parameter("venue", "path", { type: "string", enum: ["hyperliquid"] })],
      post: {
        tags: ["Trading"],
        summary: "Operator update Hyperliquid leverage for an agent position",
        description: `${tradeRecoveryDescription} Builder-perp symbols such as xyz:SPCX are forced to isolated margin and capped at 3x before submitting Hyperliquid's separate updateLeverage action.`,
        security: [{ platformKey: [] }],
        requestBody: jsonRequestBody({
          type: "object",
          required: ["agentId", "coin", "leverage"],
          properties: {
            ...recoveryInputProperties,
            coin: hyperliquidAssetSchema,
            leverage: { type: "integer", minimum: 1, maximum: 100 },
            isCross: { type: "boolean", default: false },
          },
        }),
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              properties: {
                venue: { type: "string", const: "hyperliquid" },
                walletAddress: stringSchema,
                coin: hyperliquidAssetSchema,
                leverage: { type: "integer", minimum: 1 },
                requestedLeverage: { type: "integer", minimum: 1 },
                isCross: { type: "boolean" },
                builderPerp: { type: "boolean" },
                result: { type: "object", additionalProperties: true },
              },
            }),
          ),
          "502": jsonResponse(errorResponse()),
          ...errorResponses(),
        },
      },
    },

    [`${prefix}/trade/{venue}/usd-send`]: {
      parameters: [parameter("venue", "path", { type: "string", enum: ["hyperliquid"] })],
      post: {
        tags: ["Trading"],
        summary: "Transfer internal USDC between Hyperliquid accounts",
        description: `${tradeRecoveryDescription} Platform-key only route that submits Hyperliquid's user-signed usdSend action for internal USDC transfers between Hyperliquid accounts. The transfer is signed by the sending agent's master Hyperliquid wallet.`,
        security: [{ platformKey: [] }],
        requestBody: jsonRequestBody({
          type: "object",
          required: ["agentId", "destination", "amount"],
          properties: {
            ...recoveryInputProperties,
            destination: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" },
            amount: { type: "string", pattern: "^\\d+(?:\\.\\d+)?$" },
          },
        }),
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              properties: {
                venue: { type: "string", const: "hyperliquid" },
                walletAddress: stringSchema,
                destination: stringSchema,
                amount: { type: "string" },
                result: { type: "object", additionalProperties: true },
              },
            }),
          ),
          "502": jsonResponse(errorResponse()),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/trade/{venue}/approve-builder`]: {
      parameters: [parameter("venue", "path", { type: "string", enum: ["hyperliquid"] })],
      post: {
        tags: ["Trading"],
        summary: "Approve Hyperliquid builder-code fee cap for an agent",
        description: `${tradeRecoveryDescription} Platform-key only route that submits Hyperliquid's user-signed approveBuilderFee action. The approval must be signed by the agent's master Hyperliquid wallet, not an API/agent wallet.`,
        security: [{ platformKey: [] }],
        requestBody: jsonRequestBody({
          type: "object",
          required: ["agentId", "builder", "maxFeeRate"],
          properties: {
            ...recoveryInputProperties,
            builder: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" },
            maxFeeRate: { type: "string", examples: ["0.1%"] },
          },
        }),
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              properties: {
                venue: { type: "string", const: "hyperliquid" },
                walletAddress: stringSchema,
                builder: stringSchema,
                maxFeeRate: { type: "string" },
                result: { type: "object", additionalProperties: true },
              },
            }),
          ),
          "502": jsonResponse(errorResponse()),
          ...errorResponses(),
        },
      },
    },
    [`${prefix}/trade/{venue}/withdraw`]: {
      parameters: [parameter("venue", "path", { type: "string", enum: ["hyperliquid"] })],
      post: {
        tags: ["Trading"],
        summary: "Operator withdraw venue funds for an agent",
        description: `${tradeRecoveryDescription} Withdrawals must pass the approved-addresses policy gate before signing; if amount is omitted, the route reads the venue withdrawable balance and fails closed when unavailable.`,
        security: [{ platformKey: [] }, { tenantApiKey: [] }, { bearerAuth: [] }],
        requestBody: jsonRequestBody({
          type: "object",
          required: ["agentId", "destination"],
          properties: {
            ...recoveryInputProperties,
            destination: stringSchema,
            amount: { anyOf: [{ type: "string" }, { type: "number" }] },
          },
        }),
        responses: {
          "200": jsonResponse(
            apiResponse({
              type: "object",
              properties: {
                venue: { type: "string", const: "hyperliquid" },
                walletAddress: stringSchema,
                destination: stringSchema,
                amount: { anyOf: [{ type: "string" }, { type: "number" }] },
                result: { type: "object", additionalProperties: true },
              },
            }),
          ),
          "502": jsonResponse(errorResponse()),
          ...errorResponses(),
        },
      },
    },
  };
}

function openApiPathForSensitivity(path: string): string {
  return path.replace(/\{[^}]+\}/g, "resource");
}

function sensitivePrefixForOpenApiPath(path: string): string | null {
  const normalized = openApiPathForSensitivity(path);
  return SENSITIVE_PATH_PREFIXES.find((prefix) => normalized.startsWith(prefix)) ?? null;
}

function isSensitiveOpenApiOperation(path: string, method: string): boolean {
  return (
    MUTATING_METHODS.has(method.toLowerCase()) && isSensitivePath(openApiPathForSensitivity(path))
  );
}

function hasParameter(parameters: unknown[], name: string, location: string): boolean {
  return parameters.some((param) => {
    if (!param || typeof param !== "object" || "$ref" in param) return false;
    const record = param as { name?: unknown; in?: unknown };
    return record.name === name && record.in === location;
  });
}

function addParameter(parameters: unknown[], parameterValue: ReturnType<typeof headerParameter>) {
  if (hasParameter(parameters, parameterValue.name, parameterValue.in)) return parameters;
  return [...parameters, parameterValue];
}

function addHardeningInventory(spec: OpenApiSpec): OpenApiSpec {
  for (const [path, pathItem] of Object.entries(spec.paths)) {
    for (const [method, operation] of Object.entries(pathItem)) {
      const lowerMethod = method.toLowerCase();
      if (!MUTATING_METHODS.has(lowerMethod)) continue;
      if (!operation || typeof operation !== "object" || Array.isArray(operation)) continue;
      if (!isSensitiveOpenApiOperation(path, lowerMethod)) continue;

      const op = operation as OpenApiOperation;
      const existingParameters = Array.isArray(op.parameters) ? op.parameters : [];
      op.parameters = [
        requestTimestampHeader,
        requestExpiresAtHeader,
        stewardSignatureHeader,
        signingKeyIdHeader,
        idempotencyKeyHeader,
      ].reduce((params, header) => addParameter(params, header), existingParameters);
      op["x-steward-hardening"] = {
        sensitive: true,
        sensitivePrefix: sensitivePrefixForOpenApiPath(path),
        requestExpiry: {
          requiredWhen:
            "STEWARD_REQUIRE_REQUEST_EXPIRY=true or production without STEWARD_ALLOW_STALE_SENSITIVE_REQUESTS=true",
          acceptedHeaders: ["X-Steward-Request-Timestamp", "X-Steward-Request-Expires-At"],
        },
        authorizationSignature: {
          requiredWhen: "STEWARD_REQUIRE_AUTH_SIGNATURE=true or NODE_ENV=production",
          header: "X-Steward-Signature",
          schemes: ["v1=hmac-sha256", "p256=ecdsa-secp256r1"],
          optionalSigningKeyHeader: "X-Steward-Signing-Key-Id",
        },
        idempotency: {
          header: "Idempotency-Key",
          requiredForSignedRequests: true,
          replayStorage:
            "enabled when callers provide a key in a replay-safe authenticated context",
        },
      };

      const responses = op.responses;
      if (responses && typeof responses === "object" && !Array.isArray(responses)) {
        const responseRecord = responses as Record<string, unknown>;
        responseRecord["408"] ??= jsonResponse(errorResponse());
      }
    }
  }
  return spec;
}

export function getOpenApiSpec() {
  return addHardeningInventory({
    openapi: "3.1.0",
    info: {
      title: "Steward API",
      version: "0.4.4",
      description:
        "Generated OpenAPI contract for implemented Steward API surfaces. This contract includes Privy-parity account resources, wallet external IDs, gas spend filtering, transaction reference filtering, and request-hardening inventory markers for sensitive mutating routes.",
    },
    servers: [{ url: "https://api.steward.fi" }],
    "x-steward-sensitive-prefixes": SENSITIVE_PATH_PREFIXES,
    tags: [
      { name: "Auth" },
      { name: "Digital Asset Accounts" },
      { name: "Platform Users" },
      { name: "Platform Tenants" },
      { name: "Platform Apps" },
      { name: "Tenant Users" },
      { name: "Policy Templates" },
      { name: "Condition Sets" },
      { name: "Wallets" },
      { name: "Vault" },
      { name: "Agent Authorization" },
      { name: "Intents" },
      { name: "Adapters" },
      { name: "Fiat" },
      { name: "Audits" },
      { name: "Secrets" },
      { name: "Webhooks" },
      { name: "Approvals" },
      { name: "Global Wallet" },
      { name: "Trading" },
      { name: "Tenant Config" },
    ],
    components: {
      securitySchemes: {
        tenantApiKey: { type: "apiKey", in: "header", name: "X-Steward-API-Key" },
        platformKey: { type: "apiKey", in: "header", name: "X-Steward-Platform-Key" },
        bearerAuth: { type: "http", scheme: "bearer" },
      },
      schemas: {
        TradeTokenStatus: {
          type: "object",
          required: ["agentId", "status", "exp", "observedAt", "expiresInSeconds"],
          properties: {
            agentId: stringSchema,
            status: { type: "string", enum: ["unknown", "observed"] },
            exp: { type: ["integer", "null"] },
            observedAt: nullableStringSchema,
            expiresInSeconds: { type: ["integer", "null"] },
          },
        },
      },
    },
    paths: {
      ...authPaths(),
      ...accountPaths(),
      ...accountPaths("/v1"),
      ...policyPaths(),
      ...policyPaths("/v1"),
      ...conditionSetPaths(),
      ...conditionSetPaths("/v1"),
      ...agentAuthorizationPaths(),
      ...agentAuthorizationPaths("/v1"),
      ...intentPaths(),
      ...intentPaths("/v1"),
      ...userWalletSignerPaths(),
      ...userWalletSignerPaths("/v1"),
      ...walletBatchPaths(),
      ...walletBatchPaths("/v1"),
      ...adapterPaths(),
      ...adapterPaths("/v1"),
      ...fiatPaths("/v1"),
      ...auditPaths(),
      ...secretPaths(),
      ...webhookPaths(),
      ...approvalPaths(),
      ...globalWalletPaths(),
      ...tradePaths(),
      ...tradePaths("/v1"),
      ...tenantConfigPaths(),
      ...platformTenantManagementPaths(),
      "/platform/users": {
        post: {
          tags: ["Platform Users"],
          summary: "Create or pre-provision a user",
          security: [{ platformKey: [] }],
          requestBody: jsonRequestBody({
            type: "object",
            required: ["email"],
            properties: {
              email: { type: "string", format: "email" },
              emailVerified: { type: "boolean" },
              name: stringSchema,
              customMetadata: metadataSchema,
              tenantId: stringSchema,
              walletExternalId: stringSchema,
              externalId: stringSchema,
            },
          }),
          responses: {
            "200": jsonResponse(
              apiResponse({
                type: "object",
                properties: {
                  userId: stringSchema,
                  isNew: { type: "boolean" },
                  tenantId: stringSchema,
                  walletExternalId: stringSchema,
                },
              }),
            ),
            "201": jsonResponse(
              apiResponse({
                type: "object",
                properties: {
                  userId: stringSchema,
                  isNew: { type: "boolean" },
                  tenantId: stringSchema,
                  walletExternalId: stringSchema,
                },
              }),
            ),
            ...errorResponses(),
          },
        },
      },
      "/platform/users/lookup": {
        get: {
          tags: ["Platform Users"],
          summary: "Look up a platform user identity",
          security: [{ platformKey: [] }],
          parameters: [
            parameter("email", "query"),
            parameter("phone", "query"),
            parameter("walletAddress", "query"),
            parameter("walletExternalId", "query"),
            parameter("smartWalletId", "query"),
            parameter("customAuthId", "query"),
            parameter("provider", "query"),
            parameter("providerAccountId", "query"),
            parameter("tenantId", "query"),
          ],
          responses: { "200": jsonResponse(userLookupResponse()), ...errorResponses() },
        },
        post: {
          tags: ["Platform Users"],
          summary: "Look up a platform user identity",
          security: [{ platformKey: [] }],
          requestBody: jsonRequestBody({ type: "object", additionalProperties: true }),
          responses: { "200": jsonResponse(userLookupResponse()), ...errorResponses() },
        },
      },
      "/platform/users/{userId}/wallet/external-id": {
        parameters: [parameter("userId", "path")],
        post: {
          tags: ["Platform Users"],
          summary: "Assign an immutable wallet external ID to a user",
          security: [{ platformKey: [] }],
          requestBody: jsonRequestBody(walletExternalIdBodySchema),
          responses: {
            "200": jsonResponse(
              apiResponse({
                type: "object",
                properties: {
                  userId: stringSchema,
                  tenantId: stringSchema,
                  walletExternalId: stringSchema,
                  field: { type: "string", const: "walletExternalId" },
                },
              }),
            ),
            ...errorResponses(),
          },
        },
      },
      "/platform/users/wallet/external-id": {
        post: {
          tags: ["Platform Users"],
          summary: "Resolve a wallet external ID",
          security: [{ platformKey: [] }],
          requestBody: jsonRequestBody(walletExternalIdBodySchema),
          responses: { "200": jsonResponse(userLookupResponse()), ...errorResponses() },
        },
      },
      "/platform/users/wallet/external-id/connect-or-create": {
        post: {
          tags: ["Platform Users"],
          summary: "Connect or create a user by wallet external ID",
          security: [{ platformKey: [] }],
          requestBody: jsonRequestBody({
            type: "object",
            required: ["tenantId"],
            properties: {
              tenantId: stringSchema,
              walletExternalId: stringSchema,
              externalId: stringSchema,
              email: { type: "string", format: "email" },
              emailVerified: { type: "boolean" },
              name: stringSchema,
              customMetadata: metadataSchema,
              role: { type: "string", enum: ["owner", "admin", "member"] },
            },
            anyOf: [{ required: ["walletExternalId"] }, { required: ["externalId"] }],
          }),
          responses: {
            "200": jsonResponse(
              apiResponse({
                type: "object",
                properties: {
                  userId: stringSchema,
                  isNew: { type: "boolean" },
                  createdExternalId: { type: "boolean" },
                  tenantId: stringSchema,
                  walletExternalId: stringSchema,
                  user: platformUserIdentitySchema,
                },
              }),
            ),
            "201": jsonResponse(
              apiResponse({
                type: "object",
                properties: {
                  userId: stringSchema,
                  isNew: { type: "boolean" },
                  createdExternalId: { type: "boolean" },
                  tenantId: stringSchema,
                  walletExternalId: stringSchema,
                  user: platformUserIdentitySchema,
                },
              }),
            ),
            ...errorResponses(),
          },
        },
      },
      "/platform/tenants/{tenantId}/users": {
        parameters: [parameter("tenantId", "path")],
        get: {
          tags: ["Platform Users"],
          summary: "Search tenant users, optionally by wallet external ID",
          security: [{ platformKey: [] }],
          parameters: [
            parameter("q", "query"),
            parameter("email", "query"),
            parameter("walletExternalId", "query"),
            parameter("limit", "query", { type: "integer", minimum: 1, maximum: 100 }),
            parameter("offset", "query", { type: "integer", minimum: 0 }),
          ],
          responses: {
            "200": jsonResponse(
              apiResponse({
                type: "object",
                properties: {
                  users: { type: "array", items: { type: "object", additionalProperties: true } },
                  limit: { type: "integer" },
                  offset: { type: "integer" },
                },
              }),
            ),
            ...errorResponses(),
          },
        },
      },
      "/user/me/tenants/{tenantId}/users/wallet-policy/violations": {
        parameters: [parameter("tenantId", "path")],
        get: {
          tags: ["Tenant Users"],
          summary: "Report one third-party wallet policy violations",
          description:
            "Requires an authenticated tenant admin user with recent MFA. Returns a read-only report of existing users that have multiple linked EVM/Solana third-party wallets so operators can review global linked-account remediation safely.",
          security: [{ bearerAuth: [] }],
          parameters: paginationQueryParameters,
          responses: {
            "200": jsonResponse(apiResponse(tenantWalletPolicyViolationReportSchema)),
            ...errorResponses(),
          },
        },
      },
      "/user/me/tenants/{tenantId}/users/{userId}/wallet-policy/wallets/{accountId}": {
        parameters: [
          parameter("tenantId", "path"),
          parameter("userId", "path"),
          parameter("accountId", "path"),
        ],
        delete: {
          tags: ["Tenant Users"],
          summary: "Remediate one third-party wallet policy violation",
          description:
            "Requires an authenticated tenant owner/admin user with recent MFA and a session scoped to the tenant. Deletes one selected EVM/Solana linked wallet from a tenant member, refuses to remove the user's last login method, revokes the remediated user's refresh tokens, writes authorized/final audit events, and dispatches a redacted user.unlinked_account webhook.",
          security: [{ bearerAuth: [] }],
          responses: {
            "200": jsonResponse(apiResponse(tenantWalletPolicyRemediationSchema)),
            ...errorResponses(),
          },
        },
      },
      "/platform/apps/gas_spend": {
        get: {
          tags: ["Platform Apps"],
          summary: "Get sponsored gas spend, including wallet external ID filters",
          security: [{ platformKey: [] }],
          parameters: [
            parameter("tenant_id", "query"),
            parameter("wallet_ids", "query"),
            parameter("wallet_external_ids", "query"),
            parameter("walletExternalIds", "query"),
            parameter("start_timestamp", "query", { type: "integer" }),
            parameter("end_timestamp", "query", { type: "integer" }),
          ],
          responses: {
            "200": jsonResponse(apiResponse({ type: "object", additionalProperties: true })),
            ...errorResponses(),
          },
        },
      },
      "/vault/{agentId}/import/init": {
        parameters: [parameter("agentId", "path")],
        post: {
          tags: ["Vault"],
          summary: "Initialize an encrypted private-key import session",
          description:
            "Requires an authenticated tenant owner/admin user with recent MFA plus the audited import feature flags. Returns a short-lived X25519 public key and AAD fields for a one-time encrypted import session. Responses are no-store and do not contain private-key material.",
          security: [{ bearerAuth: [] }],
          requestBody: jsonRequestBody(encryptedKeyImportInitRequestSchema),
          responses: {
            "200": jsonResponse(apiResponse(encryptedKeyImportInitResponseSchema)),
            ...errorResponses(),
          },
        },
      },
      "/vault/{agentId}/import/submit": {
        parameters: [parameter("agentId", "path")],
        post: {
          tags: ["Vault"],
          summary: "Submit an encrypted private-key import envelope",
          description:
            "Consumes a one-time encrypted import session and imports the decrypted EVM or Solana private key into encrypted vault storage. Plaintext `privateKey` fields are rejected; audit metadata records only chain/session/address metadata.",
          security: [{ bearerAuth: [] }],
          requestBody: jsonRequestBody(encryptedKeyImportSubmitRequestSchema),
          responses: {
            "200": jsonResponse(apiResponse(encryptedKeyImportResultSchema)),
            ...errorResponses(),
          },
        },
      },
      "/vault/{agentId}/actions/transfer/quote": {
        parameters: [parameter("agentId", "path")],
        post: {
          tags: ["Vault"],
          summary: "Quote an EVM transfer wallet action",
          description:
            "Requires an owner/admin browser session with recent MFA. Native transfers and ERC20 transfer-shaped requests share the same quote schema; ERC20 execution requires a constrained contract-allowlist selector policy before signing.",
          security: [{ bearerAuth: [] }],
          requestBody: jsonRequestBody(transferActionInputSchema),
          responses: {
            "200": jsonResponse(apiResponse(transferActionQuoteSchema)),
            ...walletActionErrorResponses(),
          },
        },
      },
      "/vault/{agentId}/actions/transfer": {
        parameters: [parameter("agentId", "path")],
        post: {
          tags: ["Vault"],
          summary: "Create an EVM transfer wallet action",
          description:
            "Creates and signs/broadcasts a native EVM transfer or selector-gated ERC20 transfer when policy allows. ERC20 transfers sign the token contract with `transfer(address,uint256)` calldata, zero native value, token/recipient/amount action metadata, and a required constrained `contract-allowlist` selector policy. Policy-denied actions return 403 with status `rejected`; manual-approval actions return 202 with status `pending_approval`; RPC failures return 500/502 with the created action ID when available. Broadcast actions require idempotency.",
          security: [{ bearerAuth: [] }],
          requestBody: jsonRequestBody(transferActionInputSchema),
          responses: {
            "200": jsonResponse(apiResponse(transferActionSchema)),
            "202": jsonResponse(apiResponse(transferActionSchema)),
            ...walletActionErrorResponses(),
          },
        },
      },
      "/vault/{agentId}/actions/send-calls": {
        parameters: [parameter("agentId", "path")],
        post: {
          tags: ["Vault"],
          summary: "Create an EVM batch-call wallet action intent",
          description:
            "Creates a batch-call action that currently resolves to `pending_approval` or `rejected`; approved send-calls execution remains an approval/intents workflow. Calldata-bearing calls are rejected unless unsafe contract-call signing is explicitly enabled.",
          security: [{ bearerAuth: [] }],
          requestBody: jsonRequestBody(sendCallsActionInputSchema),
          responses: {
            "202": jsonResponse(apiResponse(sendCallsActionSchema)),
            ...walletActionErrorResponses(),
          },
        },
      },
      "/vault/{agentId}/actions/{actionId}": {
        parameters: [parameter("agentId", "path"), parameter("actionId", "path")],
        get: {
          tags: ["Vault"],
          summary: "Get transfer wallet action status",
          description:
            "Returns status for transfer wallet actions. Send-calls status is currently exposed through transaction/intents history, not this transfer-only status endpoint.",
          security: [{ bearerAuth: [] }],
          responses: {
            "200": jsonResponse(apiResponse(transferActionSchema)),
            ...errorResponses(),
          },
        },
      },
      "/vault/{agentId}/sign-bitcoin-psbt": {
        parameters: [parameter("agentId", "path")],
        post: {
          tags: ["Vault"],
          summary: "Sign a Bitcoin PSBT with a scoped agent wallet",
          description:
            "Requires agent access plus owner/admin recent MFA or delegated signer credentials with `sign_transaction`. The route decodes standard Bitcoin PSBT destination outputs, computes input/output/fee totals before signing, rejects excessive fees, evaluates both destination outputs and aggregate destination+fee spend against the agent policy set, and records the signed spend for future policy counters. It also requires an enabled `raw-signing-chain` policy that explicitly allows `bitcoin` and `secp256k1`.",
          security: [{ bearerAuth: [] }, { tenantApiKey: [] }],
          requestBody: jsonRequestBody({
            type: "object",
            required: ["walletScope", "psbtBase64"],
            properties: {
              walletScope: stringSchema,
              psbtBase64: { type: "string", description: "Base64-encoded PSBT" },
              finalize: {
                type: "boolean",
                description:
                  "When true, finalize the signed PSBT and return raw transaction hex plus txid/fee metadata. No broadcast is performed.",
              },
              referenceId: stringSchema,
            },
          }),
          responses: {
            "200": jsonResponse(
              apiResponse({
                type: "object",
                required: [
                  "signedPsbtBase64",
                  "signedInputs",
                  "addressType",
                  "network",
                  "walletScope",
                  "walletAddress",
                  "transactionId",
                ],
                properties: {
                  signedPsbtBase64: { type: "string" },
                  signedInputs: { type: "integer", minimum: 1 },
                  addressType: { type: "string", enum: ["p2wpkh", "p2tr"] },
                  network: { type: "string", enum: ["mainnet", "testnet"] },
                  walletScope: stringSchema,
                  walletAddress: stringSchema,
                  transactionId: stringSchema,
                  finalizedTxHex: { type: "string" },
                  txId: { type: "string" },
                  vsize: { type: "integer", minimum: 1 },
                  feeSats: { type: "string" },
                },
              }),
            ),
            ...errorResponses(),
          },
        },
      },
      "/vault/{agentId}/transactions": {
        parameters: [parameter("agentId", "path")],
        get: {
          tags: ["Vault"],
          summary: "List transactions with optional reference ID filtering",
          security: [{ bearerAuth: [] }, { tenantApiKey: [] }],
          parameters: [
            parameter("status", "query"),
            parameter("actionType", "query"),
            parameter("txHash", "query"),
            parameter("referenceId", "query"),
            parameter("reference_id", "query"),
            parameter("limit", "query", { type: "integer", minimum: 1, maximum: 100 }),
            parameter("offset", "query", { type: "integer", minimum: 0 }),
          ],
          responses: {
            "200": jsonResponse(
              apiResponse({
                type: "object",
                properties: {
                  transactions: {
                    type: "array",
                    items: { type: "object", additionalProperties: true },
                  },
                  limit: { type: "integer" },
                  offset: { type: "integer" },
                },
              }),
            ),
            ...errorResponses(),
          },
        },
      },
    },
  } as const);
}

export function isOpenApiHttpEnabled(): boolean {
  const explicit = process.env.STEWARD_OPENAPI_ENABLED;
  if (explicit === "1" || explicit === "true") return true;
  if (explicit === "0" || explicit === "false") return false;
  return process.env.NODE_ENV !== undefined && process.env.NODE_ENV !== "production";
}

export const OPENAPI_DOC = getOpenApiSpec();
