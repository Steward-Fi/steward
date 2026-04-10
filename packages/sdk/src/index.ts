export { StewardClient, StewardApiError } from "./client.ts";
export { StewardAuth } from "./auth.ts";
export type {
  StewardAuthConfig,
  StewardAuthResult,
  StewardEmailResult,
  StewardOAuthConfig,
  StewardOAuthResult,
  StewardProviders,
  StewardTenantMembership,
  StewardTenantInfo,
  StewardSession,
  StewardUser,
  SessionStorage,
} from "./auth-types.ts";
export type {
  BatchAgentSpec,
  BatchCreateResult,
  CreateWalletResult,
  GetAddressesResult,
  GetBalanceResult,
  GetHistoryResult,
  SignMessageResult,
  SignTransactionInput,
  SignTransactionResult,
  StewardClientConfig,
  StewardErrorResponse,
  StewardHistoryEntry,
  StewardPendingApproval,
} from "./client.ts";
export type {
  AgentBalance,
  AgentIdentity,
  ApiResponse,
  ApprovedAddressesConfig,
  AutoApproveConfig,
  ChainFamily,
  PolicyResult,
  PolicyRule,
  PolicyType,
  RateLimitConfig,
  SpendingLimitConfig,
  TimeWindowConfig,
} from "./types.ts";
export type { SignRequest, TxRecord, TxStatus } from "./types.ts";
export { SUPPORTED_CHAINS } from "./types.ts";
export type { ChainIdentifier, AllowedChainsConfig } from "./types.ts";
export { CHAINS, chainFromNumeric, chainFromCaip2, toCaip2, fromCaip2 } from "./types.ts";
// v0.4.0 — Tenant config, dashboard, approvals, webhooks
export type {
  TenantControlPlaneConfig,
  AgentDashboardResponse,
  ApprovalQueueEntry,
  ApprovalStats,
  AutoApprovalRule,
  WebhookConfig,
  WebhookDelivery,
  WebhookEventType,
} from "./types.ts";
