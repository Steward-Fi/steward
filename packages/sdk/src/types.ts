// Standalone type definitions for the published SDK
// These mirror @stwd/shared but are bundled here for npm distribution

/** Identifies the blockchain family for a wallet key/address. */
export type ChainFamily = "evm" | "solana";

export interface AgentIdentity {
  id: string;
  tenantId: string;
  name: string;
  /** Primary EVM address — kept for backwards compatibility. */
  walletAddress: string;
  /**
   * All addresses for this agent, keyed by chain family.
   * Present for agents created with multi-wallet support.
   */
  walletAddresses?: { evm?: string; solana?: string };
  erc8004TokenId?: string;
  platformId?: string;
  createdAt: Date;
}

export type PolicyType =
  | "spending-limit"
  | "approved-addresses"
  | "auto-approve-threshold"
  | "time-window"
  | "rate-limit"
  | "allowed-chains"
  | "condition-set"
  | "contract-allowlist"
  | "reputation-threshold"
  | "reputation-scaling"
  | "venue-allowlist"
  | "leverage-cap";

export interface PolicyRule {
  id: string;
  type: PolicyType;
  enabled: boolean;
  config: Record<string, unknown>;
}

export interface PolicyResult {
  policyId: string;
  type: PolicyType;
  passed: boolean;
  reason?: string;
}

export interface ConditionSetConfig {
  conditionSetId: string;
  field?:
    | "to"
    | "ethereum_transaction.to"
    | "ethereum_transaction.chain_id"
    | "ethereum_transaction.value"
    | "ethereum_transaction.data"
    | "solana_system_program_instruction.Transfer.to"
    | "chain_id"
    | "value"
    | "data";
  operator?: "in_condition_set" | "not_in_condition_set";
  caseSensitive?: boolean;
}

export interface ContractAllowlistConfig {
  contracts: Array<{
    address: string;
    selectors: string[];
    constraints?: Record<
      string,
      {
        recipientAllowlist?: string[];
        recipientBlocklist?: string[];
        spenderAllowlist?: string[];
        spenderBlocklist?: string[];
        fromAllowlist?: string[];
        fromBlocklist?: string[];
        maxAmount?: string;
      }
    >;
  }>;
}

export interface ApiResponse<T = unknown> {
  ok: boolean;
  data?: T;
  error?: string;
}

export interface PlatformLinkedAccount {
  id: string;
  provider: string;
  providerAccountId: string;
  expiresAt: number | null;
}

export interface PlatformTenantUser {
  userId: string;
  tenantId: string;
  role: string;
  joinedAt: Date;
  email: string | null;
  emailVerified: boolean | null;
  name: string | null;
  tenantCustomMetadata: Record<string, unknown>;
  deactivatedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export type TenantTeamRole = "owner" | "admin" | "developer" | "billing" | "viewer" | "member";

export interface TenantAdminUser {
  userId: string;
  tenantId: string;
  role: TenantTeamRole | string;
  joinedAt: Date;
  email: string | null;
  emailVerified: boolean | null;
  name: string | null;
  tenantCustomMetadata: Record<string, unknown>;
  deactivatedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface TenantAdminUserSearchResult {
  users: TenantAdminUser[];
  limit: number;
  offset: number;
}

export interface TenantAdminUserEvent {
  id: number;
  seq: number;
  action: string;
  actorType: string;
  actorId: string | null;
  resourceType: string | null;
  resourceId: string | null;
  metadata: Record<string, unknown> | null;
  createdAt: Date;
}

export interface TenantAdminUserEventsResult {
  events: TenantAdminUserEvent[];
  limit: number;
  offset: number;
  total: number;
}

export interface PlatformUserIdentity {
  userId: string;
  email: string | null;
  emailVerified: boolean | null;
  name: string | null;
  image: string | null;
  walletAddress: string | null;
  walletChain: string | null;
  customMetadata: Record<string, unknown>;
  deactivatedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
  tenantIds: string[];
  linkedAccounts: PlatformLinkedAccount[];
}

export interface PlatformUserLookupResult {
  user: PlatformUserIdentity | null;
}

export interface PlatformUserSearchResult {
  users: PlatformTenantUser[];
  limit: number;
  offset: number;
}

export interface PlatformTenantInvitation {
  id: string;
  tenantId: string;
  email: string;
  role: Exclude<TenantTeamRole, "owner"> | string;
  status: "pending" | "accepted" | "revoked" | "expired" | string;
  invitedByUserId?: string | null;
  acceptedByUserId?: string | null;
  acceptedAt?: Date | null;
  revokedAt?: Date | null;
  expiresAt: Date;
  createdAt: Date;
  updatedAt?: Date;
}

export interface PlatformTenantInvitationListResult {
  invitations: PlatformTenantInvitation[];
}

export interface PlatformTenantInvitationCreateResult {
  invitation: PlatformTenantInvitation;
  token: string;
  emailSent?: boolean;
}

export interface PlatformLinkAccountResult extends PlatformLinkedAccount {
  isNew: boolean;
}

export interface PlatformTransferAccountResult extends PlatformLinkedAccount {
  fromUserId: string;
  toUserId: string;
}

export interface PlatformUserDeleteResult {
  userId: string;
  deleted: boolean;
}

export interface PlatformUserDeactivateResult {
  userId: string;
  deactivatedAt: Date | null;
}

export interface AgentBalance {
  agentId: string;
  walletAddress: string;
  balances: {
    native: string;
    nativeFormatted: string;
    chainId: number;
    symbol: string;
  };
}

export interface SpendingLimitConfig {
  maxPerTx: string;
  maxPerDay: string;
  maxPerWeek: string;
}

export interface ApprovedAddressesConfig {
  addresses: string[];
  mode: "whitelist" | "blacklist";
}

export interface AutoApproveConfig {
  threshold: string;
}

export interface TimeWindowConfig {
  allowedHours: { start: number; end: number }[];
  allowedDays: number[];
}

export interface RateLimitConfig {
  maxTxPerHour: number;
  maxTxPerDay: number;
}

export type TxStatus =
  | "pending"
  | "approved"
  | "rejected"
  | "signed"
  | "broadcast"
  | "confirmed"
  | "failed";

export interface SignRequest {
  agentId: string;
  tenantId: string;
  to: string;
  value: string;
  data?: string;
  chainId: number;
  nonce?: number;
  gasLimit?: string;
  broadcast?: boolean;
}

export interface TypedDataDomain {
  name?: string;
  version?: string;
  chainId?: number;
  verifyingContract?: string;
  salt?: string;
}

export interface TypedDataField {
  name: string;
  type: string;
}

export interface SignTypedDataRequest {
  agentId: string;
  tenantId: string;
  domain: TypedDataDomain;
  types: Record<string, TypedDataField[]>;
  primaryType: string;
  value: Record<string, unknown>;
}

export interface SignUserOperationRequest {
  agentId: string;
  tenantId: string;
  userOperation: {
    sender: string;
    nonce: string;
    initCode?: string;
    callData: string;
    verificationGasLimit: string;
    callGasLimit: string;
    preVerificationGas: string;
    maxPriorityFeePerGas: string;
    maxFeePerGas: string;
    paymasterAndData?: string;
  };
  entryPoint?: string;
  chainId: number;
  to: string;
  value: string;
}

export interface SignAuthorizationRequest {
  agentId: string;
  tenantId: string;
  contractAddress: string;
  chainId: number;
  nonce: number;
}

export interface SignSolanaTransactionRequest {
  agentId: string;
  tenantId: string;
  transaction: string;
  chainId?: number;
  broadcast?: boolean;
  expectedTo?: string;
  expectedValue?: string;
}

export interface RpcRequest {
  method: string;
  params?: unknown[];
  chainId: number;
}

export interface RpcResponse {
  jsonrpc: string;
  id: number;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

export interface TxRecord {
  id: string;
  agentId: string;
  status: TxStatus;
  request: SignRequest;
  actionType?: string | null;
  actionPayload?: Record<string, unknown> | null;
  txHash?: string;
  policyResults: PolicyResult[];
  createdAt: Date;
  signedAt?: Date;
  confirmedAt?: Date;
}

// ─── Tenant Config Types ──────────────────────────────────────

export interface TenantOidcProviderConfig {
  id: string;
  enabled: boolean;
  issuer: string;
  audience: string[];
  jwksUri: string;
  clientId?: string;
  clientSecretEnv?: string;
  authorizationUrl?: string;
  tokenUrl?: string;
  scopes?: string[];
  subjectClaim?: "sub";
  emailClaim?: string;
  emailVerifiedClaim?: string;
  nameClaim?: string;
  pictureClaim?: string;
  allowedAlgs?: Array<"RS256" | "ES256">;
  allowJitProvisioning?: boolean;
}

export type TenantSamlSsoStatus = "pending" | "active" | "error";
export type TenantSamlGroupRole = "admin" | "developer" | "billing" | "viewer" | "member";

export interface TenantSamlGroupRoleMapping {
  group: string;
  role: TenantSamlGroupRole;
}

export interface TenantSamlSsoConfig {
  tenantId: string;
  enabled: boolean;
  status: TenantSamlSsoStatus;
  idpEntityId: string;
  idpSsoUrl: string;
  idpCertPems: string[];
  spEntityId: string;
  acsUrl: string;
  nameIdFormat?: string;
  emailAttribute: string;
  groupsAttribute?: string;
  groupRoleMappings: TenantSamlGroupRoleMapping[];
  allowJitProvisioning: boolean;
  jitDefaultRole: "viewer";
  lastTestedAt?: Date | string | null;
  createdAt: Date | string;
  updatedAt: Date | string;
}

export interface TenantSamlSsoUpdate {
  enabled?: boolean;
  idpEntityId?: string;
  idpSsoUrl?: string;
  idpCertPems?: string[];
  nameIdFormat?: string;
  emailAttribute?: string;
  groupsAttribute?: string;
  groupRoleMappings?: TenantSamlGroupRoleMapping[];
  allowJitProvisioning?: boolean;
}

export type TenantCaptchaProvider = "turnstile" | "hcaptcha";
export type TenantCaptchaAction = "email_otp" | "sms_otp";

export interface TenantMfaPolicyConfig {
  maxAgeSeconds?: number;
  requireFor?: {
    vaultSigning?: boolean;
    keyImport?: boolean;
    keyExport?: boolean;
    recoveryCodes?: boolean;
    tenantAdmin?: boolean;
  };
  allowDelegatedSignerAutomation?: boolean;
  allowKeyQuorumAutomation?: boolean;
}

export interface TenantAuthAbuseConfig {
  loginMethods?: {
    passkey?: boolean;
    email?: boolean;
    sms?: boolean;
    whatsapp?: boolean;
    totp?: boolean;
    siwe?: boolean;
    siws?: boolean;
    telegram?: boolean;
    farcaster?: boolean;
    oauth?: Record<string, boolean>;
    oidc?: Record<string, boolean>;
  };
  captcha?: {
    enabled?: boolean;
    provider?: TenantCaptchaProvider;
    siteKey?: string;
    secretKeyEnv?: string;
    requiredFor?: TenantCaptchaAction[];
  };
  email?: {
    blockDisposable?: boolean;
    blockPlusAliases?: boolean;
    allowedEmails?: string[];
    blockedEmails?: string[];
    allowedDomains?: string[];
    blockedDomains?: string[];
  };
  wallet?: {
    allowedWallets?: string[];
    blockedWallets?: string[];
  };
  phone?: {
    blockVoip?: boolean;
    allowedPhoneNumbers?: string[];
    blockedPhoneNumbers?: string[];
    allowedCountryCodes?: string[];
    blockedCountryCodes?: string[];
  };
  mfa?: TenantMfaPolicyConfig;
}

export type TenantAccessAllowlistEntryType = "email" | "email_domain" | "wallet" | "phone";

export interface TenantAccessAllowlistEntry {
  id: string;
  tenantId: string;
  type: TenantAccessAllowlistEntryType;
  value: string;
  acceptedAt: string | null;
}

export interface TenantAccessAllowlistEntryInput {
  type: TenantAccessAllowlistEntryType;
  value: string;
}

export type TenantAppClientEnvironment = "development" | "preview" | "staging" | "production";

export interface TenantAppClient {
  id: string;
  name: string;
  environment: TenantAppClientEnvironment;
  enabled?: boolean;
  isDefault?: boolean;
  allowedOrigins?: string[];
  allowedRedirectUrls?: string[];
  loginMethods?: TenantAuthAbuseConfig["loginMethods"];
  globalWalletEnabled?: boolean;
  globalWalletAllowedScopes?: string[];
  createdAt?: Date | string;
  updatedAt?: Date | string;
}

export interface TenantAppClientSecret {
  id: string;
  tenantId: string;
  clientId: string;
  appId: string;
  secretPrefix: string;
  status: "active" | "retiring" | "revoked";
  createdAt: Date | string;
  updatedAt: Date | string;
  expiresAt?: Date | string | null;
  revokedAt?: Date | string | null;
}

export interface TenantAppClientSecretCreateResult {
  secret: TenantAppClientSecret;
  appId: string;
  appSecret: string;
}

export interface TenantSsoDomain {
  id: string;
  tenantId: string;
  domain: string;
  verificationToken: string;
  status: "pending" | "verified";
  ssoRequired: boolean;
  verifiedAt?: Date | string | null;
  createdAt: Date | string;
  updatedAt: Date | string;
}

export interface SsoDiscoveryResult {
  domain: string;
  tenantId: string | null;
  ssoRequired: boolean;
  available: boolean;
}

export interface TenantTheme {
  primaryColor?: string;
  accentColor?: string;
  backgroundColor?: string;
  surfaceColor?: string;
  textColor?: string;
  mutedColor?: string;
  successColor?: string;
  errorColor?: string;
  warningColor?: string;
  borderRadius?: number;
  fontFamily?: string;
  colorScheme?: "light" | "dark" | "system";
  logoUrl?: string;
  faviconUrl?: string;
}

export interface TenantTestAccountConfig {
  enabled?: boolean;
  email?: string;
  phone?: string;
  otp?: string;
  otpHash?: string;
  createdAt?: string;
  updatedAt?: string;
}

export type GasSponsorshipProvider =
  | "custom_evm_paymaster"
  | "custom_bundler"
  | "solana_fee_payer"
  | "mock";

export type GasSponsorshipMode = "erc4337" | "eip7702" | "solana_fee_payer";

export interface TenantGasSponsorshipConfig {
  enabled?: boolean;
  provider?: GasSponsorshipProvider;
  mode?: GasSponsorshipMode;
  allowedChainIds?: number[];
  allowedCaip2?: string[];
  paymasterUrl?: string;
  bundlerUrl?: string;
  entryPoint?: string;
  feePayerAgentId?: string;
  maxPerTxUsd?: number;
  maxPerWalletDayUsd?: number;
  maxTenantDayUsd?: number;
  maxTenantMonthUsd?: number;
  allowClientSponsorship?: boolean;
  requireSimulation?: boolean;
  circuitBreakerEnabled?: boolean;
}

export interface GasSponsorshipState {
  enabled: boolean;
  provider: GasSponsorshipProvider | null;
  mode?: GasSponsorshipMode;
  circuitBreakerEnabled?: boolean;
}

export type AccountGasSponsorshipState = GasSponsorshipState;

export interface SponsoredGasSpendEntry {
  id: string;
  tenantId: string;
  agentId: string;
  userId?: string | null;
  txId?: string | null;
  chainFamily: ChainFamily;
  chainId?: number | null;
  caip2?: string | null;
  provider: GasSponsorshipProvider | string;
  mode: GasSponsorshipMode | string;
  status: string;
  reservedUsd?: string | null;
  actualUsd?: string | null;
  txHash?: string | null;
  userOperationHash?: string | null;
  signature?: string | null;
  createdAt: Date | string;
  updatedAt: Date | string;
}

export interface SponsoredGasSpendSummary {
  currency: "USD";
  reservedUsd: string;
  actualUsd: string;
  count: number;
  entries: SponsoredGasSpendEntry[];
}

export interface TenantControlPlaneConfig {
  tenantId: string;
  displayName?: string;
  policyExposure?: Record<string, unknown>;
  policyTemplates?: Array<{ id: string; name: string; policies: PolicyRule[] }>;
  secretRoutePresets?: Array<{ id: string; name: string; path: string }>;
  approvalConfig?: Record<string, unknown>;
  featureFlags?: Record<string, boolean>;
  oidcProviders?: TenantOidcProviderConfig[];
  samlSso?: TenantSamlSsoConfig;
  authAbuseConfig?: TenantAuthAbuseConfig;
  appClients?: TenantAppClient[];
  testAccount?: TenantTestAccountConfig;
  gasSponsorshipConfig?: TenantGasSponsorshipConfig;
  /** Tenant-owned browser origins allowed for CORS, passkeys, and SIWE/SIWS. */
  allowedOrigins?: string[];
  /** Tenant-owned redirect URLs allowed for OAuth and email auth callbacks. */
  allowedRedirectUrls?: string[];
  theme?: TenantTheme;
  createdAt?: Date;
  updatedAt?: Date;
}

export type TenantSecurityChecklistStatus = "pass" | "warning" | "fail";

export interface TenantSecurityChecklistItem {
  id: string;
  label: string;
  status: TenantSecurityChecklistStatus;
  description: string;
  remediation?: string;
}

export interface TenantSecurityChecklist {
  tenantId: string;
  generatedAt: Date | string;
  summary: {
    pass: number;
    warning: number;
    fail: number;
  };
  items: TenantSecurityChecklistItem[];
}

export interface IdempotencyMetricCounters {
  observed: number;
  reserved: number;
  completed: number;
  replayed: number;
  conflicts: number;
  inFlightConflicts: number;
  suppressedAuthResponses: number;
  invalidKeys: number;
  storeErrors: number;
  skippedUnsafeContext: number;
  releasedOnError: number;
}

export interface TenantIdempotencyMetrics {
  tenantId: string;
  generatedAt: Date | string;
  windowStartedAt: Date | string;
  lastSeenAt: Date | string | null;
  ttlMs: number;
  counters: IdempotencyMetricCounters;
}

export interface TenantRequestSigningKey {
  id: string;
  tenantId: string;
  name: string;
  secretPrefix: string;
  status: "active" | "retiring" | "revoked";
  createdAt: Date | string;
  updatedAt: Date | string;
  expiresAt?: Date | string | null;
  revokedAt?: Date | string | null;
}

export interface TenantRequestSigningKeyCreateResult {
  key: TenantRequestSigningKey;
  signingSecret: string;
}

// ─── Dashboard Types ──────────────────────────────────────────

export interface AgentDashboardResponse {
  agent: AgentIdentity;
  balances: {
    evm?: {
      native: string;
      nativeFormatted: string;
      chainId: number;
      symbol: string;
    };
  };
  spend: {
    today: string;
    thisWeek: string;
    thisMonth: string;
    todayFormatted: string;
    thisWeekFormatted: string;
    thisMonthFormatted: string;
  };
  policies: PolicyRule[];
  pendingApprovals: number;
  recentTransactions: TxRecord[];
}

export interface AgentSpendSummary {
  agentId: string;
  walletAddress: string;
  onchain: {
    todayWei: string;
    weekWei: string;
    monthWei: string;
  };
  realtime: {
    enabled: boolean;
    periods: Array<{
      period: "day" | "week" | "month";
      spentUsd: number | null;
      byHost: Record<string, number>;
    }>;
  };
  sponsorship: AccountGasSponsorshipState;
}

export interface AgentAccountWallet {
  id: string;
  chainFamily: ChainFamily;
  address: string;
  venue: string | null;
  purpose: string | null;
  createdAt: Date | string;
}

export type AgentAccountCapability =
  | "sign_transaction"
  | "sign_message"
  | "sign_typed_data"
  | "sign_user_operation"
  | "sign_authorization"
  | "send_calls"
  | "transfer"
  | "solana_transaction";

export interface AgentPortfolioAsset {
  token: string;
  symbol: string;
  balance: string;
  formatted: string;
  decimals: number;
  usdPrice: number | null;
  usdValue: number | null;
  usdPriceText: string | null;
  usdValueText: string | null;
}

export interface AgentAccountSummary {
  id: string;
  type: "agent";
  agentId: string;
  tenantId: string;
  name: string;
  walletAddress: string;
  walletAddresses: Partial<Record<ChainFamily, string>>;
  wallets: AgentAccountWallet[];
  balances: {
    evm: null | {
      native: string;
      nativeFormatted: string;
      chainId: number;
      symbol: string;
      walletAddress: string;
    };
    unavailableReason?: string;
  };
  portfolio: {
    chainId: number | null;
    walletAddress: string;
    native: AgentPortfolioAsset | null;
    tokens: AgentPortfolioAsset[];
    totalUsd: number | null;
    totalUsdText: string | null;
    unavailableReason?: string;
  };
  spend: {
    todayWei: string;
    weekWei: string;
    monthWei: string;
  };
  capabilities: AgentAccountCapability[];
  sponsorship: AccountGasSponsorshipState;
  createdAt: Date | string;
}

export type UserAccountCapability =
  | "sign_transaction"
  | "sign_message"
  | "transfer"
  | "solana_transaction"
  | "export_private_key";

export interface UserAccountWallet {
  id: string;
  chainFamily: ChainFamily;
  address: string;
  venue: string | null;
  purpose: string | null;
  createdAt: Date | string;
}

export interface UserAccountSummary {
  id: string;
  type: "user";
  userId: string;
  tenantId: string;
  email: string | null;
  emailVerified: boolean | null;
  name: string | null;
  image: string | null;
  walletAddress: string | null;
  walletChain: string | null;
  customMetadata: Record<string, unknown>;
  linkedAccounts: Array<{
    id: string;
    provider: string;
    providerAccountId: string;
    expiresAt: number | null;
    type?: string;
    embeddedWallets?: Array<{ address: string }>;
    smartWallets?: Array<{ address: string }>;
    providerApp?: {
      id: string;
      name: string | null;
      logoUrl: string | null;
    };
    firstVerifiedAt?: Date | string;
    latestVerifiedAt?: Date | string;
  }>;
  primaryLoginMethods: Array<{ provider: "email" | "wallet"; providerAccountId: string }>;
  wallet: null | {
    id: string;
    agentId: string;
    walletAddress: string;
    walletAddresses: Partial<Record<ChainFamily, string>>;
    createdAt: Date | string;
  };
  walletAddresses: Partial<Record<ChainFamily, string>>;
  wallets: UserAccountWallet[];
  balances: {
    evm: null | {
      native: string;
      nativeFormatted: string;
      chainId: number;
      symbol: string;
      walletAddress: string;
    };
    unavailableReason?: string;
  };
  portfolio: {
    chainId: number | null;
    walletAddress: string | null;
    native: AgentPortfolioAsset | null;
    tokens: AgentPortfolioAsset[];
    totalUsd: number | null;
    totalUsdText: string | null;
    unavailableReason?: string;
  };
  spend: {
    todayWei: string;
    weekWei: string;
    monthWei: string;
  };
  capabilities: UserAccountCapability[];
  sponsorship: AccountGasSponsorshipState;
  createdAt: Date | string;
  updatedAt: Date | string;
}

export type UserPushProvider = "expo" | "apns" | "fcm";
export type UserPushPlatform = "ios" | "android";

export interface UserPushSubscription {
  id: string;
  tenantId: string | null;
  provider: UserPushProvider;
  token: string;
  platform: UserPushPlatform | null;
  deviceId: string | null;
  appId: string | null;
  locale: string | null;
  timezone: string | null;
  metadata: Record<string, unknown>;
  status: "active" | "revoked";
  lastSeenAt: Date | string;
  createdAt: Date | string;
  updatedAt: Date | string;
}

export interface UserPushSubscriptionInput {
  provider: UserPushProvider;
  token: string;
  platform?: UserPushPlatform;
  tenantId?: string;
  deviceId?: string;
  appId?: string;
  locale?: string;
  timezone?: string;
  metadata?: Record<string, unknown>;
}

export interface UserPushSubscriptionResult {
  subscription: UserPushSubscription;
}

export interface UserPushSubscriptionListResult {
  subscriptions: UserPushSubscription[];
}

export type AgentSignerType = "owner" | "delegated" | "service" | "quorum_member";
export type AgentSignerSubjectType = "user" | "wallet" | "api_key" | "external";
export type AgentSignerStatus = "active" | "paused" | "revoked";

export interface AgentSigner {
  id: string;
  tenantId: string;
  agentId: string;
  signerType: AgentSignerType;
  subjectType: AgentSignerSubjectType;
  subjectId: string;
  address: string | null;
  chainFamily: ChainFamily | null;
  label: string | null;
  permissions: string[];
  metadata: Record<string, unknown>;
  hasCredential?: boolean;
  status: AgentSignerStatus;
  createdBy: string | null;
  createdAt: Date | string;
  updatedAt: Date | string;
}

export interface AgentSignerCreate {
  signerType: AgentSignerType;
  subjectType: AgentSignerSubjectType;
  subjectId: string;
  address?: string | null;
  chainFamily?: ChainFamily | null;
  label?: string | null;
  permissions?: string[];
  metadata?: Record<string, unknown>;
  /** Provide a caller-generated credential secret. Stored server-side as a hash only. */
  credentialSecret?: string;
  /** Ask the server to issue a one-time credentialSecret in the create response. */
  issueCredential?: boolean;
}

export type AgentSignerCreateResult = AgentSigner & {
  credentialSecret?: string;
};

export type AgentSignerUpdate = Partial<
  Pick<
    AgentSignerCreate,
    "signerType" | "address" | "chainFamily" | "label" | "permissions" | "metadata"
  >
> & {
  status?: AgentSignerStatus;
};

export type AgentKeyQuorumStatus = "active" | "paused" | "revoked";

export interface AgentKeyQuorum {
  id: string;
  tenantId: string;
  agentId: string;
  name: string;
  threshold: number;
  memberSignerIds: string[];
  permissions: string[];
  metadata: Record<string, unknown>;
  status: AgentKeyQuorumStatus;
  createdBy: string | null;
  createdAt: Date | string;
  updatedAt: Date | string;
}

export interface AgentKeyQuorumCreate {
  name: string;
  threshold: number;
  memberSignerIds: string[];
  permissions?: string[];
  metadata?: Record<string, unknown>;
}

export type AgentKeyQuorumUpdate = Partial<
  Pick<AgentKeyQuorumCreate, "name" | "threshold" | "memberSignerIds" | "permissions" | "metadata">
> & {
  status?: AgentKeyQuorumStatus;
};

// ─── Approval Types ───────────────────────────────────────────

export interface ApprovalQueueEntry {
  id: string;
  txId: string;
  agentId: string;
  agentName?: string;
  status: "pending" | "approved" | "rejected";
  requestedAt: Date;
  resolvedAt?: Date;
  resolvedBy?: string;
  toAddress?: string;
  value?: string;
  chainId?: number;
  txStatus?: TxStatus;
  comment?: string;
  reason?: string;
}

export interface ApprovalStats {
  pending: number;
  approved: number;
  rejected: number;
  total: number;
  avgWaitSeconds: number;
}

export interface AutoApprovalRule {
  id?: string;
  tenantId: string;
  maxAmountWei: string;
  autoDenyAfterHours?: number | null;
  escalateAboveWei?: string | null;
  enabled: boolean;
  createdAt?: Date;
  updatedAt?: Date;
}

export type IntentStatus =
  | "pending"
  | "authorized"
  | "executing"
  | "executed"
  | "failed"
  | "rejected"
  | "canceled"
  | "expired";
export type IntentType =
  | "rpc"
  | "transfer"
  | "wallet_update"
  | "policy_update"
  | "policy_rule_update"
  | "quorum_update"
  | "wallet_action";

export interface Intent {
  id: string;
  intent_id: string;
  tenantId: string;
  agentId: string | null;
  wallet_id?: string | null;
  intentType: IntentType | string;
  intent_type: IntentType | string;
  status: IntentStatus;
  resourceType: string | null;
  resourceId: string | null;
  resource_id?: string | null;
  createdByType: string;
  createdById: string | null;
  created_by_id?: string | null;
  createdByDisplayName: string | null;
  created_by_display_name?: string | null;
  authorizationDetails: Array<Record<string, unknown>>;
  authorization_details?: Array<Record<string, unknown>>;
  payload: Record<string, unknown>;
  executionResult: Record<string, unknown> | null;
  execution_result?: Record<string, unknown> | null;
  expiresAt: Date | string | null;
  expires_at?: number | null;
  authorizedBy: string | null;
  authorized_by?: string | null;
  canceledAt: Date | string | null;
  canceledBy: string | null;
  canceled_by?: string | null;
  cancellationReason: string | null;
  cancellation_reason?: string | null;
  expiredAt: Date | string | null;
  expiredBy: string | null;
  expired_by?: string | null;
  rejectedAt: Date | string | null;
  rejectedBy: string | null;
  rejected_by?: string | null;
  rejectionReason: string | null;
  rejection_reason?: string | null;
  executedBy: string | null;
  executed_by?: string | null;
  failedAt: Date | string | null;
  failedBy: string | null;
  failed_by?: string | null;
  failureReason: string | null;
  failure_reason?: string | null;
  createdAt: Date | string;
  created_at?: number;
  updatedAt: Date | string;
  authorizedAt: Date | string | null;
  executedAt: Date | string | null;
}

export interface IntentCreate {
  intentType: IntentType | string;
  agentId?: string | null;
  resourceType?: string | null;
  resourceId?: string | null;
  authorizationDetails?: Array<Record<string, unknown>>;
  payload?: Record<string, unknown>;
  createdByDisplayName?: string | null;
  expiresAt?: string | null;
  ttlSeconds?: number;
}

export interface IntentListOptions {
  status?: IntentStatus;
  intentType?: IntentType | string;
  agentId?: string;
  limit?: number;
  offset?: number;
}

// ─── Webhook Types ────────────────────────────────────────────

export const WEBHOOK_EVENT_TYPES = [
  "tx.pending",
  "tx.approved",
  "tx.denied",
  "tx.signed",
  "spend.threshold",
  "policy.violation",
  "user.created",
  "user.authenticated",
  "user.linked_account",
  "user.unlinked_account",
  "user.updated_account",
  "user.transferred_account",
  "user.wallet_created",
  "mfa.enabled",
  "mfa.disabled",
  "private_key.exported",
  "wallet.recovery_setup",
  "wallet.recovered",
  "wallet.funds_deposited",
  "wallet.funds_withdrawn",
  "transaction.broadcasted",
  "transaction.confirmed",
  "transaction.execution_reverted",
  "transaction.replaced",
  "transaction.failed",
  "transaction.provider_error",
  "transaction.still_pending",
  "user_operation.completed",
  "user_operation.failed",
  "intent.created",
  "intent.authorized",
  "intent.executed",
  "intent.failed",
  "intent.rejected",
  "intent.canceled",
  "intent.expired",
  "wallet_action.transfer.created",
  "wallet_action.transfer.succeeded",
  "wallet_action.transfer.rejected",
  "wallet_action.transfer.failed",
  "wallet_action.send_calls.created",
  "wallet_action.send_calls.succeeded",
  "wallet_action.send_calls.rejected",
  "wallet_action.send_calls.failed",
  "wallet_action.swap.created",
  "wallet_action.swap.succeeded",
  "wallet_action.swap.rejected",
  "wallet_action.swap.failed",
  "wallet_action.earn_deposit.created",
  "wallet_action.earn_deposit.succeeded",
  "wallet_action.earn_deposit.rejected",
  "wallet_action.earn_deposit.failed",
  "wallet_action.earn_withdraw.created",
  "wallet_action.earn_withdraw.succeeded",
  "wallet_action.earn_withdraw.rejected",
  "wallet_action.earn_withdraw.failed",
  "wallet_action.earn_incentive_claim.created",
  "wallet_action.earn_incentive_claim.succeeded",
  "wallet_action.earn_incentive_claim.rejected",
  "wallet_action.earn_incentive_claim.failed",
] as const;

export type WebhookEventType = (typeof WEBHOOK_EVENT_TYPES)[number];

export interface WebhookConfig {
  id: string;
  tenantId: string;
  url: string;
  secret?: string;
  events: WebhookEventType[];
  enabled: boolean;
  maxRetries: number;
  retryBackoffMs: number;
  description?: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface WebhookDelivery {
  id: string;
  eventType: string;
  replayedFromDeliveryId?: string | null;
  status: "pending" | "processing" | "delivered" | "failed" | "dead";
  attempts: number;
  maxAttempts: number;
  nextRetryAt: string | Date | null;
  hasError: boolean;
  createdAt: string | Date;
  deliveredAt: string | Date | null;
}

export const SUPPORTED_CHAINS = {
  base: 8453,
  baseSepolia: 84532,
  bsc: 56,
  bscTestnet: 97,
  gnosis: 100,
} as const;

// ─── CAIP-2 Chain Identifiers ───

export interface ChainIdentifier {
  caip2: string;
  numericId: number;
  family: "evm" | "solana";
  name: string;
  symbol: string;
  testnet: boolean;
}

export interface AllowedChainsConfig {
  chains: string[];
}

/** Result of exporting private keys from a vault agent or user wallet. */
export interface ExportKeyResult {
  evm?: { privateKey: string; address: string };
  solana?: { privateKey: string; address: string };
  warning: string;
}

/**
 * Registry of all supported chains, keyed by CAIP-2 identifier.
 *
 * CAIP-2 format:
 *   EVM:    `eip155:{chainId}`
 *   Solana: `solana:{genesisHashPrefix}`
 */
export const CHAINS: Record<string, ChainIdentifier> = {
  "eip155:1": {
    caip2: "eip155:1",
    numericId: 1,
    family: "evm",
    name: "Ethereum",
    symbol: "ETH",
    testnet: false,
  },
  "eip155:56": {
    caip2: "eip155:56",
    numericId: 56,
    family: "evm",
    name: "BSC",
    symbol: "BNB",
    testnet: false,
  },
  "eip155:97": {
    caip2: "eip155:97",
    numericId: 97,
    family: "evm",
    name: "BSC Testnet",
    symbol: "tBNB",
    testnet: true,
  },
  "eip155:100": {
    caip2: "eip155:100",
    numericId: 100,
    family: "evm",
    name: "Gnosis",
    symbol: "xDAI",
    testnet: false,
  },
  "eip155:137": {
    caip2: "eip155:137",
    numericId: 137,
    family: "evm",
    name: "Polygon",
    symbol: "POL",
    testnet: false,
  },
  "eip155:8453": {
    caip2: "eip155:8453",
    numericId: 8453,
    family: "evm",
    name: "Base",
    symbol: "ETH",
    testnet: false,
  },
  "eip155:42161": {
    caip2: "eip155:42161",
    numericId: 42161,
    family: "evm",
    name: "Arbitrum",
    symbol: "ETH",
    testnet: false,
  },
  "eip155:84532": {
    caip2: "eip155:84532",
    numericId: 84532,
    family: "evm",
    name: "Base Sepolia",
    symbol: "ETH",
    testnet: true,
  },
  "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp": {
    caip2: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
    numericId: 101,
    family: "solana",
    name: "Solana",
    symbol: "SOL",
    testnet: false,
  },
  "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1": {
    caip2: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
    numericId: 102,
    family: "solana",
    name: "Solana Devnet",
    symbol: "SOL",
    testnet: true,
  },
};

export function chainFromNumeric(id: number): ChainIdentifier | undefined {
  return Object.values(CHAINS).find((c) => c.numericId === id);
}

export function chainFromCaip2(caip2: string): ChainIdentifier | undefined {
  return CHAINS[caip2];
}

export function toCaip2(numericId: number): string | undefined {
  return chainFromNumeric(numericId)?.caip2;
}

export function fromCaip2(caip2: string): number | undefined {
  return CHAINS[caip2]?.numericId;
}

// ─── Secrets ────────────────────────────────────────

export interface SecretRecord {
  id: string;
  tenantId: string;
  name: string;
  description?: string;
  version: number;
  routeCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface CreateSecretPayload {
  name: string;
  value: string;
  description?: string;
  expiresAt?: string;
}

export type InjectAs = "header" | "query" | "body";

export interface RouteRecord {
  id: string;
  agentId: string | null;
  secretId: string;
  hostPattern: string;
  pathPattern?: string;
  method?: string;
  injectAs: InjectAs;
  injectKey?: string;
  injectFormat?: string;
  /** Legacy alias for `injectKey` when `injectAs === "header"`. */
  headerName?: string;
  /** Legacy alias for `injectKey` when `injectAs === "query"`. */
  queryParam?: string;
  /** Legacy alias for `injectKey` when `injectAs === "body"`. */
  bodyPath?: string;
  priority?: number;
  enabled?: boolean;
  createdAt: string;
}

export interface CreateRoutePayload {
  secretId: string;
  agentId: string;
  hostPattern: string;
  pathPattern?: string;
  method?: string;
  injectAs: InjectAs;
  /** Preferred: header name / query param / body JSON path. */
  injectKey?: string;
  injectFormat?: string;
  /** Legacy alias — populated when `injectAs === "header"`. */
  headerName?: string;
  /** Legacy alias — populated when `injectAs === "query"`. */
  queryParam?: string;
  /** Legacy alias — populated when `injectAs === "body"`. */
  bodyPath?: string;
  priority?: number;
  enabled?: boolean;
}

export type UpdateRoutePayload = Partial<Omit<CreateRoutePayload, "secretId">>;

// ─── Policy Templates ────────────────────────────────

export interface PolicyTemplate {
  id: string;
  tenantId: string;
  name: string;
  description: string | null;
  rules: PolicyRule[];
  isDefault: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface PolicyTemplateCreate {
  name: string;
  description?: string;
  rules: PolicyRule[];
  isDefault?: boolean;
}

export type PolicyTemplateUpdate = Partial<PolicyTemplateCreate>;

// ─── Condition Sets ─────────────────────────────────

export interface ConditionSet {
  id: string;
  tenantId: string;
  name: string;
  description: string | null;
  ownerId: string | null;
  metadata: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}

export interface ConditionSetCreate {
  name: string;
  description?: string | null;
  ownerId: string;
  metadata?: Record<string, unknown>;
}

export type ConditionSetUpdate = Partial<ConditionSetCreate>;

export interface ConditionSetItem {
  id: string;
  conditionSetId: string;
  tenantId: string;
  value: string;
  label: string | null;
  metadata: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}

export interface ConditionSetItemInput {
  value: string;
  label?: string | null;
  metadata?: Record<string, unknown>;
}

/**
 * Transaction-shaped policy simulation request.
 * Used to evaluate signing policies against a hypothetical transaction.
 */
export interface PolicySimulateTransactionRequest {
  kind?: "transaction";
  to: string;
  value: string;
  data?: string;
  chainId?: number;
}

/**
 * Proxy-shaped policy simulation request.
 * Used to evaluate proxy gateway policies against an outbound API call.
 */
export interface PolicySimulateProxyRequest {
  kind: "proxy";
  method?: string;
  url?: string;
  body?: unknown;
  data?: unknown;
  value?: string;
}

export type PolicySimulateRequest = PolicySimulateTransactionRequest | PolicySimulateProxyRequest;

export interface PolicySimulateInput {
  /** Simulate an existing saved template. */
  policyId?: string;
  /** Or simulate an inline rule set. */
  rules?: PolicyRule[];
  agentId: string;
  request: PolicySimulateRequest;
}

export interface PolicySimulateResult {
  approved: boolean;
  requiresManualApproval: boolean;
  results: PolicyResult[];
  /** Present when there are no rules to evaluate. */
  note?: string;
}

// ─── Audit ─────────────────────────────────────────

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  agentId: string;
  action: "sign" | "approve" | "reject" | "proxy" | string;
  status: string;
  details?: Record<string, unknown>;
  policyResults?: PolicyResult[] | unknown;
  value?: string;
  to?: string;
}

export interface AuditLogResponse {
  data: AuditLogEntry[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

export interface AuditSummaryResponse {
  totalTransactions: number;
  totalApprovals: number;
  totalRejections: number;
  totalProxyRequests: number;
  policyViolations: number;
  topAgents: Array<{ agentId: string; name: string; txCount: number }>;
  dailyActivity: Array<{ date: string; txCount: number }>;
}

// ─── Tenants ────────────────────────────────────────

export interface TenantMembership {
  tenantId: string;
  tenantName: string;
  role: string;
  joinedAt: string;
}
