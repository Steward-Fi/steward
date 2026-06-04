import type {
  AgentBalance,
  AgentIdentity,
  ChainFamily,
  GlobalWalletApproveResult,
  GlobalWalletConsentRequest,
  PolicyResult,
  PolicyRule,
  PolicyType,
  StewardClient,
  StewardProviders as StewardProvidersState,
  StewardTenantMembership,
  TxRecord,
  TxStatus,
  UserAccountsResult,
  UserAccountUnlinkResult,
  UserLinkedAccount,
} from "@stwd/sdk";

// ─── Tenant Configuration Types ───

export type PolicyExposure = "visible" | "hidden" | "enforced";

export type PolicyExposureConfig = Partial<Record<PolicyType, PolicyExposure>>;

export interface EnforcedPolicyOverride {
  type: PolicyType;
  config: Record<string, unknown>;
  allowTightening?: boolean;
}

export interface CustomizableField {
  path: string;
  label: string;
  description: string;
  type: "currency" | "number" | "toggle" | "address-list" | "chain-select";
  default: unknown;
  min?: unknown;
  max?: unknown;
}

export interface PolicyTemplate {
  id: string;
  name: string;
  description: string;
  icon: string;
  policies: PolicyRule[];
  customizableFields: CustomizableField[];
}

export interface SecretRoutePreset {
  id: string;
  name: string;
  hostPattern: string;
  pathPattern: string;
  injectAs: "header" | "query" | "bearer";
  injectKey: string;
  injectFormat: string;
  provisioning: "platform" | "user";
  platformSecretId?: string;
}

export interface ApprovalNotificationChannel {
  type: "webhook" | "email" | "in-app";
  config: Record<string, string>;
}

export interface ApproverConfig {
  mode: "owner" | "tenant-admin" | "list";
  allowedApprovers?: string[];
}

export interface ApprovalConfig {
  notificationChannels: ApprovalNotificationChannel[];
  autoExpireSeconds: number;
  approvers: ApproverConfig;
  approvalWebhookUrl?: string;
  webhookCallbackEnabled: boolean;
}

export interface TenantTheme {
  primaryColor: string;
  accentColor: string;
  backgroundColor: string;
  surfaceColor: string;
  textColor: string;
  mutedColor: string;
  successColor: string;
  errorColor: string;
  warningColor: string;
  borderRadius: number;
  fontFamily?: string;
  colorScheme: "light" | "dark" | "system";
  logoUrl?: string;
  faviconUrl?: string;
}

export interface TenantFeatureFlags {
  showFundingQR: boolean;
  showTransactionHistory: boolean;
  showSpendDashboard: boolean;
  showPolicyControls: boolean;
  showApprovalQueue: boolean;
  showSecretManager: boolean;
  enableSolana: boolean;
  showChainSelector: boolean;
  allowAddressExport: boolean;
}

export interface TenantControlPlaneConfig {
  tenantId: string;
  displayName: string;
  exposedPolicies: PolicyExposureConfig;
  policyTemplates: PolicyTemplate[];
  secretRoutePresets: SecretRoutePreset[];
  approvalConfig: ApprovalConfig;
  theme?: TenantTheme;
  features: TenantFeatureFlags;
}

// ─── Component Data Types ───

export interface AgentDashboardResponse {
  agent: AgentIdentity;
  balances: {
    evm?: {
      native: string;
      nativeFormatted: string;
      chainId: number;
      symbol: string;
    };
    solana?: {
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

export interface PaginatedTransactionsResponse {
  transactions: TxRecord[];
  pagination: {
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
  };
}

export interface SpendStats {
  range: "24h" | "7d" | "30d" | "all";
  totalSpent: string;
  totalSpentFormatted: string;
  txCount: number;
  avgTxValue: string;
  avgTxValueFormatted: string;
  largestTx: { value: string; txHash: string; timestamp: string };
  daily: Array<{
    date: string;
    spent: string;
    spentFormatted: string;
    txCount: number;
  }>;
  topDestinations: Array<{
    address: string;
    totalSent: string;
    txCount: number;
  }>;
  budgetUsage?: {
    dailyLimit: string;
    dailyUsed: string;
    dailyPercent: number;
    weeklyLimit: string;
    weeklyUsed: string;
    weeklyPercent: number;
  };
}

export interface ApprovalQueueEntry {
  id: string;
  agentId: string;
  txId: string;
  status: "pending" | "approved" | "rejected";
  to: string;
  value: string;
  chainId: number;
  policyResults: PolicyResult[];
  createdAt: string;
  resolvedAt?: string;
  resolvedBy?: string;
}

// ─── Provider Types ───

export interface StewardProviderProps {
  client: StewardClient;
  agentId: string;
  features?: Partial<TenantFeatureFlags>;
  theme?: Partial<TenantTheme>;
  pollInterval?: number;
  children: React.ReactNode;
}

export interface StewardContextValue {
  client: StewardClient;
  agentId: string;
  features: TenantFeatureFlags;
  theme: TenantTheme;
  tenantConfig: TenantControlPlaneConfig | null;
  isLoading: boolean;
  pollInterval: number;
}

export interface StewardGlobalWalletConsentProps {
  /** Tenant app id in the form `tenant_id/client_id`. */
  appId: string;
  /** Exact app origin. Defaults to `window.location.origin` in browsers. */
  origin?: string;
  /** Optional redirect URI, validated against the tenant app client's allowlist. */
  redirectUri?: string;
  /** Requested global-wallet scopes. Defaults to `eth_accounts`. */
  scopes?: string[];
  /** Optional preloaded consent request for SSR or custom data loaders. */
  initialRequest?: GlobalWalletConsentRequest;
  onApproved?: (result: GlobalWalletApproveResult) => void;
  onError?: (error: Error) => void;
  className?: string;
}

// ─── Component Props ───

export interface WalletOverviewProps {
  chains?: ChainFamily[];
  showQR?: boolean;
  showCopy?: boolean;
  className?: string;
  onCopyAddress?: (address: string, chain: ChainFamily) => void;
}

export interface TransactionHistoryProps {
  pageSize?: number;
  statusFilter?: TxStatus[];
  chainFilter?: number[];
  showPolicyDetails?: boolean;
  renderTransaction?: (tx: TxRecord) => React.ReactNode;
  onTransactionClick?: (tx: TxRecord) => void;
  className?: string;
}

export interface PolicyControlsProps {
  showTemplates?: boolean;
  onSave?: (policies: PolicyRule[]) => void;
  readOnly?: boolean;
  labels?: Partial<Record<PolicyType, string>>;
  className?: string;
}

export interface ApprovalQueueProps {
  refreshInterval?: number;
  onResolve?: (txId: string, action: "approved" | "rejected") => void;
  showPolicyReason?: boolean;
  className?: string;
}

export interface SpendDashboardProps {
  range?: "24h" | "7d" | "30d" | "all";
  showBudgetUsage?: boolean;
  showChart?: boolean;
  showTopDestinations?: boolean;
  className?: string;
}

export interface StewardLinkedAccountsProps {
  showPrimaryLoginMethods?: boolean;
  showLinkedAccounts?: boolean;
  showPhoneLinking?: boolean;
  showWalletLinking?: boolean;
  showOAuthLinking?: boolean;
  showSocialLinking?: boolean;
  oauthProviders?: string[];
  oauthRedirectUri?: string;
  onOAuthLinkRequest?: (
    provider: string,
    challenge: {
      state: string;
      redirectUri: string;
      expiresIn: number;
    },
  ) => Promise<{
    code: string;
    redirectUri?: string;
    state?: string;
    codeVerifier?: string;
  } | null>;
  ethereumWallet?: {
    address: string;
    signMessage: (message: string) => Promise<string>;
  };
  solanaWallet?: {
    publicKey: string;
    /**
     * Sign the exact challenge message and return the encoded signature string
     * expected by the Steward API.
     */
    signMessage: (message: string) => Promise<string>;
  };
  onTelegramLinkRequest?: (challengeId: string) => Promise<Record<string, unknown> | null>;
  onFarcasterLinkRequest?: (nonce: string) => Promise<{
    message: string;
    signature: string;
    custodyAddress?: string;
    address?: string;
    fid?: string | number;
    username?: string;
    displayName?: string;
    pfpUrl?: string;
    pfp?: string;
  } | null>;
  allowUnlink?: boolean;
  className?: string;
  onLoaded?: (result: UserAccountsResult) => void;
  onLink?: (account: UserLinkedAccount) => void;
  onUnlink?: (account: UserLinkedAccount, result: UserAccountUnlinkResult) => void;
  onError?: (error: Error) => void;
}

// Re-export SDK types consumers will need
export type {
  AgentBalance,
  AgentIdentity,
  ChainFamily,
  PolicyResult,
  PolicyRule,
  PolicyType,
  StewardClient,
  TxRecord,
  TxStatus,
};

// ─── Multi-Tenant Types ───

export type { StewardTenantMembership } from "@stwd/sdk";

// ─── Auth Types ───

export type {
  SessionStorage,
  StewardProviders as StewardProvidersState,
  StewardSession,
  StewardUser,
  UserAccountsResult,
  UserAccountUnlinkResult,
  UserLinkedAccount,
} from "@stwd/sdk";

export interface StewardAuthConfig {
  baseUrl: string;
  storage?: import("@stwd/sdk").SessionStorage;
  tenantId?: string;
}

export interface StewardAuthContextValue {
  isAuthenticated: boolean;
  isLoading: boolean;
  user: import("@stwd/sdk").StewardUser | null;
  session: import("@stwd/sdk").StewardSession | null;
  /** Available auth providers (auto-fetched on mount) */
  providers: StewardProvidersState | null;
  /** Whether providers are still loading */
  isProvidersLoading: boolean;
  signOut: () => void;
  getToken: () => string | null;
  /** Sign in with a passkey (WebAuthn). Browser-only. */
  signInWithPasskey: (
    email: string,
  ) => Promise<
    import("@stwd/sdk").StewardAuthResult | import("@stwd/sdk").StewardMfaRequiredResult
  >;
  /**
   * Register an additional passkey for the current email on this device /
   * relying party. Use after a successful magic-link or OAuth sign-in to
   * upgrade the user to one-tap passkey login on this domain. Browser-only.
   */
  addPasskey: (
    email: string,
  ) => Promise<
    import("@stwd/sdk").StewardAuthResult | import("@stwd/sdk").StewardMfaRequiredResult
  >;
  /** Send a magic link email. */
  signInWithEmail: (
    email: string,
    captchaToken?: string,
  ) => Promise<import("@stwd/sdk").StewardEmailResult>;
  /** Send an SMS one-time passcode. */
  sendSmsOtp: (
    phone: string,
    captchaToken?: string,
  ) => Promise<import("@stwd/sdk").StewardSmsOtpResult>;
  /** Verify an SMS one-time passcode. */
  verifySmsOtp: (
    phone: string,
    code: string,
  ) => Promise<
    import("@stwd/sdk").StewardAuthResult | import("@stwd/sdk").StewardMfaRequiredResult
  >;
  /** Send a WhatsApp one-time passcode through the configured provider adapter. */
  sendWhatsAppOtp: (
    phone: string,
    captchaToken?: string,
  ) => Promise<import("@stwd/sdk").StewardWhatsAppOtpResult>;
  /** Verify a WhatsApp one-time passcode. */
  verifyWhatsAppOtp: (
    phone: string,
    code: string,
  ) => Promise<
    import("@stwd/sdk").StewardAuthResult | import("@stwd/sdk").StewardMfaRequiredResult
  >;
  /** Verify a magic link callback token. */
  verifyEmailCallback: (
    token: string,
    email: string,
  ) => Promise<
    import("@stwd/sdk").StewardAuthResult | import("@stwd/sdk").StewardMfaRequiredResult
  >;
  /** Sign in with an Ethereum wallet via SIWE. */
  signInWithSIWE: (
    address: string,
    signMessage: (msg: string) => Promise<string>,
  ) => Promise<
    import("@stwd/sdk").StewardAuthResult | import("@stwd/sdk").StewardMfaRequiredResult
  >;
  /**
   * Sign in with a Solana wallet via SIWS (Sign-In With Solana).
   * Optional: present only when the underlying SDK supports it. When undefined,
   * Solana wallet sign-in is disabled at runtime.
   */
  signInWithSolana?: (
    publicKey: string,
    signMessage: (msg: Uint8Array) => Promise<Uint8Array>,
  ) => Promise<
    import("@stwd/sdk").StewardAuthResult | import("@stwd/sdk").StewardMfaRequiredResult
  >;
  /** Sign in with an OAuth provider (Google, Discord, etc.) */
  signInWithOAuth: (
    provider: string,
    config?: { redirectUri?: string; tenantId?: string },
  ) => Promise<
    import("@stwd/sdk").StewardAuthResult | import("@stwd/sdk").StewardMfaRequiredResult
  >;
  /** Verify a Telegram Login Widget payload and create a Steward session. */
  signInWithTelegram: (
    payload: import("@stwd/sdk").StewardTelegramLoginPayload,
    config?: import("@stwd/sdk").StewardTelegramLoginConfig,
  ) => Promise<
    import("@stwd/sdk").StewardAuthResult | import("@stwd/sdk").StewardMfaRequiredResult
  >;
  /** Verify a Farcaster SIWF payload and create a Steward session. */
  signInWithFarcaster: (
    payload: import("@stwd/sdk").StewardFarcasterLoginPayload,
    config?: import("@stwd/sdk").StewardFarcasterLoginConfig,
  ) => Promise<
    import("@stwd/sdk").StewardAuthResult | import("@stwd/sdk").StewardMfaRequiredResult
  >;
  getIdentityToken: () => Promise<import("@stwd/sdk").StewardIdentityTokenResult>;
  getTotpStatus: () => Promise<import("@stwd/sdk").StewardTotpStatus>;
  enrollTotp: () => Promise<import("@stwd/sdk").StewardTotpEnrollResult>;
  verifyTotp: (code: string) => Promise<import("@stwd/sdk").StewardTotpVerifyResult>;
  completeTotpMfa: (
    challengeId: string,
    code: string,
  ) => Promise<import("@stwd/sdk").StewardAuthResult>;
  completeRecoveryCodeMfa: (
    challengeId: string,
    recoveryCode: string,
  ) => Promise<import("@stwd/sdk").StewardAuthResult>;
  getRecoveryCodeStatus: () => Promise<import("@stwd/sdk").StewardRecoveryCodeStatus>;
  regenerateRecoveryCodes: (
    code: string,
  ) => Promise<import("@stwd/sdk").StewardRecoveryCodesResult>;
  unenrollTotp: (code: string) => Promise<{ ok: boolean }>;
  getSmsMfaStatus: () => Promise<import("@stwd/sdk").StewardSmsMfaStatus>;
  enrollSmsMfa: (phone: string) => Promise<import("@stwd/sdk").StewardSmsMfaEnrollResult>;
  verifySmsMfa: (code: string) => Promise<import("@stwd/sdk").StewardSmsMfaVerifyResult>;
  sendSmsMfaCode: () => Promise<import("@stwd/sdk").StewardSmsMfaEnrollResult>;
  completeSmsMfa: (
    challengeId: string,
    code: string,
  ) => Promise<import("@stwd/sdk").StewardAuthResult>;
  completePasskeyMfa: () => Promise<import("@stwd/sdk").StewardAuthResult>;
  unenrollSmsMfa: (code: string) => Promise<{ ok: boolean }>;
  // ─── Multi-Tenant ───
  /** Currently active tenant ID from session */
  activeTenantId: string | null;
  /** Cached list of user's tenant memberships (null = not fetched yet) */
  tenants: StewardTenantMembership[] | null;
  /** Whether tenant list is currently being fetched */
  isTenantsLoading: boolean;
  /** Fetch or refresh the user's tenant memberships */
  listTenants: () => Promise<StewardTenantMembership[]>;
  /** Switch the active tenant context. Returns true on success. */
  switchTenant: (tenantId: string) => Promise<boolean>;
  /** Join a tenant (if open join mode). Returns the new membership. */
  joinTenant: (tenantId: string) => Promise<StewardTenantMembership>;
  /** Leave a tenant. Cannot leave personal tenant. */
  leaveTenant: (tenantId: string) => Promise<void>;
}

// ─── Auth Component Props ───

export interface StewardLoginProps {
  onSuccess?: (
    result:
      | { token: string; user: import("@stwd/sdk").StewardUser }
      | import("@stwd/sdk").StewardMfaRequiredResult,
  ) => void;
  onError?: (error: Error) => void;
  showPasskey?: boolean;
  showEmail?: boolean;
  showSms?: boolean;
  showWhatsApp?: boolean;
  showSIWE?: boolean;
  /**
   * First-class wallet sign-in (SIWE / SIWS).
   *
   * - `true`  - render both EVM and Solana wallet panels (subject to provider feature-detect).
   * - `false` (default) - hide both. Backwards-compatible.
   * - `{ evm: true }` - only EVM.
   * - `{ solana: true }` - only Solana.
   *
   * Backend feature flags from `GET /v1/auth/providers` (`siwe`, `siws`) act
   * as a hard gate: if the backend reports `siwe: false`, the EVM button is
   * hidden regardless of this prop.
   *
   * Requires the consumer to wrap the app in the matching wallet provider
   * (see `EVMWalletProvider` and `SolanaWalletProvider` from `@stwd/react/wallet`).
   */
  showWallets?: boolean | { evm?: boolean; solana?: boolean };
  showGoogle?: boolean;
  showDiscord?: boolean;
  showGithub?: boolean;
  showTwitter?: boolean;
  /**
   * Show Telegram login when the API reports Telegram is enabled.
   * Provide `getTelegramLoginPayload` from Telegram's official login widget
   * callback; the component exchanges that signed payload with Steward.
   */
  showTelegram?: boolean;
  getTelegramLoginPayload?: () =>
    | import("@stwd/sdk").StewardTelegramLoginPayload
    | Promise<import("@stwd/sdk").StewardTelegramLoginPayload>;
  /**
   * Show Farcaster login when the API reports Farcaster is enabled.
   * Provide `getFarcasterLoginPayload` from a SIWF-capable client flow.
   */
  showFarcaster?: boolean;
  getFarcasterLoginPayload?: () =>
    | import("@stwd/sdk").StewardFarcasterLoginPayload
    | Promise<import("@stwd/sdk").StewardFarcasterLoginPayload>;
  /** "card" adds bg/border/padding wrapper; "inline" renders with no container styling */
  variant?: "card" | "inline";
  /** Custom logo element rendered at top of the login widget */
  logo?: React.ReactNode;
  /** Title text (e.g. "sign in", "welcome back"). */
  title?: string;
  /** Subtitle text below the title */
  subtitle?: string;
  /** Called when an OAuth provider button is clicked (for custom handling) */
  onProviderClick?: (provider: string) => void;
  /** Tenant ID to authenticate against (passed through to sign-in methods) */
  tenantId?: string;
  className?: string;
}

export interface StewardAuthGuardProps {
  children: React.ReactNode;
  fallback?: React.ReactNode;
  loadingFallback?: React.ReactNode;
}

export interface StewardUserButtonProps {
  className?: string;
  onSignOut?: () => void;
  showWallet?: boolean;
  avatarSize?: number;
  /** Show an inline tenant switcher in the dropdown (default: false) */
  showTenantSwitcher?: boolean;
}

export interface StewardEmailCallbackProps {
  onSuccess?: (
    result:
      | { token: string; user: import("@stwd/sdk").StewardUser }
      | import("@stwd/sdk").StewardMfaRequiredResult,
  ) => void;
  onError?: (error: Error) => void;
  redirectTo?: string;
}

export interface StewardOAuthCallbackProps {
  onSuccess?: (
    result:
      | { token: string; user: import("@stwd/sdk").StewardUser }
      | { code: string; state: string },
  ) => void;
  onError?: (error: Error) => void;
  redirectTo?: string;
  provider?: string;
}

export interface StewardMfaChallengeProps {
  challenge: import("@stwd/sdk").StewardMfaRequiredResult["mfa"];
  onSuccess?: (result: import("@stwd/sdk").StewardAuthResult) => void;
  onError?: (error: Error) => void;
  allowRecoveryCode?: boolean;
  className?: string;
}

export interface StewardMfaSettingsProps {
  onRecoveryCodes?: (codes: string[]) => void;
  onError?: (error: Error) => void;
  className?: string;
}

// ─── Tenant Picker Props ───

export interface StewardTenantPickerProps {
  /** Callback after a tenant switch completes */
  onSwitch?: (tenantId: string) => void;
  /** Display variant: "dropdown" (compact, click to expand) or "list" (always visible) */
  variant?: "dropdown" | "list";
  className?: string;
}
