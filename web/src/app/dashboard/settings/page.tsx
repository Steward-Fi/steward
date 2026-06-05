"use client";

import { useAuth as useStewardAuth } from "@stwd/react";
import { motion } from "framer-motion";
import { useEffect, useState } from "react";
import { useAuth } from "@/components/auth-provider";
import { CodeBlock } from "@/components/code-block";
import { CopyButton } from "@/components/copy-button";
import {
  API_URL,
  type GasSponsorshipMode,
  type GasSponsorshipProvider,
  getTenantGasSponsorshipConfig,
  getTenantIdempotencyMetrics,
  getTenantSecurityChecklist,
  listTenantRequestSigningKeys,
  revokeTenantRequestSigningKey,
  rotateTenantRequestSigningKey,
  type TenantGasSponsorshipConfig,
  type TenantIdempotencyMetrics,
  type TenantRequestSigningKey,
  type TenantRequestSigningKeyCreateResult,
  type TenantSecurityChecklist,
  updateTenantGasSponsorshipConfig,
} from "@/lib/api";

const CHAIN_NAMES: Record<number, string> = {
  1: "Ethereum",
  137: "Polygon",
  8453: "Base",
  42161: "Arbitrum",
  56: "BNB Chain",
};

type OidcProviderForm = {
  id: string;
  enabled: boolean;
  issuer: string;
  audience: string;
  jwksUri: string;
  clientId: string;
  clientSecretEnv: string;
  authorizationUrl: string;
  tokenUrl: string;
  scopes: string;
  allowedAlgs: "RS256" | "ES256";
  allowJitProvisioning: boolean;
};

type TestAccount = {
  enabled?: boolean;
  email?: string;
  phone?: string;
  otp?: string;
  updatedAt?: string;
};

type AuthAbuseForm = {
  loginPasskey: boolean;
  loginEmail: boolean;
  loginSms: boolean;
  loginWhatsapp: boolean;
  loginTotp: boolean;
  loginSiwe: boolean;
  loginSiws: boolean;
  loginTelegram: boolean;
  loginFarcaster: boolean;
  oauthGoogle: boolean;
  oauthDiscord: boolean;
  oauthGithub: boolean;
  oauthTwitter: boolean;
  captchaEnabled: boolean;
  captchaProvider: "turnstile" | "hcaptcha";
  captchaSiteKey: string;
  captchaSecretKeyEnv: string;
  captchaEmailOtp: boolean;
  captchaSmsOtp: boolean;
  blockDisposable: boolean;
  blockPlusAliases: boolean;
  allowedEmails: string;
  blockedEmails: string;
  allowedDomains: string;
  blockedDomains: string;
  allowedWallets: string;
  blockedWallets: string;
  restrictToOneThirdPartyWallet: boolean;
  blockVoip: boolean;
  allowedCountryCodes: string;
  blockedCountryCodes: string;
  mfaMaxAgeSeconds: string;
  mfaVaultSigning: boolean;
  mfaKeyImport: boolean;
  mfaKeyExport: boolean;
  mfaRecoveryCodes: boolean;
  mfaTenantAdmin: boolean;
  mfaAllowDelegatedSignerAutomation: boolean;
  mfaAllowKeyQuorumAutomation: boolean;
};

type GasSponsorshipForm = {
  enabled: boolean;
  provider: GasSponsorshipProvider | "";
  mode: GasSponsorshipMode | "";
  allowedChainIds: string;
  maxPerTxUsd: string;
  allowClientSponsorship: boolean;
  requireSimulation: boolean;
  circuitBreakerEnabled: boolean;
};

type EmbeddedWalletCreateOnLogin = "off" | "users-without-wallets" | "all-users";
type AppClientEmbeddedWalletCreateOnLogin = "inherit" | EmbeddedWalletCreateOnLogin;

type ThemeForm = {
  primaryColor: string;
  accentColor: string;
  backgroundColor: string;
  surfaceColor: string;
  textColor: string;
  mutedColor: string;
  successColor: string;
  errorColor: string;
  warningColor: string;
  borderRadius: string;
  fontFamily: string;
  colorScheme: "light" | "dark" | "system";
  logoUrl: string;
  faviconUrl: string;
};

type ThemeConfigInput = Partial<Omit<ThemeForm, "borderRadius">> & {
  borderRadius?: number | string;
};

type AppClientEnvironment = "development" | "preview" | "staging" | "production";

type AppClientForm = {
  id: string;
  name: string;
  environment: AppClientEnvironment;
  enabled: boolean;
  allowedOrigins: string;
  allowedRedirectUrls: string;
  loginPasskey: boolean;
  loginEmail: boolean;
  loginSms: boolean;
  loginWhatsapp: boolean;
  loginTotp: boolean;
  loginSiwe: boolean;
  loginSiws: boolean;
  loginTelegram: boolean;
  loginFarcaster: boolean;
  oauthGoogle: boolean;
  oauthDiscord: boolean;
  oauthGithub: boolean;
  oauthTwitter: boolean;
  embeddedWalletCreateOnLogin: AppClientEmbeddedWalletCreateOnLogin;
  globalWalletEnabled: boolean;
  globalWalletAllowedScopes: string;
};

type RotatedAppClientSecret = {
  appId: string;
  appSecret: string;
  secretPrefix: string;
};

type TenantSsoDomain = {
  id: string;
  tenantId: string;
  domain: string;
  verificationToken: string;
  status: "pending" | "verified";
  ssoRequired: boolean;
  verifiedAt: string | null;
  createdAt: string;
  updatedAt: string;
};

type SamlServiceProvider = {
  spEntityId: string;
  acsUrl: string;
  metadataUrl: string;
};

type SamlSsoConfig = {
  tenantId: string;
  enabled: boolean;
  status: "pending" | "active" | "error";
  idpEntityId: string;
  idpSsoUrl: string;
  idpCertPems: string[];
  spEntityId: string;
  acsUrl: string;
  nameIdFormat?: string;
  emailAttribute: string;
  groupsAttribute?: string;
  groupRoleMappings: Array<{
    group: string;
    role: "admin" | "developer" | "billing" | "viewer" | "member";
  }>;
  allowJitProvisioning: boolean;
  jitDefaultRole: "viewer";
  lastTestedAt?: string | null;
  createdAt: string;
  updatedAt: string;
};

type SamlSsoForm = {
  enabled: boolean;
  idpEntityId: string;
  idpSsoUrl: string;
  idpCertPems: string;
  emailAttribute: string;
  groupsAttribute: string;
  groupRoleMappings: string;
  allowJitProvisioning: boolean;
};

type AccessAllowlistEntryType = "email" | "email_domain" | "wallet" | "phone";

type AccessAllowlistEntry = {
  id: string;
  tenantId: string;
  type: AccessAllowlistEntryType;
  value: string;
  acceptedAt: string | null;
};

const ACCESS_ALLOWLIST_TYPES: Array<{
  value: AccessAllowlistEntryType;
  label: string;
  placeholder: string;
}> = [
  { value: "email", label: "Email", placeholder: "alice@example.com" },
  { value: "email_domain", label: "Email Domain", placeholder: "example.com" },
  { value: "wallet", label: "Wallet", placeholder: "0x... or solana:..." },
  { value: "phone", label: "Phone", placeholder: "+14155550100" },
];

const GAS_SPONSORSHIP_PROVIDERS: Array<{ value: GasSponsorshipProvider; label: string }> = [
  { value: "custom_evm_paymaster", label: "Custom EVM Paymaster" },
  { value: "custom_bundler", label: "Custom Bundler" },
  { value: "solana_fee_payer", label: "Solana Fee Payer" },
  { value: "mock", label: "Mock" },
];

const GAS_SPONSORSHIP_MODES: Array<{ value: GasSponsorshipMode; label: string }> = [
  { value: "erc4337", label: "ERC-4337" },
  { value: "eip7702", label: "EIP-7702" },
  { value: "solana_fee_payer", label: "Solana Fee Payer" },
];

const THEME_COLOR_FIELDS: Array<{ key: keyof ThemeForm; label: string }> = [
  { key: "primaryColor", label: "Primary" },
  { key: "accentColor", label: "Accent" },
  { key: "backgroundColor", label: "Background" },
  { key: "surfaceColor", label: "Surface" },
  { key: "textColor", label: "Text" },
  { key: "mutedColor", label: "Muted" },
  { key: "successColor", label: "Success" },
  { key: "errorColor", label: "Error" },
  { key: "warningColor", label: "Warning" },
];

const APP_CLIENT_ENVIRONMENTS: Array<{ value: AppClientEnvironment; label: string }> = [
  { value: "development", label: "Development" },
  { value: "preview", label: "Preview" },
  { value: "staging", label: "Staging" },
  { value: "production", label: "Production" },
];

const EMBEDDED_WALLET_CREATE_ON_LOGIN_OPTIONS: Array<{
  value: EmbeddedWalletCreateOnLogin;
  label: string;
  description: string;
}> = [
  {
    value: "off",
    label: "Do not create automatically",
    description: "Users create embedded wallets only from explicit wallet flows.",
  },
  {
    value: "users-without-wallets",
    label: "Create when missing",
    description: "Create one embedded wallet after login only when the user has none.",
  },
  {
    value: "all-users",
    label: "Ensure every login",
    description: "Re-check on each login and create the embedded wallet when absent.",
  },
];

const APP_CLIENT_EMBEDDED_WALLET_CREATE_ON_LOGIN_OPTIONS: Array<{
  value: AppClientEmbeddedWalletCreateOnLogin;
  label: string;
  description: string;
}> = [
  {
    value: "inherit",
    label: "Inherit tenant policy",
    description: "Use the tenant-wide embedded wallet creation setting.",
  },
  ...EMBEDDED_WALLET_CREATE_ON_LOGIN_OPTIONS,
];

const emptyOidcProvider = (): OidcProviderForm => ({
  id: "",
  enabled: true,
  issuer: "",
  audience: "",
  jwksUri: "",
  clientId: "",
  clientSecretEnv: "",
  authorizationUrl: "",
  tokenUrl: "",
  scopes: "openid\nemail\nprofile",
  allowedAlgs: "RS256",
  allowJitProvisioning: true,
});

const emptySamlSsoForm = (): SamlSsoForm => ({
  enabled: false,
  idpEntityId: "",
  idpSsoUrl: "",
  idpCertPems: "",
  emailAttribute: "email",
  groupsAttribute: "",
  groupRoleMappings: "[]",
  allowJitProvisioning: false,
});

function samlFormFromConfig(config: SamlSsoConfig | null): SamlSsoForm {
  if (!config) return emptySamlSsoForm();
  return {
    enabled: config.enabled,
    idpEntityId: config.idpEntityId,
    idpSsoUrl: config.idpSsoUrl,
    idpCertPems: config.idpCertPems.join("\n\n"),
    emailAttribute: config.emailAttribute,
    groupsAttribute: config.groupsAttribute ?? "",
    groupRoleMappings: JSON.stringify(config.groupRoleMappings ?? [], null, 2),
    allowJitProvisioning: config.allowJitProvisioning,
  };
}

const emptyAuthAbuseForm = (): AuthAbuseForm => ({
  loginPasskey: true,
  loginEmail: true,
  loginSms: true,
  loginWhatsapp: true,
  loginTotp: true,
  loginSiwe: true,
  loginSiws: true,
  loginTelegram: true,
  loginFarcaster: true,
  oauthGoogle: true,
  oauthDiscord: true,
  oauthGithub: true,
  oauthTwitter: true,
  captchaEnabled: false,
  captchaProvider: "turnstile",
  captchaSiteKey: "",
  captchaSecretKeyEnv: "",
  captchaEmailOtp: true,
  captchaSmsOtp: true,
  blockDisposable: false,
  blockPlusAliases: false,
  allowedEmails: "",
  blockedEmails: "",
  allowedDomains: "",
  blockedDomains: "",
  allowedWallets: "",
  blockedWallets: "",
  restrictToOneThirdPartyWallet: false,
  blockVoip: false,
  allowedCountryCodes: "",
  blockedCountryCodes: "",
  mfaMaxAgeSeconds: "300",
  mfaVaultSigning: true,
  mfaKeyImport: true,
  mfaKeyExport: true,
  mfaRecoveryCodes: true,
  mfaTenantAdmin: true,
  mfaAllowDelegatedSignerAutomation: true,
  mfaAllowKeyQuorumAutomation: true,
});

const defaultThemeForm = (): ThemeForm => ({
  primaryColor: "#D4A054",
  accentColor: "#A78BFA",
  backgroundColor: "#0F0F0F",
  surfaceColor: "#1A1A2E",
  textColor: "#FAFAFA",
  mutedColor: "#6B7280",
  successColor: "#10B981",
  errorColor: "#EF4444",
  warningColor: "#F59E0B",
  borderRadius: "8",
  fontFamily: "Inter, system-ui, sans-serif",
  colorScheme: "dark",
  logoUrl: "",
  faviconUrl: "",
});

const emptyGasSponsorshipForm = (): GasSponsorshipForm => ({
  enabled: false,
  provider: "",
  mode: "",
  allowedChainIds: "",
  maxPerTxUsd: "",
  allowClientSponsorship: false,
  requireSimulation: true,
  circuitBreakerEnabled: false,
});

const emptyAppClient = (): AppClientForm => ({
  id: "",
  name: "",
  environment: "development",
  enabled: true,
  allowedOrigins: "",
  allowedRedirectUrls: "",
  loginPasskey: true,
  loginEmail: true,
  loginSms: true,
  loginWhatsapp: true,
  loginTotp: true,
  loginSiwe: true,
  loginSiws: true,
  loginTelegram: true,
  loginFarcaster: true,
  oauthGoogle: true,
  oauthDiscord: true,
  oauthGithub: true,
  oauthTwitter: true,
  embeddedWalletCreateOnLogin: "inherit",
  globalWalletEnabled: false,
  globalWalletAllowedScopes: "eth_accounts\npersonal_sign",
});

function listToLines(value: string[] | undefined): string {
  return (value ?? []).join("\n");
}

function linesToList(value: string): string[] {
  return value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function embeddedWalletCreateOnLoginFromConfig(value: unknown): EmbeddedWalletCreateOnLogin {
  if (value === "users-without-wallets" || value === "all-users") return value;
  return "off";
}

function appClientEmbeddedWalletCreateOnLoginFromConfig(
  value: unknown,
): AppClientEmbeddedWalletCreateOnLogin {
  if (value === undefined || value === null) return "inherit";
  return embeddedWalletCreateOnLoginFromConfig(value);
}

function linesToNumberList(value: string): number[] {
  return value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean)
    .map((item) => Number(item))
    .filter((item) => Number.isSafeInteger(item) && item > 0);
}

function appClientFormFromConfig(client: any): AppClientForm {
  const environment = APP_CLIENT_ENVIRONMENTS.some((item) => item.value === client?.environment)
    ? client.environment
    : "development";
  const loginMethods = client?.loginMethods ?? {};
  const oauth = loginMethods.oauth ?? {};
  return {
    id: typeof client?.id === "string" ? client.id : "",
    name: typeof client?.name === "string" ? client.name : "",
    environment,
    enabled: client?.enabled !== false,
    allowedOrigins: listToLines(client?.allowedOrigins),
    allowedRedirectUrls: listToLines(client?.allowedRedirectUrls),
    loginPasskey: loginMethods.passkey !== false,
    loginEmail: loginMethods.email !== false,
    loginSms: loginMethods.sms !== false,
    loginWhatsapp: loginMethods.whatsapp !== false,
    loginTotp: loginMethods.totp !== false,
    loginSiwe: loginMethods.siwe !== false,
    loginSiws: loginMethods.siws !== false,
    loginTelegram: loginMethods.telegram !== false,
    loginFarcaster: loginMethods.farcaster !== false,
    oauthGoogle: oauth.google !== false,
    oauthDiscord: oauth.discord !== false,
    oauthGithub: oauth.github !== false,
    oauthTwitter: oauth.twitter !== false,
    embeddedWalletCreateOnLogin: appClientEmbeddedWalletCreateOnLoginFromConfig(
      client?.embeddedWallets?.createOnLogin,
    ),
    globalWalletEnabled: client?.globalWalletEnabled === true,
    globalWalletAllowedScopes: listToLines(
      Array.isArray(client?.globalWalletAllowedScopes)
        ? client.globalWalletAllowedScopes
        : ["eth_accounts", "personal_sign"],
    ),
  };
}

function appClientPayloadFromForm(client: AppClientForm) {
  const payload = {
    id: client.id.trim(),
    name: client.name.trim(),
    environment: client.environment,
    enabled: client.enabled,
    allowedOrigins: linesToList(client.allowedOrigins),
    allowedRedirectUrls: linesToList(client.allowedRedirectUrls),
    loginMethods: {
      passkey: client.loginPasskey,
      email: client.loginEmail,
      sms: client.loginSms,
      whatsapp: client.loginWhatsapp,
      totp: client.loginTotp,
      siwe: client.loginSiwe,
      siws: client.loginSiws,
      telegram: client.loginTelegram,
      farcaster: client.loginFarcaster,
      oauth: {
        google: client.oauthGoogle,
        discord: client.oauthDiscord,
        github: client.oauthGithub,
        twitter: client.oauthTwitter,
      },
    },
    globalWalletEnabled: client.globalWalletEnabled,
    globalWalletAllowedScopes: linesToList(client.globalWalletAllowedScopes),
  };
  if (client.embeddedWalletCreateOnLogin === "inherit") return payload;
  return {
    ...payload,
    embeddedWallets: {
      createOnLogin: client.embeddedWalletCreateOnLogin,
    },
  };
}

function themeFormFromConfig(theme: ThemeConfigInput | undefined): ThemeForm {
  const fallback = defaultThemeForm();
  return {
    ...fallback,
    ...Object.fromEntries(
      Object.entries(theme ?? {}).filter(([, value]) => value !== undefined && value !== null),
    ),
    borderRadius:
      typeof theme?.borderRadius === "number" ? String(theme.borderRadius) : fallback.borderRadius,
  } as ThemeForm;
}

function themePayloadFromForm(theme: ThemeForm) {
  return {
    primaryColor: theme.primaryColor.trim(),
    accentColor: theme.accentColor.trim(),
    backgroundColor: theme.backgroundColor.trim(),
    surfaceColor: theme.surfaceColor.trim(),
    textColor: theme.textColor.trim(),
    mutedColor: theme.mutedColor.trim(),
    successColor: theme.successColor.trim(),
    errorColor: theme.errorColor.trim(),
    warningColor: theme.warningColor.trim(),
    borderRadius: Number(theme.borderRadius),
    fontFamily: theme.fontFamily.trim(),
    colorScheme: theme.colorScheme,
    logoUrl: theme.logoUrl.trim(),
    faviconUrl: theme.faviconUrl.trim(),
  };
}

function accessAllowlistTypeLabel(type: AccessAllowlistEntryType): string {
  return ACCESS_ALLOWLIST_TYPES.find((item) => item.value === type)?.label ?? type;
}

function parseAccessAllowlistBulkEntries(
  value: string,
  fallbackType: AccessAllowlistEntryType,
): Array<{ type: AccessAllowlistEntryType; value: string }> {
  const validTypes = new Set<AccessAllowlistEntryType>(
    ACCESS_ALLOWLIST_TYPES.map((item) => item.value),
  );
  return value
    .split(/[\n;]/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const typed = line.match(/^(email_domain|email|wallet|phone)\s*[:,]\s*(.+)$/i);
      if (!typed) return { type: fallbackType, value: line };
      const type = typed[1].toLowerCase() as AccessAllowlistEntryType;
      return {
        type: validTypes.has(type) ? type : fallbackType,
        value: typed[2].trim(),
      };
    })
    .filter((entry) => entry.value.length > 0);
}

function authAbuseFormFromConfig(config: any): AuthAbuseForm {
  const captchaRequiredFor = new Set<string>(config?.captcha?.requiredFor ?? []);
  const loginMethods = config?.loginMethods ?? {};
  const oauth = loginMethods.oauth ?? {};
  return {
    loginPasskey: loginMethods.passkey !== false,
    loginEmail: loginMethods.email !== false,
    loginSms: loginMethods.sms !== false,
    loginWhatsapp: loginMethods.whatsapp !== false,
    loginTotp: loginMethods.totp !== false,
    loginSiwe: loginMethods.siwe !== false,
    loginSiws: loginMethods.siws !== false,
    loginTelegram: loginMethods.telegram !== false,
    loginFarcaster: loginMethods.farcaster !== false,
    oauthGoogle: oauth.google !== false,
    oauthDiscord: oauth.discord !== false,
    oauthGithub: oauth.github !== false,
    oauthTwitter: oauth.twitter !== false,
    captchaEnabled: config?.captcha?.enabled === true,
    captchaProvider: config?.captcha?.provider === "hcaptcha" ? "hcaptcha" : "turnstile",
    captchaSiteKey: config?.captcha?.siteKey ?? "",
    captchaSecretKeyEnv: config?.captcha?.secretKeyEnv ?? "",
    captchaEmailOtp: captchaRequiredFor.size === 0 ? true : captchaRequiredFor.has("email_otp"),
    captchaSmsOtp: captchaRequiredFor.size === 0 ? true : captchaRequiredFor.has("sms_otp"),
    blockDisposable: config?.email?.blockDisposable === true,
    blockPlusAliases: config?.email?.blockPlusAliases === true,
    allowedEmails: listToLines(config?.email?.allowedEmails),
    blockedEmails: listToLines(config?.email?.blockedEmails),
    allowedDomains: listToLines(config?.email?.allowedDomains),
    blockedDomains: listToLines(config?.email?.blockedDomains),
    allowedWallets: listToLines(config?.wallet?.allowedWallets),
    blockedWallets: listToLines(config?.wallet?.blockedWallets),
    restrictToOneThirdPartyWallet: config?.wallet?.restrictToOneThirdPartyWallet === true,
    blockVoip: config?.phone?.blockVoip === true,
    allowedCountryCodes: listToLines(config?.phone?.allowedCountryCodes),
    blockedCountryCodes: listToLines(config?.phone?.blockedCountryCodes),
    mfaMaxAgeSeconds:
      typeof config?.mfa?.maxAgeSeconds === "number" ? String(config.mfa.maxAgeSeconds) : "300",
    mfaVaultSigning: config?.mfa?.requireFor?.vaultSigning !== false,
    mfaKeyImport: config?.mfa?.requireFor?.keyImport !== false,
    mfaKeyExport: config?.mfa?.requireFor?.keyExport !== false,
    mfaRecoveryCodes: config?.mfa?.requireFor?.recoveryCodes !== false,
    mfaTenantAdmin: config?.mfa?.requireFor?.tenantAdmin !== false,
    mfaAllowDelegatedSignerAutomation: config?.mfa?.allowDelegatedSignerAutomation !== false,
    mfaAllowKeyQuorumAutomation: config?.mfa?.allowKeyQuorumAutomation !== false,
  };
}

function authAbusePayloadFromForm(form: AuthAbuseForm) {
  const requiredFor = [
    ...(form.captchaEmailOtp ? ["email_otp"] : []),
    ...(form.captchaSmsOtp ? ["sms_otp"] : []),
  ];
  const mfaMaxAgeSeconds = Number(form.mfaMaxAgeSeconds);
  return {
    loginMethods: {
      passkey: form.loginPasskey,
      email: form.loginEmail,
      sms: form.loginSms,
      whatsapp: form.loginWhatsapp,
      totp: form.loginTotp,
      siwe: form.loginSiwe,
      siws: form.loginSiws,
      telegram: form.loginTelegram,
      farcaster: form.loginFarcaster,
      oauth: {
        google: form.oauthGoogle,
        discord: form.oauthDiscord,
        github: form.oauthGithub,
        twitter: form.oauthTwitter,
      },
    },
    captcha: {
      enabled: form.captchaEnabled,
      provider: form.captchaProvider,
      siteKey: form.captchaSiteKey.trim() || undefined,
      secretKeyEnv: form.captchaSecretKeyEnv.trim() || undefined,
      requiredFor,
    },
    email: {
      blockDisposable: form.blockDisposable,
      blockPlusAliases: form.blockPlusAliases,
      allowedEmails: linesToList(form.allowedEmails),
      blockedEmails: linesToList(form.blockedEmails),
      allowedDomains: linesToList(form.allowedDomains),
      blockedDomains: linesToList(form.blockedDomains),
    },
    wallet: {
      allowedWallets: linesToList(form.allowedWallets),
      blockedWallets: linesToList(form.blockedWallets),
      restrictToOneThirdPartyWallet: form.restrictToOneThirdPartyWallet,
    },
    phone: {
      blockVoip: form.blockVoip,
      allowedCountryCodes: linesToList(form.allowedCountryCodes),
      blockedCountryCodes: linesToList(form.blockedCountryCodes),
    },
    mfa: {
      maxAgeSeconds:
        Number.isSafeInteger(mfaMaxAgeSeconds) && mfaMaxAgeSeconds > 0
          ? mfaMaxAgeSeconds
          : undefined,
      requireFor: {
        vaultSigning: form.mfaVaultSigning,
        keyImport: form.mfaKeyImport,
        keyExport: form.mfaKeyExport,
        recoveryCodes: form.mfaRecoveryCodes,
        tenantAdmin: form.mfaTenantAdmin,
      },
      allowDelegatedSignerAutomation: form.mfaAllowDelegatedSignerAutomation,
      allowKeyQuorumAutomation: form.mfaAllowKeyQuorumAutomation,
    },
  };
}

function gasSponsorshipFormFromConfig(config: TenantGasSponsorshipConfig): GasSponsorshipForm {
  return {
    enabled: config.enabled === true,
    provider: config.provider ?? "",
    mode: config.mode ?? "",
    allowedChainIds: listToLines((config.allowedChainIds ?? []).map((chainId) => String(chainId))),
    maxPerTxUsd: config.maxPerTxUsd === undefined ? "" : String(config.maxPerTxUsd),
    allowClientSponsorship: config.allowClientSponsorship === true,
    requireSimulation: config.requireSimulation !== false,
    circuitBreakerEnabled: config.circuitBreakerEnabled === true,
  };
}

function gasSponsorshipPayloadFromForm(form: GasSponsorshipForm): TenantGasSponsorshipConfig {
  const maxPerTxUsd = form.maxPerTxUsd.trim() === "" ? undefined : Number(form.maxPerTxUsd);
  return {
    enabled: form.enabled,
    provider: form.provider || undefined,
    mode: form.mode || undefined,
    allowedChainIds: linesToNumberList(form.allowedChainIds),
    maxPerTxUsd:
      maxPerTxUsd !== undefined && Number.isFinite(maxPerTxUsd) ? maxPerTxUsd : undefined,
    allowClientSponsorship: form.allowClientSponsorship,
    requireSimulation: form.requireSimulation,
    circuitBreakerEnabled: form.circuitBreakerEnabled,
  };
}

function gasSponsorshipProviderLabel(provider: GasSponsorshipProvider | ""): string {
  if (!provider) return "No Provider";
  return (
    GAS_SPONSORSHIP_PROVIDERS.find((providerOption) => providerOption.value === provider)?.label ??
    provider
  );
}

function securityChecklistStatusClass(status: "pass" | "warning" | "fail") {
  if (status === "pass") return "text-emerald-400 border-emerald-500/30 bg-emerald-500/10";
  if (status === "warning") return "text-amber-300 border-amber-500/30 bg-amber-500/10";
  return "text-red-400 border-red-500/30 bg-red-500/10";
}

function securityChecklistStatusLabel(status: "pass" | "warning" | "fail") {
  if (status === "pass") return "Pass";
  if (status === "warning") return "Review";
  return "Fail";
}

export default function SettingsPage() {
  const stewardAuth = useStewardAuth();
  const { address, tenant } = useAuth();
  const authToken = stewardAuth.getToken();
  const chainId = 8453; // Base mainnet
  const [webhookUrl, setWebhookUrl] = useState("");
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [showKey, setShowKey] = useState(false);
  const [oidcProviders, setOidcProviders] = useState<OidcProviderForm[]>([]);
  const [oidcLoading, setOidcLoading] = useState(false);
  const [oidcSaving, setOidcSaving] = useState(false);
  const [oidcSaved, setOidcSaved] = useState(false);
  const [oidcError, setOidcError] = useState<string | null>(null);
  const [testAccount, setTestAccount] = useState<TestAccount>({ enabled: false });
  const [testAccountLoading, setTestAccountLoading] = useState(false);
  const [testAccountSaving, setTestAccountSaving] = useState(false);
  const [testAccountError, setTestAccountError] = useState<string | null>(null);
  const [authAbuse, setAuthAbuse] = useState<AuthAbuseForm>(emptyAuthAbuseForm);
  const [authAbuseLoading, setAuthAbuseLoading] = useState(false);
  const [authAbuseSaving, setAuthAbuseSaving] = useState(false);
  const [authAbuseSaved, setAuthAbuseSaved] = useState(false);
  const [authAbuseError, setAuthAbuseError] = useState<string | null>(null);
  const [gasSponsorship, setGasSponsorship] = useState<GasSponsorshipForm>(emptyGasSponsorshipForm);
  const [gasSponsorshipLoading, setGasSponsorshipLoading] = useState(false);
  const [gasSponsorshipSaving, setGasSponsorshipSaving] = useState(false);
  const [gasSponsorshipSaved, setGasSponsorshipSaved] = useState(false);
  const [gasSponsorshipError, setGasSponsorshipError] = useState<string | null>(null);
  const [securityChecklist, setSecurityChecklist] = useState<TenantSecurityChecklist | null>(null);
  const [securityChecklistLoading, setSecurityChecklistLoading] = useState(false);
  const [securityChecklistError, setSecurityChecklistError] = useState<string | null>(null);
  const [idempotencyMetrics, setIdempotencyMetrics] = useState<TenantIdempotencyMetrics | null>(
    null,
  );
  const [idempotencyMetricsLoading, setIdempotencyMetricsLoading] = useState(false);
  const [idempotencyMetricsError, setIdempotencyMetricsError] = useState<string | null>(null);
  const [idempotencyExportSaving, setIdempotencyExportSaving] = useState(false);
  const [requestSigningKeys, setRequestSigningKeys] = useState<TenantRequestSigningKey[]>([]);
  const [requestSigningKeyName, setRequestSigningKeyName] = useState("Production signing key");
  const [requestSigningKeyReveal, setRequestSigningKeyReveal] =
    useState<TenantRequestSigningKeyCreateResult | null>(null);
  const [requestSigningKeysLoading, setRequestSigningKeysLoading] = useState(false);
  const [requestSigningKeysSaving, setRequestSigningKeysSaving] = useState(false);
  const [requestSigningKeysError, setRequestSigningKeysError] = useState<string | null>(null);
  const [theme, setTheme] = useState<ThemeForm>(defaultThemeForm);
  const [themeSaving, setThemeSaving] = useState(false);
  const [themeSaved, setThemeSaved] = useState(false);
  const [themeError, setThemeError] = useState<string | null>(null);
  const [allowedOrigins, setAllowedOrigins] = useState("");
  const [originsLoading, setOriginsLoading] = useState(false);
  const [originsSaving, setOriginsSaving] = useState(false);
  const [originsSaved, setOriginsSaved] = useState(false);
  const [originsError, setOriginsError] = useState<string | null>(null);
  const [allowedRedirectUrls, setAllowedRedirectUrls] = useState("");
  const [redirectUrlsSaving, setRedirectUrlsSaving] = useState(false);
  const [redirectUrlsSaved, setRedirectUrlsSaved] = useState(false);
  const [redirectUrlsError, setRedirectUrlsError] = useState<string | null>(null);
  const [appClients, setAppClients] = useState<AppClientForm[]>([]);
  const [appClientsSaving, setAppClientsSaving] = useState(false);
  const [appClientsSaved, setAppClientsSaved] = useState(false);
  const [appClientsError, setAppClientsError] = useState<string | null>(null);
  const [appClientSecrets, setAppClientSecrets] = useState<Record<string, RotatedAppClientSecret>>(
    {},
  );
  const [appClientSecretRotating, setAppClientSecretRotating] = useState<string | null>(null);
  const [embeddedWalletCreateOnLogin, setEmbeddedWalletCreateOnLogin] =
    useState<EmbeddedWalletCreateOnLogin>("off");
  const [embeddedWalletSaving, setEmbeddedWalletSaving] = useState(false);
  const [embeddedWalletSaved, setEmbeddedWalletSaved] = useState(false);
  const [embeddedWalletError, setEmbeddedWalletError] = useState<string | null>(null);
  const [ssoDomains, setSsoDomains] = useState<TenantSsoDomain[]>([]);
  const [ssoDomainValue, setSsoDomainValue] = useState("");
  const [ssoDomainRequired, setSsoDomainRequired] = useState(true);
  const [ssoDomainsLoading, setSsoDomainsLoading] = useState(false);
  const [ssoDomainsSaving, setSsoDomainsSaving] = useState(false);
  const [ssoDomainsSaved, setSsoDomainsSaved] = useState(false);
  const [ssoDomainsError, setSsoDomainsError] = useState<string | null>(null);
  const [ssoDomainVerifying, setSsoDomainVerifying] = useState<string | null>(null);
  const [samlSso, setSamlSso] = useState<SamlSsoForm>(emptySamlSsoForm);
  const [samlServiceProvider, setSamlServiceProvider] = useState<SamlServiceProvider | null>(null);
  const [samlSsoLoading, setSamlSsoLoading] = useState(false);
  const [samlSsoSaving, setSamlSsoSaving] = useState(false);
  const [samlSsoSaved, setSamlSsoSaved] = useState(false);
  const [samlSsoError, setSamlSsoError] = useState<string | null>(null);
  const [accessAllowlist, setAccessAllowlist] = useState<AccessAllowlistEntry[]>([]);
  const [accessAllowlistType, setAccessAllowlistType] = useState<AccessAllowlistEntryType>("email");
  const [accessAllowlistValue, setAccessAllowlistValue] = useState("");
  const [accessAllowlistBulkValue, setAccessAllowlistBulkValue] = useState("");
  const [accessAllowlistLoading, setAccessAllowlistLoading] = useState(false);
  const [accessAllowlistSaving, setAccessAllowlistSaving] = useState(false);
  const [accessAllowlistSaved, setAccessAllowlistSaved] = useState(false);
  const [accessAllowlistError, setAccessAllowlistError] = useState<string | null>(null);

  const TENANT_ID = tenant?.tenantId || "";
  const API_KEY = tenant?.apiKey || "";

  useEffect(() => {
    if (!TENANT_ID || !authToken) return;

    let cancelled = false;
    setOriginsLoading(true);
    setOriginsError(null);
    fetch(`${API_URL}/tenants/${encodeURIComponent(TENANT_ID)}/config`, {
      headers: { Authorization: `Bearer ${authToken}` },
    })
      .then(async (res) => {
        const data = await res.json();
        if (!res.ok || !data.ok) throw new Error(data.error || "Failed to load app origins");
        if (!cancelled) {
          setAllowedOrigins(listToLines(data.data.allowedOrigins ?? []));
          setAllowedRedirectUrls(listToLines(data.data.allowedRedirectUrls ?? []));
          setAppClients((data.data.appClients ?? []).map(appClientFormFromConfig));
          setTheme(themeFormFromConfig(data.data.theme));
          setEmbeddedWalletCreateOnLogin(
            embeddedWalletCreateOnLoginFromConfig(
              data.data.featureFlags?.embeddedWallets?.createOnLogin ??
                data.data.featureFlags?.embeddedWalletCreateOnLogin,
            ),
          );
        }
      })
      .catch((e: unknown) => {
        if (!cancelled) {
          setOriginsError(e instanceof Error ? e.message : "Failed to load app origins");
        }
      })
      .finally(() => {
        if (!cancelled) setOriginsLoading(false);
      });

    setAccessAllowlistLoading(true);
    setAccessAllowlistError(null);
    fetch(`${API_URL}/tenants/${encodeURIComponent(TENANT_ID)}/access-allowlist`, {
      headers: { Authorization: `Bearer ${authToken}` },
    })
      .then(async (res) => {
        const data = await res.json();
        if (!res.ok || !data.ok) {
          throw new Error(data.error || "Failed to load access allowlist");
        }
        if (!cancelled) setAccessAllowlist(data.data.entries ?? []);
      })
      .catch((e: unknown) => {
        if (!cancelled) {
          setAccessAllowlist([]);
          setAccessAllowlistError(
            e instanceof Error ? e.message : "Failed to load access allowlist",
          );
        }
      })
      .finally(() => {
        if (!cancelled) setAccessAllowlistLoading(false);
      });

    setSsoDomainsLoading(true);
    setSsoDomainsError(null);
    fetch(`${API_URL}/tenants/${encodeURIComponent(TENANT_ID)}/sso-domains`, {
      headers: { Authorization: `Bearer ${authToken}` },
    })
      .then(async (res) => {
        const data = await res.json();
        if (!res.ok || !data.ok) throw new Error(data.error || "Failed to load SSO domains");
        if (!cancelled) setSsoDomains(data.data.domains ?? []);
      })
      .catch((e: unknown) => {
        if (!cancelled) {
          setSsoDomains([]);
          setSsoDomainsError(e instanceof Error ? e.message : "Failed to load SSO domains");
        }
      })
      .finally(() => {
        if (!cancelled) setSsoDomainsLoading(false);
      });

    setSamlSsoLoading(true);
    setSamlSsoError(null);
    fetch(`${API_URL}/tenants/${encodeURIComponent(TENANT_ID)}/saml-sso`, {
      headers: { Authorization: `Bearer ${authToken}` },
    })
      .then(async (res) => {
        const data = await res.json();
        if (!res.ok || !data.ok) throw new Error(data.error || "Failed to load SAML SSO");
        if (!cancelled) {
          setSamlSso(samlFormFromConfig(data.data.config ?? null));
          setSamlServiceProvider(data.data.serviceProvider ?? null);
        }
      })
      .catch((e: unknown) => {
        if (!cancelled) {
          setSamlSso(emptySamlSsoForm());
          setSamlSsoError(e instanceof Error ? e.message : "Failed to load SAML SSO");
        }
      })
      .finally(() => {
        if (!cancelled) setSamlSsoLoading(false);
      });

    setAuthAbuseLoading(true);
    setAuthAbuseError(null);
    fetch(`${API_URL}/tenants/${encodeURIComponent(TENANT_ID)}/auth-abuse-config`, {
      headers: { Authorization: `Bearer ${authToken}` },
    })
      .then(async (res) => {
        const data = await res.json();
        if (!res.ok || !data.ok) throw new Error(data.error || "Failed to load login controls");
        if (!cancelled) {
          setAuthAbuse(authAbuseFormFromConfig(data.data.authAbuseConfig ?? {}));
        }
      })
      .catch((e: unknown) => {
        if (!cancelled) {
          setAuthAbuseError(e instanceof Error ? e.message : "Failed to load login controls");
        }
      })
      .finally(() => {
        if (!cancelled) setAuthAbuseLoading(false);
      });

    setGasSponsorshipLoading(true);
    setGasSponsorshipError(null);
    getTenantGasSponsorshipConfig(TENANT_ID, authToken)
      .then((config) => {
        if (!cancelled) setGasSponsorship(gasSponsorshipFormFromConfig(config));
      })
      .catch((e: unknown) => {
        if (!cancelled) {
          setGasSponsorship(emptyGasSponsorshipForm());
          setGasSponsorshipError(
            e instanceof Error ? e.message : "Failed to load gas sponsorship config",
          );
        }
      })
      .finally(() => {
        if (!cancelled) setGasSponsorshipLoading(false);
      });

    setSecurityChecklistLoading(true);
    setSecurityChecklistError(null);
    getTenantSecurityChecklist(TENANT_ID, authToken)
      .then((checklist) => {
        if (!cancelled) setSecurityChecklist(checklist);
      })
      .catch((e: unknown) => {
        if (!cancelled) {
          setSecurityChecklist(null);
          setSecurityChecklistError(
            e instanceof Error ? e.message : "Failed to load security checklist",
          );
        }
      })
      .finally(() => {
        if (!cancelled) setSecurityChecklistLoading(false);
      });

    setIdempotencyMetricsLoading(true);
    setIdempotencyMetricsError(null);
    getTenantIdempotencyMetrics(TENANT_ID, authToken)
      .then((metrics) => {
        if (!cancelled) setIdempotencyMetrics(metrics);
      })
      .catch((e: unknown) => {
        if (!cancelled) {
          setIdempotencyMetrics(null);
          setIdempotencyMetricsError(
            e instanceof Error ? e.message : "Failed to load idempotency metrics",
          );
        }
      })
      .finally(() => {
        if (!cancelled) setIdempotencyMetricsLoading(false);
      });

    setRequestSigningKeysLoading(true);
    setRequestSigningKeysError(null);
    listTenantRequestSigningKeys(TENANT_ID, authToken)
      .then((keys) => {
        if (!cancelled) setRequestSigningKeys(keys);
      })
      .catch((e: unknown) => {
        if (!cancelled) {
          setRequestSigningKeys([]);
          setRequestSigningKeysError(
            e instanceof Error ? e.message : "Failed to load request signing keys",
          );
        }
      })
      .finally(() => {
        if (!cancelled) setRequestSigningKeysLoading(false);
      });

    setTestAccountLoading(true);
    setTestAccountError(null);
    fetch(`${API_URL}/tenants/${encodeURIComponent(TENANT_ID)}/test-account`, {
      headers: { Authorization: `Bearer ${authToken}` },
    })
      .then(async (res) => {
        const data = await res.json();
        if (!res.ok || !data.ok) throw new Error(data.error || "Failed to load test account");
        if (!cancelled) setTestAccount(data.data.testAccount ?? { enabled: false });
      })
      .catch((e: unknown) => {
        if (!cancelled) {
          setTestAccount({ enabled: false });
          setTestAccountError(e instanceof Error ? e.message : "Failed to load test account");
        }
      })
      .finally(() => {
        if (!cancelled) setTestAccountLoading(false);
      });

    setOidcLoading(true);
    setOidcError(null);
    fetch(`${API_URL}/tenants/${encodeURIComponent(TENANT_ID)}/oidc-providers`, {
      headers: { Authorization: `Bearer ${authToken}` },
    })
      .then(async (res) => {
        const data = await res.json();
        if (!res.ok || !data.ok) throw new Error(data.error || "Failed to load providers");
        if (cancelled) return;
        setOidcProviders(
          (data.data.providers ?? []).map(
            (provider: {
              id: string;
              enabled?: boolean;
              issuer: string;
              audience?: string[];
              jwksUri: string;
              clientId?: string;
              clientSecretEnv?: string;
              authorizationUrl?: string;
              tokenUrl?: string;
              scopes?: string[];
              allowedAlgs?: Array<"RS256" | "ES256">;
              allowJitProvisioning?: boolean;
            }) => ({
              id: provider.id,
              enabled: provider.enabled !== false,
              issuer: provider.issuer,
              audience: (provider.audience ?? []).join(", "),
              jwksUri: provider.jwksUri,
              clientId: provider.clientId ?? "",
              clientSecretEnv: provider.clientSecretEnv ?? "",
              authorizationUrl: provider.authorizationUrl ?? "",
              tokenUrl: provider.tokenUrl ?? "",
              scopes: listToLines(provider.scopes ?? ["openid", "email", "profile"]),
              allowedAlgs: provider.allowedAlgs?.[0] ?? "RS256",
              allowJitProvisioning: provider.allowJitProvisioning !== false,
            }),
          ),
        );
      })
      .catch((e: unknown) => {
        if (!cancelled) setOidcError(e instanceof Error ? e.message : "Failed to load providers");
      })
      .finally(() => {
        if (!cancelled) setOidcLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [TENANT_ID, authToken]);

  function updateAuthAbuse(patch: Partial<AuthAbuseForm>) {
    setAuthAbuse((current) => ({ ...current, ...patch }));
  }

  function updateGasSponsorship(patch: Partial<GasSponsorshipForm>) {
    setGasSponsorship((current) => ({ ...current, ...patch }));
  }

  async function saveGasSponsorship(e: React.FormEvent) {
    e.preventDefault();
    if (!TENANT_ID || !authToken) {
      setGasSponsorshipError("Sign in again to save gas sponsorship");
      return;
    }
    const payload = gasSponsorshipPayloadFromForm(gasSponsorship);
    if (gasSponsorship.enabled) {
      if (!payload.provider || !payload.mode) {
        setGasSponsorshipError("Choose a provider and mode before enabling sponsorship");
        return;
      }
      if ((payload.allowedChainIds ?? []).length === 0) {
        setGasSponsorshipError("Add at least one allowed chain ID before enabling sponsorship");
        return;
      }
      if (payload.maxPerTxUsd === undefined) {
        setGasSponsorshipError("Set a max USD per transaction before enabling sponsorship");
        return;
      }
    }

    setGasSponsorshipSaving(true);
    setGasSponsorshipSaved(false);
    setGasSponsorshipError(null);
    try {
      const config = await updateTenantGasSponsorshipConfig(TENANT_ID, authToken, payload);
      setGasSponsorship(gasSponsorshipFormFromConfig(config));
      setGasSponsorshipSaved(true);
      setTimeout(() => setGasSponsorshipSaved(false), 2000);
    } catch (e: unknown) {
      setGasSponsorshipError(
        e instanceof Error ? e.message : "Failed to save gas sponsorship config",
      );
    } finally {
      setGasSponsorshipSaving(false);
    }
  }

  async function saveAuthAbuseControls(e: React.FormEvent) {
    e.preventDefault();
    if (!TENANT_ID || !authToken) {
      setAuthAbuseError("Sign in again to save login controls");
      return;
    }
    setAuthAbuseSaving(true);
    setAuthAbuseSaved(false);
    setAuthAbuseError(null);
    try {
      const res = await fetch(
        `${API_URL}/tenants/${encodeURIComponent(TENANT_ID)}/auth-abuse-config`,
        {
          method: "PUT",
          headers: {
            Authorization: `Bearer ${authToken}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ authAbuseConfig: authAbusePayloadFromForm(authAbuse) }),
        },
      );
      const data = await res.json();
      if (!res.ok || !data.ok) throw new Error(data.error || "Failed to save login controls");
      setAuthAbuse(authAbuseFormFromConfig(data.data.authAbuseConfig ?? {}));
      setAuthAbuseSaved(true);
      setTimeout(() => setAuthAbuseSaved(false), 2000);
    } catch (e: unknown) {
      setAuthAbuseError(e instanceof Error ? e.message : "Failed to save login controls");
    } finally {
      setAuthAbuseSaving(false);
    }
  }

  async function addAccessAllowlistEntry(e: React.FormEvent) {
    e.preventDefault();
    if (!TENANT_ID || !authToken) {
      setAccessAllowlistError("Sign in again to update the access allowlist");
      return;
    }
    const value = accessAllowlistValue.trim();
    const bulkEntries = parseAccessAllowlistBulkEntries(
      accessAllowlistBulkValue,
      accessAllowlistType,
    );
    const entries = [...(value ? [{ type: accessAllowlistType, value }] : []), ...bulkEntries];
    if (entries.length === 0) {
      setAccessAllowlistError("Enter an email, domain, wallet, or phone number");
      return;
    }

    setAccessAllowlistSaving(true);
    setAccessAllowlistSaved(false);
    setAccessAllowlistError(null);
    try {
      const res = await fetch(
        `${API_URL}/tenants/${encodeURIComponent(TENANT_ID)}/access-allowlist`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${authToken}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify(entries.length === 1 ? entries[0] : { entries }),
        },
      );
      const data = await res.json();
      if (!res.ok || !data.ok) {
        throw new Error(data.error || "Failed to add access allowlist entry");
      }
      setAccessAllowlist(data.data.entries ?? []);
      setAccessAllowlistValue("");
      setAccessAllowlistBulkValue("");
      setAccessAllowlistSaved(true);
      setTimeout(() => setAccessAllowlistSaved(false), 2000);
    } catch (e: unknown) {
      setAccessAllowlistError(
        e instanceof Error ? e.message : "Failed to add access allowlist entry",
      );
    } finally {
      setAccessAllowlistSaving(false);
    }
  }

  async function removeAccessAllowlistEntry(entry: AccessAllowlistEntry) {
    if (!TENANT_ID || !authToken) {
      setAccessAllowlistError("Sign in again to update the access allowlist");
      return;
    }

    setAccessAllowlistSaving(true);
    setAccessAllowlistSaved(false);
    setAccessAllowlistError(null);
    try {
      const res = await fetch(
        `${API_URL}/tenants/${encodeURIComponent(TENANT_ID)}/access-allowlist`,
        {
          method: "DELETE",
          headers: {
            Authorization: `Bearer ${authToken}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ id: entry.id }),
        },
      );
      const data = await res.json();
      if (!res.ok || !data.ok) {
        throw new Error(data.error || "Failed to remove access allowlist entry");
      }
      setAccessAllowlist(data.data.entries ?? []);
      setAccessAllowlistSaved(true);
      setTimeout(() => setAccessAllowlistSaved(false), 2000);
    } catch (e: unknown) {
      setAccessAllowlistError(
        e instanceof Error ? e.message : "Failed to remove access allowlist entry",
      );
    } finally {
      setAccessAllowlistSaving(false);
    }
  }

  async function addSsoDomain(e: React.FormEvent) {
    e.preventDefault();
    if (!TENANT_ID || !authToken) {
      setSsoDomainsError("Sign in again to update SSO domains");
      return;
    }
    const domain = ssoDomainValue.trim().toLowerCase();
    if (!domain) {
      setSsoDomainsError("Enter a domain to verify for SSO");
      return;
    }

    setSsoDomainsSaving(true);
    setSsoDomainsSaved(false);
    setSsoDomainsError(null);
    try {
      const res = await fetch(`${API_URL}/tenants/${encodeURIComponent(TENANT_ID)}/sso-domains`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${authToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ domain, ssoRequired: ssoDomainRequired }),
      });
      const data = await res.json();
      if (!res.ok || !data.ok) throw new Error(data.error || "Failed to add SSO domain");
      const nextDomain = data.data.domain as TenantSsoDomain;
      setSsoDomains((current) => [
        nextDomain,
        ...current.filter((item) => item.domain !== nextDomain.domain),
      ]);
      setSsoDomainValue("");
      setSsoDomainsSaved(true);
      setTimeout(() => setSsoDomainsSaved(false), 2000);
    } catch (e: unknown) {
      setSsoDomainsError(e instanceof Error ? e.message : "Failed to add SSO domain");
    } finally {
      setSsoDomainsSaving(false);
    }
  }

  async function verifySsoDomain(domain: string) {
    if (!TENANT_ID || !authToken) {
      setSsoDomainsError("Sign in again to verify SSO domains");
      return;
    }

    setSsoDomainVerifying(domain);
    setSsoDomainsSaved(false);
    setSsoDomainsError(null);
    try {
      const res = await fetch(
        `${API_URL}/tenants/${encodeURIComponent(TENANT_ID)}/sso-domains/${encodeURIComponent(
          domain,
        )}/verify`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${authToken}` },
        },
      );
      const data = await res.json();
      if (!res.ok || !data.ok) throw new Error(data.error || "Failed to verify SSO domain");
      const nextDomain = data.data.domain as TenantSsoDomain;
      setSsoDomains((current) =>
        current.map((item) => (item.domain === nextDomain.domain ? nextDomain : item)),
      );
      setSsoDomainsSaved(true);
      setTimeout(() => setSsoDomainsSaved(false), 2000);
    } catch (e: unknown) {
      setSsoDomainsError(e instanceof Error ? e.message : "Failed to verify SSO domain");
    } finally {
      setSsoDomainVerifying(null);
    }
  }

  async function deleteSsoDomain(domain: string) {
    if (!TENANT_ID || !authToken) {
      setSsoDomainsError("Sign in again to update SSO domains");
      return;
    }

    setSsoDomainsSaving(true);
    setSsoDomainsSaved(false);
    setSsoDomainsError(null);
    try {
      const res = await fetch(
        `${API_URL}/tenants/${encodeURIComponent(TENANT_ID)}/sso-domains/${encodeURIComponent(
          domain,
        )}`,
        {
          method: "DELETE",
          headers: { Authorization: `Bearer ${authToken}` },
        },
      );
      const data = await res.json();
      if (!res.ok || !data.ok) throw new Error(data.error || "Failed to delete SSO domain");
      setSsoDomains((current) => current.filter((item) => item.domain !== domain));
      setSsoDomainsSaved(true);
      setTimeout(() => setSsoDomainsSaved(false), 2000);
    } catch (e: unknown) {
      setSsoDomainsError(e instanceof Error ? e.message : "Failed to delete SSO domain");
    } finally {
      setSsoDomainsSaving(false);
    }
  }

  function updateSamlSso(patch: Partial<SamlSsoForm>) {
    setSamlSso((current) => ({ ...current, ...patch }));
  }

  async function saveSamlSso(e: React.FormEvent) {
    e.preventDefault();
    if (!TENANT_ID || !authToken) {
      setSamlSsoError("Sign in again to save SAML SSO");
      return;
    }

    setSamlSsoSaving(true);
    setSamlSsoSaved(false);
    setSamlSsoError(null);
    try {
      const res = await fetch(`${API_URL}/tenants/${encodeURIComponent(TENANT_ID)}/saml-sso`, {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${authToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          enabled: samlSso.enabled,
          idpEntityId: samlSso.idpEntityId.trim(),
          idpSsoUrl: samlSso.idpSsoUrl.trim(),
          idpCertPems: samlSso.idpCertPems
            .split(/(?=-----BEGIN CERTIFICATE-----)/g)
            .map((cert) => cert.trim())
            .filter(Boolean),
          emailAttribute: samlSso.emailAttribute.trim() || "email",
          groupsAttribute: samlSso.groupsAttribute.trim() || undefined,
          groupRoleMappings: JSON.parse(samlSso.groupRoleMappings || "[]"),
          allowJitProvisioning: samlSso.allowJitProvisioning,
        }),
      });
      const data = await res.json();
      if (!res.ok || !data.ok) throw new Error(data.error || "Failed to save SAML SSO");
      setSamlSso(samlFormFromConfig(data.data.config ?? null));
      setSamlSsoSaved(true);
      setTimeout(() => setSamlSsoSaved(false), 2000);
    } catch (e: unknown) {
      setSamlSsoError(e instanceof Error ? e.message : "Failed to save SAML SSO");
    } finally {
      setSamlSsoSaving(false);
    }
  }

  async function rotateTestAccount() {
    if (!TENANT_ID || !authToken) {
      setTestAccountError("Sign in again to manage test credentials");
      return;
    }
    setTestAccountSaving(true);
    setTestAccountError(null);
    try {
      const res = await fetch(`${API_URL}/tenants/${encodeURIComponent(TENANT_ID)}/test-account`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${authToken}`,
          "Content-Type": "application/json",
        },
      });
      const data = await res.json();
      if (!res.ok || !data.ok) throw new Error(data.error || "Failed to rotate test account");
      setTestAccount(data.data.testAccount ?? { enabled: false });
    } catch (e: unknown) {
      setTestAccountError(e instanceof Error ? e.message : "Failed to rotate test account");
    } finally {
      setTestAccountSaving(false);
    }
  }

  async function disableTestAccount() {
    if (!TENANT_ID || !authToken) {
      setTestAccountError("Sign in again to manage test credentials");
      return;
    }
    setTestAccountSaving(true);
    setTestAccountError(null);
    try {
      const res = await fetch(`${API_URL}/tenants/${encodeURIComponent(TENANT_ID)}/test-account`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${authToken}` },
      });
      const data = await res.json();
      if (!res.ok || !data.ok) throw new Error(data.error || "Failed to disable test account");
      setTestAccount(data.data.testAccount ?? { enabled: false });
    } catch (e: unknown) {
      setTestAccountError(e instanceof Error ? e.message : "Failed to disable test account");
    } finally {
      setTestAccountSaving(false);
    }
  }

  async function saveWebhook(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    try {
      if (!authToken) throw new Error("Sign in again to save settings");
      const res = await fetch(`${API_URL}/tenants/${encodeURIComponent(TENANT_ID)}/webhook`, {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${authToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ webhookUrl: webhookUrl || undefined }),
      });
      const data = await res.json();
      if (data.ok) {
        setSaved(true);
        setTimeout(() => setSaved(false), 2000);
      }
    } catch (e: unknown) {
      alert(e instanceof Error ? e.message : "Failed to save");
    } finally {
      setSaving(false);
    }
  }

  async function saveAllowedOrigins(e: React.FormEvent) {
    e.preventDefault();
    if (!TENANT_ID || !authToken) {
      setOriginsError("Sign in again to save app origins");
      return;
    }
    setOriginsSaving(true);
    setOriginsSaved(false);
    setOriginsError(null);
    try {
      const res = await fetch(`${API_URL}/tenants/${encodeURIComponent(TENANT_ID)}/config`, {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${authToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ allowedOrigins: linesToList(allowedOrigins) }),
      });
      const data = await res.json();
      if (!res.ok || !data.ok) throw new Error(data.error || "Failed to save app origins");
      setAllowedOrigins(listToLines(data.data.allowedOrigins ?? []));
      setOriginsSaved(true);
      setTimeout(() => setOriginsSaved(false), 2000);
    } catch (e: unknown) {
      setOriginsError(e instanceof Error ? e.message : "Failed to save app origins");
    } finally {
      setOriginsSaving(false);
    }
  }

  async function saveAllowedRedirectUrls(e: React.FormEvent) {
    e.preventDefault();
    if (!TENANT_ID || !authToken) {
      setRedirectUrlsError("Sign in again to save redirect URLs");
      return;
    }
    setRedirectUrlsSaving(true);
    setRedirectUrlsSaved(false);
    setRedirectUrlsError(null);
    try {
      const res = await fetch(`${API_URL}/tenants/${encodeURIComponent(TENANT_ID)}/config`, {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${authToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ allowedRedirectUrls: linesToList(allowedRedirectUrls) }),
      });
      const data = await res.json();
      if (!res.ok || !data.ok) throw new Error(data.error || "Failed to save redirect URLs");
      setAllowedRedirectUrls(listToLines(data.data.allowedRedirectUrls ?? []));
      setRedirectUrlsSaved(true);
      setTimeout(() => setRedirectUrlsSaved(false), 2000);
    } catch (e: unknown) {
      setRedirectUrlsError(e instanceof Error ? e.message : "Failed to save redirect URLs");
    } finally {
      setRedirectUrlsSaving(false);
    }
  }

  async function saveEmbeddedWalletCreation(e: React.FormEvent) {
    e.preventDefault();
    if (!TENANT_ID || !authToken) {
      setEmbeddedWalletError("Sign in again to save embedded wallet creation");
      return;
    }
    setEmbeddedWalletSaving(true);
    setEmbeddedWalletSaved(false);
    setEmbeddedWalletError(null);
    try {
      const res = await fetch(`${API_URL}/tenants/${encodeURIComponent(TENANT_ID)}/config`, {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${authToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          featureFlags: {
            embeddedWallets: {
              createOnLogin: embeddedWalletCreateOnLogin,
            },
          },
        }),
      });
      const data = await res.json();
      if (!res.ok || !data.ok) {
        throw new Error(data.error || "Failed to save embedded wallet creation");
      }
      setEmbeddedWalletCreateOnLogin(
        embeddedWalletCreateOnLoginFromConfig(
          data.data.featureFlags?.embeddedWallets?.createOnLogin ??
            data.data.featureFlags?.embeddedWalletCreateOnLogin,
        ),
      );
      setEmbeddedWalletSaved(true);
      setTimeout(() => setEmbeddedWalletSaved(false), 2000);
    } catch (e: unknown) {
      setEmbeddedWalletError(
        e instanceof Error ? e.message : "Failed to save embedded wallet creation",
      );
    } finally {
      setEmbeddedWalletSaving(false);
    }
  }

  function addAppClient() {
    setAppClients((clients) => [...clients, emptyAppClient()]);
  }

  function updateAppClient(index: number, patch: Partial<AppClientForm>) {
    setAppClients((clients) =>
      clients.map((client, clientIndex) =>
        clientIndex === index ? { ...client, ...patch } : client,
      ),
    );
  }

  function removeAppClient(index: number) {
    setAppClients((clients) => clients.filter((_, clientIndex) => clientIndex !== index));
  }

  async function rotateAppClientSecret(clientId: string) {
    if (!TENANT_ID || !authToken) {
      setAppClientsError("Sign in again to rotate app secrets");
      return;
    }
    const normalizedClientId = clientId.trim().toLowerCase();
    if (!normalizedClientId) {
      setAppClientsError("Save a client ID before rotating its secret");
      return;
    }
    setAppClientSecretRotating(normalizedClientId);
    setAppClientsError(null);
    try {
      const res = await fetch(
        `${API_URL}/tenants/${encodeURIComponent(TENANT_ID)}/app-clients/${encodeURIComponent(
          normalizedClientId,
        )}/secrets`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${authToken}`,
            "Content-Type": "application/json",
          },
        },
      );
      const data = await res.json();
      if (!res.ok || !data.ok) throw new Error(data.error || "Failed to rotate app secret");
      setAppClientSecrets((current) => ({
        ...current,
        [normalizedClientId]: {
          appId: data.data.appId,
          appSecret: data.data.appSecret,
          secretPrefix: data.data.secret.secretPrefix,
        },
      }));
    } catch (e: unknown) {
      setAppClientsError(e instanceof Error ? e.message : "Failed to rotate app secret");
    } finally {
      setAppClientSecretRotating(null);
    }
  }

  async function rotateRequestSigningKey() {
    if (!TENANT_ID || !authToken) {
      setRequestSigningKeysError("Sign in again to rotate request signing keys");
      return;
    }
    setRequestSigningKeysSaving(true);
    setRequestSigningKeysError(null);
    try {
      const result = await rotateTenantRequestSigningKey(
        TENANT_ID,
        authToken,
        requestSigningKeyName,
      );
      setRequestSigningKeyReveal(result);
      setRequestSigningKeys((keys) => [
        result.key,
        ...keys.map((key) =>
          key.status === "active" ? { ...key, status: "retiring" as const } : key,
        ),
      ]);
    } catch (e: unknown) {
      setRequestSigningKeysError(
        e instanceof Error ? e.message : "Failed to rotate request signing key",
      );
    } finally {
      setRequestSigningKeysSaving(false);
    }
  }

  async function exportIdempotencyMetrics() {
    if (!TENANT_ID || !authToken) return;
    try {
      setIdempotencyExportSaving(true);
      setIdempotencyMetricsError(null);
      const response = await fetch(
        `${API_URL}/tenants/${encodeURIComponent(TENANT_ID)}/idempotency-metrics/export`,
        {
          headers: {
            Accept: "text/csv",
            Authorization: `Bearer ${authToken}`,
          },
        },
      );
      if (!response.ok) {
        const body = (await response.json().catch(() => null)) as { error?: string } | null;
        throw new Error(body?.error || `Export failed with ${response.status}`);
      }
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `${TENANT_ID}-idempotency-metrics.csv`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      setIdempotencyMetricsError(
        err instanceof Error ? err.message : "Failed to export idempotency metrics",
      );
    } finally {
      setIdempotencyExportSaving(false);
    }
  }

  async function revokeRequestSigningKey(keyId: string) {
    if (!TENANT_ID || !authToken) {
      setRequestSigningKeysError("Sign in again to revoke request signing keys");
      return;
    }
    setRequestSigningKeysSaving(true);
    setRequestSigningKeysError(null);
    try {
      const key = await revokeTenantRequestSigningKey(TENANT_ID, authToken, keyId);
      setRequestSigningKeys((keys) => keys.map((entry) => (entry.id === key.id ? key : entry)));
    } catch (e: unknown) {
      setRequestSigningKeysError(
        e instanceof Error ? e.message : "Failed to revoke request signing key",
      );
    } finally {
      setRequestSigningKeysSaving(false);
    }
  }

  async function saveAppClients(e: React.FormEvent) {
    e.preventDefault();
    if (!TENANT_ID || !authToken) {
      setAppClientsError("Sign in again to save app clients");
      return;
    }
    setAppClientsSaving(true);
    setAppClientsSaved(false);
    setAppClientsError(null);
    try {
      const res = await fetch(`${API_URL}/tenants/${encodeURIComponent(TENANT_ID)}/config`, {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${authToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ appClients: appClients.map(appClientPayloadFromForm) }),
      });
      const data = await res.json();
      if (!res.ok || !data.ok) throw new Error(data.error || "Failed to save app clients");
      setAppClients((data.data.appClients ?? []).map(appClientFormFromConfig));
      setAppClientsSaved(true);
      setTimeout(() => setAppClientsSaved(false), 2000);
    } catch (e: unknown) {
      setAppClientsError(e instanceof Error ? e.message : "Failed to save app clients");
    } finally {
      setAppClientsSaving(false);
    }
  }

  function updateTheme(patch: Partial<ThemeForm>) {
    setTheme((current) => ({ ...current, ...patch }));
  }

  async function saveTheme(e: React.FormEvent) {
    e.preventDefault();
    if (!TENANT_ID || !authToken) {
      setThemeError("Sign in again to save appearance");
      return;
    }
    setThemeSaving(true);
    setThemeSaved(false);
    setThemeError(null);
    try {
      const res = await fetch(`${API_URL}/tenants/${encodeURIComponent(TENANT_ID)}/config`, {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${authToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ theme: themePayloadFromForm(theme) }),
      });
      const data = await res.json();
      if (!res.ok || !data.ok) throw new Error(data.error || "Failed to save appearance");
      setTheme(themeFormFromConfig(data.data.theme));
      setThemeSaved(true);
      setTimeout(() => setThemeSaved(false), 2000);
    } catch (e: unknown) {
      setThemeError(e instanceof Error ? e.message : "Failed to save appearance");
    } finally {
      setThemeSaving(false);
    }
  }

  function updateOidcProvider(index: number, patch: Partial<OidcProviderForm>) {
    setOidcProviders((providers) =>
      providers.map((provider, providerIndex) =>
        providerIndex === index ? { ...provider, ...patch } : provider,
      ),
    );
  }

  async function saveOidcProviders(e: React.FormEvent) {
    e.preventDefault();
    if (!TENANT_ID || !authToken) {
      setOidcError("Sign in again to save providers");
      return;
    }

    setOidcSaving(true);
    setOidcSaved(false);
    setOidcError(null);
    try {
      const providers = oidcProviders.map((provider) => ({
        id: provider.id.trim(),
        enabled: provider.enabled,
        issuer: provider.issuer.trim(),
        audience: provider.audience
          .split(",")
          .map((item) => item.trim())
          .filter(Boolean),
        jwksUri: provider.jwksUri.trim(),
        clientId: provider.clientId.trim() || undefined,
        clientSecretEnv: provider.clientSecretEnv.trim() || undefined,
        authorizationUrl: provider.authorizationUrl.trim() || undefined,
        tokenUrl: provider.tokenUrl.trim() || undefined,
        scopes: linesToList(provider.scopes),
        allowedAlgs: [provider.allowedAlgs],
        allowJitProvisioning: provider.allowJitProvisioning,
      }));
      const res = await fetch(
        `${API_URL}/tenants/${encodeURIComponent(TENANT_ID)}/oidc-providers`,
        {
          method: "PUT",
          headers: {
            Authorization: `Bearer ${authToken}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ providers }),
        },
      );
      const data = await res.json();
      if (!res.ok || !data.ok) throw new Error(data.error || "Failed to save providers");
      setOidcProviders(
        (data.data.providers ?? []).map(
          (provider: {
            id: string;
            enabled?: boolean;
            issuer: string;
            audience?: string[];
            jwksUri: string;
            clientId?: string;
            clientSecretEnv?: string;
            authorizationUrl?: string;
            tokenUrl?: string;
            scopes?: string[];
            allowedAlgs?: Array<"RS256" | "ES256">;
            allowJitProvisioning?: boolean;
          }) => ({
            id: provider.id,
            enabled: provider.enabled !== false,
            issuer: provider.issuer,
            audience: (provider.audience ?? []).join(", "),
            jwksUri: provider.jwksUri,
            clientId: provider.clientId ?? "",
            clientSecretEnv: provider.clientSecretEnv ?? "",
            authorizationUrl: provider.authorizationUrl ?? "",
            tokenUrl: provider.tokenUrl ?? "",
            scopes: listToLines(provider.scopes ?? ["openid", "email", "profile"]),
            allowedAlgs: provider.allowedAlgs?.[0] ?? "RS256",
            allowJitProvisioning: provider.allowJitProvisioning !== false,
          }),
        ),
      );
      setOidcSaved(true);
      setTimeout(() => setOidcSaved(false), 2000);
    } catch (e: unknown) {
      setOidcError(e instanceof Error ? e.message : "Failed to save providers");
    } finally {
      setOidcSaving(false);
    }
  }

  const sdkSnippet = `import { StewardClient } from "@stwd/sdk"

const steward = new StewardClient({
  baseUrl: "${API_URL}",
  tenantId: "${TENANT_ID}",
  apiKey: "your-api-key",
})

// Create an agent wallet
const agent = await steward.createWallet(
  "my-agent",
  "Trading Bot"
)

// Sign a transaction (policy-checked)
const result = await steward.signTransaction(
  "my-agent",
  {
    to: "0x...",
    value: "1000000000000000", // 0.001 ETH
    chainId: 8453,
  }
)

// Get policies
const policies = await steward.getPolicies("my-agent")`;

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.3 }}
      className="space-y-10"
    >
      {/* Header */}
      <div>
        <h1 className="font-display text-2xl font-700 tracking-tight">Settings</h1>
        <p className="text-sm text-text-tertiary mt-1">Tenant configuration and integration</p>
      </div>

      {/* Account */}
      {address && (
        <div className="space-y-4">
          <h2 className="font-display text-sm font-600 text-text-secondary tracking-wider uppercase">
            Account
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-px bg-border">
            <div className="bg-bg p-5">
              <label className="text-xs text-text-tertiary block mb-2">Wallet</label>
              <span className="font-mono text-sm text-text-secondary break-all">{address}</span>
            </div>
            <div className="bg-bg p-5">
              <label className="text-xs text-text-tertiary block mb-2">Chain</label>
              <span className="font-mono text-sm text-text-secondary">
                {chainId ? CHAIN_NAMES[chainId] || `Chain ${chainId}` : "\u2014"}
              </span>
            </div>
            <div className="bg-bg p-5">
              <label className="text-xs text-text-tertiary block mb-2">Workspace</label>
              <span className="font-mono text-sm text-text-secondary">
                {tenant?.tenantName || "\u2014"}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Connection */}
      <div className="space-y-4">
        <h2 className="font-display text-sm font-600 text-text-secondary tracking-wider uppercase">
          API Connection
        </h2>
        <div className="space-y-px bg-border">
          <div className="bg-bg p-5">
            <label className="text-xs text-text-tertiary block mb-2">API Endpoint</label>
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono text-sm text-text-secondary truncate">{API_URL}</span>
              <CopyButton text={API_URL} />
            </div>
          </div>
          <div className="bg-bg p-5">
            <label className="text-xs text-text-tertiary block mb-2">Tenant ID</label>
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono text-sm text-text-secondary truncate">{TENANT_ID}</span>
              <CopyButton text={TENANT_ID} />
            </div>
          </div>
          {API_KEY && (
            <div className="bg-bg p-5">
              <label className="text-xs text-text-tertiary block mb-2">API Key</label>
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-sm text-text-secondary truncate">
                  {showKey ? API_KEY : `${API_KEY.slice(0, 8)}${"•".repeat(32)}`}
                </span>
                <div className="flex items-center gap-2 flex-shrink-0">
                  <button
                    onClick={() => setShowKey(!showKey)}
                    className="text-xs text-text-tertiary hover:text-text-secondary transition-colors"
                  >
                    {showKey ? "Hide" : "Reveal"}
                  </button>
                  <CopyButton text={API_KEY} />
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Appearance */}
      <form onSubmit={saveTheme} className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="font-display text-sm font-600 text-text-secondary tracking-wider uppercase">
              Appearance
            </h2>
            <p className="text-xs text-text-tertiary max-w-2xl mt-1">
              Configure tenant theme tokens used by embedded Steward components.
            </p>
          </div>
          <button
            type="submit"
            disabled={themeSaving || originsLoading || !TENANT_ID}
            className="px-4 py-2 text-sm bg-accent text-bg hover:bg-accent-hover transition-colors disabled:opacity-40 font-medium"
          >
            {themeSaving ? "Saving..." : "Save Appearance"}
          </button>
        </div>
        <div className="grid grid-cols-1 xl:grid-cols-[minmax(0,1fr)_360px] gap-px bg-border max-w-6xl">
          <div className="bg-bg p-5 space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-px bg-border-subtle">
              {THEME_COLOR_FIELDS.map((field) => (
                <label key={field.key} className="bg-bg p-4 space-y-1.5 block">
                  <span className="text-xs text-text-tertiary block">{field.label}</span>
                  <div className="flex items-center gap-2">
                    <input
                      aria-label={`${field.label} color picker`}
                      type="color"
                      value={String(theme[field.key])}
                      onChange={(event) => updateTheme({ [field.key]: event.target.value })}
                      className="h-9 w-10 border border-border bg-bg"
                    />
                    <input
                      aria-label={`${field.label} color`}
                      value={String(theme[field.key])}
                      onChange={(event) => updateTheme({ [field.key]: event.target.value })}
                      className="min-w-0 flex-1 bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono"
                    />
                  </div>
                </label>
              ))}
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-px bg-border-subtle">
              <label className="bg-bg p-4 space-y-1.5 block">
                <span className="text-xs text-text-tertiary block">Color Scheme</span>
                <select
                  value={theme.colorScheme}
                  onChange={(event) =>
                    updateTheme({ colorScheme: event.target.value as ThemeForm["colorScheme"] })
                  }
                  className="w-full bg-bg border border-border px-3 py-2 text-sm text-text focus:outline-none focus:border-accent transition-colors"
                >
                  <option value="dark">Dark</option>
                  <option value="light">Light</option>
                  <option value="system">System</option>
                </select>
              </label>
              <label className="bg-bg p-4 space-y-1.5 block">
                <span className="text-xs text-text-tertiary block">Border Radius</span>
                <input
                  type="number"
                  min="0"
                  max="32"
                  value={theme.borderRadius}
                  onChange={(event) => updateTheme({ borderRadius: event.target.value })}
                  className="w-full bg-bg border border-border px-3 py-2 text-sm text-text focus:outline-none focus:border-accent transition-colors"
                />
              </label>
              <label className="bg-bg p-4 space-y-1.5 block">
                <span className="text-xs text-text-tertiary block">Font Family</span>
                <input
                  value={theme.fontFamily}
                  onChange={(event) => updateTheme({ fontFamily: event.target.value })}
                  className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors"
                />
              </label>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-px bg-border-subtle">
              <label className="bg-bg p-4 space-y-1.5 block">
                <span className="text-xs text-text-tertiary block">Logo URL</span>
                <input
                  type="url"
                  value={theme.logoUrl}
                  onChange={(event) => updateTheme({ logoUrl: event.target.value })}
                  placeholder="https://app.example/logo.png"
                  className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors"
                />
              </label>
              <label className="bg-bg p-4 space-y-1.5 block">
                <span className="text-xs text-text-tertiary block">Favicon URL</span>
                <input
                  type="url"
                  value={theme.faviconUrl}
                  onChange={(event) => updateTheme({ faviconUrl: event.target.value })}
                  placeholder="https://app.example/favicon.ico"
                  className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors"
                />
              </label>
            </div>
          </div>
          <div
            className="p-5 space-y-4"
            style={{
              backgroundColor: theme.backgroundColor,
              color: theme.textColor,
              fontFamily: theme.fontFamily,
            }}
            data-testid="appearance-preview"
          >
            <div className="text-xs uppercase tracking-wider" style={{ color: theme.mutedColor }}>
              Preview
            </div>
            <div
              className="border p-4 space-y-3"
              style={{
                backgroundColor: theme.surfaceColor,
                borderColor: theme.mutedColor,
                borderRadius: `${Number(theme.borderRadius) || 0}px`,
              }}
            >
              <div className="flex items-center gap-3">
                {theme.logoUrl.trim() ? (
                  <img
                    src={theme.logoUrl.trim()}
                    alt=""
                    className="h-9 w-9 object-contain border"
                    style={{
                      borderColor: theme.mutedColor,
                      borderRadius: `${Math.max((Number(theme.borderRadius) || 0) - 4, 0)}px`,
                    }}
                  />
                ) : (
                  <div
                    className="h-9 w-9 border grid place-items-center text-xs font-semibold"
                    style={{
                      borderColor: theme.mutedColor,
                      borderRadius: `${Math.max((Number(theme.borderRadius) || 0) - 4, 0)}px`,
                      color: theme.primaryColor,
                    }}
                  >
                    ST
                  </div>
                )}
                <div className="min-w-0">
                  <div className="text-sm font-medium">Sign in to Steward</div>
                  <div className="text-xs truncate" style={{ color: theme.mutedColor }}>
                    {theme.faviconUrl.trim() ? "Custom icon configured" : "Default icon"}
                  </div>
                </div>
              </div>
              <div className="text-xs" style={{ color: theme.mutedColor }}>
                Continue with your wallet or email.
              </div>
              <button
                type="button"
                className="w-full px-3 py-2 text-sm font-medium"
                style={{
                  backgroundColor: theme.primaryColor,
                  color: theme.backgroundColor,
                  borderRadius: `${Math.max((Number(theme.borderRadius) || 0) - 2, 0)}px`,
                }}
              >
                Continue
              </button>
              <div className="grid grid-cols-3 gap-2 text-center text-xs">
                <div style={{ color: theme.successColor }}>Ready</div>
                <div style={{ color: theme.warningColor }}>Review</div>
                <div style={{ color: theme.errorColor }}>Blocked</div>
              </div>
            </div>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          {themeSaved && (
            <motion.span
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              className="text-xs text-emerald-400"
            >
              Saved
            </motion.span>
          )}
          {themeError && <span className="text-xs text-red-400">{themeError}</span>}
        </div>
      </form>

      {/* App Clients */}
      <form onSubmit={saveAppClients} className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="font-display text-sm font-600 text-text-secondary tracking-wider uppercase">
              App Clients
            </h2>
            <p className="text-xs text-text-tertiary max-w-2xl mt-1">
              Group redirect URLs and browser origins by development, preview, and production client
              environments.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={addAppClient}
              className="px-4 py-2 text-sm border border-border text-text-secondary hover:border-accent hover:text-text transition-colors font-medium"
            >
              Add Client
            </button>
            <button
              type="submit"
              disabled={appClientsSaving || originsLoading || !TENANT_ID}
              className="px-4 py-2 text-sm bg-accent text-bg hover:bg-accent-hover transition-colors disabled:opacity-40 font-medium"
            >
              {appClientsSaving ? "Saving..." : "Save Clients"}
            </button>
          </div>
        </div>
        <div className="space-y-px bg-border max-w-5xl">
          {appClients.length === 0 ? (
            <div className="bg-bg p-5">
              <p className="text-sm text-text-tertiary">
                No app clients configured. Add one to separate local, preview, and production
                integration settings.
              </p>
            </div>
          ) : (
            appClients.map((client, index) => (
              <div
                key={`${client.id || "new-client"}-${index}`}
                className="bg-bg p-5 space-y-4"
                data-testid="app-client-row"
              >
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <div className="text-xs text-text-secondary uppercase tracking-wider">
                      {client.name.trim() || client.id.trim() || `Client ${index + 1}`}
                    </div>
                    <div className="text-xs text-text-tertiary mt-1">
                      {client.environment} {client.enabled ? "enabled" : "disabled"}
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => removeAppClient(index)}
                    className="text-xs text-text-tertiary hover:text-red-400 transition-colors"
                  >
                    Remove
                  </button>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-4 gap-px bg-border-subtle">
                  <label className="bg-bg p-4 space-y-1.5 block">
                    <span className="text-xs text-text-tertiary block">Client ID</span>
                    <input
                      value={client.id}
                      onChange={(event) => updateAppClient(index, { id: event.target.value })}
                      placeholder="web-prod"
                      className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono"
                    />
                  </label>
                  <label className="bg-bg p-4 space-y-1.5 block">
                    <span className="text-xs text-text-tertiary block">Name</span>
                    <input
                      value={client.name}
                      onChange={(event) => updateAppClient(index, { name: event.target.value })}
                      placeholder="Production Web"
                      className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors"
                    />
                  </label>
                  <label className="bg-bg p-4 space-y-1.5 block">
                    <span className="text-xs text-text-tertiary block">Environment</span>
                    <select
                      value={client.environment}
                      onChange={(event) =>
                        updateAppClient(index, {
                          environment: event.target.value as AppClientEnvironment,
                        })
                      }
                      className="w-full bg-bg border border-border px-3 py-2 text-sm text-text focus:outline-none focus:border-accent transition-colors"
                    >
                      {APP_CLIENT_ENVIRONMENTS.map((environment) => (
                        <option key={environment.value} value={environment.value}>
                          {environment.label}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="bg-bg p-4 flex items-center gap-3">
                    <input
                      type="checkbox"
                      checked={client.enabled}
                      onChange={(event) =>
                        updateAppClient(index, { enabled: event.target.checked })
                      }
                      className="h-4 w-4 accent-accent"
                    />
                    <span className="text-xs text-text-tertiary">Enabled</span>
                  </label>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-px bg-border-subtle">
                  <label className="bg-bg p-4 space-y-1.5 block">
                    <span className="text-xs text-text-tertiary block">Allowed Origins</span>
                    <textarea
                      value={client.allowedOrigins}
                      onChange={(event) =>
                        updateAppClient(index, { allowedOrigins: event.target.value })
                      }
                      rows={4}
                      placeholder={
                        "https://app.example.com\nhttps://preview.example.com\nhttp://localhost:3000"
                      }
                      className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono resize-y"
                    />
                  </label>
                  <label className="bg-bg p-4 space-y-1.5 block">
                    <span className="text-xs text-text-tertiary block">Redirect URLs</span>
                    <textarea
                      value={client.allowedRedirectUrls}
                      onChange={(event) =>
                        updateAppClient(index, { allowedRedirectUrls: event.target.value })
                      }
                      rows={4}
                      placeholder={
                        "https://app.example.com/auth/callback\nhttps://preview.example.com/auth/callback"
                      }
                      className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono resize-y"
                    />
                  </label>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-px bg-border-subtle">
                  <label className="bg-bg p-4 flex items-center gap-3">
                    <input
                      type="checkbox"
                      checked={client.globalWalletEnabled}
                      onChange={(event) =>
                        updateAppClient(index, { globalWalletEnabled: event.target.checked })
                      }
                      className="h-4 w-4 accent-accent"
                    />
                    <span className="text-xs text-text-tertiary">Global Wallet</span>
                  </label>
                  <label className="bg-bg p-4 space-y-1.5 block">
                    <span className="text-xs text-text-tertiary block">Global Wallet Scopes</span>
                    <textarea
                      value={client.globalWalletAllowedScopes}
                      onChange={(event) =>
                        updateAppClient(index, {
                          globalWalletAllowedScopes: event.target.value,
                        })
                      }
                      rows={3}
                      placeholder={"eth_accounts\npersonal_sign"}
                      className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono resize-y"
                    />
                  </label>
                </div>
                <div className="bg-bg border border-border-subtle p-4 space-y-3">
                  <div>
                    <div className="text-xs text-text-secondary uppercase tracking-wider">
                      Embedded Wallet Creation
                    </div>
                    <p className="text-xs text-text-tertiary mt-1">
                      Override the tenant create-on-login policy for this client.
                    </p>
                  </div>
                  <label className="space-y-1.5 block max-w-sm">
                    <span className="text-xs text-text-tertiary block">Create on Login</span>
                    <select
                      value={client.embeddedWalletCreateOnLogin}
                      onChange={(event) =>
                        updateAppClient(index, {
                          embeddedWalletCreateOnLogin: event.target
                            .value as AppClientEmbeddedWalletCreateOnLogin,
                        })
                      }
                      className="w-full bg-bg border border-border px-3 py-2 text-sm text-text focus:outline-none focus:border-accent transition-colors"
                    >
                      {APP_CLIENT_EMBEDDED_WALLET_CREATE_ON_LOGIN_OPTIONS.map((option) => (
                        <option key={option.value} value={option.value}>
                          {option.label}
                        </option>
                      ))}
                    </select>
                  </label>
                </div>
                <div className="bg-bg border border-border-subtle p-4 space-y-3">
                  <div>
                    <div className="text-xs text-text-secondary uppercase tracking-wider">
                      Login Methods
                    </div>
                    <p className="text-xs text-text-tertiary mt-1">
                      Override which tenant login methods this client can request.
                    </p>
                  </div>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    {[
                      ["Passkey", "loginPasskey"],
                      ["Email", "loginEmail"],
                      ["SMS", "loginSms"],
                      ["WhatsApp", "loginWhatsapp"],
                      ["TOTP", "loginTotp"],
                      ["SIWE", "loginSiwe"],
                      ["SIWS", "loginSiws"],
                      ["Telegram", "loginTelegram"],
                      ["Farcaster", "loginFarcaster"],
                      ["Google", "oauthGoogle"],
                      ["Discord", "oauthDiscord"],
                      ["GitHub", "oauthGithub"],
                      ["Twitter/X", "oauthTwitter"],
                    ].map(([label, key]) => (
                      <label
                        key={key}
                        className="flex items-center gap-2 text-sm text-text-secondary"
                      >
                        <input
                          type="checkbox"
                          checked={client[key as keyof AppClientForm] as boolean}
                          onChange={(event) =>
                            updateAppClient(index, {
                              [key]: event.target.checked,
                            } as Partial<AppClientForm>)
                          }
                          className="accent-accent"
                        />
                        {label}
                      </label>
                    ))}
                  </div>
                </div>
                <div className="border border-border-subtle bg-bg-elevated p-4 space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <div className="text-xs text-text-secondary uppercase tracking-wider">
                        Backend App Secret
                      </div>
                      <div className="text-xs text-text-tertiary mt-1 font-mono">
                        {TENANT_ID && client.id.trim()
                          ? `${TENANT_ID}/${client.id.trim().toLowerCase()}`
                          : "Save a client ID to create an app secret"}
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={() => rotateAppClientSecret(client.id)}
                      disabled={appClientSecretRotating === client.id.trim().toLowerCase()}
                      className="px-3 py-2 text-xs border border-border text-text-secondary hover:border-accent hover:text-text transition-colors disabled:opacity-40"
                    >
                      {appClientSecretRotating === client.id.trim().toLowerCase()
                        ? "Rotating..."
                        : "Rotate Secret"}
                    </button>
                  </div>
                  {appClientSecrets[client.id.trim().toLowerCase()] && (
                    <div className="border border-amber-400/20 bg-amber-400/5 p-3 text-xs">
                      <div className="text-amber-300">Copy this app secret now.</div>
                      <div className="mt-2 font-mono text-text-secondary break-all">
                        App ID: {appClientSecrets[client.id.trim().toLowerCase()].appId}
                      </div>
                      <div
                        className="mt-1 font-mono text-text-secondary break-all"
                        data-testid="app-client-secret-value"
                      >
                        Secret: {appClientSecrets[client.id.trim().toLowerCase()].appSecret}
                      </div>
                      <div className="mt-3 text-text-tertiary">
                        Use the same secret as requestSigningSecret for signed server requests.
                      </div>
                      <CodeBlock
                        code={`const steward = new StewardClient({
  baseUrl: "${API_URL}",
  appId: "${appClientSecrets[client.id.trim().toLowerCase()].appId}",
  appSecret: "${appClientSecrets[client.id.trim().toLowerCase()].appSecret}",
  requestSigningSecret: "${appClientSecrets[client.id.trim().toLowerCase()].appSecret}",
});`}
                        language="typescript"
                        className="mt-2"
                      />
                    </div>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
        <div className="flex flex-wrap items-center gap-3">
          {appClientsSaved && (
            <motion.span
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              className="text-xs text-emerald-400"
            >
              Saved
            </motion.span>
          )}
          {appClientsError && <span className="text-xs text-red-400">{appClientsError}</span>}
        </div>
      </form>

      {/* Embedded Wallet Creation */}
      <form onSubmit={saveEmbeddedWalletCreation} className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="font-display text-sm font-600 text-text-secondary tracking-wider uppercase">
              Embedded Wallet Creation
            </h2>
            <p className="text-xs text-text-tertiary max-w-2xl mt-1">
              Control whether authenticated app login bootstraps create embedded user wallets.
            </p>
          </div>
          <button
            type="submit"
            disabled={embeddedWalletSaving || originsLoading || !TENANT_ID}
            className="px-4 py-2 text-sm bg-accent text-bg hover:bg-accent-hover transition-colors disabled:opacity-40 font-medium"
          >
            {embeddedWalletSaving ? "Saving..." : "Save Wallet Creation"}
          </button>
        </div>
        <div className="space-y-px bg-border max-w-5xl">
          <div className="bg-bg p-5 grid grid-cols-1 md:grid-cols-[320px_minmax(0,1fr)] gap-4">
            <label className="space-y-1.5">
              <span className="text-xs text-text-tertiary block">Create on Login</span>
              <select
                value={embeddedWalletCreateOnLogin}
                onChange={(event) =>
                  setEmbeddedWalletCreateOnLogin(event.target.value as EmbeddedWalletCreateOnLogin)
                }
                className="w-full bg-bg border border-border px-3 py-2 text-sm text-text focus:outline-none focus:border-accent transition-colors"
              >
                {EMBEDDED_WALLET_CREATE_ON_LOGIN_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </label>
            <div className="text-sm text-text-secondary">
              <div className="text-text">
                {
                  EMBEDDED_WALLET_CREATE_ON_LOGIN_OPTIONS.find(
                    (option) => option.value === embeddedWalletCreateOnLogin,
                  )?.label
                }
              </div>
              <div className="text-xs text-text-tertiary mt-1">
                {
                  EMBEDDED_WALLET_CREATE_ON_LOGIN_OPTIONS.find(
                    (option) => option.value === embeddedWalletCreateOnLogin,
                  )?.description
                }
              </div>
            </div>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          {embeddedWalletSaved && (
            <motion.span
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              className="text-xs text-emerald-400"
            >
              Saved
            </motion.span>
          )}
          {embeddedWalletError && (
            <span className="text-xs text-red-400">{embeddedWalletError}</span>
          )}
        </div>
      </form>

      {/* SSO Domains */}
      <form onSubmit={addSsoDomain} className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="font-display text-sm font-600 text-text-secondary tracking-wider uppercase">
              SSO Domains
            </h2>
            <p className="text-xs text-text-tertiary max-w-2xl mt-1">
              Verify email domains for tenant SSO discovery and enforce SSO before passwordless or
              built-in OAuth login.
            </p>
          </div>
          <button
            type="submit"
            disabled={ssoDomainsSaving || ssoDomainsLoading || !TENANT_ID}
            className="px-4 py-2 text-sm bg-accent text-bg hover:bg-accent-hover transition-colors disabled:opacity-40 font-medium"
          >
            {ssoDomainsSaving ? "Saving..." : "Add Domain"}
          </button>
        </div>
        <div className="space-y-px bg-border max-w-5xl">
          <div className="bg-bg p-5">
            <div className="grid grid-cols-1 md:grid-cols-[minmax(0,1fr)_220px] gap-4">
              <label className="space-y-1.5">
                <span className="text-xs text-text-tertiary block">Domain</span>
                <input
                  value={ssoDomainValue}
                  onChange={(event) => setSsoDomainValue(event.target.value)}
                  placeholder="example.com"
                  className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono"
                />
              </label>
              <label className="flex items-end gap-2 text-sm text-text-secondary pb-2">
                <input
                  type="checkbox"
                  checked={ssoDomainRequired}
                  onChange={(event) => setSsoDomainRequired(event.target.checked)}
                  className="h-4 w-4 accent-accent"
                />
                Require SSO
              </label>
            </div>
          </div>
          <div className="bg-bg overflow-x-auto">
            <table className="w-full min-w-[820px] text-sm">
              <thead className="border-b border-border-subtle">
                <tr className="text-left text-xs text-text-tertiary">
                  <th className="font-medium px-5 py-3">Domain</th>
                  <th className="font-medium px-5 py-3">Status</th>
                  <th className="font-medium px-5 py-3">Policy</th>
                  <th className="font-medium px-5 py-3">DNS TXT</th>
                  <th className="font-medium px-5 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle">
                {ssoDomains.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="px-5 py-5 text-sm text-text-tertiary">
                      {ssoDomainsLoading ? "Loading SSO domains..." : "No SSO domains configured"}
                    </td>
                  </tr>
                ) : (
                  ssoDomains.map((domain) => (
                    <tr key={domain.id} className="text-text-secondary align-top">
                      <td className="px-5 py-3 font-mono break-all">{domain.domain}</td>
                      <td className="px-5 py-3 whitespace-nowrap">
                        <span
                          className={
                            domain.status === "verified" ? "text-emerald-400" : "text-amber-300"
                          }
                        >
                          {domain.status === "verified" ? "Verified" : "Pending"}
                        </span>
                      </td>
                      <td className="px-5 py-3 whitespace-nowrap text-xs text-text-tertiary">
                        {domain.ssoRequired ? "SSO required" : "SSO optional"}
                      </td>
                      <td className="px-5 py-3">
                        <div className="space-y-1 font-mono text-xs">
                          <div className="break-all">_steward-sso.{domain.domain}</div>
                          <div className="break-all text-text-tertiary">
                            {domain.verificationToken}
                          </div>
                        </div>
                      </td>
                      <td className="px-5 py-3 text-right">
                        <div className="flex justify-end gap-3">
                          {domain.status !== "verified" && (
                            <button
                              type="button"
                              onClick={() => verifySsoDomain(domain.domain)}
                              disabled={ssoDomainVerifying === domain.domain}
                              className="text-xs text-text-tertiary hover:text-emerald-400 transition-colors disabled:opacity-40"
                            >
                              {ssoDomainVerifying === domain.domain ? "Verifying..." : "Verify"}
                            </button>
                          )}
                          <button
                            type="button"
                            onClick={() => deleteSsoDomain(domain.domain)}
                            disabled={ssoDomainsSaving || ssoDomainsLoading || !TENANT_ID}
                            className="text-xs text-text-tertiary hover:text-red-400 transition-colors disabled:opacity-40"
                          >
                            Delete
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          {ssoDomainsSaved && (
            <motion.span
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              className="text-xs text-emerald-400"
            >
              Saved
            </motion.span>
          )}
          {ssoDomainsError && <span className="text-xs text-red-400">{ssoDomainsError}</span>}
        </div>
      </form>

      {/* SAML SSO */}
      <form onSubmit={saveSamlSso} className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="font-display text-sm font-600 text-text-secondary tracking-wider uppercase">
              SAML SSO
            </h2>
            <p className="text-xs text-text-tertiary max-w-2xl mt-1">
              Configure the tenant IdP for dashboard SSO. Verified domains still control email
              routing.
            </p>
          </div>
          <button
            type="submit"
            disabled={samlSsoSaving || samlSsoLoading || !TENANT_ID}
            className="px-4 py-2 text-sm bg-accent text-bg hover:bg-accent-hover transition-colors disabled:opacity-40 font-medium"
          >
            {samlSsoSaving ? "Saving..." : "Save SAML"}
          </button>
        </div>
        <div className="space-y-px bg-border max-w-5xl">
          <div className="bg-bg p-5 grid grid-cols-1 md:grid-cols-3 gap-px bg-border-subtle">
            {[
              ["Entity ID", samlServiceProvider?.spEntityId ?? ""],
              ["ACS URL", samlServiceProvider?.acsUrl ?? ""],
              ["Metadata URL", samlServiceProvider?.metadataUrl ?? ""],
            ].map(([label, value]) => (
              <div key={label} className="bg-bg p-4 min-w-0">
                <div className="text-xs text-text-tertiary mb-2">{label}</div>
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-xs text-text-secondary break-all">{value}</span>
                  {value && <CopyButton text={value} />}
                </div>
              </div>
            ))}
          </div>
          <div className="bg-bg p-5 space-y-4">
            <label className="flex items-center gap-2 text-sm text-text-secondary">
              <input
                type="checkbox"
                checked={samlSso.enabled}
                onChange={(event) => updateSamlSso({ enabled: event.target.checked })}
                className="h-4 w-4 accent-accent"
              />
              Enable SAML SSO
            </label>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <label className="space-y-1.5">
                <span className="text-xs text-text-tertiary block">IdP Entity ID</span>
                <input
                  value={samlSso.idpEntityId}
                  onChange={(event) => updateSamlSso({ idpEntityId: event.target.value })}
                  placeholder="https://idp.example.com/saml"
                  className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono"
                />
              </label>
              <label className="space-y-1.5">
                <span className="text-xs text-text-tertiary block">IdP SSO URL</span>
                <input
                  type="url"
                  value={samlSso.idpSsoUrl}
                  onChange={(event) => updateSamlSso({ idpSsoUrl: event.target.value })}
                  placeholder="https://idp.example.com/sso"
                  className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono"
                />
              </label>
              <label className="space-y-1.5">
                <span className="text-xs text-text-tertiary block">Email Attribute</span>
                <input
                  value={samlSso.emailAttribute}
                  onChange={(event) => updateSamlSso({ emailAttribute: event.target.value })}
                  placeholder="email"
                  className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono"
                />
              </label>
              <label className="space-y-1.5">
                <span className="text-xs text-text-tertiary block">Groups Attribute</span>
                <input
                  value={samlSso.groupsAttribute}
                  onChange={(event) => updateSamlSso({ groupsAttribute: event.target.value })}
                  placeholder="groups"
                  className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono"
                />
              </label>
            </div>
            <label className="space-y-1.5 block">
              <span className="text-xs text-text-tertiary block">Group Role Mappings</span>
              <textarea
                value={samlSso.groupRoleMappings}
                onChange={(event) => updateSamlSso({ groupRoleMappings: event.target.value })}
                rows={5}
                placeholder={'[{"group":"Engineering","role":"developer"}]'}
                className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono resize-y"
              />
            </label>
            <label className="space-y-1.5 block">
              <span className="text-xs text-text-tertiary block">IdP Certificate PEMs</span>
              <textarea
                value={samlSso.idpCertPems}
                onChange={(event) => updateSamlSso({ idpCertPems: event.target.value })}
                rows={7}
                placeholder={"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"}
                className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono resize-y"
              />
            </label>
            <label className="flex items-center gap-2 text-sm text-text-secondary">
              <input
                type="checkbox"
                checked={samlSso.allowJitProvisioning}
                onChange={(event) => updateSamlSso({ allowJitProvisioning: event.target.checked })}
                className="h-4 w-4 accent-accent"
              />
              Auto-create SSO users as Viewer
            </label>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          {samlSsoSaved && (
            <motion.span
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              className="text-xs text-emerald-400"
            >
              Saved
            </motion.span>
          )}
          {samlSsoError && <span className="text-xs text-red-400">{samlSsoError}</span>}
        </div>
      </form>

      {/* App Origins */}
      <form onSubmit={saveAllowedOrigins} className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="font-display text-sm font-600 text-text-secondary tracking-wider uppercase">
              App Origins
            </h2>
            <p className="text-xs text-text-tertiary max-w-2xl mt-1">
              Used for browser CORS, passkey relying-party selection, and wallet sign-in domains.
              Use exact origins only.
            </p>
          </div>
          <button
            type="submit"
            disabled={originsSaving || originsLoading || !TENANT_ID}
            className="px-4 py-2 text-sm bg-accent text-bg hover:bg-accent-hover transition-colors disabled:opacity-40 font-medium"
          >
            {originsSaving ? "Saving..." : "Save Origins"}
          </button>
        </div>
        <div className="space-y-px bg-border max-w-4xl">
          <div className="bg-bg p-5 space-y-3">
            <label className="space-y-1.5 block">
              <span className="text-xs text-text-tertiary block">Allowed Origins</span>
              <textarea
                value={allowedOrigins}
                onChange={(event) => setAllowedOrigins(event.target.value)}
                rows={5}
                placeholder={
                  "https://app.example.com\nhttps://dashboard.example.com\nhttp://localhost:3000"
                }
                className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono resize-y"
              />
            </label>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-px bg-border-subtle">
              {[
                ["CORS", "Browser requests from these origins can call tenant-scoped APIs."],
                ["Wallet Login", "SIWE and SIWS signed domains are checked against this list."],
                [
                  "Passkeys",
                  "Subdomains can share a relying-party ID with a configured apex origin.",
                ],
              ].map(([label, copy]) => (
                <div key={label} className="bg-bg p-4">
                  <div className="text-xs text-text-secondary uppercase tracking-wider">
                    {label}
                  </div>
                  <div className="text-xs text-text-tertiary mt-1">{copy}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          {originsSaved && (
            <motion.span
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              className="text-xs text-emerald-400"
            >
              Saved
            </motion.span>
          )}
          {originsError && <span className="text-xs text-red-400">{originsError}</span>}
        </div>
      </form>

      {/* Redirect URLs */}
      <form onSubmit={saveAllowedRedirectUrls} className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="font-display text-sm font-600 text-text-secondary tracking-wider uppercase">
              Redirect URLs
            </h2>
            <p className="text-xs text-text-tertiary max-w-2xl mt-1">
              Exact OAuth and email callback URLs. Existing tenants fall back to app origins only
              when this list is empty.
            </p>
          </div>
          <button
            type="submit"
            disabled={redirectUrlsSaving || originsLoading || !TENANT_ID}
            className="px-4 py-2 text-sm bg-accent text-bg hover:bg-accent-hover transition-colors disabled:opacity-40 font-medium"
          >
            {redirectUrlsSaving ? "Saving..." : "Save Redirects"}
          </button>
        </div>
        <div className="space-y-px bg-border max-w-4xl">
          <div className="bg-bg p-5 space-y-3">
            <label className="space-y-1.5 block">
              <span className="text-xs text-text-tertiary block">Allowed Redirect URLs</span>
              <textarea
                value={allowedRedirectUrls}
                onChange={(event) => setAllowedRedirectUrls(event.target.value)}
                rows={5}
                placeholder={
                  "https://app.example.com/auth/callback\nhttps://app.example.com/login\nhttp://localhost:3000/auth/callback"
                }
                className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono resize-y"
              />
            </label>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          {redirectUrlsSaved && (
            <motion.span
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              className="text-xs text-emerald-400"
            >
              Saved
            </motion.span>
          )}
          {redirectUrlsError && <span className="text-xs text-red-400">{redirectUrlsError}</span>}
        </div>
      </form>

      {/* App Access Allowlist */}
      <form onSubmit={addAccessAllowlistEntry} className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="font-display text-sm font-600 text-text-secondary tracking-wider uppercase">
              App Access Allowlist
            </h2>
            <p className="text-xs text-text-tertiary max-w-2xl mt-1">
              Restrict who can authenticate by exact email, email domain, wallet address, or E.164
              phone number.
            </p>
          </div>
          <button
            type="submit"
            disabled={accessAllowlistSaving || accessAllowlistLoading || !TENANT_ID}
            className="px-4 py-2 text-sm bg-accent text-bg hover:bg-accent-hover transition-colors disabled:opacity-40 font-medium"
          >
            {accessAllowlistSaving ? "Saving..." : "Add Entry"}
          </button>
        </div>
        <div className="space-y-px bg-border max-w-5xl">
          <div className="bg-bg p-5">
            <div className="grid grid-cols-1 md:grid-cols-[180px_minmax(0,1fr)] gap-4">
              <label className="space-y-1.5">
                <span className="text-xs text-text-tertiary block">Type</span>
                <select
                  value={accessAllowlistType}
                  onChange={(event) =>
                    setAccessAllowlistType(event.target.value as AccessAllowlistEntryType)
                  }
                  className="w-full bg-bg border border-border px-3 py-2 text-sm text-text focus:outline-none focus:border-accent transition-colors"
                >
                  {ACCESS_ALLOWLIST_TYPES.map((type) => (
                    <option key={type.value} value={type.value}>
                      {type.label}
                    </option>
                  ))}
                </select>
              </label>
              <label className="space-y-1.5">
                <span className="text-xs text-text-tertiary block">Value</span>
                <input
                  value={accessAllowlistValue}
                  onChange={(event) => setAccessAllowlistValue(event.target.value)}
                  placeholder={
                    ACCESS_ALLOWLIST_TYPES.find((type) => type.value === accessAllowlistType)
                      ?.placeholder
                  }
                  className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono"
                />
              </label>
            </div>
            <label className="space-y-1.5 block mt-4">
              <span className="text-xs text-text-tertiary block">Bulk Entries</span>
              <textarea
                value={accessAllowlistBulkValue}
                onChange={(event) => setAccessAllowlistBulkValue(event.target.value)}
                rows={4}
                placeholder={
                  "email: alice@example.com\nemail_domain: example.com\nwallet: 0x...\nphone: +14155550100"
                }
                className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono resize-y"
              />
              <span className="text-xs text-text-tertiary block">
                Use one entry per line. Start with email, email_domain, wallet, or phone; unprefixed
                lines use the selected category.
              </span>
            </label>
          </div>
          <div className="bg-bg overflow-x-auto">
            <table className="w-full min-w-[640px] text-sm">
              <thead className="border-b border-border-subtle">
                <tr className="text-left text-xs text-text-tertiary">
                  <th className="font-medium px-5 py-3">Type</th>
                  <th className="font-medium px-5 py-3">Value</th>
                  <th className="font-medium px-5 py-3">Status</th>
                  <th className="font-medium px-5 py-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle">
                {accessAllowlist.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="px-5 py-5 text-sm text-text-tertiary">
                      {accessAllowlistLoading
                        ? "Loading entries..."
                        : "No access allowlist entries configured"}
                    </td>
                  </tr>
                ) : (
                  accessAllowlist.map((entry) => (
                    <tr key={entry.id} className="text-text-secondary">
                      <td className="px-5 py-3 whitespace-nowrap">
                        {accessAllowlistTypeLabel(entry.type)}
                      </td>
                      <td className="px-5 py-3 font-mono break-all">{entry.value}</td>
                      <td className="px-5 py-3 whitespace-nowrap text-xs text-text-tertiary">
                        {entry.acceptedAt ? "Accepted" : "Active"}
                      </td>
                      <td className="px-5 py-3 text-right">
                        <button
                          type="button"
                          onClick={() => removeAccessAllowlistEntry(entry)}
                          disabled={accessAllowlistSaving || accessAllowlistLoading || !TENANT_ID}
                          className="text-xs text-text-tertiary hover:text-red-400 transition-colors disabled:opacity-40"
                        >
                          Remove
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          {accessAllowlistSaved && (
            <motion.span
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              className="text-xs text-emerald-400"
            >
              Saved
            </motion.span>
          )}
          {accessAllowlistError && (
            <span className="text-xs text-red-400">{accessAllowlistError}</span>
          )}
        </div>
      </form>

      {/* Gas Sponsorship */}
      <form onSubmit={saveGasSponsorship} className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="font-display text-sm font-600 text-text-secondary tracking-wider uppercase">
              Gas Sponsorship
            </h2>
            <p className="text-xs text-text-tertiary max-w-2xl mt-1">
              Configure tenant-level paymaster or fee-payer sponsorship. Updates may require a
              recent tenant-admin MFA challenge.
            </p>
          </div>
          <button
            type="submit"
            disabled={gasSponsorshipSaving || gasSponsorshipLoading || !TENANT_ID}
            className="px-4 py-2 text-sm bg-accent text-bg hover:bg-accent-hover transition-colors disabled:opacity-40 font-medium"
          >
            {gasSponsorshipSaving ? "Saving..." : "Save Sponsorship"}
          </button>
        </div>
        <div className="space-y-px bg-border max-w-5xl">
          <div className="bg-bg p-5 space-y-4">
            <div className="flex flex-wrap items-center gap-4">
              <label className="flex items-center gap-2 text-sm text-text-secondary">
                <input
                  type="checkbox"
                  checked={gasSponsorship.enabled}
                  onChange={(event) => updateGasSponsorship({ enabled: event.target.checked })}
                  className="accent-accent"
                />
                Enabled
              </label>
              <label className="flex items-center gap-2 text-sm text-text-secondary">
                <input
                  type="checkbox"
                  checked={gasSponsorship.circuitBreakerEnabled}
                  onChange={(event) =>
                    updateGasSponsorship({ circuitBreakerEnabled: event.target.checked })
                  }
                  className="accent-accent"
                />
                Circuit breaker
              </label>
              <label className="flex items-center gap-2 text-sm text-text-secondary">
                <input
                  type="checkbox"
                  checked={gasSponsorship.allowClientSponsorship}
                  onChange={(event) =>
                    updateGasSponsorship({ allowClientSponsorship: event.target.checked })
                  }
                  className="accent-accent"
                />
                Client requests
              </label>
              <label className="flex items-center gap-2 text-sm text-text-secondary">
                <input
                  type="checkbox"
                  checked={gasSponsorship.requireSimulation}
                  onChange={(event) =>
                    updateGasSponsorship({ requireSimulation: event.target.checked })
                  }
                  className="accent-accent"
                />
                Require simulation
              </label>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <label className="space-y-1.5">
                <span className="text-xs text-text-tertiary block">Provider</span>
                <select
                  value={gasSponsorship.provider}
                  onChange={(event) =>
                    updateGasSponsorship({
                      provider: event.target.value as GasSponsorshipProvider | "",
                    })
                  }
                  className="w-full bg-bg border border-border px-3 py-2 text-sm text-text focus:outline-none focus:border-accent transition-colors"
                >
                  <option value="">Select provider</option>
                  {GAS_SPONSORSHIP_PROVIDERS.map((provider) => (
                    <option key={provider.value} value={provider.value}>
                      {provider.label}
                    </option>
                  ))}
                </select>
              </label>
              <label className="space-y-1.5">
                <span className="text-xs text-text-tertiary block">Mode</span>
                <select
                  value={gasSponsorship.mode}
                  onChange={(event) =>
                    updateGasSponsorship({ mode: event.target.value as GasSponsorshipMode | "" })
                  }
                  className="w-full bg-bg border border-border px-3 py-2 text-sm text-text focus:outline-none focus:border-accent transition-colors"
                >
                  <option value="">Select mode</option>
                  {GAS_SPONSORSHIP_MODES.map((mode) => (
                    <option key={mode.value} value={mode.value}>
                      {mode.label}
                    </option>
                  ))}
                </select>
              </label>
              <label className="space-y-1.5">
                <span className="text-xs text-text-tertiary block">Max USD Per Tx</span>
                <input
                  type="number"
                  min="0"
                  step="0.01"
                  value={gasSponsorship.maxPerTxUsd}
                  onChange={(event) => updateGasSponsorship({ maxPerTxUsd: event.target.value })}
                  placeholder="1.00"
                  className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono"
                />
              </label>
            </div>
            <label className="space-y-1.5 block">
              <span className="text-xs text-text-tertiary block">Allowed Chain IDs</span>
              <textarea
                value={gasSponsorship.allowedChainIds}
                onChange={(event) => updateGasSponsorship({ allowedChainIds: event.target.value })}
                rows={4}
                placeholder={"8453\n137\n42161"}
                className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono resize-y"
              />
            </label>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-px bg-border-subtle">
              {[
                [
                  gasSponsorship.enabled ? "Enabled" : "Disabled",
                  gasSponsorship.enabled
                    ? "Sponsored requests can be accepted on configured chains."
                    : "Client requests for sponsorship will remain blocked.",
                ],
                [
                  gasSponsorshipProviderLabel(gasSponsorship.provider),
                  "Provider adapter selection for reservation and settlement.",
                ],
                [
                  gasSponsorship.circuitBreakerEnabled ? "Breaker On" : "Breaker Off",
                  gasSponsorship.circuitBreakerEnabled
                    ? "Sponsorship is paused even if enabled."
                    : "Circuit breaker is not pausing sponsorship.",
                ],
                [
                  gasSponsorship.allowClientSponsorship ? "Client Opt-In" : "Server Only",
                  gasSponsorship.allowClientSponsorship
                    ? "Wallet actions may request sponsorship with sponsor=true."
                    : "Client-requested sponsor=true actions remain blocked.",
                ],
              ].map(([label, copy]) => (
                <div key={label} className="bg-bg p-4">
                  <div className="text-xs text-text-secondary uppercase tracking-wider">
                    {label}
                  </div>
                  <div className="text-xs text-text-tertiary mt-1">{copy}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          {gasSponsorshipSaved && (
            <motion.span
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              className="text-xs text-emerald-400"
            >
              Saved
            </motion.span>
          )}
          {gasSponsorshipError && (
            <span className="text-xs text-red-400">{gasSponsorshipError}</span>
          )}
        </div>
      </form>

      {/* Security Checklist */}
      <section className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 className="font-display text-sm font-600 text-text-secondary tracking-wider uppercase">
            Security Checklist
          </h2>
          {securityChecklist && (
            <div className="flex items-center gap-2 text-xs text-text-tertiary">
              <span>{securityChecklist.summary.pass} pass</span>
              <span>{securityChecklist.summary.warning} review</span>
              <span>{securityChecklist.summary.fail} fail</span>
            </div>
          )}
        </div>
        <div className="space-y-px bg-border max-w-5xl">
          <div className="bg-bg p-5 space-y-4">
            {securityChecklistLoading && (
              <div className="text-sm text-text-tertiary">Loading security posture...</div>
            )}
            {!securityChecklistLoading && securityChecklistError && (
              <div className="text-sm text-red-400">{securityChecklistError}</div>
            )}
            {!securityChecklistLoading && securityChecklist && (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-px bg-border-subtle">
                {securityChecklist.items.map((item) => (
                  <div key={item.id} className="bg-bg p-4 space-y-2">
                    <div className="flex items-start justify-between gap-3">
                      <div className="text-sm font-medium text-text-secondary">{item.label}</div>
                      <span
                        className={`shrink-0 border px-2 py-0.5 text-[11px] uppercase tracking-wider ${securityChecklistStatusClass(
                          item.status,
                        )}`}
                      >
                        {securityChecklistStatusLabel(item.status)}
                      </span>
                    </div>
                    <p className="text-xs text-text-tertiary">{item.description}</p>
                    {item.remediation && (
                      <p className="text-xs text-text-secondary">{item.remediation}</p>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </section>

      {/* Idempotency Metrics */}
      <section className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="font-display text-sm font-600 text-text-secondary tracking-wider uppercase">
              Idempotency Metrics
            </h2>
            {idempotencyMetrics?.lastSeenAt && (
              <p className="text-xs text-text-tertiary mt-1">
                Last idempotent request: {new Date(idempotencyMetrics.lastSeenAt).toLocaleString()}
              </p>
            )}
          </div>
          <div className="flex items-center gap-3">
            {idempotencyMetrics && (
              <div className="text-xs text-text-tertiary">
                TTL {Math.round(idempotencyMetrics.ttlMs / 1000)}s
              </div>
            )}
            <button
              type="button"
              onClick={exportIdempotencyMetrics}
              disabled={!TENANT_ID || !authToken || idempotencyExportSaving}
              className="px-3 py-2 text-xs border border-border text-text-secondary hover:border-accent hover:text-accent disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            >
              {idempotencyExportSaving ? "Exporting" : "Export CSV"}
            </button>
          </div>
        </div>
        <div className="space-y-px bg-border max-w-5xl">
          <div className="bg-bg p-5 space-y-4">
            {idempotencyMetricsLoading && (
              <div className="text-sm text-text-tertiary">Loading idempotency metrics...</div>
            )}
            {!idempotencyMetricsLoading && idempotencyMetricsError && (
              <div className="text-sm text-red-400">{idempotencyMetricsError}</div>
            )}
            {!idempotencyMetricsLoading && idempotencyMetrics && (
              <div className="grid grid-cols-2 md:grid-cols-4 gap-px bg-border-subtle">
                {[
                  ["Observed", idempotencyMetrics.counters.observed],
                  ["Reserved", idempotencyMetrics.counters.reserved],
                  ["Completed", idempotencyMetrics.counters.completed],
                  ["Replayed", idempotencyMetrics.counters.replayed],
                  ["Conflicts", idempotencyMetrics.counters.conflicts],
                  ["In flight", idempotencyMetrics.counters.inFlightConflicts],
                  ["Auth suppressed", idempotencyMetrics.counters.suppressedAuthResponses],
                  ["Store errors", idempotencyMetrics.counters.storeErrors],
                ].map(([label, value]) => (
                  <div key={label} className="bg-bg p-4">
                    <div className="text-[11px] uppercase tracking-wider text-text-tertiary">
                      {label}
                    </div>
                    <div className="mt-2 font-mono text-xl text-text-secondary">{value}</div>
                  </div>
                ))}
              </div>
            )}
            {!idempotencyMetricsLoading && idempotencyMetrics && (
              <div className="text-xs text-text-tertiary">
                Counters are tenant-scoped and do not expose idempotency keys, request bodies, or
                replayed response payloads.
              </div>
            )}
          </div>
        </div>
      </section>

      {/* Request Signing Keys */}
      <section className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 className="font-display text-sm font-600 text-text-secondary tracking-wider uppercase">
            Request Signing Keys
          </h2>
          <button
            type="button"
            onClick={rotateRequestSigningKey}
            disabled={requestSigningKeysSaving || requestSigningKeysLoading || !TENANT_ID}
            className="px-4 py-2 text-sm bg-accent text-bg hover:bg-accent-hover transition-colors disabled:opacity-40 font-medium"
          >
            {requestSigningKeysSaving ? "Rotating..." : "Rotate Key"}
          </button>
        </div>
        <div className="space-y-px bg-border max-w-5xl">
          <div className="bg-bg p-5 space-y-4">
            <label className="space-y-1.5 block max-w-md">
              <span className="text-xs text-text-tertiary block">Key Name</span>
              <input
                value={requestSigningKeyName}
                onChange={(event) => setRequestSigningKeyName(event.target.value)}
                className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors"
              />
            </label>
            {requestSigningKeyReveal && (
              <div className="border border-amber-400/20 bg-amber-400/5 p-3 text-xs">
                <div className="text-amber-300">Copy this signing secret now.</div>
                <div className="mt-2 font-mono text-text-secondary break-all">
                  Key ID: {requestSigningKeyReveal.key.id}
                </div>
                <div className="mt-1 font-mono text-text-secondary break-all">
                  Secret: {requestSigningKeyReveal.signingSecret}
                </div>
                <CodeBlock
                  code={`const steward = new StewardClient({
  baseUrl: "${API_URL}",
  tenantId: "${TENANT_ID}",
  requestSigningSecret: "${requestSigningKeyReveal.signingSecret}",
  requestSigningKeyId: "${requestSigningKeyReveal.key.id}",
});`}
                  language="typescript"
                  className="mt-2"
                />
              </div>
            )}
            {requestSigningKeysLoading && (
              <div className="text-sm text-text-tertiary">Loading request signing keys...</div>
            )}
            {!requestSigningKeysLoading && requestSigningKeys.length === 0 && (
              <div className="text-sm text-text-tertiary">No request signing keys yet.</div>
            )}
            {requestSigningKeys.length > 0 && (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-px bg-border-subtle">
                {requestSigningKeys.map((key) => (
                  <div key={key.id} className="bg-bg p-4 space-y-2">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="text-sm font-medium text-text-secondary">{key.name}</div>
                        <div className="text-xs font-mono text-text-tertiary mt-1">
                          {key.secretPrefix}
                        </div>
                      </div>
                      <span className="text-[11px] uppercase tracking-wider text-text-tertiary">
                        {key.status}
                      </span>
                    </div>
                    <div className="text-xs font-mono text-text-tertiary break-all">{key.id}</div>
                    {key.status !== "revoked" && (
                      <button
                        type="button"
                        onClick={() => revokeRequestSigningKey(key.id)}
                        disabled={requestSigningKeysSaving}
                        className="px-3 py-1.5 text-xs border border-border text-text-secondary hover:border-red-400 hover:text-red-300 transition-colors disabled:opacity-40"
                      >
                        Revoke
                      </button>
                    )}
                  </div>
                ))}
              </div>
            )}
            {requestSigningKeysError && (
              <span className="text-xs text-red-400">{requestSigningKeysError}</span>
            )}
          </div>
        </div>
      </section>

      {/* Webhook */}
      <form onSubmit={saveWebhook} className="space-y-4">
        <h2 className="font-display text-sm font-600 text-text-secondary tracking-wider uppercase">
          Webhooks
        </h2>
        <p className="text-xs text-text-tertiary max-w-lg">
          Receive POST requests when transactions need approval or change status. Events include:
          approval_required, tx_signed, tx_confirmed, tx_failed.
        </p>
        <div>
          <label className="text-xs text-text-tertiary block mb-1.5">Webhook URL</label>
          <input
            type="url"
            value={webhookUrl}
            onChange={(e) => setWebhookUrl(e.target.value)}
            placeholder="https://your-app.com/steward-webhook"
            className="w-full max-w-lg bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono"
          />
        </div>
        <div className="flex items-center gap-3">
          <button
            type="submit"
            disabled={saving}
            className="px-4 py-2 text-sm bg-accent text-bg hover:bg-accent-hover transition-colors disabled:opacity-40 font-medium"
          >
            {saving ? "Saving..." : "Save Webhook"}
          </button>
          {saved && (
            <motion.span
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              className="text-xs text-emerald-400"
            >
              Saved
            </motion.span>
          )}
        </div>
      </form>

      {/* Login Controls */}
      <form onSubmit={saveAuthAbuseControls} className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 className="font-display text-sm font-600 text-text-secondary tracking-wider uppercase">
            Login Controls
          </h2>
          <button
            type="submit"
            disabled={authAbuseSaving || authAbuseLoading || !TENANT_ID}
            className="px-4 py-2 text-sm bg-accent text-bg hover:bg-accent-hover transition-colors disabled:opacity-40 font-medium"
          >
            {authAbuseSaving ? "Saving..." : "Save Controls"}
          </button>
        </div>
        <div className="space-y-px bg-border max-w-5xl">
          <div className="bg-bg p-5 space-y-4">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              {[
                ["Passkey", "loginPasskey"],
                ["Email", "loginEmail"],
                ["SMS", "loginSms"],
                ["WhatsApp", "loginWhatsapp"],
                ["TOTP", "loginTotp"],
                ["SIWE", "loginSiwe"],
                ["SIWS", "loginSiws"],
                ["Telegram", "loginTelegram"],
                ["Farcaster", "loginFarcaster"],
                ["Google", "oauthGoogle"],
                ["Discord", "oauthDiscord"],
                ["GitHub", "oauthGithub"],
                ["Twitter/X", "oauthTwitter"],
              ].map(([label, key]) => (
                <label key={key} className="flex items-center gap-2 text-sm text-text-secondary">
                  <input
                    type="checkbox"
                    checked={authAbuse[key as keyof AuthAbuseForm] as boolean}
                    onChange={(event) =>
                      updateAuthAbuse({ [key]: event.target.checked } as Partial<AuthAbuseForm>)
                    }
                    className="accent-accent"
                  />
                  {label}
                </label>
              ))}
            </div>
          </div>
          <div className="bg-bg p-5 space-y-4">
            <div className="flex flex-wrap items-center gap-4">
              <label className="flex items-center gap-2 text-sm text-text-secondary">
                <input
                  type="checkbox"
                  checked={authAbuse.captchaEnabled}
                  onChange={(event) => updateAuthAbuse({ captchaEnabled: event.target.checked })}
                  className="accent-accent"
                />
                CAPTCHA
              </label>
              <label className="space-y-1.5">
                <span className="text-xs text-text-tertiary block">Provider</span>
                <select
                  value={authAbuse.captchaProvider}
                  onChange={(event) =>
                    updateAuthAbuse({
                      captchaProvider: event.target.value as "turnstile" | "hcaptcha",
                    })
                  }
                  className="bg-bg border border-border px-3 py-2 text-sm text-text focus:outline-none focus:border-accent transition-colors"
                >
                  <option value="turnstile">Turnstile</option>
                  <option value="hcaptcha">hCaptcha</option>
                </select>
              </label>
              <label className="flex items-center gap-2 text-sm text-text-secondary mt-5">
                <input
                  type="checkbox"
                  checked={authAbuse.captchaEmailOtp}
                  onChange={(event) => updateAuthAbuse({ captchaEmailOtp: event.target.checked })}
                  className="accent-accent"
                />
                Email OTP
              </label>
              <label className="flex items-center gap-2 text-sm text-text-secondary mt-5">
                <input
                  type="checkbox"
                  checked={authAbuse.captchaSmsOtp}
                  onChange={(event) => updateAuthAbuse({ captchaSmsOtp: event.target.checked })}
                  className="accent-accent"
                />
                SMS OTP
              </label>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <label className="space-y-1.5">
                <span className="text-xs text-text-tertiary block">Site Key</span>
                <input
                  value={authAbuse.captchaSiteKey}
                  onChange={(event) => updateAuthAbuse({ captchaSiteKey: event.target.value })}
                  placeholder="0x4AAAA..."
                  className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono"
                />
              </label>
              <label className="space-y-1.5">
                <span className="text-xs text-text-tertiary block">Secret Env Var</span>
                <input
                  value={authAbuse.captchaSecretKeyEnv}
                  onChange={(event) => updateAuthAbuse({ captchaSecretKeyEnv: event.target.value })}
                  placeholder="TENANT_TURNSTILE_SECRET"
                  className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono"
                />
              </label>
            </div>
          </div>
          <div className="bg-bg p-5 space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-[180px_minmax(0,1fr)] gap-4">
              <label className="space-y-1.5">
                <span className="text-xs text-text-tertiary block">MFA Max Age Seconds</span>
                <input
                  type="number"
                  min={30}
                  max={3600}
                  step={30}
                  inputMode="numeric"
                  value={authAbuse.mfaMaxAgeSeconds}
                  onChange={(event) => updateAuthAbuse({ mfaMaxAgeSeconds: event.target.value })}
                  className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono"
                />
              </label>
              <div className="space-y-4">
                <div className="space-y-2">
                  <div className="text-xs uppercase tracking-[0.18em] text-text-tertiary">
                    Sensitive Actions
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                    {[
                      ["Require MFA for vault signing", "mfaVaultSigning"],
                      ["Require MFA for key import", "mfaKeyImport"],
                      ["Require MFA for key export", "mfaKeyExport"],
                      ["Require MFA for recovery codes", "mfaRecoveryCodes"],
                      ["Require MFA for tenant admin changes", "mfaTenantAdmin"],
                    ].map(([label, key]) => (
                      <label
                        key={key}
                        className="flex items-center gap-2 text-sm text-text-secondary"
                      >
                        <input
                          type="checkbox"
                          checked={authAbuse[key as keyof AuthAbuseForm] as boolean}
                          onChange={(event) =>
                            updateAuthAbuse({
                              [key]: event.target.checked,
                            } as Partial<AuthAbuseForm>)
                          }
                          className="accent-accent"
                        />
                        {label}
                      </label>
                    ))}
                  </div>
                </div>
                <div className="space-y-2">
                  <div className="text-xs uppercase tracking-[0.18em] text-text-tertiary">
                    Automation Exceptions
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    {[
                      ["Allow delegated signer automation", "mfaAllowDelegatedSignerAutomation"],
                      ["Allow key quorum automation", "mfaAllowKeyQuorumAutomation"],
                    ].map(([label, key]) => (
                      <label
                        key={key}
                        className="flex items-center gap-2 text-sm text-text-secondary"
                      >
                        <input
                          type="checkbox"
                          checked={authAbuse[key as keyof AuthAbuseForm] as boolean}
                          onChange={(event) =>
                            updateAuthAbuse({
                              [key]: event.target.checked,
                            } as Partial<AuthAbuseForm>)
                          }
                          className="accent-accent"
                        />
                        {label}
                      </label>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
          <div className="bg-bg p-5 space-y-4">
            <div className="flex flex-wrap items-center gap-4">
              <label className="flex items-center gap-2 text-sm text-text-secondary">
                <input
                  type="checkbox"
                  checked={authAbuse.blockDisposable}
                  onChange={(event) => updateAuthAbuse({ blockDisposable: event.target.checked })}
                  className="accent-accent"
                />
                Disposable email block
              </label>
              <label className="flex items-center gap-2 text-sm text-text-secondary">
                <input
                  type="checkbox"
                  checked={authAbuse.blockPlusAliases}
                  onChange={(event) => updateAuthAbuse({ blockPlusAliases: event.target.checked })}
                  className="accent-accent"
                />
                Plus alias block
              </label>
              <label className="flex items-center gap-2 text-sm text-text-secondary">
                <input
                  type="checkbox"
                  checked={authAbuse.blockVoip}
                  onChange={(event) => updateAuthAbuse({ blockVoip: event.target.checked })}
                  className="accent-accent"
                />
                VOIP phone block
              </label>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
              {[
                ["Allowed Emails", "allowedEmails", "alice@example.com"],
                ["Blocked Emails", "blockedEmails", "blocked@example.com"],
                ["Allowed Domains", "allowedDomains", "example.com"],
                ["Blocked Domains", "blockedDomains", "mailinator.com"],
                ["Allowed Phone Codes", "allowedCountryCodes", "1"],
                ["Blocked Phone Codes", "blockedCountryCodes", "7"],
              ].map(([label, key, placeholder]) => (
                <label key={key} className="space-y-1.5">
                  <span className="text-xs text-text-tertiary block">{label}</span>
                  <textarea
                    value={authAbuse[key as keyof AuthAbuseForm] as string}
                    onChange={(event) =>
                      updateAuthAbuse({ [key]: event.target.value } as Partial<AuthAbuseForm>)
                    }
                    rows={4}
                    placeholder={placeholder}
                    className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono resize-y"
                  />
                </label>
              ))}
            </div>
            <div className="border-t border-border pt-4 space-y-3">
              <div>
                <h3 className="text-xs font-600 uppercase tracking-wider text-text-secondary">
                  Third-Party Wallet Sign-In Policy
                </h3>
                <p className="text-xs text-text-tertiary mt-1 max-w-2xl">
                  Applied to SIWE and SIWS login attempts before a session is issued.
                </p>
              </div>
              <label className="flex items-start gap-3 text-sm text-text-secondary">
                <input
                  type="checkbox"
                  checked={authAbuse.restrictToOneThirdPartyWallet}
                  onChange={(event) =>
                    updateAuthAbuse({ restrictToOneThirdPartyWallet: event.target.checked })
                  }
                  className="mt-0.5 h-4 w-4 accent-accent"
                />
                <span>
                  <span className="block text-text">Restrict users to one linked wallet</span>
                  <span className="block text-xs text-text-tertiary">
                    Prevents a user from linking more than one external EVM or Solana wallet.
                  </span>
                </span>
              </label>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {[
                  [
                    "Third-party Wallet Allowlist",
                    "allowedWallets",
                    "0x0000000000000000000000000000000000000001\nsolana:11111111111111111111111111111111",
                  ],
                  [
                    "Third-party Wallet Blocklist",
                    "blockedWallets",
                    "0x0000000000000000000000000000000000000002\nsolana:22222222222222222222222222222222",
                  ],
                ].map(([label, key, placeholder]) => (
                  <label key={key} className="space-y-1.5">
                    <span className="text-xs text-text-tertiary block">{label}</span>
                    <textarea
                      value={authAbuse[key as keyof AuthAbuseForm] as string}
                      onChange={(event) =>
                        updateAuthAbuse({ [key]: event.target.value } as Partial<AuthAbuseForm>)
                      }
                      rows={4}
                      placeholder={placeholder}
                      className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono resize-y"
                    />
                  </label>
                ))}
              </div>
            </div>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          {authAbuseSaved && (
            <motion.span
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              className="text-xs text-emerald-400"
            >
              Saved
            </motion.span>
          )}
          {authAbuseError && <span className="text-xs text-red-400">{authAbuseError}</span>}
        </div>
      </form>

      {/* Test Credentials */}
      <div className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 className="font-display text-sm font-600 text-text-secondary tracking-wider uppercase">
            Test Credentials
          </h2>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={rotateTestAccount}
              disabled={testAccountSaving || testAccountLoading || !TENANT_ID}
              className="px-3 py-1.5 text-xs bg-accent text-bg hover:bg-accent-hover transition-colors disabled:opacity-40 font-medium"
            >
              {testAccount.enabled ? "Rotate" : "Enable"}
            </button>
            {testAccount.enabled && (
              <button
                type="button"
                onClick={disableTestAccount}
                disabled={testAccountSaving || testAccountLoading || !TENANT_ID}
                className="px-3 py-1.5 text-xs border border-border text-text-secondary hover:border-red-400 hover:text-red-400 transition-colors disabled:opacity-40"
              >
                Disable
              </button>
            )}
          </div>
        </div>
        <div className="space-y-px bg-border max-w-4xl">
          {!testAccount.enabled ? (
            <div className="bg-bg p-5 text-sm text-text-tertiary">
              {testAccountLoading ? "Loading credentials..." : "No test credentials enabled"}
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-px bg-border">
              <div className="bg-bg p-5 min-w-0">
                <label className="text-xs text-text-tertiary block mb-2">Email</label>
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-sm text-text-secondary truncate">
                    {testAccount.email}
                  </span>
                  {testAccount.email && <CopyButton text={testAccount.email} />}
                </div>
              </div>
              <div className="bg-bg p-5 min-w-0">
                <label className="text-xs text-text-tertiary block mb-2">Phone</label>
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-sm text-text-secondary truncate">
                    {testAccount.phone}
                  </span>
                  {testAccount.phone && <CopyButton text={testAccount.phone} />}
                </div>
              </div>
              <div className="bg-bg p-5 min-w-0">
                <label className="text-xs text-text-tertiary block mb-2">OTP</label>
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-sm text-text-secondary tracking-wider">
                    {testAccount.otp}
                  </span>
                  {testAccount.otp && <CopyButton text={testAccount.otp} />}
                </div>
              </div>
            </div>
          )}
        </div>
        {testAccountError && <span className="text-xs text-red-400">{testAccountError}</span>}
      </div>

      {/* OIDC/JWT Providers */}
      <form onSubmit={saveOidcProviders} className="space-y-4">
        <div className="flex items-center justify-between gap-3">
          <h2 className="font-display text-sm font-600 text-text-secondary tracking-wider uppercase">
            OIDC / JWT Login
          </h2>
          <button
            type="button"
            onClick={() => setOidcProviders((providers) => [...providers, emptyOidcProvider()])}
            className="px-3 py-1.5 text-xs border border-border text-text-secondary hover:border-accent hover:text-text transition-colors"
          >
            Add Provider
          </button>
        </div>
        <div className="space-y-px bg-border max-w-4xl">
          {oidcProviders.length === 0 && (
            <div className="bg-bg p-5 text-sm text-text-tertiary">
              {oidcLoading ? "Loading providers..." : "No OIDC providers configured"}
            </div>
          )}
          {oidcProviders.map((provider, index) => (
            <div key={`${provider.id || "provider"}-${index}`} className="bg-bg p-5 space-y-4">
              <div className="flex items-center justify-between gap-3">
                <label className="flex items-center gap-2 text-sm text-text-secondary">
                  <input
                    type="checkbox"
                    checked={provider.enabled}
                    onChange={(e) => updateOidcProvider(index, { enabled: e.target.checked })}
                    className="accent-accent"
                  />
                  Enabled
                </label>
                <button
                  type="button"
                  onClick={() =>
                    setOidcProviders((providers) =>
                      providers.filter((_, providerIndex) => providerIndex !== index),
                    )
                  }
                  className="text-xs text-text-tertiary hover:text-red-400 transition-colors"
                >
                  Remove
                </button>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <label className="space-y-1.5">
                  <span className="text-xs text-text-tertiary block">Provider ID</span>
                  <input
                    value={provider.id}
                    onChange={(e) => updateOidcProvider(index, { id: e.target.value })}
                    placeholder="auth0-prod"
                    className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono"
                  />
                </label>
                <label className="space-y-1.5">
                  <span className="text-xs text-text-tertiary block">Audience</span>
                  <input
                    value={provider.audience}
                    onChange={(e) => updateOidcProvider(index, { audience: e.target.value })}
                    placeholder="steward-api, mobile-app"
                    className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono"
                  />
                </label>
                <label className="space-y-1.5">
                  <span className="text-xs text-text-tertiary block">Issuer</span>
                  <input
                    type="url"
                    value={provider.issuer}
                    onChange={(e) => updateOidcProvider(index, { issuer: e.target.value })}
                    placeholder="https://tenant.example.com"
                    className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono"
                  />
                </label>
                <label className="space-y-1.5">
                  <span className="text-xs text-text-tertiary block">JWKS URL</span>
                  <input
                    type="url"
                    value={provider.jwksUri}
                    onChange={(e) => updateOidcProvider(index, { jwksUri: e.target.value })}
                    placeholder="https://tenant.example.com/.well-known/jwks.json"
                    className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono"
                  />
                </label>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <label className="space-y-1.5">
                  <span className="text-xs text-text-tertiary block">Client ID</span>
                  <input
                    value={provider.clientId}
                    onChange={(e) => updateOidcProvider(index, { clientId: e.target.value })}
                    placeholder="enterprise-sso-client"
                    className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono"
                  />
                </label>
                <label className="space-y-1.5">
                  <span className="text-xs text-text-tertiary block">Client Secret Env Var</span>
                  <input
                    value={provider.clientSecretEnv}
                    onChange={(e) => updateOidcProvider(index, { clientSecretEnv: e.target.value })}
                    placeholder="ACME_SSO_CLIENT_SECRET"
                    className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono"
                  />
                </label>
                <label className="space-y-1.5">
                  <span className="text-xs text-text-tertiary block">Authorization URL</span>
                  <input
                    type="url"
                    value={provider.authorizationUrl}
                    onChange={(e) =>
                      updateOidcProvider(index, { authorizationUrl: e.target.value })
                    }
                    placeholder="https://tenant.example.com/oauth2/v1/authorize"
                    className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono"
                  />
                </label>
                <label className="space-y-1.5">
                  <span className="text-xs text-text-tertiary block">Token URL</span>
                  <input
                    type="url"
                    value={provider.tokenUrl}
                    onChange={(e) => updateOidcProvider(index, { tokenUrl: e.target.value })}
                    placeholder="https://tenant.example.com/oauth2/v1/token"
                    className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono"
                  />
                </label>
              </div>
              <label className="space-y-1.5 block">
                <span className="text-xs text-text-tertiary block">Scopes</span>
                <textarea
                  value={provider.scopes}
                  onChange={(e) => updateOidcProvider(index, { scopes: e.target.value })}
                  rows={3}
                  placeholder={"openid\nemail\nprofile"}
                  className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono resize-y"
                />
              </label>
              <div className="flex flex-wrap items-center gap-4">
                <label className="space-y-1.5">
                  <span className="text-xs text-text-tertiary block">Algorithm</span>
                  <select
                    value={provider.allowedAlgs}
                    onChange={(e) =>
                      updateOidcProvider(index, {
                        allowedAlgs: e.target.value as "RS256" | "ES256",
                      })
                    }
                    className="bg-bg border border-border px-3 py-2 text-sm text-text focus:outline-none focus:border-accent transition-colors"
                  >
                    <option value="RS256">RS256</option>
                    <option value="ES256">ES256</option>
                  </select>
                </label>
                <label className="flex items-center gap-2 text-sm text-text-secondary mt-5">
                  <input
                    type="checkbox"
                    checked={provider.allowJitProvisioning}
                    onChange={(e) =>
                      updateOidcProvider(index, { allowJitProvisioning: e.target.checked })
                    }
                    className="accent-accent"
                  />
                  Auto-create users
                </label>
              </div>
            </div>
          ))}
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <button
            type="submit"
            disabled={oidcSaving || oidcLoading || !TENANT_ID}
            className="px-4 py-2 text-sm bg-accent text-bg hover:bg-accent-hover transition-colors disabled:opacity-40 font-medium"
          >
            {oidcSaving ? "Saving..." : "Save Providers"}
          </button>
          {oidcSaved && (
            <motion.span
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              className="text-xs text-emerald-400"
            >
              Saved
            </motion.span>
          )}
          {oidcError && <span className="text-xs text-red-400">{oidcError}</span>}
        </div>
      </form>

      {/* SDK Quick Start */}
      <div className="space-y-4">
        <h2 className="font-display text-sm font-600 text-text-secondary tracking-wider uppercase">
          SDK Quick Start
        </h2>
        <p className="text-xs text-text-tertiary max-w-lg">
          Install the SDK and start managing agent wallets in minutes.
        </p>
        <div className="border border-border bg-bg-elevated max-w-3xl">
          <div className="px-4 py-2.5 border-b border-border-subtle flex items-center justify-between">
            <span className="text-xs text-text-tertiary font-mono">npm i @stwd/sdk</span>
            <CopyButton text="npm i @stwd/sdk" />
          </div>
        </div>
        <div className="border border-border bg-bg-elevated max-w-3xl">
          <CodeBlock filename="example.ts" language="typescript" code={sdkSnippet} />
        </div>
      </div>
    </motion.div>
  );
}
