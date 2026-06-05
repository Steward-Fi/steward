import type {
  SessionStorage,
  StewardAuthConfig,
  StewardAuthExchangeResponse,
  StewardAuthResult,
  StewardClientConfig,
  StewardCurrentUserResult,
  StewardEmailResult,
  StewardMfaRequiredResult,
  StewardOAuthConfig,
  StewardOAuthResult,
  StewardSession,
  StewardSmsOtpResult,
  StewardTestAccountLoginOptions,
  StewardWhatsAppOtpResult,
  UserPushSubscriptionResult,
} from "@stwd/sdk";
import { StewardApiError, StewardAuth, StewardClient } from "@stwd/sdk";

export interface AsyncKeyValueStorage {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  removeItem(key: string): Promise<void>;
}

export interface ReactNativeStorageOptions {
  /**
   * Namespace used for Steward session keys. Defaults to "steward".
   * Use a different value when one app hosts multiple isolated Steward tenants.
   */
  namespace?: string;
}

export interface HydratedSessionStorage extends SessionStorage {
  hydrate(): Promise<void>;
  flush(): Promise<void>;
}

const SDK_SESSION_KEYS = [
  "steward_session_token",
  "steward_refresh_token",
  "steward_user",
] as const;

function storageKey(namespace: string, key: string): string {
  return `${namespace}:${key}`;
}

/**
 * Adapts React Native AsyncStorage to the synchronous storage interface used by
 * the shared TypeScript SDK. Call `hydrate()` before constructing `StewardAuth`,
 * or use `createStewardNativeAuth()`.
 */
export function createReactNativeSessionStorage(
  storage: AsyncKeyValueStorage,
  { namespace = "steward" }: ReactNativeStorageOptions = {},
): HydratedSessionStorage {
  const cache = new Map<string, string>();
  const pending = new Map<string, string | null>();

  return {
    async hydrate() {
      await Promise.all(
        SDK_SESSION_KEYS.map(async (key) => {
          const value = await storage.getItem(storageKey(namespace, key));
          if (value === null) cache.delete(key);
          else cache.set(key, value);
        }),
      );
    },
    async flush() {
      const writes = [...pending.entries()];
      pending.clear();
      await Promise.all(
        writes.map(([key, value]) => {
          const namespaced = storageKey(namespace, key);
          return value === null
            ? storage.removeItem(namespaced)
            : storage.setItem(namespaced, value);
        }),
      );
    },
    getItem(key) {
      return cache.get(key) ?? null;
    },
    setItem(key, value) {
      cache.set(key, value);
      pending.set(key, value);
      void storage.setItem(storageKey(namespace, key), value).catch(() => {
        pending.set(key, value);
      });
    },
    removeItem(key) {
      cache.delete(key);
      pending.set(key, null);
      void storage.removeItem(storageKey(namespace, key)).catch(() => {
        pending.set(key, null);
      });
    },
  };
}

export interface StewardNativeAuthConfig extends Omit<StewardAuthConfig, "storage"> {
  storage: AsyncKeyValueStorage | HydratedSessionStorage;
  storageNamespace?: string;
  /**
   * Calls /user/me after a hydrated or newly-created session so tenant
   * create-on-login embedded-wallet policy can run. Defaults to true.
   */
  bootstrapCurrentUser?: boolean;
}

export async function createStewardNativeAuth({
  storage,
  storageNamespace,
  bootstrapCurrentUser = true,
  ...config
}: StewardNativeAuthConfig): Promise<StewardAuth> {
  const sessionStorage =
    "hydrate" in storage
      ? storage
      : createReactNativeSessionStorage(storage, { namespace: storageNamespace });
  await sessionStorage.hydrate();
  const auth = new StewardAuth({ ...config, storage: sessionStorage });
  if (bootstrapCurrentUser) {
    scheduleNativeCurrentUserBootstrap(auth, { tenantId: config.tenantId });
  }
  return auth;
}

export interface StewardNativeClientConfig extends StewardClientConfig {
  token?: string | (() => string | null | Promise<string | null>);
}

export function createStewardNativeClient(config: StewardNativeClientConfig): StewardClient {
  return new StewardClient(config);
}

export function getNativeSession(auth: StewardAuth): StewardSession | null {
  return auth.getSession();
}

export interface NativeEmailCallback {
  token: string;
  email: string;
}

export interface NativeOtpOptions {
  captchaToken?: string;
}

export type NativeOtpChannel = "sms" | "whatsapp";

export interface NativeOAuthStartOptions
  extends Partial<Omit<StewardOAuthConfig, "provider" | "popupWidth" | "popupHeight">> {
  openUrl?: (url: string) => void | Promise<void>;
}

export interface NativeOAuthCallbackOptions {
  redirectUri?: string;
}

export interface NativePasskeyBridge {
  startAuthentication(options: Record<string, unknown>): Promise<unknown> | unknown;
  startRegistration(options: Record<string, unknown>): Promise<unknown> | unknown;
}

export interface NativePasskeyOptions {
  tenantId?: string;
  origin?: string;
}

export interface NativePasskeyRegistrationOptions extends NativePasskeyOptions {
  authenticatorAttachment?: "platform" | "cross-platform";
}

export interface NativeEthereumWalletConnector {
  getAddress(): Promise<string> | string;
  getChainId?(): Promise<number | string> | number | string;
  signMessage(message: string): Promise<string> | string;
}

export interface NativeEip1193Provider {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
}

export interface NativeSolanaWalletConnector {
  getPublicKey(): Promise<string> | string;
  signMessage(
    message: Uint8Array,
  ): Promise<Uint8Array | number[] | { signature: Uint8Array | number[] }>;
}

export interface NativeSolanaWalletAdapter {
  publicKey?: { toBase58?: () => string; toString?: () => string } | string | null;
  signMessage(
    message: Uint8Array,
  ): Promise<Uint8Array | number[] | { signature: Uint8Array | number[] }>;
}

export interface NativeWalletSignInOptions {
  chainId?: number;
  chain?: string;
}

export type NativePushProvider = "expo" | "apns" | "fcm";
export type NativePushPlatform = "ios" | "android";

export interface NativePushRegistrationOptions {
  provider?: NativePushProvider;
  platform?: NativePushPlatform;
  deviceId?: string;
  appId?: string;
  tenantId?: string;
  userId?: string;
  locale?: string;
  timezone?: string;
  metadata?: Record<string, unknown>;
  now?: () => Date;
}

export interface NativePushTokenRegistration {
  provider: NativePushProvider;
  token: string;
  platform?: NativePushPlatform;
  deviceId?: string;
  appId?: string;
  tenantId?: string;
  userId?: string;
  locale?: string;
  timezone?: string;
  metadata?: Record<string, unknown>;
  createdAt: string;
}

export interface NativeNotificationAction {
  url: string | null;
  event?: string;
  actionId?: string;
  tenantId?: string;
  data: Record<string, unknown>;
}

const OAUTH_REDIRECT_PREFIX = "OAuth popup flow requires a browser. Redirect to: ";
const OAUTH_STATE_KEY = "steward_oauth_state";
const OAUTH_VERIFIER_KEY = "steward_oauth_verifier";
const OAUTH_TENANT_KEY = "steward_oauth_tenant";

type NativeOAuthAuthInternals = {
  storage: SessionStorage;
  exchangeOAuthCode: (
    provider: string,
    code: string,
    redirectUri: string,
    state: string,
    codeVerifier: string,
    tenantId?: string,
  ) => Promise<StewardOAuthResult | StewardMfaRequiredResult>;
};

type NativeAuthStoreInternals = {
  storeExchangeResponse: (
    data: StewardAuthExchangeResponse,
  ) => StewardAuthResult | StewardMfaRequiredResult;
  storeAndReturn: (
    token: string | undefined,
    refreshToken: string,
    user: StewardAuthExchangeResponse["user"],
    expiresIn?: number,
  ) => StewardAuthResult;
};

type NativeAuthApiResult<T> =
  | { ok: true; status: number; data: T }
  | { ok: false; status: number; error: string };

function parseUrl(url: string): URL {
  try {
    return new URL(url);
  } catch {
    throw new StewardApiError("Invalid callback URL", 400);
  }
}

function callbackRedirectUri(parsed: URL): string {
  return `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
}

async function nativeAuthRequest<T>(
  auth: StewardAuth,
  path: string,
  init: RequestInit = {},
  token?: string | null,
): Promise<NativeAuthApiResult<T>> {
  const headers = new Headers({
    "Content-Type": "application/json",
    Accept: "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  });
  if (init.headers) new Headers(init.headers).forEach((value, key) => headers.set(key, value));

  let response: Response;
  try {
    response = await fetch(`${auth.getBaseUrl()}${path}`, { ...init, headers });
  } catch (error) {
    throw new StewardApiError(error instanceof Error ? error.message : "Network request failed", 0);
  }

  const text = await response.text();
  let payload: Record<string, unknown> = { ok: response.ok };
  if (text) {
    try {
      payload = JSON.parse(text) as Record<string, unknown>;
    } catch {
      throw new StewardApiError("Received invalid JSON from Steward API", response.status);
    }
  }
  if (!response.ok || payload.ok === false) {
    return {
      ok: false,
      status: response.status,
      error:
        typeof payload.error === "string"
          ? payload.error
          : `Request failed with status ${response.status}`,
    };
  }
  return { ok: true, status: response.status, data: payload as T };
}

function tenantForNativeAuth(auth: StewardAuth, tenantId?: string): string | undefined {
  return tenantId ?? auth.getTenantId();
}

function authResultHasSession(
  result: StewardAuthResult | StewardMfaRequiredResult | StewardOAuthResult,
): result is StewardAuthResult | StewardOAuthResult {
  return !("mfaRequired" in result && result.mfaRequired);
}

export async function bootstrapNativeCurrentUser(
  auth: StewardAuth,
  options: { tenantId?: string } = {},
): Promise<StewardCurrentUserResult | null> {
  if (!auth.getSession()) return null;
  try {
    return await auth.getCurrentUser({ tenantId: tenantForNativeAuth(auth, options.tenantId) });
  } catch {
    return null;
  }
}

function scheduleNativeCurrentUserBootstrap(
  auth: StewardAuth,
  options: { tenantId?: string } = {},
): void {
  void bootstrapNativeCurrentUser(auth, options);
}

function bootstrapNativeAuthResult<
  T extends StewardAuthResult | StewardMfaRequiredResult | StewardOAuthResult,
>(auth: StewardAuth, result: T, tenantId?: string): T {
  if (authResultHasSession(result)) {
    scheduleNativeCurrentUserBootstrap(auth, { tenantId });
  }
  return result;
}

function storeNativeExchangeResponse(
  auth: StewardAuth,
  data: StewardAuthExchangeResponse,
): StewardAuthResult | StewardMfaRequiredResult {
  return (auth as unknown as NativeAuthStoreInternals).storeExchangeResponse(data);
}

function storeNativeAuthResult(
  auth: StewardAuth,
  data: StewardAuthExchangeResponse,
): StewardAuthResult {
  return (auth as unknown as NativeAuthStoreInternals).storeAndReturn(
    data.token,
    data.refreshToken ?? "",
    data.user,
    data.expiresIn,
  );
}

function normalizeEvmChainId(value: number | string | undefined): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value === "number" && Number.isSafeInteger(value) && value > 0) return value;
  if (typeof value === "string") {
    const parsed = value.startsWith("0x")
      ? Number.parseInt(value.slice(2), 16)
      : Number.parseInt(value, 10);
    if (Number.isSafeInteger(parsed) && parsed > 0) return parsed;
  }
  throw new StewardApiError("Native Ethereum wallet returned an invalid chain id", 0);
}

function normalizeSolanaPublicKey(
  value: NativeSolanaWalletAdapter["publicKey"] | string | null | undefined,
): string {
  if (!value) throw new StewardApiError("Native Solana wallet is not connected", 0);
  if (typeof value === "string") return value;
  if (typeof value.toBase58 === "function") return value.toBase58();
  if (typeof value.toString === "function") return value.toString();
  throw new StewardApiError("Native Solana wallet returned an invalid public key", 0);
}

function normalizeSignatureBytes(
  value: Uint8Array | number[] | { signature: Uint8Array | number[] },
): Uint8Array {
  const signature = typeof value === "object" && "signature" in value ? value.signature : value;
  if (signature instanceof Uint8Array) return signature;
  if (Array.isArray(signature)) return Uint8Array.from(signature);
  throw new StewardApiError("Native Solana wallet returned an invalid signature", 0);
}

function normalizePushProvider(token: string, provider?: NativePushProvider): NativePushProvider {
  if (provider) return provider;
  if (/^(ExponentPushToken|ExpoPushToken)\[[^\]]+\]$/.test(token)) return "expo";
  if (/^[0-9a-f]{64}$/i.test(token)) return "apns";
  return "fcm";
}

function getRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function notificationData(input: unknown): Record<string, unknown> {
  const root = getRecord(input);
  if (!root) return {};
  const directData = getRecord(root.data);
  if (directData) return directData;

  const request = getRecord(root.request);
  const requestContent = getRecord(request?.content);
  const requestData = getRecord(requestContent?.data);
  if (requestData) return requestData;

  const notification = getRecord(root.notification);
  const notificationRequest = getRecord(notification?.request);
  const notificationContent = getRecord(notificationRequest?.content);
  return getRecord(notificationContent?.data) ?? {};
}

function stringField(data: Record<string, unknown>, ...keys: string[]): string | undefined {
  for (const key of keys) {
    const value = data[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return undefined;
}

function safeNativeDeepLink(value: string | undefined): string | null {
  if (!value || value.length > 2048) return null;
  try {
    const parsed = new URL(value);
    const protocol = parsed.protocol.toLowerCase();
    if (protocol === "javascript:" || protocol === "data:" || protocol === "vbscript:") {
      return null;
    }
    return value;
  } catch {
    return null;
  }
}

export function parseNativeEmailCallbackUrl(url: string): NativeEmailCallback {
  const parsed = parseUrl(url);
  const token = parsed.searchParams.get("token") ?? "";
  const email = parsed.searchParams.get("email") ?? "";
  if (!token || !email) {
    throw new StewardApiError("Email callback URL must include token and email", 400);
  }
  return { token, email };
}

export async function completeNativeEmailCallback(
  auth: StewardAuth,
  url: string,
): Promise<StewardAuthResult | StewardMfaRequiredResult> {
  const callback = parseNativeEmailCallbackUrl(url);
  return bootstrapNativeAuthResult(
    auth,
    await auth.verifyEmailCallback(callback.token, callback.email),
  );
}

export async function sendNativeOtp(
  auth: StewardAuth,
  phone: string,
  channel: NativeOtpChannel = "sms",
  options: NativeOtpOptions = {},
): Promise<StewardSmsOtpResult | StewardWhatsAppOtpResult> {
  return channel === "whatsapp"
    ? auth.sendWhatsAppOtp(phone, options.captchaToken)
    : auth.sendSmsOtp(phone, options.captchaToken);
}

export async function verifyNativeOtp(
  auth: StewardAuth,
  phone: string,
  code: string,
  channel: NativeOtpChannel = "sms",
): Promise<StewardAuthResult | StewardMfaRequiredResult> {
  const result =
    channel === "whatsapp"
      ? await auth.verifyWhatsAppOtp(phone, code)
      : await auth.verifySmsOtp(phone, code);
  return bootstrapNativeAuthResult(auth, result);
}

export async function getNativeTestAccessToken(
  auth: StewardAuth,
  options: StewardTestAccountLoginOptions,
): Promise<StewardAuthResult | StewardMfaRequiredResult> {
  return bootstrapNativeAuthResult(auth, await auth.getTestAccessToken(options), options.tenantId);
}

export async function signInWithNativePasskey(
  auth: StewardAuth,
  email: string,
  bridge: Pick<NativePasskeyBridge, "startAuthentication">,
  options: NativePasskeyOptions = {},
): Promise<StewardAuthResult | StewardMfaRequiredResult> {
  const tenantId = tenantForNativeAuth(auth, options.tenantId);
  const optionsRes = await nativeAuthRequest<Record<string, unknown>>(
    auth,
    "/auth/passkey/login/options",
    {
      method: "POST",
      body: JSON.stringify({ email, ...(tenantId ? { tenantId } : {}) }),
      ...(options.origin ? { headers: { Origin: options.origin } } : {}),
    },
  );
  if (optionsRes.ok === false) throw new StewardApiError(optionsRes.error, optionsRes.status);
  const challengeId =
    typeof optionsRes.data.challengeId === "string" ? optionsRes.data.challengeId : "";
  if (!challengeId) {
    throw new StewardApiError("Native passkey login options did not include a challengeId", 0);
  }

  let passkeyResponse: unknown;
  try {
    passkeyResponse = await bridge.startAuthentication(optionsRes.data);
  } catch (error) {
    throw new StewardApiError(
      `Native passkey authentication cancelled or failed: ${error instanceof Error ? error.message : String(error)}`,
      0,
    );
  }

  const verifyRes = await nativeAuthRequest<StewardAuthExchangeResponse>(
    auth,
    "/auth/passkey/login/verify",
    {
      method: "POST",
      body: JSON.stringify({
        email,
        challengeId,
        response: passkeyResponse,
        ...(tenantId ? { tenantId } : {}),
      }),
      ...(options.origin ? { headers: { Origin: options.origin } } : {}),
    },
  );
  if (verifyRes.ok === false) throw new StewardApiError(verifyRes.error, verifyRes.status);
  return bootstrapNativeAuthResult(
    auth,
    storeNativeExchangeResponse(auth, verifyRes.data),
    tenantId,
  );
}

export async function registerNativePasskey(
  auth: StewardAuth,
  email: string,
  bridge: Pick<NativePasskeyBridge, "startRegistration">,
  options: NativePasskeyRegistrationOptions = {},
): Promise<StewardAuthResult | StewardMfaRequiredResult> {
  const token = auth.getToken();
  if (!token) throw new StewardApiError("Not authenticated. Sign in first.", 0);
  const tenantId = tenantForNativeAuth(auth, options.tenantId);
  const requestInit: RequestInit = {
    method: "POST",
    body: JSON.stringify({
      email,
      ...(tenantId ? { tenantId } : {}),
      ...(options.authenticatorAttachment
        ? { authenticatorAttachment: options.authenticatorAttachment }
        : {}),
    }),
    ...(options.origin ? { headers: { Origin: options.origin } } : {}),
  };
  const optionsRes = await nativeAuthRequest<Record<string, unknown>>(
    auth,
    "/auth/passkey/register/options",
    requestInit,
    token,
  );
  if (optionsRes.ok === false) throw new StewardApiError(optionsRes.error, optionsRes.status);

  let passkeyResponse: unknown;
  try {
    passkeyResponse = await bridge.startRegistration(optionsRes.data);
  } catch (error) {
    throw new StewardApiError(
      `Native passkey registration cancelled or failed: ${error instanceof Error ? error.message : String(error)}`,
      0,
    );
  }

  const verifyRes = await nativeAuthRequest<StewardAuthExchangeResponse>(
    auth,
    "/auth/passkey/register/verify",
    {
      method: "POST",
      body: JSON.stringify({
        email,
        response: passkeyResponse,
        ...(tenantId ? { tenantId } : {}),
      }),
      ...(options.origin ? { headers: { Origin: options.origin } } : {}),
    },
    token,
  );
  if (verifyRes.ok === false) throw new StewardApiError(verifyRes.error, verifyRes.status);
  return bootstrapNativeAuthResult(
    auth,
    storeNativeExchangeResponse(auth, verifyRes.data),
    tenantId,
  );
}

export async function completeNativePasskeyMfa(
  auth: StewardAuth,
  bridge: Pick<NativePasskeyBridge, "startAuthentication">,
  options: Pick<NativePasskeyOptions, "origin"> = {},
): Promise<StewardAuthResult> {
  const token = auth.getToken();
  if (!token) throw new StewardApiError("Not authenticated. Sign in first.", 0);
  const optionsRes = await nativeAuthRequest<Record<string, unknown>>(
    auth,
    "/auth/mfa/passkey/options",
    {
      method: "POST",
      body: JSON.stringify({}),
      ...(options.origin ? { headers: { Origin: options.origin } } : {}),
    },
    token,
  );
  if (optionsRes.ok === false) throw new StewardApiError(optionsRes.error, optionsRes.status);
  const challengeId =
    typeof optionsRes.data.challengeId === "string" ? optionsRes.data.challengeId : "";
  if (!challengeId) {
    throw new StewardApiError("Native passkey MFA options did not include a challengeId", 0);
  }

  let passkeyResponse: unknown;
  try {
    passkeyResponse = await bridge.startAuthentication(optionsRes.data);
  } catch (error) {
    throw new StewardApiError(
      `Native passkey authentication cancelled or failed: ${error instanceof Error ? error.message : String(error)}`,
      0,
    );
  }

  const verifyRes = await nativeAuthRequest<StewardAuthExchangeResponse>(
    auth,
    "/auth/mfa/passkey/complete",
    {
      method: "POST",
      body: JSON.stringify({ challengeId, response: passkeyResponse }),
      ...(options.origin ? { headers: { Origin: options.origin } } : {}),
    },
    token,
  );
  if (verifyRes.ok === false) throw new StewardApiError(verifyRes.error, verifyRes.status);
  return bootstrapNativeAuthResult(auth, storeNativeAuthResult(auth, verifyRes.data));
}

export function createNativeEthereumConnectorFromProvider(
  provider: NativeEip1193Provider,
): NativeEthereumWalletConnector {
  const getAddress = async () => {
    const accounts = await provider.request({ method: "eth_requestAccounts" });
    if (!Array.isArray(accounts) || typeof accounts[0] !== "string") {
      throw new StewardApiError("Native Ethereum wallet did not return an account", 0);
    }
    return accounts[0];
  };

  return {
    getAddress,
    async getChainId() {
      return provider.request({ method: "eth_chainId" }) as Promise<string | number>;
    },
    async signMessage(message: string) {
      const [address] = (await provider.request({ method: "eth_accounts" })) as unknown[];
      const signer = typeof address === "string" ? address : await getAddress();
      const signature = await provider.request({
        method: "personal_sign",
        params: [message, signer],
      });
      if (typeof signature !== "string") {
        throw new StewardApiError("Native Ethereum wallet returned an invalid signature", 0);
      }
      return signature;
    },
  };
}

export function createNativeSolanaConnectorFromAdapter(
  adapter: NativeSolanaWalletAdapter,
): NativeSolanaWalletConnector {
  return {
    getPublicKey() {
      return normalizeSolanaPublicKey(adapter.publicKey);
    },
    async signMessage(message: Uint8Array) {
      return normalizeSignatureBytes(await adapter.signMessage(message));
    },
  };
}

export async function signInWithNativeEthereumWallet(
  auth: StewardAuth,
  connector: NativeEthereumWalletConnector,
  options: NativeWalletSignInOptions = {},
): Promise<StewardAuthResult | StewardMfaRequiredResult> {
  const address = await connector.getAddress();
  const chainId = options.chainId ?? normalizeEvmChainId(await connector.getChainId?.());
  return bootstrapNativeAuthResult(
    auth,
    await auth.signInWithSIWE(
      address,
      (message) => Promise.resolve(connector.signMessage(message)),
      chainId,
    ),
  );
}

export async function signInWithNativeSolanaWallet(
  auth: StewardAuth,
  connector: NativeSolanaWalletConnector,
  options: NativeWalletSignInOptions = {},
): Promise<StewardAuthResult | StewardMfaRequiredResult> {
  const publicKey = await connector.getPublicKey();
  return bootstrapNativeAuthResult(
    auth,
    await auth.signInWithSolana(
      publicKey,
      async (message) => normalizeSignatureBytes(await connector.signMessage(message)),
      options.chain,
    ),
  );
}

export function createNativePushTokenRegistration(
  token: string,
  options: NativePushRegistrationOptions = {},
): NativePushTokenRegistration {
  const normalizedToken = token.trim();
  if (normalizedToken.length < 16 || normalizedToken.length > 4096 || /\s/.test(normalizedToken)) {
    throw new StewardApiError("Native push token is invalid", 400);
  }
  const provider = normalizePushProvider(normalizedToken, options.provider);
  if (provider === "apns" && !/^[0-9a-f]{64}$/i.test(normalizedToken)) {
    throw new StewardApiError("APNs push tokens must be 64 hex characters", 400);
  }
  if (
    provider === "expo" &&
    !/^(ExponentPushToken|ExpoPushToken)\[[^\]]+\]$/.test(normalizedToken)
  ) {
    throw new StewardApiError("Expo push token is invalid", 400);
  }

  return {
    provider,
    token: normalizedToken,
    platform: options.platform,
    deviceId: options.deviceId,
    appId: options.appId,
    tenantId: options.tenantId,
    userId: options.userId,
    locale: options.locale,
    timezone: options.timezone,
    metadata: options.metadata,
    createdAt: (options.now?.() ?? new Date()).toISOString(),
  };
}

export async function registerNativePushToken(
  client: StewardClient,
  token: string,
  options: NativePushRegistrationOptions = {},
): Promise<UserPushSubscriptionResult> {
  return client.registerUserPushSubscription(createNativePushTokenRegistration(token, options));
}

export function parseNativeNotificationAction(input: unknown): NativeNotificationAction {
  if (typeof input === "string") {
    return { url: safeNativeDeepLink(input), data: {} };
  }
  const data = notificationData(input);
  return {
    url: safeNativeDeepLink(stringField(data, "url", "deepLink", "link")),
    event: stringField(data, "event", "type"),
    actionId: stringField(data, "actionId", "action_id"),
    tenantId: stringField(data, "tenantId", "tenant_id"),
    data,
  };
}

export async function startNativeOAuthRedirect(
  auth: StewardAuth,
  provider: string,
  options: NativeOAuthStartOptions = {},
): Promise<string> {
  try {
    await auth.signInWithOAuth(provider, {
      redirectUri: options.redirectUri,
      tenantId: options.tenantId,
    });
  } catch (error) {
    if (error instanceof StewardApiError && error.message.startsWith(OAUTH_REDIRECT_PREFIX)) {
      const authorizeUrl = error.message.slice(OAUTH_REDIRECT_PREFIX.length);
      await options.openUrl?.(authorizeUrl);
      return authorizeUrl;
    }
    throw error;
  }
  throw new StewardApiError("Native OAuth redirect unexpectedly completed without a deep link", 0);
}

export async function completeNativeOAuthCallback(
  auth: StewardAuth,
  provider: string,
  callbackUrl: string,
  options: NativeOAuthCallbackOptions = {},
): Promise<StewardOAuthResult | StewardMfaRequiredResult> {
  const parsed = parseUrl(callbackUrl);
  const code = parsed.searchParams.get("code") ?? undefined;
  const state = parsed.searchParams.get("state") ?? undefined;
  const error = parsed.searchParams.get("error") ?? undefined;
  if (error) {
    throw new StewardApiError(`OAuth error: ${error}`, 0);
  }
  if (!code || !state) {
    throw new StewardApiError("Missing code or state in OAuth callback", 0);
  }

  const internals = auth as unknown as NativeOAuthAuthInternals;
  const storedState = internals.storage.getItem(OAUTH_STATE_KEY);
  const storedVerifier = internals.storage.getItem(OAUTH_VERIFIER_KEY);
  const storedTenantId = internals.storage.getItem(OAUTH_TENANT_KEY) ?? undefined;
  if (!storedState || !storedVerifier) {
    throw new StewardApiError(
      "No OAuth state found in storage. Did you call startNativeOAuthRedirect first?",
      0,
    );
  }
  if (state !== storedState) {
    throw new StewardApiError("OAuth state mismatch, possible CSRF attack", 0);
  }

  return bootstrapNativeAuthResult(
    auth,
    await internals.exchangeOAuthCode(
      provider,
      code,
      options.redirectUri ?? callbackRedirectUri(parsed),
      state,
      storedVerifier,
      storedTenantId,
    ),
    storedTenantId,
  );
}

export function assertNativePasskeysUnsupported(): never {
  throw new StewardApiError(
    "Passkey sign-in uses browser WebAuthn in @stwd/sdk. Native apps should use email, SMS, WhatsApp, OAuth deep links, SIWE/SIWS, or a platform-specific WebAuthn bridge.",
    0,
  );
}

export type {
  SessionStorage,
  StewardAuth,
  StewardAuthConfig,
  StewardAuthResult,
  StewardClient,
  StewardClientConfig,
  StewardCurrentUserResult,
  StewardEmailResult,
  StewardMfaRequiredResult,
  StewardOAuthConfig,
  StewardOAuthResult,
  StewardSession,
  StewardSmsOtpResult,
  StewardTestAccountLoginOptions,
  StewardWhatsAppOtpResult,
  UserPushSubscriptionResult,
};
