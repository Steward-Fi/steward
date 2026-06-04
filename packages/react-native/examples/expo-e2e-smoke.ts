/**
 * Expo/Detox smoke-test wiring for Steward native auth.
 *
 * This file is intentionally framework-light: use it from a Detox, Maestro, or
 * Appium test app after injecting real AsyncStorage, Linking, notification, and
 * wallet/passkey modules from your Expo runtime.
 */

import type { AsyncKeyValueStorage, NativePasskeyBridge } from "../src/index.js";
import {
  completeNativePasskeyMfa,
  createNativeEthereumConnectorFromProvider,
  createNativePushTokenRegistration,
  createStewardNativeAuth,
  createStewardNativeClient,
  getNativeTestAccessToken,
  parseNativeNotificationAction,
  registerNativePasskey,
  registerNativePushToken,
  signInWithNativeEthereumWallet,
  signInWithNativePasskey,
} from "../src/index.js";

export interface ExpoE2ESmokeOptions {
  baseUrl: string;
  tenantId: string;
  storage: AsyncKeyValueStorage;
  openUrl: (url: string) => void | Promise<void>;
  getExpoPushToken: () => Promise<string>;
  getDeviceId: () => string | Promise<string>;
  testEmail: string;
  testOtp: string;
  eip1193Provider?: {
    request(args: { method: string; params?: unknown[] }): Promise<unknown>;
  };
  passkeyBridge?: NativePasskeyBridge;
  appOrigin?: string;
}

export async function runExpoStewardE2ESmoke(options: ExpoE2ESmokeOptions): Promise<{
  userId: string;
  pushSubscriptionId: string;
}> {
  const auth = await createStewardNativeAuth({
    baseUrl: options.baseUrl,
    tenantId: options.tenantId,
    storage: options.storage,
  });

  const authResult = await getNativeTestAccessToken(auth, {
    tenantId: options.tenantId,
    email: options.testEmail,
    otp: options.testOtp,
  });
  if (!("token" in authResult)) throw new Error("test account unexpectedly required MFA");

  if (options.eip1193Provider) {
    await signInWithNativeEthereumWallet(
      auth,
      createNativeEthereumConnectorFromProvider(options.eip1193Provider),
    );
  }

  if (options.passkeyBridge && options.appOrigin) {
    await registerNativePasskey(auth, options.testEmail, options.passkeyBridge, {
      origin: options.appOrigin,
      authenticatorAttachment: "platform",
    });
    await completeNativePasskeyMfa(auth, options.passkeyBridge, {
      origin: options.appOrigin,
    });
    await signInWithNativePasskey(auth, options.testEmail, options.passkeyBridge, {
      origin: options.appOrigin,
    });
  }

  const token = auth.getSession()?.token;
  if (!token) throw new Error("Steward session was not stored after native auth");

  const pushToken = await options.getExpoPushToken();
  const pushRegistration = createNativePushTokenRegistration(pushToken, {
    platform: "ios",
    tenantId: options.tenantId,
    userId: auth.getSession()?.userId,
    deviceId: await options.getDeviceId(),
  });
  const client = createStewardNativeClient({
    baseUrl: options.baseUrl,
    bearerToken: token,
  });
  const { subscription } = await registerNativePushToken(client, pushToken, pushRegistration);

  return {
    userId: auth.getSession()?.userId ?? authResult.user.id,
    pushSubscriptionId: subscription.id,
  };
}

export async function openStewardNotificationDeepLink(
  notificationResponse: unknown,
  openUrl: (url: string) => void | Promise<void>,
): Promise<boolean> {
  const action = parseNativeNotificationAction(notificationResponse);
  if (!action.url) return false;
  await openUrl(action.url);
  return true;
}
