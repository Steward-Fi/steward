# @stwd/react-native

React Native and Expo helpers for Steward.

This package reuses the shared `@stwd/sdk` auth and API clients, and adds
React Native helpers for async storage, OTP flows, OAuth deep links, and callback
parsing.

## Install

```bash
bun add @stwd/react-native @stwd/sdk @react-native-async-storage/async-storage
```

## Auth

```tsx
import AsyncStorage from "@react-native-async-storage/async-storage";
import { createStewardNativeAuth } from "@stwd/react-native";

const auth = await createStewardNativeAuth({
  baseUrl: "https://api.steward.fi",
  tenantId: "my-app",
  storage: AsyncStorage,
});

const session = auth.getSession();
```

The SDK expects synchronous session storage, while React Native storage is
async. `createStewardNativeAuth()` hydrates the async store first, then passes a
synchronous cache into `StewardAuth`.

## Email and OTP

```tsx
import {
  completeNativeEmailCallback,
  sendNativeOtp,
  verifyNativeOtp,
} from "@stwd/react-native";

await auth.signInWithEmail("me@example.com");

// From your Linking callback handler:
await completeNativeEmailCallback(auth, "steward://auth/email?token=...&email=me%40example.com");

await sendNativeOtp(auth, "+15551234567", "sms");
await verifyNativeOtp(auth, "+15551234567", "123456", "sms");

await sendNativeOtp(auth, "+15551234567", "whatsapp");
await verifyNativeOtp(auth, "+15551234567", "123456", "whatsapp");
```

## Test Credentials

```tsx
import { getNativeTestAccessToken } from "@stwd/react-native";

await getNativeTestAccessToken(auth, {
  email: "test@example.com",
  otp: "000000",
});
```

Test credential exchange is intended for configured tenant test accounts and
local/mobile automation. It stores the returned session through the same
hydrated native storage adapter.

## OAuth Deep Links

```tsx
import * as Linking from "expo-linking";
import {
  completeNativeOAuthCallback,
  startNativeOAuthRedirect,
} from "@stwd/react-native";

await startNativeOAuthRedirect(auth, "google", {
  redirectUri: "myapp://oauth/google",
  tenantId: "my-app",
  openUrl: Linking.openURL,
});

// From your Linking callback handler:
await completeNativeOAuthCallback(auth, "google", callbackUrl, {
  redirectUri: "myapp://oauth/google",
});
```

## Wallet Connectors

```tsx
import {
  createNativeEthereumConnectorFromProvider,
  createNativeSolanaConnectorFromAdapter,
  signInWithNativeEthereumWallet,
  signInWithNativeSolanaWallet,
} from "@stwd/react-native";

const evmConnector = createNativeEthereumConnectorFromProvider(eip1193Provider);
await signInWithNativeEthereumWallet(auth, evmConnector);

const solanaConnector = createNativeSolanaConnectorFromAdapter(walletAdapter);
await signInWithNativeSolanaWallet(auth, solanaConnector, {
  chain: "mainnet",
});
```

The Ethereum helper accepts any EIP-1193 provider that implements
`eth_requestAccounts`, `eth_accounts`, `eth_chainId`, and `personal_sign`. The
Solana helper accepts adapters with `publicKey` and `signMessage()`, including
adapters that return either raw signature bytes or `{ signature }`.

## Push Notifications

```tsx
import * as Linking from "expo-linking";
import {
  createNativePushTokenRegistration,
  createStewardNativeClient,
  parseNativeNotificationAction,
  registerNativePushToken,
} from "@stwd/react-native";

const registration = createNativePushTokenRegistration(expoPushToken, {
  platform: "ios",
  tenantId: "my-app",
  userId: auth.getSession()?.userId,
  deviceId,
});

const client = createStewardNativeClient({
  baseUrl: "https://api.steward.fi",
  bearerToken: auth.getSession()?.token,
});
await registerNativePushToken(client, expoPushToken, registration);

const action = parseNativeNotificationAction(notificationResponse);
if (action.url) {
  await Linking.openURL(action.url);
}
```

`createNativePushTokenRegistration()` normalizes Expo, APNs, and FCM tokens into
a bounded registration payload. `registerNativePushToken()` sends that payload
to Steward's user push-subscription API using the shared client.
`parseNativeNotificationAction()` accepts native/Expo notification response
shapes, extracts `url`, `deepLink`, or `link`, and rejects unsafe URL schemes
before handing the link to `Linking.openURL()`.

## Native Passkeys

```tsx
import {
  completeNativePasskeyMfa,
  registerNativePasskey,
  signInWithNativePasskey,
} from "@stwd/react-native";

const passkeyBridge = {
  startAuthentication: (options) => NativePasskeys.authenticate(options),
  startRegistration: (options) => NativePasskeys.register(options),
};

await signInWithNativePasskey(auth, "me@example.com", passkeyBridge, {
  origin: "https://app.example.com",
});

await registerNativePasskey(auth, "me@example.com", passkeyBridge, {
  origin: "https://app.example.com",
  authenticatorAttachment: "platform",
});

await completeNativePasskeyMfa(auth, passkeyBridge, {
  origin: "https://app.example.com",
});
```

Steward does not bundle an iOS/Android credential-manager dependency. Supply a
bridge that adapts your platform library to WebAuthn-shaped
`startAuthentication()` and `startRegistration()` calls. `origin` should be the
HTTPS app-associated domain configured for the tenant relying party; it is sent
to the API so the server can select the same RP metadata used by the native
credential manager.

## Manual Storage

```tsx
import AsyncStorage from "@react-native-async-storage/async-storage";
import { createReactNativeSessionStorage } from "@stwd/react-native";

const storage = createReactNativeSessionStorage(AsyncStorage, {
  namespace: "my-app",
});

await storage.hydrate();
```

Use a namespace per app/tenant when one native shell can authenticate into
multiple Steward tenants.

## Mobile E2E Smoke

`examples/expo-e2e-smoke.ts` provides a Detox/Maestro/Appium-friendly smoke
helper that exercises the native package without depending on one test runner:

- exchanges configured test credentials with `getNativeTestAccessToken()`
- optionally signs in through an injected EIP-1193 native wallet
- optionally registers and completes MFA through an injected passkey bridge
- registers an Expo push token through the user push-subscription API
- extracts and opens Steward deep links from notification response payloads

Use it inside an Expo test app where AsyncStorage, Linking, notifications,
wallets, and credential-manager modules are real native modules.

## API And Global Wallet Helpers

`createStewardNativeClient()` returns the shared `StewardClient`, so API helpers
such as `getGlobalWalletConsentRequest()`, `approveGlobalWalletConsent()`,
`confirmGlobalWalletAction()`, `scanGlobalWalletTransaction()`, and
`globalWalletRpc()` are available directly when the client is configured with a
user token.
