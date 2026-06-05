# steward_flutter

Flutter and Dart helpers for Steward.

This package mirrors the core server-auth and user-auth surface from the
TypeScript, React Native, Java, and Android SDKs:

- API client with bearer, platform key, app id/app secret, API key, tenant, and
  request-signing headers
- email magic-link, SMS OTP, WhatsApp OTP, test-account, OAuth PKCE callback,
  refresh, revoke, and local session helpers
- push-token registration for FCM, APNs, and Expo-compatible tokens
- storage abstraction for `flutter_secure_storage`, `shared_preferences`, or a
  tenant-specific app storage adapter

## Install

```yaml
dependencies:
  steward_flutter:
    git:
      url: https://github.com/Steward-Fi/steward
      path: packages/flutter
```

## API Client

```dart
import 'package:steward_flutter/steward.dart';

final client = StewardClient(
  StewardClientConfig(
    baseUrl: 'https://api.steward.fi',
    bearerToken: session.token,
    tenantId: 'my-app',
  ),
);

await client.registerUserPushSubscription(
  PushSubscriptionInput(
    provider: 'fcm',
    token: fcmToken,
    platform: 'android',
    tenantId: 'my-app',
  ),
);
```

## Auth

```dart
final storage = MemoryStewardSessionStorage();
final auth = StewardAuth(
  StewardAuthConfig(
    baseUrl: 'https://api.steward.fi',
    tenantId: 'my-app',
    storage: storage,
  ),
);

await auth.signInWithEmail('me@example.com');
await auth.verifyEmailCallback(token: token, email: 'me@example.com');

await auth.sendSmsOtp('+15551234567');
await auth.verifySmsOtp(phone: '+15551234567', code: '123456');
```

Use a durable storage implementation in production. The SDK intentionally accepts
a small async key/value interface so apps can use secure storage on mobile and
isolated storage in tests.

## OAuth Redirects

```dart
final start = await auth.startOAuthRedirect(
  provider: 'google',
  redirectUri: 'myapp://oauth/google',
);

// Open start.authorizationUrl with url_launcher, then handle the deep link:
await auth.handleOAuthCallback(
  provider: 'google',
  callbackUrl: callbackUrl,
  redirectUri: 'myapp://oauth/google',
);
```

The helper stores PKCE state and verifier in the configured session storage and
rejects callback state mismatches before exchanging the OAuth code.

## Toolchain Note

This repo environment does not currently include `dart` or `flutter`, so local
CI validates this package with a repository static contract check. When the
Flutter toolchain is available, run:

```bash
cd packages/flutter
flutter pub get
flutter analyze
flutter test
```
