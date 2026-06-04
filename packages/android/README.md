# steward-android

First-pass Android-compatible JVM facade over the Steward Java SDK.

This package is intentionally small until the Kotlin/Gradle toolchain is added
to the repo. It provides Android-oriented helpers for the flows that do not need
native framework APIs, especially bearer-token API calls and FCM push-token
registration.

```java
StewardAndroidClient client = StewardAndroidClient.withBearerToken(
    "https://api.steward.fi",
    "user_access_token"
);

client.registerFcmPushToken(DevicePushRegistration.builder("fcm-token")
    .tenantId("tenant_...")
    .deviceId("android-device-id")
    .appId("fi.steward.app")
    .locale("en-US")
    .timezone("America/New_York")
    .build());
```

Local verification:

```sh
rm -rf packages/android/build
mkdir -p packages/android/build/classes
javac -d packages/android/build/classes $(find packages/java/src/main/java packages/android/src/main/java packages/android/src/test/java -name '*.java')
java -cp packages/android/build/classes com.steward.android.StewardAndroidClientTest
```

Remaining work: add Kotlin-first APIs, Android `SharedPreferences`/Keystore
storage adapters, native passkey Credential Manager wrappers, FCM service
integration, Gradle/Maven publishing metadata, and emulator/device e2e tests.

