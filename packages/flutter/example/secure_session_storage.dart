// Production-ready StewardSessionStorage backed by `flutter_secure_storage`
// (Keychain on iOS, EncryptedSharedPreferences/Keystore on Android).
//
// This file is an example, not part of the published library, so that the
// package stays free of a hard flutter_secure_storage dependency. To use it:
//
//   1. Add the dependency to your app's pubspec.yaml:
//
//        dependencies:
//          flutter_secure_storage: ^9.2.2
//
//   2. Copy this class into your app (or import it from your own shared
//      module) and wire it into StewardAuth:
//
//        final auth = StewardAuth(
//          StewardAuthConfig(
//            baseUrl: 'https://api.steward.example',
//            tenantId: 'my-app',
//            storage: FlutterSecureSessionStorage(),
//          ),
//        );
//
// Session tokens, refresh tokens, and OAuth PKCE verifiers all flow through
// this interface, so they must never land in plain shared preferences or
// in-memory-only storage in a shipped app.

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:steward_flutter/steward.dart';

class FlutterSecureSessionStorage implements StewardSessionStorage {
  FlutterSecureSessionStorage([FlutterSecureStorage? storage])
      : _storage = storage ??
            const FlutterSecureStorage(
              // encryptedSharedPreferences keeps values inside the Android
              // Keystore-backed encrypted store instead of plain prefs.
              aOptions: AndroidOptions(encryptedSharedPreferences: true),
            );

  final FlutterSecureStorage _storage;

  @override
  Future<String?> getItem(String key) => _storage.read(key: key);

  @override
  Future<void> setItem(String key, String value) =>
      _storage.write(key: key, value: value);

  @override
  Future<void> removeItem(String key) => _storage.delete(key: key);
}
