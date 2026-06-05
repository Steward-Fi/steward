import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;

import 'models.dart';
import 'storage.dart';

const _sessionTokenKey = 'steward_session_token';
const _refreshTokenKey = 'steward_refresh_token';
const _oauthStateKey = 'steward_oauth_state';
const _oauthVerifierKey = 'steward_oauth_verifier';
const _oauthTenantKey = 'steward_oauth_tenant';

class StewardAuthConfig {
  StewardAuthConfig({
    required this.baseUrl,
    required this.storage,
    this.tenantId,
    this.httpClient,
  });

  final String baseUrl;
  final StewardSessionStorage storage;
  final String? tenantId;
  final http.Client? httpClient;
}

class StewardAuth {
  StewardAuth(this.config)
      : _baseUrl = config.baseUrl.replaceFirst(RegExp(r'/+$'), ''),
        _client = config.httpClient ?? http.Client();

  final StewardAuthConfig config;
  final String _baseUrl;
  final http.Client _client;

  Future<StewardSession?> getSession() async {
    final token = await config.storage.getItem(_sessionTokenKey);
    if (token == null) return null;
    final refreshToken = await config.storage.getItem(_refreshTokenKey);
    return _sessionFromToken(token, refreshToken: refreshToken);
  }

  Future<void> signOut() async {
    await config.storage.removeItem(_sessionTokenKey);
    await config.storage.removeItem(_refreshTokenKey);
  }

  Future<StewardSession?> refreshSession() async {
    final refreshToken = await config.storage.getItem(_refreshTokenKey);
    if (refreshToken == null || refreshToken.isEmpty) return null;
    final payload = await _request('/auth/refresh', body: {'refreshToken': refreshToken});
    final result = await _storeExchangeResponse(payload);
    return _sessionFromToken(result.token, refreshToken: result.refreshToken);
  }

  Future<void> revokeSession() async {
    final refreshToken = await config.storage.getItem(_refreshTokenKey);
    if (refreshToken != null) {
      await _request('/auth/revoke', body: {'refreshToken': refreshToken});
    }
    await signOut();
  }

  Future<StewardEmailResult> signInWithEmail(String email, {String? captchaToken}) async {
    final payload = await _request('/auth/email/send', body: {
      'email': email,
      if (captchaToken != null) 'captchaToken': captchaToken,
      if (config.tenantId != null) 'tenantId': config.tenantId,
    });
    final data = _dataMap(payload);
    return StewardEmailResult(expiresAt: (data['expiresAt'] ?? '').toString());
  }

  Future<Object> verifyEmailCallback({required String token, required String email}) =>
      _exchange('/auth/email/verify', {
        'token': token,
        'email': email,
        if (config.tenantId != null) 'tenantId': config.tenantId,
      });

  Future<StewardOtpResult> sendSmsOtp(String phone, {String? captchaToken}) =>
      _sendOtp('/auth/sms/send', phone, captchaToken: captchaToken);

  Future<Object> verifySmsOtp({required String phone, required String code}) =>
      _exchange('/auth/sms/verify', {
        'phone': phone,
        'code': code,
        if (config.tenantId != null) 'tenantId': config.tenantId,
      });

  Future<StewardOtpResult> sendWhatsAppOtp(String phone, {String? captchaToken}) =>
      _sendOtp('/auth/whatsapp/send', phone, captchaToken: captchaToken);

  Future<Object> verifyWhatsAppOtp({required String phone, required String code}) =>
      _exchange('/auth/whatsapp/verify', {
        'phone': phone,
        'code': code,
        if (config.tenantId != null) 'tenantId': config.tenantId,
      });

  Future<Object> getTestAccessToken({
    String? tenantId,
    String? email,
    String? phone,
    required String otp,
  }) {
    final effectiveTenantId = tenantId ?? config.tenantId;
    return _exchange('/auth/test/token', {
      if (effectiveTenantId != null) 'tenantId': effectiveTenantId,
      if (email != null) 'email': email,
      if (phone != null) 'phone': phone,
      'otp': otp,
    });
  }

  Future<StewardOAuthStartResult> startOAuthRedirect({
    required String provider,
    required String redirectUri,
    String? tenantId,
  }) async {
    final state = _randomHex(16);
    final verifier = _randomVerifier();
    final challenge = _base64UrlNoPadding(sha256.convert(ascii.encode(verifier)).bytes);
    await config.storage.setItem(_oauthStateKey, state);
    await config.storage.setItem(_oauthVerifierKey, verifier);
    final effectiveTenantId = tenantId ?? config.tenantId;
    if (effectiveTenantId != null) {
      await config.storage.setItem(_oauthTenantKey, effectiveTenantId);
    } else {
      await config.storage.removeItem(_oauthTenantKey);
    }
    final uri = Uri.parse('$_baseUrl/auth/oauth/${Uri.encodeComponent(provider)}/authorize')
        .replace(queryParameters: {
      'redirect_uri': redirectUri,
      'code_challenge': challenge,
      'code_challenge_method': 'S256',
      'state': state,
      if (effectiveTenantId != null) 'tenant_id': effectiveTenantId,
    });
    return StewardOAuthStartResult(
      authorizationUrl: uri,
      state: state,
      codeVerifier: verifier,
    );
  }

  Future<Object> handleOAuthCallback({
    required String provider,
    required Uri callbackUrl,
    required String redirectUri,
  }) async {
    final error = callbackUrl.queryParameters['error'];
    if (error != null) throw StewardApiException('OAuth error: $error', 0);
    final code = callbackUrl.queryParameters['code'];
    final state = callbackUrl.queryParameters['state'];
    if (code == null || state == null) {
      throw StewardApiException('Missing code or state in OAuth callback', 0);
    }
    final storedState = await config.storage.getItem(_oauthStateKey);
    final verifier = await config.storage.getItem(_oauthVerifierKey);
    if (storedState == null || verifier == null) {
      throw StewardApiException('No OAuth state found in storage', 0);
    }
    if (state != storedState) {
      throw StewardApiException('OAuth state mismatch, possible CSRF attack', 0);
    }
    final tenantId = await config.storage.getItem(_oauthTenantKey);
    return _exchange('/auth/oauth/${Uri.encodeComponent(provider)}/token', {
      'code': code,
      'redirectUri': redirectUri,
      'state': state,
      'codeVerifier': verifier,
      if (tenantId != null) 'tenantId': tenantId,
    });
  }

  Future<StewardOtpResult> _sendOtp(
    String path,
    String phone, {
    String? captchaToken,
  }) async {
    final payload = await _request(path, body: {
      'phone': phone,
      if (captchaToken != null) 'captchaToken': captchaToken,
      if (config.tenantId != null) 'tenantId': config.tenantId,
    });
    final data = _dataMap(payload);
    return StewardOtpResult(expiresAt: (data['expiresAt'] ?? '').toString());
  }

  Future<Object> _exchange(String path, Map<String, Object?> body) async {
    final payload = await _request(path, body: body);
    return _storeExchangeResponse(payload);
  }

  Future<StewardAuthResult> _storeExchangeResponse(Object payload) async {
    final data = _dataMap(payload);
    if (data['mfaRequired'] == true) {
      throw StewardApiException('MFA required; call the matching MFA completion endpoint', 409, data);
    }
    final token = data['token']?.toString();
    if (token == null || token.isEmpty) {
      throw StewardApiException('Auth response did not include a token', 0, data);
    }
    final refreshToken = data['refreshToken']?.toString();
    await config.storage.setItem(_sessionTokenKey, token);
    if (refreshToken != null && refreshToken.isNotEmpty) {
      await config.storage.setItem(_refreshTokenKey, refreshToken);
    }
    return StewardAuthResult(
      token: token,
      refreshToken: refreshToken,
      user: data['user'] is Map ? Map<String, Object?>.from(data['user'] as Map) : null,
    );
  }

  Future<Object> _request(String path, {required Map<String, Object?> body}) async {
    final response = await _client.post(
      Uri.parse('$_baseUrl$path'),
      headers: const {'Content-Type': 'application/json', 'Accept': 'application/json'},
      body: jsonEncode(body),
    );
    final text = response.body;
    Object payload = <String, Object?>{};
    if (text.isNotEmpty) {
      try {
        payload = jsonDecode(text) as Object;
      } on FormatException {
        throw StewardApiException('Received invalid JSON from Steward API', response.statusCode);
      }
    }
    if (response.statusCode >= 400 || (payload is Map && payload['ok'] == false)) {
      final message = payload is Map && payload['error'] is String
          ? payload['error'] as String
          : 'Request failed with status ${response.statusCode}';
      throw StewardApiException(message, response.statusCode, payload);
    }
    return payload;
  }

  static Map<String, Object?> _dataMap(Object payload) {
    if (payload is Map) {
      final data = payload['data'];
      if (data is Map) return Map<String, Object?>.from(data);
      return Map<String, Object?>.from(payload);
    }
    throw StewardApiException('Expected object response from Steward API', 0, payload);
  }

  static StewardSession _sessionFromToken(String token, {String? refreshToken}) {
    final parts = token.split('.');
    Map<String, Object?> claims = <String, Object?>{};
    if (parts.length == 3) {
      try {
        claims = Map<String, Object?>.from(jsonDecode(utf8.decode(base64Url.decode(
          base64Url.normalize(parts[1]),
        ))) as Map);
      } catch (_) {
        claims = <String, Object?>{};
      }
    }
    final exp = claims['exp'];
    return StewardSession(
      token: token,
      refreshToken: refreshToken,
      userId: claims['userId']?.toString(),
      email: claims['email']?.toString(),
      tenantId: claims['tenantId']?.toString(),
      expiresAt: exp is num ? DateTime.fromMillisecondsSinceEpoch(exp.toInt() * 1000) : null,
    );
  }

  static String _randomHex(int bytes) {
    final random = Random.secure();
    return List<int>.generate(bytes, (_) => random.nextInt(256))
        .map((byte) => byte.toRadixString(16).padLeft(2, '0'))
        .join();
  }

  static String _randomVerifier() {
    final random = Random.secure();
    return _base64UrlNoPadding(List<int>.generate(32, (_) => random.nextInt(256)));
  }

  static String _base64UrlNoPadding(List<int> bytes) => base64Url.encode(bytes).replaceAll('=', '');
}
