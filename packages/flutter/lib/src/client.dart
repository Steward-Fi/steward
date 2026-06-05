import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;

import 'models.dart';

typedef StewardIdFactory = String Function();

class StewardClientConfig {
  StewardClientConfig({
    required this.baseUrl,
    this.apiKey,
    this.appId,
    this.appSecret,
    this.platformKey,
    this.bearerToken,
    this.tenantId,
    this.requestSigningSecret,
    this.requestSigningKeyId,
    this.httpClient,
    this.idFactory,
  });

  final String baseUrl;
  final String? apiKey;
  final String? appId;
  final String? appSecret;
  final String? platformKey;
  final String? bearerToken;
  final String? tenantId;
  final String? requestSigningSecret;
  final String? requestSigningKeyId;
  final http.Client? httpClient;
  final StewardIdFactory? idFactory;
}

class StewardClient {
  StewardClient(this.config)
      : _baseUri = Uri.parse(config.baseUrl.replaceFirst(RegExp(r'/+$'), '')),
        _client = config.httpClient ?? http.Client();

  static const _sensitivePrefixes = <String>[
    '/vault',
    '/agents',
    '/policies',
    '/secrets',
    '/trade',
    '/v1/trade',
    '/approvals',
    '/intents',
    '/user',
    '/webhooks',
    '/tenants',
    '/platform',
    '/condition-sets',
    '/condition_sets',
    '/v1/condition_sets',
    '/global-wallet',
    '/accounts',
  ];

  static const _mutatingMethods = <String>{'POST', 'PUT', 'PATCH', 'DELETE'};

  final StewardClientConfig config;
  final Uri _baseUri;
  final http.Client _client;

  Future<Object?> get(String path, {Map<String, Object?>? query}) =>
      request('GET', path, query: query);

  Future<Object?> post(String path, Object? body) => request('POST', path, body: body);

  Future<Object?> patch(String path, Object? body) => request('PATCH', path, body: body);

  Future<Object?> delete(String path) => request('DELETE', path);

  Future<Object?> request(
    String method,
    String path, {
    Object? body,
    Map<String, Object?>? query,
    Map<String, String>? headers,
    String? idempotencyKey,
  }) async {
    final canonicalPath = path.startsWith('/') ? path : '/$path';
    final encodedBody = body == null ? null : utf8.encode(jsonEncode(body));
    final uri = _baseUri.replace(
      path: _joinBasePath(_baseUri.path, canonicalPath),
      queryParameters: _cleanQuery(query),
    );
    final requestHeaders = _headers(
      canonicalPath,
      method.toUpperCase(),
      encodedBody,
      headers ?? const <String, String>{},
      idempotencyKey,
    );
    final response = await _client.send(
      http.Request(method.toUpperCase(), uri)
        ..headers.addAll(requestHeaders)
        ..bodyBytes = encodedBody ?? const <int>[],
    );
    return _decodeResponse(response);
  }

  Future<Map<String, Object?>> createUser(Map<String, Object?> input) async =>
      _asMap(await post('/platform/users', input));

  Future<Map<String, Object?>> getUser(String userId) async =>
      _asMap(await get('/platform/users/${Uri.encodeComponent(userId)}'));

  Future<Map<String, Object?>> lookupUser(Map<String, Object?> query) async =>
      _asMap(await get('/platform/users/lookup', query: query));

  Future<Map<String, Object?>> searchPlatformUsers(
    String tenantId,
    PlatformUserSearchQuery query,
  ) async =>
      _asMap(await get(
        '/platform/tenants/${Uri.encodeComponent(tenantId)}/users',
        query: query.toQuery(),
      ));

  Future<Map<String, Object?>> getUserByWalletExternalId(
    String walletExternalId, {
    required String tenantId,
  }) async =>
      lookupUser({
        'walletExternalId': walletExternalId,
        'tenantId': tenantId,
      });

  Future<Map<String, Object?>> assignWalletExternalId(
    String userId,
    WalletExternalIdInput input,
  ) async =>
      _asMap(await post(
        '/platform/users/${Uri.encodeComponent(userId)}/wallet/external-id',
        input.toJson(),
      ));

  Future<Map<String, Object?>> resolveWalletExternalId(WalletExternalIdInput input) async =>
      _asMap(await post('/platform/users/wallet/external-id', input.toJson()));

  Future<Map<String, Object?>> connectOrCreateByWalletExternalId(
    WalletExternalIdConnectOrCreateInput input,
  ) async =>
      _asMap(await post('/platform/users/wallet/external-id/connect-or-create', input.toJson()));

  Future<Map<String, Object?>> listAccounts() async => _asMap(await get('/accounts'));

  Future<Map<String, Object?>> createAccount(DigitalAssetAccountMutationInput input) async =>
      _asMap(await post('/accounts', input.toJson()));

  Future<Map<String, Object?>> getAccount(String accountId) async =>
      _asMap(await get('/accounts/${Uri.encodeComponent(accountId)}'));

  Future<Map<String, Object?>> getAccountBalance(String accountId) async =>
      _asMap(await get('/accounts/${Uri.encodeComponent(accountId)}/balance'));

  Future<Map<String, Object?>> updateAccount(
    String accountId,
    DigitalAssetAccountMutationInput input,
  ) async =>
      _asMap(await patch('/accounts/${Uri.encodeComponent(accountId)}', input.toJson()));

  Future<Map<String, Object?>> deleteAccount(String accountId) async =>
      _asMap(await delete('/accounts/${Uri.encodeComponent(accountId)}'));

  Future<Map<String, Object?>> listUserPushSubscriptions() async =>
      _asMap(await get('/user/me/push-subscriptions'));

  Future<Map<String, Object?>> registerUserPushSubscription(PushSubscriptionInput input) async =>
      _asMap(await post('/user/me/push-subscriptions', input.toJson()));

  Future<Map<String, Object?>> revokeUserPushSubscription(String subscriptionId) async =>
      _asMap(await delete('/user/me/push-subscriptions/${Uri.encodeComponent(subscriptionId)}'));

  Future<Map<String, Object?>> setupUserWalletRecovery() async =>
      _asMap(await post('/user/me/wallet/recovery/setup', null));

  Future<Map<String, Object?>> restoreUserWalletRecovery(
    UserWalletRecoveryRestoreInput input,
  ) async =>
      _asMap(await post('/user/me/wallet/recovery/restore', input.toJson()));

  Future<Map<String, Object?>> claimPregeneratedUserWallet(
    PregeneratedWalletClaimInput input,
  ) async =>
      _asMap(await post('/user/me/wallet/claim-pregenerated', input.toJson()));

  Future<Map<String, Object?>> getGlobalWalletConsentRequest(
    GlobalWalletConsentRequestInput input,
  ) async =>
      _asMap(await get('/global-wallet/consent/request', query: input.toQuery()));

  Future<Map<String, Object?>> approveGlobalWalletConsent(
    GlobalWalletConsentApproveInput input,
  ) async =>
      _asMap(await post('/global-wallet/consent/approve', input.toJson()));

  Future<Map<String, Object?>> listGlobalWalletConsents() async =>
      _asMap(await get('/global-wallet/consents'));

  Future<Map<String, Object?>> revokeGlobalWalletConsent(String consentId) async =>
      _asMap(await post(
        '/global-wallet/consents/${Uri.encodeComponent(consentId)}/revoke',
        null,
      ));

  Future<Map<String, Object?>> confirmGlobalWalletAction(
    GlobalWalletActionInput input,
  ) async =>
      _asMap(await post('/global-wallet/rpc/confirm', input.toJson()));

  Future<Map<String, Object?>> scanGlobalWalletTransaction(
    GlobalWalletTransactionScanInput input,
  ) async =>
      _asMap(await post('/global-wallet/rpc/scan', input.toJson()));

  Future<Map<String, Object?>> globalWalletRpc(GlobalWalletRpcInput input) async =>
      _asMap(await post('/global-wallet/rpc', input.toJson()));

  Map<String, String> _headers(
    String path,
    String method,
    List<int>? body,
    Map<String, String> extra,
    String? idempotencyKey,
  ) {
    final merged = <String, String>{
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      ...extra,
    };
    if (_notBlank(config.platformKey)) {
      merged['X-Steward-Platform-Key'] = config.platformKey!;
    } else if (_notBlank(config.bearerToken)) {
      merged['Authorization'] = 'Bearer ${config.bearerToken}';
    } else if (_notBlank(config.appId) && _notBlank(config.appSecret)) {
      final basic = base64Encode(utf8.encode('${config.appId}:${config.appSecret}'));
      merged['Authorization'] = 'Basic $basic';
      merged['X-Steward-App-Id'] = config.appId!;
    } else if (_notBlank(config.apiKey)) {
      merged['X-Steward-Key'] = config.apiKey!;
    }
    if (_notBlank(config.tenantId)) {
      merged['X-Steward-Tenant'] = config.tenantId!;
    }
    if (_notBlank(config.requestSigningSecret) && _isSensitiveMutation(path, method)) {
      final timestamp = merged.putIfAbsent(
        'X-Steward-Request-Timestamp',
        () => (DateTime.now().millisecondsSinceEpoch ~/ 1000).toString(),
      );
      final idem = merged.putIfAbsent(
        'Idempotency-Key',
        () => idempotencyKey ?? (config.idFactory?.call() ?? _fallbackId()),
      );
      if (_notBlank(config.requestSigningKeyId)) {
        merged.putIfAbsent('X-Steward-Signing-Key-Id', () => config.requestSigningKeyId!);
      }
      final bodyHash = sha256.convert(body ?? const <int>[]).toString();
      final canonical = [method, path, timestamp, idem, bodyHash].join('\n');
      final sig = Hmac(sha256, utf8.encode(config.requestSigningSecret!))
          .convert(utf8.encode(canonical))
          .toString();
      merged['X-Steward-Signature'] = 'v1=$sig';
    }
    return merged;
  }

  Future<Object?> _decodeResponse(http.StreamedResponse response) async {
    final text = await response.stream.bytesToString();
    Object? payload;
    if (text.isNotEmpty) {
      try {
        payload = jsonDecode(text);
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
    if (payload is Map && payload.containsKey('data')) {
      return payload['data'];
    }
    return payload;
  }

  static Map<String, dynamic>? _cleanQuery(Map<String, Object?>? query) {
    if (query == null) return null;
    return {
      for (final entry in query.entries)
        if (entry.value != null)
          entry.key: entry.value is Iterable
              ? (entry.value as Iterable).map((value) => value.toString()).toList()
              : entry.value.toString(),
    };
  }

  static bool _isSensitiveMutation(String path, String method) =>
      _mutatingMethods.contains(method) &&
      _sensitivePrefixes.any((prefix) => path.startsWith(prefix));

  static bool _notBlank(String? value) => value != null && value.trim().isNotEmpty;

  static String _fallbackId() {
    final random = Random.secure();
    return List<int>.generate(16, (_) => random.nextInt(256))
        .map((byte) => byte.toRadixString(16).padLeft(2, '0'))
        .join();
  }

  static String _joinBasePath(String basePath, String canonicalPath) {
    final base = basePath == '/' ? '' : basePath.replaceFirst(RegExp(r'/+$'), '');
    return '$base$canonicalPath';
  }

  static Map<String, Object?> _asMap(Object? value) {
    if (value is Map) {
      return value.map((key, value) => MapEntry(key.toString(), value));
    }
    throw StewardApiException('Expected object response from Steward API', 0, value);
  }
}
