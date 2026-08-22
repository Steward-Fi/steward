import 'dart:collection';
import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:steward_flutter/steward.dart';

const _baseUrl = 'https://api.example.test/v1/';

Map<String, String> _lowercaseHeaders(Map<String, String> headers) => {
      for (final entry in headers.entries) entry.key.toLowerCase(): entry.value,
    };

Uri _uri(List<String> pathSegments, {Map<String, dynamic>? query}) {
  final encodedPath = ['v1', ...pathSegments].map(Uri.encodeComponent).join('/');
  return Uri.parse('https://api.example.test/$encodedPath').replace(
    queryParameters: query,
  );
}

final class _Exchange {
  _Exchange({
    required this.method,
    required this.uri,
    required this.body,
    required this.statusCode,
    required this.responseBody,
  });

  final String method;
  final Uri uri;
  final Object? body;
  final int statusCode;
  final String responseBody;
}

final class _ControlledHttpClient extends http.BaseClient {
  final Queue<_Exchange> exchanges = Queue<_Exchange>();

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    expect(
      exchanges,
      isNotEmpty,
      reason: 'unexpected HTTP request: ${request.method} ${request.url}',
    );
    final exchange = exchanges.removeFirst();
    expect(request, isA<http.Request>());
    final concrete = request as http.Request;

    expect(concrete.method, exchange.method);
    expect(concrete.url, exchange.uri);
    expect(concrete.followRedirects, isFalse);
    final headers = _lowercaseHeaders(concrete.headers);
    final expectedHeaders = <String, String>{
      'accept': 'application/json',
      'authorization': 'Bearer wire-token',
      'content-type': 'application/json',
      'x-steward-tenant': 'tenant-header',
    };
    if (exchange.method != 'GET') {
      final timestamp = headers['x-steward-request-timestamp'];
      expect(timestamp, matches(RegExp(r'^\d+$')));
      final encodedBody = exchange.body == null ? '' : jsonEncode(exchange.body);
      final bodyHash = sha256.convert(utf8.encode(encodedBody)).toString();
      final encodedUri = exchange.uri.toString();
      final pathAndQuery = encodedUri.substring('https://api.example.test/v1'.length);
      final signingPath = pathAndQuery.split('?').first;
      final canonical = [
        exchange.method,
        signingPath,
        timestamp,
        'wire-id',
        bodyHash,
      ].join('\n');
      final signature = Hmac(sha256, utf8.encode('wire-signing-secret'))
          .convert(utf8.encode(canonical))
          .toString();
      expectedHeaders.addAll({
        'idempotency-key': 'wire-id',
        'x-steward-request-timestamp': timestamp!,
        'x-steward-signature': 'v1=$signature',
        'x-steward-signing-key-id': 'wire-key',
      });
    }
    expect(headers, expectedHeaders);
    expect(
      concrete.body,
      exchange.body == null ? isEmpty : jsonEncode(exchange.body),
    );

    return http.StreamedResponse(
      Stream<List<int>>.value(utf8.encode(exchange.responseBody)),
      exchange.statusCode,
      headers: const {'content-type': 'application/json'},
      request: request,
    );
  }
}

final class _WireHarness {
  _WireHarness() {
    transport = _ControlledHttpClient();
    client = StewardClient(
      StewardClientConfig(
        baseUrl: _baseUrl,
        bearerToken: 'wire-token',
        tenantId: 'tenant-header',
        requestSigningSecret: 'wire-signing-secret',
        requestSigningKeyId: 'wire-key',
        idFactory: () => 'wire-id',
        httpClient: transport,
      ),
    );
  }

  late final _ControlledHttpClient transport;
  late final StewardClient client;

  Future<void> expectSuccess(
    String label, {
    required String method,
    required Uri uri,
    required Object? body,
    required Future<Map<String, Object?>> Function() invoke,
  }) async {
    transport.exchanges.add(_Exchange(
      method: method,
      uri: uri,
      body: body,
      statusCode: 200,
      responseBody: jsonEncode({
        'ok': true,
        'data': {'call': label},
      }),
    ));

    expect(await invoke(), {'call': label});
    expect(transport.exchanges, isEmpty);
  }

  Future<void> expectFailure({
    required String method,
    required Uri uri,
    required Object? body,
    required int statusCode,
    required String error,
    required Future<Map<String, Object?>> Function() invoke,
  }) async {
    transport.exchanges.add(_Exchange(
      method: method,
      uri: uri,
      body: body,
      statusCode: statusCode,
      responseBody: jsonEncode({'error': error}),
    ));

    await expectLater(
      invoke(),
      throwsA(isA<StewardApiException>()
          .having((exception) => exception.statusCode, 'statusCode', statusCode)
          .having((exception) => exception.message, 'message', error)),
    );
    expect(transport.exchanges, isEmpty);
  }
}

void main() {
  test('namespaced session storage isolates tenant keys', () async {
    final inner = MemoryStewardSessionStorage();
    final a = NamespacedStewardSessionStorage(inner, namespace: 'tenant-a');
    final b = NamespacedStewardSessionStorage(inner, namespace: 'tenant-b');

    await a.setItem('steward_session_token', 'token-a');
    await b.setItem('steward_session_token', 'token-b');

    expect(await a.getItem('steward_session_token'), 'token-a');
    expect(await b.getItem('steward_session_token'), 'token-b');
  });

  test('push subscription payload omits null values', () {
    final input = PushSubscriptionInput(
      provider: 'fcm',
      token: 'push-token',
      platform: 'android',
      tenantId: 'tenant-1',
    );

    expect(input.toJson(), {
      'provider': 'fcm',
      'token': 'push-token',
      'platform': 'android',
      'tenantId': 'tenant-1',
    });
  });

  test('wallet recovery and claim helpers execute their exact wire contracts', () async {
    final harness = _WireHarness();

    await harness.expectSuccess(
      'recovery-setup',
      method: 'POST',
      uri: _uri(['user', 'me', 'wallet', 'recovery', 'setup']),
      body: null,
      invoke: harness.client.setupUserWalletRecovery,
    );

    final restore = UserWalletRecoveryRestoreInput(mnemonic: 'word /?#% ü');
    await harness.expectSuccess(
      'recovery-restore',
      method: 'POST',
      uri: _uri(['user', 'me', 'wallet', 'recovery', 'restore']),
      body: restore.toJson(),
      invoke: () => harness.client.restoreUserWalletRecovery(restore),
    );

    final claim = PregeneratedWalletClaimInput(
      tenantId: 'tenant /?#% ü',
      claimToken: 'claim /?#% ü',
    );
    await harness.expectSuccess(
      'wallet-claim',
      method: 'POST',
      uri: _uri(['user', 'me', 'wallet', 'claim-pregenerated']),
      body: claim.toJson(),
      invoke: () => harness.client.claimPregeneratedUserWallet(claim),
    );

    await harness.expectFailure(
      method: 'POST',
      uri: _uri(['user', 'me', 'wallet', 'recovery', 'restore']),
      body: restore.toJson(),
      statusCode: 422,
      error: 'invalid recovery phrase',
      invoke: () => harness.client.restoreUserWalletRecovery(restore),
    );
  });

  test('wallet external ID helpers encode hostile paths and queries', () async {
    final harness = _WireHarness();
    const hostile = 'value /?#% ü&=+';
    final search = PlatformUserSearchQuery(
      q: hostile,
      email: 'alice+wire@example.test',
      walletExternalId: hostile,
      limit: 17,
      offset: 23,
    );

    await harness.expectSuccess(
      'platform-search',
      method: 'GET',
      uri: _uri(
        ['platform', 'tenants', hostile, 'users'],
        query: {
          'q': hostile,
          'email': 'alice+wire@example.test',
          'walletExternalId': hostile,
          'limit': '17',
          'offset': '23',
        },
      ),
      body: null,
      invoke: () => harness.client.searchPlatformUsers(hostile, search),
    );

    await harness.expectSuccess(
      'wallet-lookup',
      method: 'GET',
      uri: _uri(
        ['platform', 'users', 'lookup'],
        query: {'walletExternalId': hostile, 'tenantId': hostile},
      ),
      body: null,
      invoke: () => harness.client.getUserByWalletExternalId(hostile, tenantId: hostile),
    );

    final externalId = WalletExternalIdInput(tenantId: hostile, walletExternalId: hostile);
    await harness.expectSuccess(
      'wallet-assign',
      method: 'POST',
      uri: _uri(['platform', 'users', hostile, 'wallet', 'external-id']),
      body: externalId.toJson(),
      invoke: () => harness.client.assignWalletExternalId(hostile, externalId),
    );
    await harness.expectSuccess(
      'wallet-resolve',
      method: 'POST',
      uri: _uri(['platform', 'users', 'wallet', 'external-id']),
      body: externalId.toJson(),
      invoke: () => harness.client.resolveWalletExternalId(externalId),
    );

    final connect = WalletExternalIdConnectOrCreateInput(
      tenantId: hostile,
      walletExternalId: hostile,
      email: 'alice+wire@example.test',
      emailVerified: true,
      name: hostile,
      customMetadata: const {'hostile': '../?x=1&x=2'},
    );
    await harness.expectSuccess(
      'wallet-connect-or-create',
      method: 'POST',
      uri: _uri(['platform', 'users', 'wallet', 'external-id', 'connect-or-create']),
      body: connect.toJson(),
      invoke: () => harness.client.connectOrCreateByWalletExternalId(connect),
    );
  });

  test('digital asset account helpers execute the complete resource wire contract', () async {
    final harness = _WireHarness();
    const accountId = 'account /?#% ü&=+';
    final mutation = DigitalAssetAccountMutationInput(
      id: accountId,
      displayName: 'Treasury /?#%',
      metadata: const {'desk': 'ops', 'hostile': '../?x=1&x=2'},
      walletIds: const ['wallet / one', 'wallet?two'],
      walletsConfiguration: [
        DigitalAssetAccountWalletConfiguration(
          chainType: 'ethereum',
          name: 'Treasury EVM',
          walletId: 'wallet / one',
        ),
      ],
    );

    await harness.expectSuccess(
      'accounts-list',
      method: 'GET',
      uri: _uri(['accounts']),
      body: null,
      invoke: harness.client.listAccounts,
    );
    await harness.expectSuccess(
      'accounts-create',
      method: 'POST',
      uri: _uri(['accounts']),
      body: mutation.toJson(),
      invoke: () => harness.client.createAccount(mutation),
    );
    await harness.expectSuccess(
      'accounts-get',
      method: 'GET',
      uri: _uri(['accounts', accountId]),
      body: null,
      invoke: () => harness.client.getAccount(accountId),
    );
    await harness.expectSuccess(
      'accounts-balance',
      method: 'GET',
      uri: _uri(['accounts', accountId, 'balance']),
      body: null,
      invoke: () => harness.client.getAccountBalance(accountId),
    );
    await harness.expectSuccess(
      'accounts-update',
      method: 'PATCH',
      uri: _uri(['accounts', accountId]),
      body: mutation.toJson(),
      invoke: () => harness.client.updateAccount(accountId, mutation),
    );
    await harness.expectSuccess(
      'accounts-delete',
      method: 'DELETE',
      uri: _uri(['accounts', accountId]),
      body: null,
      invoke: () => harness.client.deleteAccount(accountId),
    );
  });

  test('global wallet helpers preserve repeated query values and refuse redirects', () async {
    final harness = _WireHarness();
    const hostile = 'value /?#% ü&=+';
    final consentRequest = GlobalWalletConsentRequestInput(
      appId: hostile,
      origin: 'https://app.example.test/a?x=1&x=2#fragment',
      redirectUri: 'https://app.example.test/callback?next=/a%2Fb',
      scopes: const ['eth_accounts', 'personal_sign /?#%', 'eth_accounts'],
    );
    await harness.expectSuccess(
      'global-consent-request',
      method: 'GET',
      uri: _uri(
        ['global-wallet', 'consent', 'request'],
        query: {
          'app_id': hostile,
          'origin': 'https://app.example.test/a?x=1&x=2#fragment',
          'redirect_uri': 'https://app.example.test/callback?next=/a%2Fb',
          'scope': ['eth_accounts', 'personal_sign /?#%', 'eth_accounts'],
        },
      ),
      body: null,
      invoke: () => harness.client.getGlobalWalletConsentRequest(consentRequest),
    );

    final approve = GlobalWalletConsentApproveInput(
      appId: hostile,
      origin: 'https://app.example.test/a?x=1',
      redirectUri: 'https://app.example.test/callback?next=/a%2Fb',
      scopes: const ['eth_accounts', 'personal_sign'],
    );
    await harness.expectSuccess(
      'global-consent-approve',
      method: 'POST',
      uri: _uri(['global-wallet', 'consent', 'approve']),
      body: approve.toJson(),
      invoke: () => harness.client.approveGlobalWalletConsent(approve),
    );
    await harness.expectSuccess(
      'global-consents-list',
      method: 'GET',
      uri: _uri(['global-wallet', 'consents']),
      body: null,
      invoke: harness.client.listGlobalWalletConsents,
    );
    await harness.expectSuccess(
      'global-consent-revoke',
      method: 'POST',
      uri: _uri(['global-wallet', 'consents', hostile, 'revoke']),
      body: null,
      invoke: () => harness.client.revokeGlobalWalletConsent(hostile),
    );

    final action = GlobalWalletActionInput(
      appId: hostile,
      method: 'personal_sign',
      origin: 'https://app.example.test',
      params: const ['0x1234', '../?x=1'],
    );
    await harness.expectSuccess(
      'global-confirm',
      method: 'POST',
      uri: _uri(['global-wallet', 'rpc', 'confirm']),
      body: action.toJson(),
      invoke: () => harness.client.confirmGlobalWalletAction(action),
    );

    final scan = GlobalWalletTransactionScanInput(
      appId: hostile,
      origin: 'https://app.example.test',
      params: const [
        {'to': '0x1234', 'data': '0xdeadbeef'}
      ],
    );
    await harness.expectSuccess(
      'global-scan',
      method: 'POST',
      uri: _uri(['global-wallet', 'rpc', 'scan']),
      body: scan.toJson(),
      invoke: () => harness.client.scanGlobalWalletTransaction(scan),
    );

    final rpc = GlobalWalletRpcInput(
      appId: hostile,
      method: 'eth_sendTransaction',
      origin: 'https://app.example.test',
      params: const [
        {'to': '0x1234'}
      ],
      confirmationId: hostile,
      id: 'rpc /?#%',
      jsonrpc: '2.0',
    );
    await harness.expectSuccess(
      'global-rpc',
      method: 'POST',
      uri: _uri(['global-wallet', 'rpc']),
      body: rpc.toJson(),
      invoke: () => harness.client.globalWalletRpc(rpc),
    );

    await harness.expectFailure(
      method: 'POST',
      uri: _uri(['global-wallet', 'rpc']),
      body: rpc.toJson(),
      statusCode: 302,
      error: 'redirect refused',
      invoke: () => harness.client.globalWalletRpc(rpc),
    );
  });
}
