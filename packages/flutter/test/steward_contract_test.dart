import 'package:flutter_test/flutter_test.dart';
import 'package:steward_flutter/steward.dart';

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

  test('wallet recovery and pregenerated wallet payloads match API contract', () {
    expect(
      UserWalletRecoveryRestoreInput(mnemonic: 'test test test').toJson(),
      {'mnemonic': 'test test test'},
    );
    expect(
      PregeneratedWalletClaimInput(
        tenantId: 'tenant-1',
        claimToken: 'stwd_claim_123',
      ).toJson(),
      {
        'tenantId': 'tenant-1',
        'claimToken': 'stwd_claim_123',
      },
    );
  });

  test('wallet external ID payloads match platform API contract', () {
    expect(
      PlatformUserSearchQuery(
        q: 'alice',
        walletExternalId: 'wallet-ext-1',
        limit: 10,
        offset: 5,
      ).toQuery(),
      {
        'q': 'alice',
        'walletExternalId': 'wallet-ext-1',
        'limit': 10,
        'offset': 5,
      },
    );
    expect(
      WalletExternalIdInput(
        tenantId: 'tenant-1',
        walletExternalId: 'wallet-ext-2',
      ).toJson(),
      {
        'tenantId': 'tenant-1',
        'walletExternalId': 'wallet-ext-2',
      },
    );
    expect(
      WalletExternalIdConnectOrCreateInput(
        tenantId: 'tenant-1',
        walletExternalId: 'wallet-ext-3',
        email: 'new@example.test',
        emailVerified: true,
      ).toJson(),
      {
        'tenantId': 'tenant-1',
        'walletExternalId': 'wallet-ext-3',
        'email': 'new@example.test',
        'emailVerified': true,
      },
    );
  });

  test('digital asset account payloads match JS SDK wire fields', () {
    final input = DigitalAssetAccountMutationInput(
      id: 'acct-1',
      displayName: 'Treasury',
      metadata: const {'desk': 'ops'},
      walletIds: const ['agent-wallet-1'],
      walletsConfiguration: [
        DigitalAssetAccountWalletConfiguration(
          chainType: 'ethereum',
          name: 'Treasury EVM',
          walletId: 'agent-wallet-1',
        ),
      ],
    );

    expect(input.toJson(), {
      'id': 'acct-1',
      'display_name': 'Treasury',
      'metadata': {'desk': 'ops'},
      'wallet_ids': ['agent-wallet-1'],
      'wallets_configuration': [
        {
          'chain_type': 'ethereum',
          'name': 'Treasury EVM',
          'wallet_id': 'agent-wallet-1',
        },
      ],
    });
  });

  test('global wallet payloads match JS SDK wire fields', () {
    expect(
      GlobalWalletConsentRequestInput(
        appId: 'tenant-1/client-1',
        origin: 'https://app.example',
        redirectUri: 'https://app.example/callback',
        scopes: const ['eth_accounts', 'personal_sign'],
      ).toQuery(),
      {
        'app_id': 'tenant-1/client-1',
        'origin': 'https://app.example',
        'redirect_uri': 'https://app.example/callback',
        'scope': ['eth_accounts', 'personal_sign'],
      },
    );

    expect(
      GlobalWalletConsentApproveInput(
        appId: 'tenant-1/client-1',
        origin: 'https://app.example',
        scopes: const ['eth_accounts'],
      ).toJson(),
      {
        'app_id': 'tenant-1/client-1',
        'origin': 'https://app.example',
        'scopes': ['eth_accounts'],
      },
    );

    expect(
      GlobalWalletRpcInput(
        appId: 'tenant-1/client-1',
        origin: 'https://app.example',
        method: 'personal_sign',
        params: const ['0x1234'],
        confirmationId: 'gwc_123',
        id: 1,
        jsonrpc: '2.0',
      ).toJson(),
      {
        'app_id': 'tenant-1/client-1',
        'origin': 'https://app.example',
        'method': 'personal_sign',
        'params': ['0x1234'],
        'confirmation_id': 'gwc_123',
        'id': 1,
        'jsonrpc': '2.0',
      },
    );
  });
}
