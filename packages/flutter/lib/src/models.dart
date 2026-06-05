class StewardApiException implements Exception {
  StewardApiException(this.message, this.statusCode, [this.payload]);

  final String message;
  final int statusCode;
  final Object? payload;

  @override
  String toString() => 'StewardApiException($statusCode): $message';
}

class StewardSession {
  StewardSession({
    required this.token,
    this.refreshToken,
    this.userId,
    this.email,
    this.tenantId,
    this.expiresAt,
    this.user,
  });

  final String token;
  final String? refreshToken;
  final String? userId;
  final String? email;
  final String? tenantId;
  final DateTime? expiresAt;
  final Map<String, Object?>? user;
}

class StewardAuthResult {
  StewardAuthResult({
    required this.token,
    this.refreshToken,
    this.user,
  });

  final String token;
  final String? refreshToken;
  final Map<String, Object?>? user;
}

class StewardMfaRequiredResult {
  StewardMfaRequiredResult({
    required this.challengeId,
    required this.methods,
  });

  final String challengeId;
  final List<String> methods;
}

class StewardEmailResult {
  StewardEmailResult({required this.expiresAt});

  final String expiresAt;
}

class StewardOtpResult {
  StewardOtpResult({required this.expiresAt});

  final String expiresAt;
}

class StewardOAuthStartResult {
  StewardOAuthStartResult({
    required this.authorizationUrl,
    required this.state,
    required this.codeVerifier,
  });

  final Uri authorizationUrl;
  final String state;
  final String codeVerifier;
}

class PushSubscriptionInput {
  PushSubscriptionInput({
    required this.provider,
    required this.token,
    this.platform,
    this.deviceId,
    this.appId,
    this.tenantId,
    this.userId,
    this.locale,
    this.timezone,
    this.metadata,
  });

  final String provider;
  final String token;
  final String? platform;
  final String? deviceId;
  final String? appId;
  final String? tenantId;
  final String? userId;
  final String? locale;
  final String? timezone;
  final Map<String, Object?>? metadata;

  Map<String, Object?> toJson() => {
        'provider': provider,
        'token': token,
        if (platform != null) 'platform': platform,
        if (deviceId != null) 'deviceId': deviceId,
        if (appId != null) 'appId': appId,
        if (tenantId != null) 'tenantId': tenantId,
        if (userId != null) 'userId': userId,
        if (locale != null) 'locale': locale,
        if (timezone != null) 'timezone': timezone,
        if (metadata != null) 'metadata': metadata,
      };
}

class UserWalletRecoveryRestoreInput {
  UserWalletRecoveryRestoreInput({required this.mnemonic});

  final String mnemonic;

  Map<String, Object?> toJson() => {'mnemonic': mnemonic};
}

class PregeneratedWalletClaimInput {
  PregeneratedWalletClaimInput({
    required this.tenantId,
    required this.claimToken,
  });

  final String tenantId;
  final String claimToken;

  Map<String, Object?> toJson() => {
        'tenantId': tenantId,
        'claimToken': claimToken,
      };
}

class PlatformUserSearchQuery {
  PlatformUserSearchQuery({
    this.q,
    this.email,
    this.walletExternalId,
    this.limit,
    this.offset,
  });

  final String? q;
  final String? email;
  final String? walletExternalId;
  final int? limit;
  final int? offset;

  Map<String, Object?> toQuery() => {
        if (q != null) 'q': q,
        if (email != null) 'email': email,
        if (walletExternalId != null) 'walletExternalId': walletExternalId,
        if (limit != null) 'limit': limit,
        if (offset != null) 'offset': offset,
      };
}

class WalletExternalIdInput {
  WalletExternalIdInput({
    required this.tenantId,
    required this.walletExternalId,
  });

  final String tenantId;
  final String walletExternalId;

  Map<String, Object?> toJson() => {
        'tenantId': tenantId,
        'walletExternalId': walletExternalId,
      };
}

class WalletExternalIdConnectOrCreateInput {
  WalletExternalIdConnectOrCreateInput({
    required this.tenantId,
    required this.walletExternalId,
    this.email,
    this.emailVerified,
    this.name,
    this.customMetadata,
  });

  final String tenantId;
  final String walletExternalId;
  final String? email;
  final bool? emailVerified;
  final String? name;
  final Map<String, Object?>? customMetadata;

  Map<String, Object?> toJson() => {
        'tenantId': tenantId,
        'walletExternalId': walletExternalId,
        if (email != null) 'email': email,
        if (emailVerified != null) 'emailVerified': emailVerified,
        if (name != null) 'name': name,
        if (customMetadata != null) 'customMetadata': customMetadata,
      };
}

class DigitalAssetAccountWalletConfiguration {
  DigitalAssetAccountWalletConfiguration({
    this.chainType,
    this.name,
    this.walletId,
  });

  final String? chainType;
  final String? name;
  final String? walletId;

  Map<String, Object?> toJson() => {
        if (chainType != null) 'chain_type': chainType,
        if (name != null) 'name': name,
        if (walletId != null) 'wallet_id': walletId,
      };
}

class DigitalAssetAccountMutationInput {
  DigitalAssetAccountMutationInput({
    this.id,
    this.displayName,
    this.metadata,
    this.walletIds,
    this.walletsConfiguration,
  });

  final String? id;
  final String? displayName;
  final Map<String, Object?>? metadata;
  final List<String>? walletIds;
  final List<DigitalAssetAccountWalletConfiguration>? walletsConfiguration;

  Map<String, Object?> toJson() => {
        if (id != null) 'id': id,
        if (displayName != null) 'display_name': displayName,
        if (metadata != null) 'metadata': metadata,
        if (walletIds != null) 'wallet_ids': walletIds,
        if (walletsConfiguration != null)
          'wallets_configuration':
              walletsConfiguration!.map((configuration) => configuration.toJson()).toList(),
      };
}

class GlobalWalletConsentRequestInput {
  GlobalWalletConsentRequestInput({
    required this.appId,
    this.origin,
    this.redirectUri,
    this.scopes,
  });

  final String appId;
  final String? origin;
  final String? redirectUri;
  final List<String>? scopes;

  Map<String, Object?> toQuery() => {
        'app_id': appId,
        if (origin != null) 'origin': origin,
        if (redirectUri != null) 'redirect_uri': redirectUri,
        if (scopes != null) 'scope': scopes,
      };
}

class GlobalWalletConsentApproveInput {
  GlobalWalletConsentApproveInput({
    required this.appId,
    this.origin,
    this.redirectUri,
    this.scopes,
  });

  final String appId;
  final String? origin;
  final String? redirectUri;
  final List<String>? scopes;

  Map<String, Object?> toJson() => {
        'app_id': appId,
        if (origin != null) 'origin': origin,
        if (redirectUri != null) 'redirect_uri': redirectUri,
        if (scopes != null) 'scopes': scopes,
      };
}

class GlobalWalletActionInput {
  GlobalWalletActionInput({
    required this.appId,
    required this.method,
    this.origin,
    this.params,
  });

  final String appId;
  final String method;
  final String? origin;
  final Object? params;

  Map<String, Object?> toJson() => {
        'app_id': appId,
        if (origin != null) 'origin': origin,
        'method': method,
        if (params != null) 'params': params,
      };
}

class GlobalWalletTransactionScanInput {
  GlobalWalletTransactionScanInput({
    required this.appId,
    required this.params,
    this.origin,
    this.method = 'eth_sendTransaction',
  });

  final String appId;
  final Object? params;
  final String? origin;
  final String method;

  Map<String, Object?> toJson() => {
        'app_id': appId,
        if (origin != null) 'origin': origin,
        'method': method,
        'params': params,
      };
}

class GlobalWalletRpcInput {
  GlobalWalletRpcInput({
    required this.appId,
    required this.method,
    this.origin,
    this.params,
    this.confirmationId,
    this.id,
    this.jsonrpc,
  });

  final String appId;
  final String method;
  final String? origin;
  final Object? params;
  final String? confirmationId;
  final Object? id;
  final String? jsonrpc;

  Map<String, Object?> toJson() => {
        'app_id': appId,
        if (origin != null) 'origin': origin,
        'method': method,
        if (params != null) 'params': params,
        if (confirmationId != null) 'confirmation_id': confirmationId,
        if (id != null) 'id': id,
        if (jsonrpc != null) 'jsonrpc': jsonrpc,
      };
}
