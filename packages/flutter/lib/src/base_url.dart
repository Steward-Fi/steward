// Fail-closed baseUrl validation shared by StewardClient and StewardAuth.
// These clients transmit API keys, bearer tokens, and HMAC-signed
// credentials; none of that may travel to a plaintext non-loopback endpoint.
// Keep in lockstep with the equivalent check in EVERY other SDK (sdk, go,
// java, python, ruby, rust, swift, csharp) (SEC-200, mirroring SEC-048).

bool _isLoopbackHost(String host) =>
    host == 'localhost' || host == '127.0.0.1' || host == '::1' || host == '[::1]';

/// Throws unless [baseUrl] is HTTPS or targets loopback. Operators on trusted
/// private networks may opt out explicitly with `allowInsecureBaseUrl`, which
/// still warns loudly at construction.
void assertSecureBaseUrl(String baseUrl, {bool allowInsecureBaseUrl = false}) {
  final uri = Uri.parse(baseUrl);
  if (uri.scheme.isEmpty || uri.host.isEmpty) {
    throw ArgumentError('baseUrl must be a valid absolute URL');
  }
  final scheme = uri.scheme.toLowerCase();
  if (scheme == 'https' ||
      (scheme == 'http' && _isLoopbackHost(uri.host.toLowerCase()))) {
    return;
  }
  if (allowInsecureBaseUrl) {
    // dart:io stderr is unavailable on Flutter web; print is the portable
    // loud-warning channel here.
    // ignore: avoid_print
    print(
      '[steward-sdk] WARNING: baseUrl '$baseUrl' is not HTTPS; credentials '
      'travel in cleartext. Use allowInsecureBaseUrl only on trusted private '
      'networks.',
    );
    return;
  }
  throw ArgumentError(
    'baseUrl must use HTTPS unless it targets loopback (http://localhost, '
    'http://127.0.0.1, http://[::1]). Set allowInsecureBaseUrl: true to '
    'override on trusted private networks.',
  );
}
