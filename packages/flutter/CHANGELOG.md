# Changelog

All notable changes to `steward_flutter` are documented here.

## 0.1.1

### Security

- Reject every HTTP response outside the 2xx range, including redirects, before decoding a successful Steward API result.
- Preserve percent-encoded hostile path segments when resolving public helper routes against a configured base path.

### Tests

- Exercise recovery, pregenerated-wallet claims, external wallet IDs, digital-asset accounts, and global-wallet helpers through a controlled HTTP client with independent literal request maps, exact encoded URLs, authentication and signing headers, decoded results, non-2xx failures, and redirect refusal.
