# @stwd/react Changelog

## 0.9.1

- Security audit hardening release.
- StewardLogin scrubs the magic-link token and email from the URL via history.replaceState after capture, so credentials no longer land in browser history or the Referer header.
