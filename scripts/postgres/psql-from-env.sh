#!/bin/sh
set -eu

# libpq does not parse a connection URI stored in PGDATABASE. Split the
# userinfo password into PGPASSWORD and pass a credential-free URI to psql so
# the secret never appears in the observable process argv.
case "${PGDATABASE:-}" in
  postgres://*) connection="${PGDATABASE#postgres://}" ;;
  postgresql://*) connection="${PGDATABASE#postgresql://}" ;;
  *)
    echo "PGDATABASE must be a postgres:// or postgresql:// connection URI" >&2
    exit 1
    ;;
esac

case "$connection" in
  *#*|*'?'*password=*|*'&'password=*)
    echo "PGDATABASE must carry its password in URI userinfo" >&2
    exit 1
    ;;
esac

authority="${connection%%/*}"
path="${connection#*/}"
case "$authority" in
  *@*) ;;
  *)
    echo "PGDATABASE must include URI userinfo" >&2
    exit 1
    ;;
esac

userinfo="${authority%@*}"
host="${authority##*@}"
case "$userinfo" in
  *:*) ;;
  *)
    echo "PGDATABASE must include a userinfo password" >&2
    exit 1
    ;;
esac

user="${userinfo%%:*}"
encoded_password="${userinfo#*:}"
case "$encoded_password" in
  *%*)
    # URI passwords are percent encoded. Validate every percent escape before
    # asking printf to decode it so malformed input fails closed.
    remainder="$encoded_password"
    while [ -n "$remainder" ]; do
      case "$remainder" in
        %??*)
          escape="${remainder#%}"
          escape="${escape%${escape#??}}"
          case "$escape" in
            *[!0-9A-Fa-f]*)
              echo "PGDATABASE contains an invalid password escape" >&2
              exit 1
              ;;
          esac
          remainder="${remainder#???}"
          ;;
        %*)
          echo "PGDATABASE contains an invalid password escape" >&2
          exit 1
          ;;
        *) remainder="${remainder#?}" ;;
      esac
    done
    PGPASSWORD="$(printf '%b' "$(printf '%s' "$encoded_password" | sed 's/%/\\x/g')")"
    ;;
  *) PGPASSWORD="$encoded_password" ;;
esac

unset PGDATABASE
export PGPASSWORD
exec psql "postgresql://${user}@${host}/${path}" "$@"
