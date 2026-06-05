/**
 * Regression test for issues #101 and #111.
 *
 * These guard the shipped deploy artifacts (no app logic is exercised), so the
 * test is dependency-free: it reads the files as text and asserts on their
 * content. It FAILS against the pre-fix artifacts and passes after the fix.
 *
 * #101 — steward-proxy runs NODE_ENV=production, which makes request signing and
 *        Redis enforcement fail CLOSED. The compose proxy service must therefore
 *        supply REDIS_URL and a request-signing secret (or set the explicit
 *        soft-fail / no-signature overrides), and the docs must not call
 *        REDIS_URL optional while the code treats production as requiring it.
 *
 * #111 — provision-steward-node.sh must not interpolate secret variables into an
 *        ssh / ${SSH_CMD} "..." command-line argument, and must not echo the
 *        platform admin key to stdout.
 */
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const DEPLOY_DIR = join(import.meta.dir, "..", "..", "..", "..", "deploy");

function read(name: string): string {
  return readFileSync(join(DEPLOY_DIR, name), "utf8");
}

/**
 * Extract the `steward-proxy:` service block from the compose file (everything
 * from the `steward-proxy:` key up to the next top-level service or section).
 */
function extractProxyService(compose: string): string {
  const lines = compose.split("\n");
  const start = lines.findIndex((l) => /^\s{2}steward-proxy:\s*$/.test(l));
  expect(start).toBeGreaterThanOrEqual(0);
  const body: string[] = [];
  for (let i = start + 1; i < lines.length; i += 1) {
    const l = lines[i];
    // Stop at the next 2-space-indented key (next service) or a 0-indent line.
    if (/^\s{2}\S/.test(l) || /^\S/.test(l)) break;
    body.push(l);
  }
  return body.join("\n");
}

describe("#101 deploy/docker-compose.yml proxy production env", () => {
  const compose = read("docker-compose.yml");
  const proxy = extractProxyService(compose);

  test("proxy service runs NODE_ENV=production (precondition for fail-closed)", () => {
    expect(/NODE_ENV:\s*production/.test(proxy)).toBe(true);
  });

  test("production proxy supplies a request-signing secret or opts out explicitly", () => {
    const hasSigningSecret =
      /STEWARD_PROXY_REQUEST_SIGNING_SECRETS?\s*:/.test(proxy) ||
      /STEWARD_REQUEST_SIGNING_SECRETS?\s*:/.test(proxy);
    const optsOutOfSigning = /STEWARD_PROXY_REQUIRE_REQUEST_SIGNATURE\s*:\s*["']?false/.test(proxy);
    expect(hasSigningSecret || optsOutOfSigning).toBe(true);
  });

  test("production proxy supplies REDIS_URL or opts out of Redis enforcement", () => {
    const hasRedisUrl = /REDIS_URL\s*:/.test(proxy);
    const optsOutOfRedis = /STEWARD_ALLOW_PROXY_REDIS_SOFT_FAIL\s*:\s*["']?true/.test(proxy);
    expect(hasRedisUrl || optsOutOfRedis).toBe(true);
  });

  test("a redis service is defined when REDIS_URL points at the redis host", () => {
    if (/REDIS_URL\s*:\s*["']?\S*redis:\/\/redis(:|\b)/.test(proxy)) {
      expect(/^\s{2}redis:\s*$/m.test(compose)).toBe(true);
    }
  });
});

describe("#101 deploy/DEPLOYMENT.md docs reconciled with fail-closed code", () => {
  const doc = read("DEPLOYMENT.md");

  test("REDIS_URL is not marked optional in the critical-env table", () => {
    // Pre-fix row: `| `REDIS_URL` | ... | No |`
    const optionalRow = /\|\s*`REDIS_URL`\s*\|[^|]*\|\s*No\s*\|/i;
    expect(optionalRow.test(doc)).toBe(false);
  });

  test("docs do not claim Redis-absent uses in-memory fallbacks without noting prod fails closed", () => {
    // The misleading sentence asserts in-memory fallback as the unconditional
    // behavior. After the fix the surrounding text must mention fail-closed.
    const claimsFallback = /in-memory fallback/i.test(doc);
    if (claimsFallback) {
      expect(/fail(s)?\s*closed/i.test(doc)).toBe(true);
    }
  });
});

describe("#111 deploy/provision-steward-node.sh does not leak secrets", () => {
  const script = read("provision-steward-node.sh");
  const lines = script.split("\n");

  const SECRET_VARS = [
    "STEWARD_MASTER_PASSWORD",
    "STEWARD_PLATFORM_KEY",
    "STEWARD_JWT_SECRET",
    "STEWARD_KDF_SALT",
    "POSTGRES_PASSWORD",
    "STEWARD_PROXY_REQUEST_SIGNING_SECRETS",
    "PLATFORM_KEY",
  ];

  test('no secret is interpolated inside an ssh / ${SSH_CMD} "..." command argument', () => {
    // Flag any line that invokes ssh (directly or via ${SSH_CMD}) AND, on the
    // same line, interpolates a secret var (${VAR} or 'literal=${VAR}'). This
    // is the heredoc-in-double-quoted-ssh leak from #111. We allow ssh lines
    // that pipe a file over stdin ( ... < "${LOCAL_ENV_FILE}" ) and lines that
    // read the secret on the REMOTE side ($(sed ...)/$(grep ...)).
    const offenders: string[] = [];
    for (const line of lines) {
      const isSshLine = /\$\{SSH_CMD\}|(^|\s)ssh\s/.test(line);
      if (!isSshLine) continue;
      // Remote-side capture (PK=$(...)) or stdin pipe is fine — skip those.
      const pipesStdin = /<\s*"?\$\{LOCAL_ENV_FILE\}"?/.test(line);
      if (pipesStdin) continue;
      for (const v of SECRET_VARS) {
        // Local interpolation of the secret on the ssh command line:
        //   ...${VAR}...  (but NOT the escaped remote form \${VAR})
        const localInterp = new RegExp(`(^|[^\\\\])\\$\\{${v}(:-[^}]*)?\\}`);
        if (localInterp.test(line)) {
          offenders.push(line.trim());
          break;
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  test("the platform key is never echoed to stdout", () => {
    // Pre-fix:  echo "  Platform Key:   ${PLATFORM_KEY}"
    const echoesKey = lines.some(
      (l) =>
        /^\s*echo\b/.test(l) &&
        /\$\{PLATFORM_KEY(:-[^}]*)?\}|\$\{STEWARD_PLATFORM_KEY(:-[^}]*)?\}/.test(l),
    );
    expect(echoesKey).toBe(false);
  });

  test("the proxy request signing secret value is never echoed to stdout", () => {
    const agentConfigLine = lines.find((l) =>
      /^\s*echo\b/.test(l) && /STEWARD_PROXY_REQUEST_SIGNING_SECRETS=/.test(l),
    );
    expect(agentConfigLine).toBeDefined();
    expect(agentConfigLine).not.toContain("${STEWARD_PROXY_REQUEST_SIGNING_SECRETS}");
    expect(agentConfigLine).toContain("retrieve from ${REMOTE_DIR}/deploy/.env on the node");
    expect(script).toContain("the node-side .env is mode 0600");
  });

  test(".env is rendered locally and piped over ssh stdin", () => {
    // The fixed flow writes a local temp env file and streams it to the node.
    expect(/LOCAL_ENV_FILE/.test(script)).toBe(true);
    expect(/<\s*"?\$\{LOCAL_ENV_FILE\}"?/.test(script)).toBe(true);
  });

  test("rsync does not delete an existing remote deploy/.env before secret reuse", () => {
    expect(/--delete/.test(script)).toBe(true);
    expect(/--exclude=['"]deploy\/\.env['"]/.test(script)).toBe(true);
    expect(script.indexOf("--exclude='deploy/.env'")).toBeLessThan(
      script.indexOf('"${REPO_ROOT}/" "root@${NODE_IP}:${REMOTE_DIR}/"'),
    );
  });

  test("rendered .env includes the keys the production image requires", () => {
    for (const key of [
      "STEWARD_MASTER_PASSWORD",
      "STEWARD_JWT_SECRET",
      "STEWARD_KDF_SALT",
      "POSTGRES_PASSWORD",
    ]) {
      expect(new RegExp(`^${key}=`, "m").test(script)).toBe(true);
    }
  });
});
