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

  test("production proxy supplies STEWARD_AUDIT_HMAC_KEY (approval-expiry now extends the audit chain, fails closed without it)", () => {
    // The proxy release handler's approval-expiry paths now commit a
    // `proxy.approval.expired` event to the tamper-evident audit chain
    // (release.ts -> withTenantAuditedTransaction). getHmacKey() throws under
    // NODE_ENV=production when STEWARD_AUDIT_HMAC_KEY is unset, so an expired
    // approval polled through the proxy would 5xx and never transition. The
    // production proxy service must therefore supply the key.
    expect(/STEWARD_AUDIT_HMAC_KEY\s*:/.test(proxy)).toBe(true);
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

describe("SEC-130 no production node inventory committed in deploy artifacts", () => {
  const SCRIPTS_DIR = join(DEPLOY_DIR, "..", "scripts");

  test("deploy-all.sh carries no hardcoded node IPs and reads an operator-local inventory", () => {
    const script = readFileSync(join(SCRIPTS_DIR, "deploy-all.sh"), "utf8");
    // Pre-fix: seven production host IPs were committed in the NODES map —
    // a confirmed target list in a public repo.
    expect(script).not.toMatch(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/);
    expect(script).toContain("STEWARD_NODES");
    expect(script).toContain("deploy-nodes.local.conf");
  });

  test("DEPLOYMENT.md carries no production node IPs and documents the bridge threat", () => {
    const doc = read("DEPLOYMENT.md");
    expect(doc).not.toContain("88.99.66.168");
    expect(doc).not.toContain("178.63.251.122");
    expect(doc).not.toContain("138.201.80.125");
    expect(doc).not.toContain("85.10.193.52");
    expect(doc).not.toContain("136.243.47.243");
    expect(doc).not.toContain("195.201.57.227");
    expect(doc).not.toContain("89.167.63.246");
    // The agent→API plain-HTTP-on-the-docker-bridge topology must be
    // documented as a threat with the isolated-network path preferred.
    expect(doc).toContain("Threat note");
  });

  test("the operator-local inventory file is gitignored", () => {
    const gitignore = readFileSync(join(DEPLOY_DIR, "..", ".gitignore"), "utf8");
    expect(gitignore).toContain("deploy-nodes.local.conf");
  });
});

describe("SEC-081 enterprise backup service keeps the DSN out of container env and dumps owner-only", () => {
  const compose = readFileSync(
    join(DEPLOY_DIR, "enterprise-reference", "docker-compose.yml"),
    "utf8",
  );
  const lines = compose.split("\n");
  const start = lines.findIndex((l) => /^\s{2}backup:\s*$/.test(l));
  const body: string[] = [];
  for (let i = start + 1; i < lines.length; i += 1) {
    const l = lines[i];
    if (/^\s{2}\S/.test(l) || /^\S/.test(l)) break;
    body.push(l);
  }
  const backup = body.join("\n");

  test("backup service does not carry DATABASE_URL in container env (docker inspect)", () => {
    expect(start).toBeGreaterThanOrEqual(0);
    expect(/environment:/.test(backup)).toBe(false);
    // DSN is sourced from the mounted env file instead.
    expect(backup).toContain("/run/steward/env");
    expect(backup).toContain("./.env:/run/steward/env:ro");
  });

  test("dumps are written owner-only (umask 077)", () => {
    expect(backup).toContain("umask 077");
  });
});

describe("SEC-079 deploy/docker-compose.yml passes vault/email secrets through", () => {
  const compose = read("docker-compose.yml");

  test("steward service passes STEWARD_KDF_SALT and STEWARD_EMAIL_CODE_SECRET", () => {
    // The provisioner writes STEWARD_KDF_SALT into deploy/.env and the
    // production image's KeyStore throws without it — but the compose env
    // list used to omit both vars, so the shipped stack was degraded out of
    // the box.
    const lines = compose.split("\n");
    const start = lines.findIndex((l) => /^\s{2}steward:\s*$/.test(l));
    expect(start).toBeGreaterThanOrEqual(0);
    const body: string[] = [];
    for (let i = start + 1; i < lines.length; i += 1) {
      const l = lines[i];
      if (/^\s{2}\S/.test(l) || /^\S/.test(l)) break;
      body.push(l);
    }
    const steward = body.join("\n");
    expect(/STEWARD_KDF_SALT\s*:/.test(steward)).toBe(true);
    expect(/STEWARD_EMAIL_CODE_SECRET\s*:/.test(steward)).toBe(true);
  });
});

describe("SEC-022 DEPLOYMENT.md installs shipped hardened units, no root units or cleartext admin ops", () => {
  const doc = read("DEPLOYMENT.md");

  test("no inline systemd unit runs services as root", () => {
    // Pre-fix the doc shipped inline units with `User=root` + `Restart=always`
    // and none of the hardening in deploy/*.service.
    expect(doc).not.toContain("User=root");
    expect(doc).not.toContain("Restart=always");
  });

  test("doc installs the shipped hardened units", () => {
    expect(doc).toContain("deploy/steward.service");
    expect(doc).toContain("deploy/steward-proxy.service");
  });

  test("platform key is not interpolated into a remote ssh curl argv", () => {
    // Pre-fix Step 6: PLATFORM_KEY="<...>"; ssh ... "curl ... ${PLATFORM_KEY}"
    expect(doc).not.toContain("X-Steward-Platform-Key: ${PLATFORM_KEY}");
  });

  test("doc warns against driving admin keys over plain HTTP to node IPs", () => {
    expect(doc).toContain("cleartext");
  });
});

describe("SEC-021 deploy/docker-compose.yml redis persists enforcement counters", () => {
  const compose = read("docker-compose.yml");

  test("redis runs with AOF persistence and a bounded memory policy", () => {
    // Redis holds spend-limit / rate-limit counters. Pre-fix it ran
    // `--save "" --appendonly no` with no maxmemory: any restart silently
    // zeroed daily-spend and rate-limit counters while the proxy kept
    // serving, leaving financial policies unenforced.
    expect(compose).not.toContain('"--appendonly", "no"');
    expect(compose).toContain('"--appendonly"');
    expect(compose).toContain('"yes"');
    expect(compose).toContain('"--appendfsync"');
    expect(compose).toContain('"everysec"');
    expect(compose).toContain('"--maxmemory"');
    expect(compose).toContain('"--maxmemory-policy"');
  });

  test("redis AOF data dir is on a named volume", () => {
    expect(/steward-redis-data:\s*\/data/.test(compose)).toBe(true);
    expect(/^\s{2}steward-redis-data:\s*$/m.test(compose)).toBe(true);
  });
});

describe("SEC-020 deploy/migrate-agent-keys.sh keeps the platform key off every argv", () => {
  const script = read("migrate-agent-keys.sh");

  test("platform key is read on the remote side, never interpolated into ssh/curl argv", () => {
    // Pre-fix: the key was a positional arg interpolated into the remote curl
    // header (visible in local ps/history AND the node's process list):
    //   -H 'X-Steward-Platform-Key: ${PLATFORM_KEY}'
    expect(script).not.toContain("X-Steward-Platform-Key: ${PLATFORM_KEY}");
    // The remote shell resolves the key itself (sed on the node's 0600 .env,
    // or cat from ssh stdin for the deprecated arg path).
    expect(script).toContain("sed -n 's/^STEWARD_PLATFORM_KEY=//p'");
    expect(script).toContain("X-Steward-Platform-Key: \\${PK}");
  });

  test("agent tokens are written to a mode-0600 file, not echoed to stdout", () => {
    // Pre-fix: `echo "${NEW_ENV_VARS}"` printed per-agent STEWARD_AGENT_TOKEN
    // values to stdout (scrollback / CI logs).
    expect(script).not.toMatch(/echo\s+"\$\{NEW_ENV_VARS\}"/);
    expect(script).toContain("mktemp");
    expect(script).toContain("not printed here");
  });
});

describe("SEC-019 no deploy/provision SSH runs with host-key verification disabled", () => {
  const SCRIPTS_DIR = join(DEPLOY_DIR, "..", "scripts");
  const artifacts: Array<[string, string]> = [
    ["deploy/provision-steward-node.sh", read("provision-steward-node.sh")],
    ["deploy/migrate-agent-keys.sh", read("migrate-agent-keys.sh")],
    ["deploy/DEPLOYMENT.md", read("DEPLOYMENT.md")],
    ["scripts/deploy.sh", readFileSync(join(SCRIPTS_DIR, "deploy.sh"), "utf8")],
    ["scripts/deploy-all.sh", readFileSync(join(SCRIPTS_DIR, "deploy-all.sh"), "utf8")],
  ];

  for (const [name, content] of artifacts) {
    test(`${name} never disables SSH host-key checking`, () => {
      // Provisioning streams the full secret .env over this channel; with
      // StrictHostKeyChecking=no a first-connection MITM captures everything.
      expect(content).not.toContain("StrictHostKeyChecking=no");
    });
  }
});

describe("SEC-011 deploy/docker-compose.yml publishes no port on all interfaces", () => {
  const compose = read("docker-compose.yml");

  test("every published port is bound to 127.0.0.1", () => {
    // Collect the entries of each `ports:` list. A bare "3200:3200" binds
    // 0.0.0.0 — the API and credential proxy would be reachable on every host
    // interface over plain HTTP, bypassing the nginx TLS layer (upstreams point
    // at 127.0.0.1).
    const lines = compose.split("\n");
    const published: string[] = [];
    let inPorts = false;
    for (const line of lines) {
      if (/^\s+ports:\s*$/.test(line)) {
        inPorts = true;
        continue;
      }
      if (inPorts) {
        const m = line.match(/^\s+-\s+"?([^"\s]+)"?\s*$/);
        if (m) {
          published.push(m[1]);
        } else if (line.trim() !== "" && !line.trim().startsWith("#")) {
          inPorts = false;
        }
      }
    }
    expect(published.length).toBeGreaterThan(0);
    for (const mapping of published) {
      expect(mapping.startsWith("127.0.0.1:")).toBe(true);
    }
  });

  test("provision-steward-node.sh does not advertise plain-HTTP external access", () => {
    const script = read("provision-steward-node.sh");
    // Pre-fix: `echo "    STEWARD_API_URL=http://${NODE_IP}:3200"` told operators
    // to drive tenant keys / platform key / agent JWTs over cleartext HTTP.
    expect(/STEWARD_API_URL=http:\/\/\$\{NODE_IP\}/.test(script)).toBe(false);
    expect(/Steward URL:\s+http:\/\/\$\{NODE_IP\}/.test(script)).toBe(false);
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
    const agentConfigLine = lines.find(
      (l) => /^\s*echo\b/.test(l) && /STEWARD_PROXY_REQUEST_SIGNING_SECRETS=/.test(l),
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
      // The production proxy fails closed on audit-chain writes (approval expiry)
      // without this; the provisioner must render it into the node .env.
      "STEWARD_AUDIT_HMAC_KEY",
      "POSTGRES_PASSWORD",
    ]) {
      expect(new RegExp(`^${key}=`, "m").test(script)).toBe(true);
    }
  });
});
