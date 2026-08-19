import { afterEach, describe, expect, test } from "bun:test";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const REPOSITORY = "Steward-Fi/steward";
const TARGET_SHA = "a".repeat(40);
const workflowPath = join(import.meta.dir, "..", "..", ".github", "workflows", "wallet-e2e.yml");
const temporaryDirectories: string[] = [];

interface ReviewFixture {
  commit_id: string;
  id: number;
  state: string;
  submitted_at: string;
  user: { login: string; type: string };
}

interface Fixtures {
  branch: Record<string, unknown>;
  checkRuns: Record<string, unknown>[];
  permission: string;
  pulls: Record<string, unknown>[];
  readiness: Record<string, unknown>;
  reviews: ReviewFixture[];
  statuses: Record<string, unknown>[];
}

function authorizationScript(): string {
  const source = readFileSync(workflowPath, "utf8");
  const step = source.indexOf("      - name: Require the trusted default-branch dispatcher");
  const marker = "        run: |\n";
  const start = source.indexOf(marker, step);
  if (step < 0 || start < 0) throw new Error("wallet authorization step is missing");
  const block: string[] = [];
  for (const line of source.slice(start + marker.length).split("\n")) {
    if (line.startsWith("          ")) {
      block.push(line.slice(10));
      continue;
    }
    if (line.length === 0) {
      block.push("");
      continue;
    }
    break;
  }
  if (block.length === 0) throw new Error("wallet authorization script is empty");
  return block.join("\n");
}

function baselineFixtures(): Fixtures {
  return {
    pulls: [
      {
        base: { ref: "develop" },
        draft: false,
        head: { repo: { full_name: REPOSITORY }, sha: TARGET_SHA },
        number: 42,
        state: "open",
        user: { login: "pr-author" },
      },
    ],
    readiness: {
      headRefOid: TARGET_SHA,
      isDraft: false,
      mergeStateStatus: "CLEAN",
      reviewDecision: "APPROVED",
      state: "OPEN",
    },
    branch: {
      protection: {
        required_status_checks: {
          checks: [{ app_id: 15368, context: "Required Check" }],
          contexts: ["Required Check"],
        },
      },
    },
    checkRuns: [
      {
        app: { id: 15368 },
        completed_at: "2026-08-19T20:00:10Z",
        conclusion: "success",
        head_sha: TARGET_SHA,
        id: 100,
        name: "Required Check",
        started_at: "2026-08-19T20:00:00Z",
        status: "completed",
      },
    ],
    statuses: [],
    reviews: [
      {
        commit_id: TARGET_SHA,
        id: 200,
        state: "APPROVED",
        submitted_at: "2026-08-19T20:01:00Z",
        user: { login: "trusted-reviewer", type: "User" },
      },
    ],
    permission: "write",
  };
}

function writeJson(directory: string, name: string, value: unknown): void {
  writeFileSync(join(directory, `${name}.json`), `${JSON.stringify(value)}\n`);
}

function installMockGh(directory: string, fixtures: Fixtures): void {
  writeJson(directory, "pulls", [fixtures.pulls]);
  writeJson(directory, "readiness", fixtures.readiness);
  writeJson(directory, "branch", fixtures.branch);
  writeJson(directory, "check-runs", [{ check_runs: fixtures.checkRuns }]);
  writeJson(directory, "statuses", [fixtures.statuses]);
  writeJson(directory, "reviews", [fixtures.reviews]);
  writeJson(directory, "permission", { permission: fixtures.permission });
  const mock = `#!/usr/bin/env bash
set -euo pipefail
args="$*"
if [[ "$args" == "pr view "* ]]; then file="readiness";
elif [[ "$args" == *"/commits/"*"/pulls"* ]]; then file="pulls";
elif [[ "$args" == *"/branches/develop"* ]]; then file="branch";
elif [[ "$args" == *"/check-runs"* ]]; then file="check-runs";
elif [[ "$args" == *"/statuses"* ]]; then file="statuses";
elif [[ "$args" == *"/reviews"* ]]; then file="reviews";
elif [[ "$args" == *"/collaborators/"*"/permission"* ]]; then
  if [[ "$args" == *"--jq"* ]]; then bun -e 'console.log(JSON.parse(await Bun.file(process.env.MOCK_DIR + "/permission.json").text()).permission)'; exit 0; fi
  file="permission";
else echo "unexpected gh invocation: $args" >&2; exit 97; fi
exec bun -e 'process.stdout.write(await Bun.file(process.env.MOCK_DIR + "/" + process.argv[1] + ".json").text())' "$file"
`;
  const executable = join(directory, "gh");
  writeFileSync(executable, mock, { mode: 0o700 });
  chmodSync(executable, 0o700);
}

async function execute(fixtures: Fixtures): Promise<{ exitCode: number; output: string; stderr: string }> {
  const directory = mkdtempSync(join(tmpdir(), "steward-wallet-auth-"));
  temporaryDirectories.push(directory);
  installMockGh(directory, fixtures);
  const outputPath = join(directory, "github-output");
  writeFileSync(outputPath, "");
  const child = Bun.spawn(["bash", "-euo", "pipefail", "-c", authorizationScript()], {
    cwd: join(import.meta.dir, "..", ".."),
    env: {
      ...process.env,
      GITHUB_OUTPUT: outputPath,
      GITHUB_REF: "refs/heads/develop",
      GITHUB_REPOSITORY: REPOSITORY,
      MOCK_DIR: directory,
      PATH: `${directory}:${process.env.PATH ?? ""}`,
      TARGET_SHA,
    },
    stderr: "pipe",
    stdout: "pipe",
  });
  const [exitCode, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  return {
    exitCode,
    output: readFileSync(outputPath, "utf8"),
    stderr: `${stdout}${stderr}`,
  };
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { force: true, recursive: true });
  }
});

describe("wallet E2E target authorization", () => {
  test("accepts an exact green head with a current write-capable approval", async () => {
    const result = await execute(baselineFixtures());
    expect(result.exitCode).toBe(0);
    expect(result.output).toContain(`target_sha=${TARGET_SHA}`);
  });

  test("rejects a required check from the wrong GitHub App", async () => {
    const fixtures = baselineFixtures();
    fixtures.checkRuns[0] = { ...fixtures.checkRuns[0], app: { id: 999 } };
    const result = await execute(fixtures);
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain("every required develop check");
  });

  for (const latest of [
    { conclusion: null, status: "in_progress" },
    { conclusion: "failure", status: "completed" },
  ] as const) {
    test(`rejects an ambiguous same-second ${latest.status} required-check rerun`, async () => {
      const fixtures = baselineFixtures();
      fixtures.checkRuns.push({
        ...fixtures.checkRuns[0],
        completed_at: latest.status === "completed" ? "2026-08-19T20:00:20Z" : null,
        conclusion: latest.conclusion,
        id: 101,
        status: latest.status,
      });
      const result = await execute(fixtures);
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain("every required develop check");
    });
  }

  test("rejects a later changes-requested review", async () => {
    const fixtures = baselineFixtures();
    fixtures.reviews.push({
      commit_id: TARGET_SHA,
      id: 201,
      state: "CHANGES_REQUESTED",
      submitted_at: "2026-08-19T20:02:00Z",
      user: { login: "trusted-reviewer", type: "User" },
    });
    const result = await execute(fixtures);
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain("current approval from an independent write-capable reviewer");
  });

  test("uses the contents-readable branch endpoint", () => {
    const script = authorizationScript();
    expect(script).toContain('"repos/$GITHUB_REPOSITORY/branches/develop"');
    expect(script).not.toContain("/protection/required_status_checks");
  });
});
