import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

const WORKFLOWS = [".github/workflows/pr.yml", ".github/workflows/ci.yml"] as const;
const NON_WORKSPACE_MATRIX_ENTRIES = ["scripts/__tests__"] as const;
const WALLET_CONTRACT = "web/e2e/wallets/wallet-e2e-contract.test.ts";
const WALLET_CONTRACT_COMMAND = "bun test --isolate src e2e/wallets/wallet-e2e-contract.test.ts";
const CHROMIUM_INSTALL_COMMAND = "bun run playwright install --with-deps chromium";
const CHROMIUM_LAUNCH_ASSERTION =
  "bun -e 'import { chromium } from \"@playwright/test\"; const browser = await chromium.launch(); await browser.close();'";
const WALLET_SPECS = [
  "web/e2e/wallets/metamask-siwe.spec.ts",
  "web/e2e/wallets/phantom-siws.spec.ts",
] as const;
const PACKAGE_TEST_FILE_PATTERNS = [
  "src/**/*.test.ts",
  "src/**/*.spec.ts",
  "src/**/*.test.tsx",
  "src/**/*.spec.tsx",
] as const;
const CROSS_LANGUAGE_TEST_FILE_PATTERNS = [
  "**/*_test.go",
  "src/test/**/*.{java,kt,kts,scala}",
  "tests/**/*.{c,cc,cpp,cs,fs,fsx,go,py,rs,swift}",
  "test/**/*_test.{dart,go,rb}",
  "Tests/**/*.{cs,fs,fsx,swift}",
] as const;

// These suites need infrastructure or a non-Bun toolchain that the generic
// unit matrix does not provide. Keep the mapping explicit so an omitted suite
// cannot be disguised as a comment-only exception.
const DEDICATED_JOBS = {
  "packages/agent-trader": "unit-agent-trader",
  "packages/android": "unit-android",
  "packages/api": "integration",
  "packages/csharp": "unit-csharp",
  "packages/eliza-plugin": "unit-eliza-plugin",
  "packages/flutter": "unit-flutter",
  "packages/go": "unit-go",
  "packages/java": "unit-java",
  "packages/python": "unit-python",
  "packages/redis": "unit-redis",
  "packages/ruby": "unit-ruby",
  "packages/rust": "unit-rust",
  "packages/signer-frost": "unit-signer-frost",
  "packages/swift": "unit-swift",
  web: "unit-web",
} as const;

function hasMatchingFiles(
  rootDir: string,
  directory: string,
  patterns: readonly string[],
): boolean {
  return patterns.some(
    (pattern) =>
      new Bun.Glob(pattern).scanSync({ cwd: resolve(rootDir, directory) }).next().value !==
      undefined,
  );
}

export function repositoryTestTargets(rootDir: string): string[] {
  const rootPackage = JSON.parse(readFileSync(resolve(rootDir, "package.json"), "utf8")) as {
    workspaces?: string[];
  };
  if (!Array.isArray(rootPackage.workspaces)) {
    throw new Error("root package.json must declare a workspaces array");
  }

  const packageJsonPaths = new Set<string>();
  for (const workspace of rootPackage.workspaces) {
    const manifestPattern = workspace.endsWith("package.json")
      ? workspace
      : `${workspace}/package.json`;
    for (const manifest of new Bun.Glob(manifestPattern).scanSync({ cwd: rootDir })) {
      packageJsonPaths.add(manifest);
    }
  }

  const targets = [...packageJsonPaths]
    .map((manifest) => dirname(manifest))
    .filter((directory) => hasMatchingFiles(rootDir, directory, PACKAGE_TEST_FILE_PATTERNS));

  // Native SDKs do not necessarily have package.json manifests and therefore
  // cannot be discovered through the JavaScript workspace list. Scan every
  // immediate packages/* directory for conventional cross-language test
  // layouts so a newly added SDK fails closed until CI gives it a real job.
  const packagesDir = resolve(rootDir, "packages");
  for (const entry of readdirSync(packagesDir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const directory = `packages/${entry.name}`;
    if (hasMatchingFiles(rootDir, directory, CROSS_LANGUAGE_TEST_FILE_PATTERNS)) {
      targets.push(directory);
    }
  }

  return [...new Set(targets)].sort();
}

export function extractUnitMatrix(workflow: string): string[] {
  const lines = workflow.split(/\r?\n/);
  const unitStart = lines.indexOf("  unit:");
  if (unitStart < 0) throw new Error("workflow is missing the unit job");
  const unitEnd = lines.findIndex((line, index) => index > unitStart && /^ {2}[\w-]+:$/.test(line));
  const unitLines = lines.slice(unitStart, unitEnd < 0 ? undefined : unitEnd);
  const packageStart = unitLines.indexOf("        package:");
  if (packageStart < 0) throw new Error("unit job is missing strategy.matrix.package");

  const packages: string[] = [];
  for (const line of unitLines.slice(packageStart + 1)) {
    const match = line.match(/^ {10}- (\S+)$/);
    if (match) {
      packages.push(match[1]);
      continue;
    }
    if (/^ {8}\S/.test(line)) break;
  }
  return packages;
}

export function extractJob(workflow: string, jobName: string): string {
  const lines = workflow.split(/\r?\n/);
  const start = lines.indexOf(`  ${jobName}:`);
  if (start < 0) throw new Error(`workflow is missing dedicated job ${jobName}`);
  const end = lines.findIndex((line, index) => index > start && /^ {2}[\w-]+:$/.test(line));
  return lines.slice(start, end < 0 ? undefined : end).join("\n");
}

interface WorkflowStep {
  workingDirectory?: string;
  run?: string;
  inlineRun?: boolean;
}

function extractRunSteps(job: string): WorkflowStep[] {
  const lines = job.split(/\r?\n/);
  const steps: WorkflowStep[] = [];
  let current: WorkflowStep | undefined;

  const finishStep = () => {
    if (current) steps.push(current);
    current = undefined;
  };

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (/^ {6}- /.test(line)) {
      finishStep();
      current = {};
      continue;
    }
    if (!current) continue;

    const workingDirectory = line.match(/^ {8}working-directory:\s*["']?([^"'\s]+)["']?\s*$/);
    if (workingDirectory) {
      current.workingDirectory = workingDirectory[1];
      continue;
    }

    if (/^ {8}run:\s*[|>][-+]?\s*$/.test(line)) {
      const command: string[] = [];
      while (index + 1 < lines.length && /^(?: {10,}\S|\s*$)/.test(lines[index + 1])) {
        index += 1;
        command.push(lines[index].replace(/^ {10}/, ""));
      }
      current.run = command.join("\n");
      current.inlineRun = false;
      continue;
    }

    const inlineRun = line.match(/^ {8}run:\s*(.+)$/);
    if (inlineRun) {
      current.run = inlineRun[1].trim();
      current.inlineRun = true;
    }
  }
  finishStep();
  return steps;
}

export function jobExecutesPackageTests(job: string, packagePath: string): boolean {
  return extractRunSteps(job).some((step) => {
    // Only an inline scalar can be checked as one shell command without a
    // shell parser. Literal/folded blocks can hide apparent runner lines in a
    // heredoc, continuation, or folded argument, so fail closed for inventory
    // evidence. Dedicated jobs intentionally keep their runner command inline.
    if (!step.run || !step.inlineRun) {
      return false;
    }
    return step.run
      .split(/\r?\n/)
      .map((line) => line.trim())
      .some((line) => {
        const executableLine = stripUnquotedShellComment(line).trimEnd();
        const shellSyntax = executableLine
          .replace(/'(?:[^']*)'/g, "")
          .replace(/"(?:\\.|[^"\\])*"/g, "");
        // A command that masks its own failure or explicitly disables tests is
        // not CI evidence even if its spelling otherwise resembles a runner.
        if (
          /[;&|`]|\$\(|--no-run\b|-DskipTests\b|-Dmaven\.test\.skip(?:=true)?\b/.test(shellSyntax)
        ) {
          return false;
        }
        if (!isExecutableTestCommand(executableLine)) return false;
        // Bind the package reference to the same executable line. Merely
        // echoing a package name elsewhere in a multiline step cannot make an
        // unrelated test command satisfy this target.
        return step.workingDirectory === packagePath || executableLine.includes(packagePath);
      });
  });
}

function stripUnquotedShellComment(line: string): string {
  let quote: '"' | "'" | undefined;
  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    if (quote === '"' && char === "\\") {
      index += 1;
      continue;
    }
    if (char === '"' || char === "'") {
      quote = quote === char ? undefined : quote === undefined ? char : quote;
      continue;
    }
    if (
      char === "#" &&
      quote === undefined &&
      (index === 0 || isShellWhitespace(line[index - 1]))
    ) {
      return line.slice(0, index);
    }
  }
  return line;
}

function isShellWhitespace(char: string | undefined): boolean {
  return char !== undefined && char.trim().length === 0;
}

function skipEnvironmentAssignments(line: string, initial: number): number {
  let cursor = initial;
  while (cursor < line.length) {
    const assignmentStart = cursor;
    const first = line.charCodeAt(cursor);
    if (!((first >= 0x41 && first <= 0x5a) || (first >= 0x61 && first <= 0x7a) || first === 0x5f))
      break;
    cursor += 1;
    while (cursor < line.length) {
      const code = line.charCodeAt(cursor);
      if (
        (code >= 0x41 && code <= 0x5a) ||
        (code >= 0x61 && code <= 0x7a) ||
        (code >= 0x30 && code <= 0x39) ||
        code === 0x5f
      ) {
        cursor += 1;
      } else {
        break;
      }
    }
    if (line[cursor] !== "=") return assignmentStart;
    cursor += 1;
    const quote = line[cursor] === '"' || line[cursor] === "'" ? line[cursor] : undefined;
    if (quote) {
      cursor += 1;
      while (cursor < line.length && line[cursor] !== quote) cursor += 1;
      if (line[cursor] !== quote) return assignmentStart;
      cursor += 1;
    } else {
      const valueStart = cursor;
      while (cursor < line.length && !isShellWhitespace(line[cursor])) cursor += 1;
      if (cursor === valueStart) return assignmentStart;
    }
    if (!isShellWhitespace(line[cursor])) return assignmentStart;
    while (isShellWhitespace(line[cursor])) cursor += 1;
  }
  return cursor;
}

function isWordCode(code: number): boolean {
  return (
    (code >= 0x30 && code <= 0x39) ||
    (code >= 0x41 && code <= 0x5a) ||
    (code >= 0x61 && code <= 0x7a) ||
    code === 0x5f
  );
}

function startsWithWord(value: string, word: string): boolean {
  return (
    value.startsWith(word) &&
    (value.length === word.length || !isWordCode(value.charCodeAt(word.length)))
  );
}

function containsBoundedWord(value: string, word: string): boolean {
  let index = value.indexOf(word);
  while (index !== -1) {
    const before = index === 0 ? -1 : value.charCodeAt(index - 1);
    const afterIndex = index + word.length;
    const after = afterIndex === value.length ? -1 : value.charCodeAt(afterIndex);
    if ((before === -1 || !isWordCode(before)) && (after === -1 || !isWordCode(after))) return true;
    index = value.indexOf(word, index + 1);
  }
  return false;
}

function isExecutableTestCommand(line: string): boolean {
  let cursor = 0;
  if (line[cursor] === "(") cursor += 1;
  while (isShellWhitespace(line[cursor])) cursor += 1;
  cursor = skipEnvironmentAssignments(line, cursor);
  const command = line.slice(cursor);

  for (const runner of ["bun", "cargo", "flutter", "go", "mvn", "swift"]) {
    if (startsWithWord(command, runner)) {
      return containsBoundedWord(command, "test") || containsBoundedWord(command, "run-tests");
    }
  }
  if (startsWithWord(command, "dotnet")) {
    const remainder = command.slice("dotnet".length).trimStart();
    return startsWithWord(remainder, "run");
  }
  if (startsWithWord(command, "python") || startsWithWord(command, "python3")) {
    const tokens = command.split(/\s+/);
    return tokens[1] === "-m" && tokens[2] === "unittest";
  }
  if (startsWithWord(command, "ruby")) {
    const testPath = command.indexOf("test/");
    if (testPath === -1) return false;
    if (testPath > 0 && isWordCode(command.charCodeAt(testPath - 1))) return false;
    const tokenEnd = command.indexOf(" ", testPath);
    const pathToken = command.slice(testPath, tokenEnd === -1 ? undefined : tokenEnd);
    const suffix = pathToken.indexOf("_test.rb");
    if (suffix === -1) return false;
    const afterSuffix = suffix + "_test.rb".length;
    return afterSuffix === pathToken.length || !isWordCode(pathToken.charCodeAt(afterSuffix));
  }
  return false;
}

export function assertCompleteCoverage(
  testTargets: string[],
  matrix: string[],
  dedicatedPaths: string[],
): void {
  const declaredTargets = [...matrix, ...dedicatedPaths];
  const duplicates = declaredTargets.filter(
    (entry, index) => declaredTargets.indexOf(entry) !== index,
  );
  if (duplicates.length > 0) {
    throw new Error(`duplicate CI test inventory entries: ${[...new Set(duplicates)].join(", ")}`);
  }

  const covered = new Set(declaredTargets);
  const missing = testTargets.filter((path) => !covered.has(path));
  const stale = [...covered].filter((path) => !testTargets.includes(path));
  if (missing.length > 0)
    throw new Error(`test-bearing targets missing from CI: ${missing.join(", ")}`);
  if (stale.length > 0)
    throw new Error(`CI inventory contains non-test targets: ${stale.join(", ")}`);
}

export function assertWalletE2EInventory(rootDir: string): void {
  for (const path of [WALLET_CONTRACT, ...WALLET_SPECS]) {
    if (!existsSync(resolve(rootDir, path)))
      throw new Error(`wallet E2E inventory is missing ${path}`);
  }
  for (const workflowPath of WORKFLOWS) {
    const workflow = readFileSync(resolve(rootDir, workflowPath), "utf8");
    if (!workflow.includes(WALLET_CONTRACT_COMMAND)) {
      throw new Error(
        `${workflowPath} does not explicitly execute the isolated wallet E2E contract`,
      );
    }
    if (workflow.includes("bunx playwright")) {
      throw new Error(`${workflowPath} uses an unpinned Playwright CLI`);
    }
    if (!workflow.includes(`working-directory: web\n        run: ${CHROMIUM_INSTALL_COMMAND}`)) {
      throw new Error(`${workflowPath} does not install Chromium through the web workspace CLI`);
    }
    if (!workflow.includes(`working-directory: web\n        run: ${CHROMIUM_LAUNCH_ASSERTION}`)) {
      throw new Error(`${workflowPath} does not verify the workspace Chromium launch`);
    }
  }

  const walletWorkflowPath = ".github/workflows/wallet-e2e.yml";
  const walletWorkflow = readFileSync(resolve(rootDir, walletWorkflowPath), "utf8");
  for (const command of [
    "bun test e2e/wallets/wallet-e2e-contract.test.ts",
    "bun run test:e2e:wallets:list",
    "bun run test:e2e:wallets",
  ]) {
    if (!walletWorkflow.includes(command)) {
      throw new Error(`${walletWorkflowPath} does not explicitly execute ${command}`);
    }
  }
}

export function checkCiTestInventory(rootDir = resolve(import.meta.dir, "..")): void {
  assertWalletE2EInventory(rootDir);
  const testTargets = repositoryTestTargets(rootDir);
  const dedicatedPaths = Object.keys(DEDICATED_JOBS);
  let canonicalMatrix: string[] | undefined;

  for (const workflowPath of WORKFLOWS) {
    const workflow = readFileSync(resolve(rootDir, workflowPath), "utf8");
    const matrix = extractUnitMatrix(workflow);
    const workspaceMatrix = matrix.filter(
      (entry) =>
        !NON_WORKSPACE_MATRIX_ENTRIES.includes(
          entry as (typeof NON_WORKSPACE_MATRIX_ENTRIES)[number],
        ),
    );
    assertCompleteCoverage(testTargets, workspaceMatrix, dedicatedPaths);

    for (const nonWorkspaceEntry of NON_WORKSPACE_MATRIX_ENTRIES) {
      if (!matrix.includes(nonWorkspaceEntry)) {
        throw new Error(`${workflowPath} unit matrix is missing ${nonWorkspaceEntry}`);
      }
    }

    for (const [packagePath, jobName] of Object.entries(DEDICATED_JOBS)) {
      const job = extractJob(workflow, jobName);
      if (!jobExecutesPackageTests(job, packagePath)) {
        throw new Error(
          `${workflowPath} job ${jobName} does not visibly execute the ${packagePath} test suite`,
        );
      }
    }

    if (canonicalMatrix && JSON.stringify(matrix) !== JSON.stringify(canonicalMatrix)) {
      throw new Error(`${workflowPath} unit matrix diverges from ${WORKFLOWS[0]}`);
    }
    canonicalMatrix = matrix;
  }

  console.log(`CI test inventory covers all ${testTargets.length} test-bearing targets`);
}

if (import.meta.main) checkCiTestInventory();
