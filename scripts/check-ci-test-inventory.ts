import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

const WORKFLOWS = [".github/workflows/pr.yml", ".github/workflows/ci.yml"] as const;
const NON_WORKSPACE_MATRIX_ENTRIES = ["scripts/__tests__"] as const;

// These suites need infrastructure or a non-Bun toolchain that the generic
// unit matrix does not provide. Keep the mapping explicit so an omitted suite
// cannot be disguised as a comment-only exception.
const DEDICATED_JOBS = {
  "packages/api": "integration",
  "packages/eliza-plugin": "unit-eliza-plugin",
  "packages/redis": "unit-redis",
  "packages/signer-frost": "unit-signer-frost",
} as const;

function workspacePackagePaths(rootDir: string): string[] {
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

  return [...packageJsonPaths]
    .filter((manifest) => {
      const pkg = JSON.parse(readFileSync(resolve(rootDir, manifest), "utf8")) as {
        scripts?: { test?: unknown };
      };
      return typeof pkg.scripts?.test === "string" && pkg.scripts.test.trim().length > 0;
    })
    .map((manifest) => dirname(manifest))
    .sort();
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

    const inlineRun = line.match(/^ {8}run:\s*(?![|>][-+]?\s*$)(.+)$/);
    if (inlineRun) {
      current.run = inlineRun[1].trim();
      continue;
    }

    if (/^ {8}run:\s*[|>][-+]?\s*$/.test(line)) {
      const command: string[] = [];
      while (index + 1 < lines.length && /^(?: {10,}\S|\s*$)/.test(lines[index + 1])) {
        index += 1;
        command.push(lines[index].replace(/^ {10}/, ""));
      }
      current.run = command.join("\n");
    }
  }
  finishStep();
  return steps;
}

export function jobExecutesPackageTests(job: string, packagePath: string): boolean {
  return extractRunSteps(job).some((step) => {
    if (!step.run || !/(?:^|[;&|()\s])(?:bun|cargo|flutter)(?:\s|$)[^\n]*\b(?:test|run-tests)\b/m.test(step.run)) {
      return false;
    }
    return step.workingDirectory === packagePath || step.run.includes(packagePath);
  });
}

export function assertCompleteCoverage(
  workspaceTests: string[],
  matrix: string[],
  dedicatedPaths: string[],
): void {
  const duplicates = matrix.filter((entry, index) => matrix.indexOf(entry) !== index);
  if (duplicates.length > 0) {
    throw new Error(`duplicate unit matrix entries: ${[...new Set(duplicates)].join(", ")}`);
  }

  const covered = new Set([...matrix, ...dedicatedPaths]);
  const missing = workspaceTests.filter((path) => !covered.has(path));
  const stale = [...covered].filter((path) => !workspaceTests.includes(path));
  if (missing.length > 0)
    throw new Error(`workspace test packages missing from CI: ${missing.join(", ")}`);
  if (stale.length > 0)
    throw new Error(`CI inventory contains non-test workspace packages: ${stale.join(", ")}`);
}

export function checkCiTestInventory(rootDir = resolve(import.meta.dir, "..")): void {
  const workspaceTests = workspacePackagePaths(rootDir);
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
    assertCompleteCoverage(workspaceTests, workspaceMatrix, dedicatedPaths);

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

  console.log(
    `CI test inventory covers all ${workspaceTests.length} test-bearing workspace packages`,
  );
}

if (import.meta.main) checkCiTestInventory();
