import { appendFileSync } from "node:fs";

interface WorkflowRun {
  id: number;
  event: string;
  head_branch: string | null;
  head_sha: string;
  status: string;
  conclusion: string | null;
  run_started_at: string | null;
  created_at: string;
}

interface Deployment {
  id: number;
  creator?: { login?: string } | null;
  description?: string | null;
  environment?: string | null;
  sha?: string | null;
}

interface DeploymentStatus {
  state?: string | null;
}

export type StagingReadiness =
  | { kind: "ready"; ciRunId: number; dockerRunId: number }
  | { kind: "pending"; reason: string }
  | { kind: "rejected"; reason: string };

function evaluateWorkflowRuns(input: {
  workflowName: string;
  targetSha: string;
  targetBranch: string;
  runs: WorkflowRun[];
}): StagingReadiness | { kind: "workflow-ready"; runId: number } {
  const matches = input.runs.filter(
    (run) =>
      run.event === "push" &&
      run.head_branch === input.targetBranch &&
      run.head_sha === input.targetSha,
  );
  if (matches.length === 0) {
    return { kind: "pending", reason: `exact ${input.workflowName} run has not appeared` };
  }
  const timestamps = matches.map((run) => run.run_started_at ?? run.created_at);
  const latestTimestamp = timestamps.sort().at(-1);
  const latest = matches.filter(
    (run) => (run.run_started_at ?? run.created_at) === latestTimestamp,
  );
  if (latest.length !== 1) {
    return {
      kind: "rejected",
      reason: `exact ${input.workflowName} retry ordering is ambiguous`,
    };
  }
  const run = latest[0];
  if (run.status !== "completed") {
    return { kind: "pending", reason: `exact ${input.workflowName} run is not complete` };
  }
  if (run.conclusion !== "success") {
    return {
      kind: "rejected",
      reason: `exact ${input.workflowName} run concluded ${run.conclusion ?? "unknown"}`,
    };
  }
  return { kind: "workflow-ready", runId: run.id };
}

export function evaluateStagingReadiness(input: {
  targetSha: string;
  targetBranch: string;
  liveBranchSha: string;
  ciRuns: WorkflowRun[];
  dockerRuns: WorkflowRun[];
}): StagingReadiness {
  if (input.liveBranchSha !== input.targetSha) {
    return { kind: "rejected", reason: "candidate is no longer the live branch tip" };
  }
  const ci = evaluateWorkflowRuns({
    workflowName: "CI",
    targetSha: input.targetSha,
    targetBranch: input.targetBranch,
    runs: input.ciRuns,
  });
  if (ci.kind !== "workflow-ready") return ci;
  const docker = evaluateWorkflowRuns({
    workflowName: "Docker",
    targetSha: input.targetSha,
    targetBranch: input.targetBranch,
    runs: input.dockerRuns,
  });
  if (docker.kind !== "workflow-ready") return docker;
  return { kind: "ready", ciRunId: ci.runId, dockerRunId: docker.runId };
}

async function githubJson(path: string, token: string): Promise<unknown> {
  const response = await fetch(`https://api.github.com${path}`, {
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      "X-GitHub-Api-Version": "2022-11-28",
    },
    signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok) throw new Error(`GitHub API ${path} returned ${response.status}`);
  return response.json();
}

function workflowEnvironmentValue(name: string): string | undefined {
  return process.env[name];
}

export function isSuccessfulAutomaticStagingDeployment(input: {
  deployment: Deployment;
  latestStatus: DeploymentStatus | undefined;
  targetSha: string;
}): boolean {
  return (
    input.deployment.sha === input.targetSha &&
    input.deployment.environment === "staging" &&
    input.deployment.creator?.login === "github-actions[bot]" &&
    input.deployment.description ===
      `Deploy ghcr.io/steward-fi/steward:sha-${input.targetSha} to Railway staging` &&
    input.latestStatus?.state === "success"
  );
}

function writeDeployOutput(deploy: boolean): void {
  const outputPath = workflowEnvironmentValue("GITHUB_OUTPUT");
  if (!outputPath) throw new Error("GITHUB_OUTPUT is unavailable");
  appendFileSync(outputPath, `deploy=${deploy ? "true" : "false"}\n`, { encoding: "utf8" });
}

async function main(): Promise<void> {
  const token = workflowEnvironmentValue("GH_TOKEN");
  const repository = workflowEnvironmentValue("TARGET_REPOSITORY");
  const targetSha = workflowEnvironmentValue("TARGET_SHA");
  const targetBranch = workflowEnvironmentValue("TARGET_BRANCH");
  if (!token || !repository || !targetSha || !targetBranch) {
    throw new Error("staging readiness environment is incomplete");
  }

  for (let attempt = 0; attempt < 40; attempt++) {
    const branch = (await githubJson(
      `/repos/${repository}/git/ref/heads/${encodeURIComponent(targetBranch)}`,
      token,
    )) as { object?: { sha?: string } };
    const [ciRuns, dockerRuns] = (await Promise.all([
      githubJson(
        `/repos/${repository}/actions/workflows/ci.yml/runs?branch=${encodeURIComponent(targetBranch)}&event=push&per_page=100`,
        token,
      ),
      githubJson(
        `/repos/${repository}/actions/workflows/docker.yml/runs?branch=${encodeURIComponent(targetBranch)}&event=push&per_page=100`,
        token,
      ),
    ])) as [{ workflow_runs?: WorkflowRun[] }, { workflow_runs?: WorkflowRun[] }];
    const result = evaluateStagingReadiness({
      targetSha,
      targetBranch,
      liveBranchSha: branch.object?.sha ?? "",
      ciRuns: ciRuns.workflow_runs ?? [],
      dockerRuns: dockerRuns.workflow_runs ?? [],
    });
    if (result.kind === "ready") {
      console.log(
        `Exact CI run ${result.ciRunId} and Docker run ${result.dockerRunId} are complete and successful.`,
      );
      const deployments = (await githubJson(
        `/repos/${repository}/deployments?environment=staging&per_page=1`,
        token,
      )) as Deployment[];
      const deployment = deployments[0];
      if (deployment) {
        const statuses = (await githubJson(
          `/repos/${repository}/deployments/${deployment.id}/statuses?per_page=1`,
          token,
        )) as DeploymentStatus[];
        if (
          isSuccessfulAutomaticStagingDeployment({
            deployment,
            latestStatus: statuses[0],
            targetSha,
          })
        ) {
          console.log(`Exact SHA ${targetSha} already has a successful staging deployment.`);
          writeDeployOutput(false);
          return;
        }
      }
      writeDeployOutput(true);
      return;
    }
    if (result.kind === "rejected") throw new Error(result.reason);
    if (attempt === 39) throw new Error(`Timed out: ${result.reason}`);
    await Bun.sleep(15_000);
  }
}

if (import.meta.main) {
  main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : "staging readiness failed");
    process.exit(1);
  });
}
