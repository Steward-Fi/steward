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

export type StagingReadiness =
  | { kind: "ready"; runId: number }
  | { kind: "pending"; reason: string }
  | { kind: "rejected"; reason: string };

export function evaluateStagingReadiness(input: {
  targetSha: string;
  targetBranch: string;
  ciConclusion: string;
  liveBranchSha: string;
  dockerRuns: WorkflowRun[];
}): StagingReadiness {
  if (input.ciConclusion !== "success") {
    return { kind: "rejected", reason: `exact CI concluded ${input.ciConclusion}` };
  }
  if (input.liveBranchSha !== input.targetSha) {
    return { kind: "rejected", reason: "candidate is no longer the live branch tip" };
  }
  const matches = input.dockerRuns.filter(
    (run) =>
      run.event === "push" &&
      run.head_branch === input.targetBranch &&
      run.head_sha === input.targetSha,
  );
  if (matches.length === 0) {
    return { kind: "pending", reason: "exact Docker run has not appeared" };
  }
  const timestamps = matches.map((run) => run.run_started_at ?? run.created_at);
  const latestTimestamp = timestamps.sort().at(-1);
  const latest = matches.filter(
    (run) => (run.run_started_at ?? run.created_at) === latestTimestamp,
  );
  if (latest.length !== 1) {
    return { kind: "rejected", reason: "exact Docker retry ordering is ambiguous" };
  }
  const run = latest[0];
  if (run.status !== "completed") {
    return { kind: "pending", reason: "exact Docker run is not complete" };
  }
  if (run.conclusion !== "success") {
    return {
      kind: "rejected",
      reason: `exact Docker run concluded ${run.conclusion ?? "unknown"}`,
    };
  }
  return { kind: "ready", runId: run.id };
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

async function main(): Promise<void> {
  const token = workflowEnvironmentValue("GH_TOKEN");
  const repository = workflowEnvironmentValue("TARGET_REPOSITORY");
  const targetSha = workflowEnvironmentValue("TARGET_SHA");
  const targetBranch = workflowEnvironmentValue("TARGET_BRANCH");
  const ciConclusion = workflowEnvironmentValue("TARGET_CI_CONCLUSION");
  if (!token || !repository || !targetSha || !targetBranch || !ciConclusion) {
    throw new Error("staging readiness environment is incomplete");
  }

  for (let attempt = 0; attempt < 40; attempt++) {
    const branch = (await githubJson(
      `/repos/${repository}/git/ref/heads/${encodeURIComponent(targetBranch)}`,
      token,
    )) as { object?: { sha?: string } };
    const runs = (await githubJson(
      `/repos/${repository}/actions/workflows/docker.yml/runs?branch=${encodeURIComponent(targetBranch)}&event=push&per_page=100`,
      token,
    )) as { workflow_runs?: WorkflowRun[] };
    const result = evaluateStagingReadiness({
      targetSha,
      targetBranch,
      ciConclusion,
      liveBranchSha: branch.object?.sha ?? "",
      dockerRuns: runs.workflow_runs ?? [],
    });
    if (result.kind === "ready") {
      console.log(`Exact Docker run ${result.runId} is complete and successful.`);
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
