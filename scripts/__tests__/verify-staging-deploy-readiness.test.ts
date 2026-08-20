import { describe, expect, test } from "bun:test";
import {
  evaluateStagingReadiness,
  isSuccessfulAutomaticStagingDeployment,
} from "../verify-staging-deploy-readiness";

const SHA = "a".repeat(40);
const successfulRun = {
  id: 10,
  event: "push",
  head_branch: "develop",
  head_sha: SHA,
  status: "completed",
  conclusion: "success",
  run_started_at: "2026-08-20T08:00:00Z",
  created_at: "2026-08-20T07:59:00Z",
};

function evaluate(overrides: Partial<Parameters<typeof evaluateStagingReadiness>[0]> = {}) {
  return evaluateStagingReadiness({
    targetSha: SHA,
    targetBranch: "develop",
    liveBranchSha: SHA,
    ciRuns: [{ ...successfulRun, id: 9 }],
    dockerRuns: [successfulRun],
    ...overrides,
  });
}

describe("staging deployment readiness", () => {
  test("accepts only the live SHA with an exact completed successful Docker run", () => {
    expect(evaluate()).toEqual({ kind: "ready", ciRunId: 9, dockerRunId: 10 });
  });

  test("rejects a stale candidate before considering Docker results", () => {
    expect(evaluate({ liveBranchSha: "b".repeat(40) })).toEqual({
      kind: "rejected",
      reason: "candidate is no longer the live branch tip",
    });
  });

  test("rejects a red exact CI run", () => {
    for (const conclusion of ["failure", "cancelled", "skipped", "neutral", ""]) {
      expect(evaluate({ ciRuns: [{ ...successfulRun, id: 9, conclusion }] }).kind).toBe("rejected");
    }
  });

  test("waits for missing and pending exact CI or Docker runs", () => {
    expect(evaluate({ ciRuns: [] }).kind).toBe("pending");
    expect(
      evaluate({ ciRuns: [{ ...successfulRun, id: 9, status: "in_progress", conclusion: null }] })
        .kind,
    ).toBe("pending");
    expect(evaluate({ dockerRuns: [] }).kind).toBe("pending");
    expect(
      evaluate({ dockerRuns: [{ ...successfulRun, status: "in_progress", conclusion: null }] })
        .kind,
    ).toBe("pending");
  });

  test("rejects failed, cancelled, wrong-branch, and wrong-SHA runs", () => {
    for (const conclusion of ["failure", "cancelled", "skipped", "neutral"]) {
      expect(evaluate({ dockerRuns: [{ ...successfulRun, conclusion }] }).kind).toBe("rejected");
    }
    expect(evaluate({ dockerRuns: [{ ...successfulRun, head_branch: "main" }] }).kind).toBe(
      "pending",
    );
    expect(evaluate({ dockerRuns: [{ ...successfulRun, head_sha: "b".repeat(40) }] }).kind).toBe(
      "pending",
    );
  });

  test("uses the latest retry and rejects an ambiguous latest start", () => {
    const olderFailure = {
      ...successfulRun,
      id: 9,
      conclusion: "failure",
      run_started_at: "2026-08-20T07:00:00Z",
    };
    expect(evaluate({ dockerRuns: [olderFailure, successfulRun] })).toEqual({
      kind: "ready",
      ciRunId: 9,
      dockerRunId: 10,
    });
    expect(evaluate({ dockerRuns: [successfulRun, { ...successfulRun, id: 11 }] }).kind).toBe(
      "rejected",
    );
  });

  test("reconciles either completion order and accepts a later successful retry", () => {
    const pending = { ...successfulRun, status: "in_progress", conclusion: null };
    expect(evaluate({ dockerRuns: [pending] }).kind).toBe("pending");
    expect(evaluate({ ciRuns: [{ ...pending, id: 9 }] }).kind).toBe("pending");

    const failed = { ...successfulRun, conclusion: "failure" };
    const successfulRetry = {
      ...successfulRun,
      id: 11,
      run_started_at: "2026-08-20T09:00:00Z",
    };
    expect(evaluate({ dockerRuns: [failed] }).kind).toBe("rejected");
    expect(evaluate({ dockerRuns: [failed, successfulRetry] })).toEqual({
      kind: "ready",
      ciRunId: 9,
      dockerRunId: 11,
    });
    expect(
      evaluate({
        ciRuns: [
          { ...failed, id: 9 },
          { ...successfulRetry, id: 12 },
        ],
      }),
    ).toEqual({ kind: "ready", ciRunId: 12, dockerRunId: 10 });
  });

  test("suppresses only an exact successful latest automatic staging deployment", () => {
    const deployment = {
      id: 20,
      creator: { login: "github-actions[bot]" },
      description: `Deploy ghcr.io/steward-fi/steward:sha-${SHA} to Railway staging`,
      environment: "staging",
      sha: SHA,
    };
    expect(
      isSuccessfulAutomaticStagingDeployment({
        deployment,
        latestStatus: { state: "success" },
        targetSha: SHA,
      }),
    ).toBe(true);
    for (const changed of [
      { deployment: { ...deployment, sha: "b".repeat(40) } },
      { deployment: { ...deployment, environment: "Production" } },
      { deployment: { ...deployment, creator: { login: "attacker" } } },
      { deployment: { ...deployment, description: "unrelated deployment" } },
      { latestStatus: { state: "failure" } },
    ]) {
      expect(
        isSuccessfulAutomaticStagingDeployment({
          deployment: changed.deployment ?? deployment,
          latestStatus: changed.latestStatus ?? { state: "success" },
          targetSha: SHA,
        }),
      ).toBe(false);
    }
  });
});
