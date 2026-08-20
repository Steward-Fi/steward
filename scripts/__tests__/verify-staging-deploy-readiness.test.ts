import { describe, expect, test } from "bun:test";
import { evaluateStagingReadiness } from "../verify-staging-deploy-readiness";

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
    ciConclusion: "success",
    liveBranchSha: SHA,
    dockerRuns: [successfulRun],
    ...overrides,
  });
}

describe("staging deployment readiness", () => {
  test("accepts only the live SHA with an exact completed successful Docker run", () => {
    expect(evaluate()).toEqual({ kind: "ready", runId: 10 });
  });

  test("rejects a stale candidate before considering Docker results", () => {
    expect(evaluate({ liveBranchSha: "b".repeat(40) })).toEqual({
      kind: "rejected",
      reason: "candidate is no longer the live branch tip",
    });
  });

  test("rejects a red or incomplete CI conclusion", () => {
    for (const conclusion of ["failure", "cancelled", "skipped", "neutral", ""]) {
      expect(evaluate({ ciConclusion: conclusion }).kind).toBe("rejected");
    }
  });

  test("waits for missing and pending exact Docker runs", () => {
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
      runId: 10,
    });
    expect(evaluate({ dockerRuns: [successfulRun, { ...successfulRun, id: 11 }] }).kind).toBe(
      "rejected",
    );
  });
});
