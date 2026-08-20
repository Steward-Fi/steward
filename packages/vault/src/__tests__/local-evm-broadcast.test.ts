import { describe, expect, test } from "bun:test";
import { type Hex, keccak256 } from "viem";
import { ExternalBroadcastOutcomeUnknownError } from "../external-key-custody";
import { executeLocalEvmBroadcast, type LocalEvmBroadcastLifecycle } from "../local-evm-broadcast";

const SERIALIZED =
  "0x02f86c0180843b9aca00847735940082520894aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0180c0" as Hex;
const HASH = keccak256(SERIALIZED);

function lifecycle(
  overrides: Partial<LocalEvmBroadcastLifecycle> = {},
): LocalEvmBroadcastLifecycle & { events: string[] } {
  const events: string[] = [];
  return {
    events,
    prepare: async () => {
      events.push("prepare");
      return SERIALIZED;
    },
    checkpoint: async (hash) => {
      events.push(`checkpoint:${hash}`);
    },
    broadcast: async () => {
      events.push("broadcast");
      return HASH;
    },
    reconcile: async () => {
      events.push("reconcile");
      return false;
    },
    releaseBeforeBroadcast: async () => {
      events.push("release");
    },
    finalizeAccepted: async (hash) => {
      events.push(`finalize:${hash}`);
    },
    ...overrides,
  };
}

describe("local EVM deterministic broadcast lifecycle", () => {
  test("checkpoints the deterministic hash before one broadcast and finalizes success", async () => {
    const subject = lifecycle();
    await expect(executeLocalEvmBroadcast(subject)).resolves.toBe(HASH);
    expect(subject.events).toEqual([
      "prepare",
      `checkpoint:${HASH}`,
      "broadcast",
      `finalize:${HASH}`,
    ]);
  });

  test("releases the nonce when preparation fails before the checkpoint", async () => {
    const subject = lifecycle({
      prepare: async () => {
        subject.events.push("prepare");
        throw new Error("estimate failed");
      },
    });
    await expect(executeLocalEvmBroadcast(subject)).rejects.toThrow("estimate failed");
    expect(subject.events).toEqual(["prepare", "release"]);
  });

  test("releases the nonce when the durable checkpoint fails before broadcast", async () => {
    const subject = lifecycle({
      checkpoint: async () => {
        subject.events.push("checkpoint");
        throw new Error("database unavailable");
      },
    });
    await expect(executeLocalEvmBroadcast(subject)).rejects.toThrow("database unavailable");
    expect(subject.events).toEqual(["prepare", "checkpoint", "release"]);
  });

  test("preserves pre-broadcast failures and reports release failures with redacted diagnostics", async () => {
    const originalConsoleError = console.error;
    const diagnostics: unknown[][] = [];
    console.error = (...args: unknown[]) => diagnostics.push(args);

    try {
      for (const stage of ["prepare", "checkpoint"] as const) {
        const operationError = new Error(`${stage} failed`);
        const subject = lifecycle({
          prepare: async () => {
            subject.events.push("prepare");
            if (stage === "prepare") throw operationError;
            return SERIALIZED;
          },
          checkpoint: async () => {
            subject.events.push("checkpoint");
            if (stage === "checkpoint") throw operationError;
          },
          releaseBeforeBroadcast: async () => {
            subject.events.push("release");
            throw new Error("DATABASE_URL=postgres://nonce-release-secret");
          },
        });

        expect(await executeLocalEvmBroadcast(subject).catch((error) => error)).toBe(
          operationError,
        );
        expect(subject.events).toEqual(
          stage === "prepare" ? ["prepare", "release"] : ["prepare", "checkpoint", "release"],
        );
      }
    } finally {
      console.error = originalConsoleError;
    }

    expect(diagnostics).toEqual([
      [
        "[vault] Failed to release EVM nonce after pre-broadcast failure",
        { errorClass: "Error", errorCode: null },
      ],
      [
        "[vault] Failed to release EVM nonce after pre-broadcast failure",
        { errorClass: "Error", errorCode: null },
      ],
    ]);
    expect(JSON.stringify(diagnostics)).not.toContain("nonce-release-secret");
  });

  test("preserves the operation failure when the diagnostic sink throws", async () => {
    const originalConsoleError = console.error;
    const operationError = new Error("checkpoint failed");
    console.error = () => {
      throw new Error("diagnostic sink failed");
    };

    try {
      const subject = lifecycle({
        checkpoint: async () => {
          throw operationError;
        },
        releaseBeforeBroadcast: async () => {
          throw new Error("release failed");
        },
      });

      expect(await executeLocalEvmBroadcast(subject).catch((error) => error)).toBe(operationError);
    } finally {
      console.error = originalConsoleError;
    }
  });

  test("reconciles a lost RPC response by deterministic hash without rebroadcasting", async () => {
    let broadcasts = 0;
    const subject = lifecycle({
      broadcast: async () => {
        subject.events.push("broadcast");
        broadcasts += 1;
        throw new Error("response lost");
      },
      reconcile: async (hash) => {
        subject.events.push(`reconcile:${hash}`);
        return true;
      },
    });
    await expect(executeLocalEvmBroadcast(subject)).resolves.toBe(HASH);
    expect(broadcasts).toBe(1);
    expect(subject.events).toEqual([
      "prepare",
      `checkpoint:${HASH}`,
      "broadcast",
      `reconcile:${HASH}`,
      `finalize:${HASH}`,
    ]);
  });

  test("keeps the nonce allocated and returns outcome-unknown when reconciliation fails", async () => {
    const subject = lifecycle({
      broadcast: async () => {
        subject.events.push("broadcast");
        throw new Error("timeout after submit");
      },
      reconcile: async () => {
        subject.events.push("reconcile");
        return false;
      },
    });
    const error = await executeLocalEvmBroadcast(subject).catch((cause) => cause);
    expect(error).toBeInstanceOf(ExternalBroadcastOutcomeUnknownError);
    expect((error as ExternalBroadcastOutcomeUnknownError).transactionHash).toBe(HASH);
    expect(subject.events).toEqual(["prepare", `checkpoint:${HASH}`, "broadcast", "reconcile"]);
    expect(subject.events).not.toContain("release");
  });

  test("treats mismatched RPC hashes and post-broadcast persistence failures as unknown", async () => {
    for (const failure of ["mismatch", "finalize"] as const) {
      const subject = lifecycle(
        failure === "mismatch"
          ? { broadcast: async () => `0x${"11".repeat(32)}` as Hex }
          : {
              finalizeAccepted: async () => {
                throw new Error("database unavailable");
              },
            },
      );
      const error = await executeLocalEvmBroadcast(subject).catch((cause) => cause);
      expect(error).toBeInstanceOf(ExternalBroadcastOutcomeUnknownError);
      expect((error as ExternalBroadcastOutcomeUnknownError).transactionHash).toBe(HASH);
      expect(subject.events).not.toContain("release");
    }
  });
});
