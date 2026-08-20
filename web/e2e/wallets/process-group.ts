type Child = ReturnType<typeof Bun.spawn>;

interface ProcessGroupOptions {
  cwd: string;
  env?: NodeJS.ProcessEnv;
  stdin: "inherit";
  stdout: "inherit";
  stderr: "inherit";
}

function signalProcessGroup(child: Child, signal: "SIGTERM" | "SIGKILL"): void {
  if (!Number.isSafeInteger(child.pid) || child.pid <= 1) return;
  try {
    process.kill(-child.pid, signal);
  } catch {
    try {
      child.kill(signal);
    } catch {}
  }
}

function processGroupIsAlive(child: Child): boolean {
  if (!Number.isSafeInteger(child.pid) || child.pid <= 1) return false;
  try {
    process.kill(-child.pid, 0);
    return true;
  } catch {
    return child.exitCode === null;
  }
}

async function terminateProcessGroup(child: Child, killGraceMs: number): Promise<void> {
  if (!processGroupIsAlive(child)) {
    await child.exited;
    return;
  }
  signalProcessGroup(child, "SIGTERM");
  await Bun.sleep(killGraceMs);
  if (processGroupIsAlive(child)) signalProcessGroup(child, "SIGKILL");
  await child.exited;
}

/** Run Playwright as an owned process group and leave no browser descendants behind. */
export async function runProcessGroup(
  command: string[],
  options: ProcessGroupOptions,
  killGraceMs = Number(process.env.WALLET_E2E_KILL_GRACE_MS ?? "2000"),
): Promise<number> {
  if (!Number.isFinite(killGraceMs) || killGraceMs <= 0) {
    throw new Error("Wallet E2E kill grace must be a positive number");
  }

  const child = Bun.spawn(command, { ...options, detached: true });
  let interrupted: "SIGINT" | "SIGTERM" | undefined;
  let termination: Promise<void> | undefined;
  const terminate = () => (termination ??= terminateProcessGroup(child, killGraceMs));
  const handlers = {
    SIGINT: () => {
      interrupted ??= "SIGINT";
      void terminate();
    },
    SIGTERM: () => {
      interrupted ??= "SIGTERM";
      void terminate();
    },
  } as const;

  process.on("SIGINT", handlers.SIGINT);
  process.on("SIGTERM", handlers.SIGTERM);
  try {
    const exitCode = await child.exited;
    await terminate();
    return interrupted === "SIGINT" ? 130 : interrupted === "SIGTERM" ? 143 : exitCode;
  } finally {
    process.off("SIGINT", handlers.SIGINT);
    process.off("SIGTERM", handlers.SIGTERM);
    if (child.exitCode === null) await terminate();
  }
}
