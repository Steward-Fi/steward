import { existsSync, writeFileSync } from "node:fs";
import { WALLET_E2E_CREDENTIAL_NAMES } from "./credentials";
import { runProcessGroup } from "./process-group";

const [role, ...args] = Bun.argv.slice(2);

if (role === "wallet-environment") {
  console.log(JSON.stringify(WALLET_E2E_CREDENTIAL_NAMES.map((name) => process.env[name] ?? null)));
  process.exit(0);
}

const [mode, cwd, childPidFile, descendantPidFile, childTermFile, descendantTermFile] = args;

if (
  !role ||
  !mode ||
  !cwd ||
  !childPidFile ||
  !descendantPidFile ||
  !childTermFile ||
  !descendantTermFile
) {
  throw new Error("Missing process-group fixture arguments");
}

const command = (nextRole: "child" | "descendant") => [
  process.execPath,
  import.meta.path,
  nextRole,
  mode,
  cwd,
  childPidFile,
  descendantPidFile,
  childTermFile,
  descendantTermFile,
];

if (role === "harness") {
  process.exitCode = await runProcessGroup(
    command("child"),
    {
      cwd,
      stdin: "inherit",
      stdout: "inherit",
      stderr: "inherit",
    },
    200,
  );
} else if (role === "child") {
  if (mode === "term-tree") {
    process.on("SIGTERM", () => writeFileSync(childTermFile, "term"));
  }
  const descendant = Bun.spawn(command("descendant"), { stdout: "ignore", stderr: "ignore" });
  if (mode === "clean-tree") descendant.unref();
  writeFileSync(childPidFile, String(process.pid));
  while (!existsSync(descendantPidFile)) await Bun.sleep(10);
  if (mode === "term-tree") await new Promise(() => {});
} else if (role === "descendant") {
  process.on("SIGTERM", () => writeFileSync(descendantTermFile, "term"));
  writeFileSync(descendantPidFile, String(process.pid));
  await new Promise(() => {});
} else {
  throw new Error("Unknown process-group fixture role");
}
