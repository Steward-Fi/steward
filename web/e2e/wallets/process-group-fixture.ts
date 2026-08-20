import { existsSync, writeFileSync } from "node:fs";
import { runProcessGroup } from "./process-group";

const [role, ...args] = process.argv.slice(2);

if (role === "descendant") {
  const [pidFile, termFile] = args;
  process.on("SIGTERM", () => writeFileSync(termFile, "term"));
  writeFileSync(pidFile, String(process.pid));
  await new Promise(() => {});
} else if (role === "child") {
  const [mode, childPidFile, childTermFile, descendantPidFile, descendantTermFile] = args;
  process.on("SIGTERM", () => writeFileSync(childTermFile, "term"));
  const descendant = Bun.spawn(
    [process.execPath, import.meta.path, "descendant", descendantPidFile, descendantTermFile],
    { stderr: "ignore", stdout: "ignore" },
  );
  writeFileSync(childPidFile, String(process.pid));
  if (mode === "linger") {
    await new Promise(() => {});
  }
  while (!existsSync(descendantPidFile)) await Bun.sleep(10);
  descendant.unref();
} else if (role === "harness") {
  const [cwd, mode, graceMs, childPidFile, childTermFile, descendantPidFile, descendantTermFile] =
    args;
  process.exitCode = await runProcessGroup(
    [
      process.execPath,
      import.meta.path,
      "child",
      mode,
      childPidFile,
      childTermFile,
      descendantPidFile,
      descendantTermFile,
    ],
    { cwd, stdin: "inherit", stdout: "inherit", stderr: "inherit" },
    Number(graceMs),
  );
} else {
  throw new Error("Unknown process-group fixture role");
}
