import { randomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";

const GENERATED_PASSWORD_RE = /^[0-9a-f]{64}$/;

function readPasswordFile(path: string): string {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile()) throw new Error("embedded master password path must be a regular file");
    if ((stat.mode & 0o077) !== 0) {
      throw new Error("embedded master password file permissions must be 0600 or stricter");
    }
    if (typeof process.getuid === "function" && stat.uid !== process.getuid()) {
      throw new Error("embedded master password file must be owned by the current user");
    }
    const value = readFileSync(fd, "utf8").trim();
    if (!GENERATED_PASSWORD_RE.test(value)) {
      throw new Error("embedded master password file is malformed");
    }
    return value;
  } finally {
    closeSync(fd);
  }
}

export function loadOrCreateEmbeddedMasterPassword(dataDir: string): string {
  mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  const dirStat = lstatSync(dataDir);
  if (dirStat.isSymbolicLink() || !dirStat.isDirectory()) {
    throw new Error("embedded data directory must be a real directory, not a symbolic link");
  }
  chmodSync(dataDir, 0o700);
  const path = join(dataDir, ".master-password");
  try {
    return readPasswordFile(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }

  const generated = randomBytes(32).toString("hex");
  let fd: number;
  try {
    fd = openSync(
      path,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
    );
  } catch (error) {
    // Another embedded process may have won the exclusive create race. Read
    // the winner through the same no-follow and permission checks.
    if ((error as NodeJS.ErrnoException).code === "EEXIST") return readPasswordFile(path);
    throw error;
  }
  try {
    writeFileSync(fd, `${generated}\n`, "utf8");
    fchmodSync(fd, 0o600);
  } finally {
    closeSync(fd);
  }
  return generated;
}
