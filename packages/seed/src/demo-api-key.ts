import { randomBytes } from "node:crypto";
import {
  closeSync,
  fchmodSync,
  constants as fsConstants,
  fstatSync,
  fsyncSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { type ApiKeyPair, generateApiKey } from "@stwd/auth";

export type PendingDemoCredentials = {
  finalPath: string;
  pendingPath: string;
  parentDevice: number;
  parentInode: number;
};

export function generateDemoApiKey(): ApiKeyPair {
  return generateApiKey();
}

function assertTenantId(tenantId: string): void {
  if (!/^[A-Za-z0-9_.:-]{1,64}$/.test(tenantId)) {
    throw new Error("Demo credential tenant id is invalid");
  }
}

function assertApiKey(apiKey: string): void {
  if (!/^stw_[0-9a-f]{32}$/.test(apiKey)) {
    throw new Error("Demo credential API key is invalid");
  }
}

function credentialParent(path: string): { device: number; inode: number } {
  const parentPath = dirname(path);
  mkdirSync(parentPath, { recursive: true, mode: 0o700 });
  const parent = lstatSync(parentPath);
  if (!parent.isDirectory() || parent.isSymbolicLink() || realpathSync(parentPath) !== parentPath) {
    throw new Error("Demo credentials parent must not contain redirected directories");
  }
  if (typeof process.geteuid === "function" && parent.uid !== process.geteuid()) {
    throw new Error("Demo credentials parent must be owned by the current user");
  }
  const fd = openSync(
    parentPath,
    fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW,
  );
  try {
    const opened = fstatSync(fd);
    if (!opened.isDirectory() || opened.dev !== parent.dev || opened.ino !== parent.ino) {
      throw new Error("Demo credentials parent changed during validation");
    }
    fchmodSync(fd, 0o700);
    return { device: opened.dev, inode: opened.ino };
  } finally {
    closeSync(fd);
  }
}

function writeNewCredentialFile(path: string, contents: string): void {
  const fd = openSync(
    path,
    fsConstants.O_WRONLY |
      fsConstants.O_CREAT |
      fsConstants.O_EXCL |
      fsConstants.O_NOFOLLOW |
      fsConstants.O_NONBLOCK,
    0o600,
  );
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1) {
      throw new Error("Demo credentials output must be a regular, non-linked file");
    }
    if (typeof process.geteuid === "function" && stat.uid !== process.geteuid()) {
      throw new Error("Demo credentials output must be owned by the current user");
    }
    fchmodSync(fd, 0o600);
    writeFileSync(fd, contents, "utf8");
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function syncDirectory(path: string, expected: { device: number; inode: number }): void {
  const fd = openSync(
    path,
    fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW,
  );
  try {
    const opened = fstatSync(fd);
    if (!opened.isDirectory() || opened.dev !== expected.device || opened.ino !== expected.inode) {
      throw new Error("Demo credentials parent changed before durable storage");
    }
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/** Stage a unique credential without replacing the currently valid one. */
export function stageDemoCredentials(
  tenantId: string,
  apiKey: string,
  outputPath = process.env.STEWARD_DEMO_CREDENTIALS_FILE ?? ".steward/demo-credentials.env",
): PendingDemoCredentials {
  assertTenantId(tenantId);
  assertApiKey(apiKey);
  const finalPath = resolve(outputPath);
  const parent = credentialParent(finalPath);
  for (let attempt = 0; attempt < 4; attempt++) {
    const pendingPath = `${finalPath}.pending-${randomBytes(12).toString("hex")}`;
    try {
      writeNewCredentialFile(
        pendingPath,
        `STEWARD_TENANT_ID=${tenantId}\nSTEWARD_API_KEY=${apiKey}\n`,
      );
      syncDirectory(dirname(finalPath), parent);
      return {
        finalPath,
        pendingPath,
        parentDevice: parent.device,
        parentInode: parent.inode,
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST" || attempt === 3) throw error;
    }
  }
  throw new Error("Could not allocate a unique pending credential file");
}

/** Atomically make a staged credential canonical after the DB commit. */
export function promoteDemoCredentials(
  pending: PendingDemoCredentials,
  afterPendingOpen?: () => void,
  beforePromotionRename?: (promotionPath: string) => void,
): string {
  const parent = credentialParent(pending.finalPath);
  if (parent.device !== pending.parentDevice || parent.inode !== pending.parentInode) {
    throw new Error(`Credential directory changed; recover ${pending.pendingPath}`);
  }
  const pendingFd = openSync(
    pending.pendingPath,
    fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK,
  );
  try {
    const staged = fstatSync(pendingFd);
    if (!staged.isFile() || staged.nlink !== 1 || (staged.mode & 0o777) !== 0o600) {
      throw new Error(`Pending credential is unsafe; recover ${pending.pendingPath}`);
    }
    if (typeof process.geteuid === "function" && staged.uid !== process.geteuid()) {
      throw new Error(`Pending credential owner changed; recover ${pending.pendingPath}`);
    }

    afterPendingOpen?.();

    let promotionPath: string | undefined;
    for (let attempt = 0; attempt < 4; attempt++) {
      const candidate = `${pending.finalPath}.promote-${randomBytes(12).toString("hex")}`;
      try {
        linkSync(pending.pendingPath, candidate);
        promotionPath = candidate;
        break;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST" || attempt === 3) throw error;
      }
    }
    if (!promotionPath) {
      throw new Error(`Could not allocate promotion link; recover ${pending.pendingPath}`);
    }

    const linkedPath = lstatSync(promotionPath);
    const promotionFd = openSync(
      promotionPath,
      fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK,
    );
    try {
      const linkedFd = fstatSync(promotionFd);
      if (
        !linkedPath.isFile() ||
        !linkedFd.isFile() ||
        linkedPath.dev !== staged.dev ||
        linkedPath.ino !== staged.ino ||
        linkedFd.dev !== staged.dev ||
        linkedFd.ino !== staged.ino
      ) {
        throw new Error(
          `Pending credential changed during promotion; recover ${pending.pendingPath}`,
        );
      }

      beforePromotionRename?.(promotionPath);
      const beforeRename = lstatSync(promotionPath);
      if (
        !beforeRename.isFile() ||
        beforeRename.dev !== linkedFd.dev ||
        beforeRename.ino !== linkedFd.ino
      ) {
        throw new Error(
          `Pending credential changed before canonical rename; recover ${pending.pendingPath}`,
        );
      }

      renameSync(promotionPath, pending.finalPath);
      const canonical = lstatSync(pending.finalPath);
      if (!canonical.isFile() || canonical.dev !== linkedFd.dev || canonical.ino !== linkedFd.ino) {
        throw new Error(
          `Canonical credential changed during promotion; recover ${pending.pendingPath}`,
        );
      }
      syncDirectory(dirname(pending.finalPath), parent);
      // The canonical name is durable now. Removing the recovery name is cleanup:
      // if the process crashes first, both names point to the same valid key.
      unlinkSync(pending.pendingPath);
      return pending.finalPath;
    } finally {
      closeSync(promotionFd);
    }
  } finally {
    closeSync(pendingFd);
  }
}

/** Preserve a recoverable pending key across ambiguous DB or promotion failures. */
export async function rotateDemoCredentials(
  tenantId: string,
  apiKey: string,
  rotateHash: () => Promise<void>,
  outputPath?: string,
  promote: (pending: PendingDemoCredentials) => string = promoteDemoCredentials,
): Promise<string> {
  const pending = stageDemoCredentials(tenantId, apiKey, outputPath);
  try {
    await rotateHash();
  } catch {
    throw new Error(`Credential rotation outcome is uncertain; recover ${pending.pendingPath}`);
  }
  try {
    return promote(pending);
  } catch {
    throw new Error(`Credential hash committed; recover ${pending.pendingPath}`);
  }
}
