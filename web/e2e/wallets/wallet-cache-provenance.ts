import { createHash } from "node:crypto";
import { type BigIntStats, constants } from "node:fs";
import { lstat, open, readdir, rename, rm, writeFile } from "node:fs/promises";
import { join, relative } from "node:path";

export const WALLET_CACHE_MANIFEST = ".steward-wallet-cache.json";

export interface WalletCacheIdentity {
  wallet: "metamask" | "phantom";
  cacheId: string;
  extensionVersion: string;
  extensionSha256: string;
}

interface WalletCacheManifest extends WalletCacheIdentity {
  schemaVersion: 1;
  contentSha256: string;
}

function sameFile(left: BigIntStats, right: BigIntStats): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function sameFileVersion(left: BigIntStats, right: BigIntStats): boolean {
  return (
    sameFile(left, right) &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
  );
}

async function readStableRegularFile(
  path: string,
  label: string,
  expected?: BigIntStats,
): Promise<Buffer> {
  if (!Number.isSafeInteger(constants.O_NOFOLLOW) || constants.O_NOFOLLOW <= 0) {
    throw new Error("Wallet cache verification requires O_NOFOLLOW support");
  }

  // O_NONBLOCK prevents a path swap to a FIFO from blocking the verifier in open().
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = (await handle.stat({ bigint: true })) as BigIntStats;
    if (!before.isFile() || (expected && !sameFile(expected, before))) {
      throw new Error("Wallet cache entry is not a stable regular file: " + label);
    }
    const content = await handle.readFile();
    const after = (await handle.stat({ bigint: true })) as BigIntStats;
    if (!sameFileVersion(before, after) || BigInt(content.byteLength) !== before.size) {
      throw new Error("Wallet cache entry changed while it was being verified: " + label);
    }
    return content;
  } finally {
    await handle.close();
  }
}

async function updateTreeHash(root: string, path: string, hash: ReturnType<typeof createHash>) {
  const entries = (await readdir(path, { withFileTypes: true })).sort((a, b) =>
    a.name.localeCompare(b.name),
  );
  for (const entry of entries) {
    if (path === root && entry.name === WALLET_CACHE_MANIFEST) continue;
    const absolute = join(path, entry.name);
    const name = relative(root, absolute);
    const metadata = (await lstat(absolute, { bigint: true })) as BigIntStats;
    if (metadata.isDirectory()) {
      hash.update("d\0" + name + "\0");
      await updateTreeHash(root, absolute, hash);
    } else if (metadata.isFile()) {
      const content = await readStableRegularFile(absolute, name, metadata);
      hash.update("f\0" + name + "\0" + metadata.size.toString() + "\0");
      hash.update(content);
    } else {
      throw new Error("Unsupported wallet cache entry: " + name);
    }
  }
}

export async function walletCacheContentSha256(root: string): Promise<string> {
  const hash = createHash("sha256");
  await updateTreeHash(root, root, hash);
  return hash.digest("hex");
}

export async function writeWalletCacheManifest(
  root: string,
  identity: WalletCacheIdentity,
): Promise<void> {
  const temporary = join(root, WALLET_CACHE_MANIFEST + ".tmp");
  await rm(temporary, { force: true });
  const manifest: WalletCacheManifest = {
    schemaVersion: 1,
    ...identity,
    contentSha256: await walletCacheContentSha256(root),
  };
  await writeFile(temporary, JSON.stringify(manifest) + "\n", { mode: 0o600 });
  await rename(temporary, join(root, WALLET_CACHE_MANIFEST));
}

export async function assertWalletCacheIdentity(
  root: string,
  expected: WalletCacheIdentity,
): Promise<void> {
  const manifestPath = join(root, WALLET_CACHE_MANIFEST);
  const manifest = JSON.parse(
    (await readStableRegularFile(manifestPath, WALLET_CACHE_MANIFEST)).toString("utf8"),
  ) as Partial<WalletCacheManifest>;
  if (
    manifest.schemaVersion !== 1 ||
    manifest.wallet !== expected.wallet ||
    manifest.cacheId !== expected.cacheId ||
    manifest.extensionVersion !== expected.extensionVersion ||
    manifest.extensionSha256 !== expected.extensionSha256
  ) {
    throw new Error("Wallet cache provenance mismatch: " + expected.wallet);
  }
  const contentSha256 = await walletCacheContentSha256(root);
  if (manifest.contentSha256 !== contentSha256) {
    throw new Error("Wallet cache content digest mismatch: " + expected.wallet);
  }
}
