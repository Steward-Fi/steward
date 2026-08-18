const REPOSITORY_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const TAG_PATTERN = /^v[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const TOMBSTONED_DRAFTS = new Set(["Steward-Fi/steward@v0.3.16"]);

export type ReleaseState = "missing" | "draft" | "published";

type ReleasePayload = {
  draft?: unknown;
  tag_name?: unknown;
};

async function readBoundedJson(response: Response): Promise<unknown> {
  // GitHub's list representation includes release bodies, authors, and asset
  // metadata. This repository's current 21-release response is already about
  // 52 KiB, so 64 KiB would make ordinary release-note growth an outage.
  const maxBytes = 2 * 1024 * 1024;
  const contentLength = Number(response.headers.get("content-length") ?? "0");
  if (Number.isFinite(contentLength) && contentLength > maxBytes) {
    throw new Error("GitHub release lookup response exceeded 2 MiB");
  }

  const reader = response.body?.getReader();
  if (!reader) throw new Error("GitHub release lookup returned an empty response");
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > maxBytes) {
        await reader.cancel();
        throw new Error("GitHub release lookup response exceeded 2 MiB");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown;
  } catch {
    throw new Error("GitHub release lookup returned invalid JSON");
  }
}

export function classifyReleaseResponse(
  status: number,
  payload: ReleasePayload | undefined,
  expectedTag: string,
): ReleaseState {
  if (status === 404) return "missing";
  if (status !== 200) {
    throw new Error(`GitHub release lookup failed with HTTP ${status}`);
  }
  if (!payload || payload.tag_name !== expectedTag || typeof payload.draft !== "boolean") {
    throw new Error("GitHub release lookup returned an invalid response");
  }
  return payload.draft ? "draft" : "published";
}

export async function checkReleaseRerun(
  repository: string,
  tag: string,
  token: string,
  fetchImpl: typeof fetch = fetch,
): Promise<ReleaseState> {
  if (!REPOSITORY_PATTERN.test(repository)) throw new Error("Invalid GITHUB_REPOSITORY");
  if (!TAG_PATTERN.test(tag)) throw new Error("Release tag must be a bounded v* tag");
  if (!token) throw new Error("GITHUB_TOKEN is required");
  if (TOMBSTONED_DRAFTS.has(`${repository}@${tag}`)) {
    throw new Error(`Release ${tag} is a tombstoned legacy draft and must not be reused`);
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10_000);
  try {
    const [owner, repo] = repository.split("/");
    const headers = {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      "X-GitHub-Api-Version": "2026-03-10",
      "User-Agent": "steward-release-preflight",
    };
    const baseUrl = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`;
    const request = (url: string) =>
      fetchImpl(url, {
        headers: {
          ...headers,
        },
        redirect: "error",
        signal: controller.signal,
      });
    const response = await request(`${baseUrl}/releases/tags/${encodeURIComponent(tag)}`);

    if (response.status !== 404) {
      const payload = (await readBoundedJson(response)) as ReleasePayload;
      return classifyReleaseResponse(response.status, payload, tag);
    }

    // GitHub's exact tag endpoint omits drafts that have no backing Git tag.
    // Search the authenticated release list so those drafts remain recoverable
    // rather than being mistaken for a first publication.
    for (let page = 1; page <= 10; page += 1) {
      const listResponse = await request(`${baseUrl}/releases?per_page=100&page=${page}`);
      if (listResponse.status !== 200) {
        throw new Error(`GitHub draft lookup failed with HTTP ${listResponse.status}`);
      }
      const payload = await readBoundedJson(listResponse);
      if (!Array.isArray(payload))
        throw new Error("GitHub release list returned an invalid response");
      for (const item of payload) {
        if (!item || typeof item !== "object") {
          throw new Error("GitHub release list returned an invalid response");
        }
        const release = item as ReleasePayload;
        // Do not silently skip a partially decoded entry. A schema change or
        // truncated object could otherwise hide the target draft and turn an
        // uncertain lookup into permission to publish.
        if (typeof release.tag_name !== "string" || typeof release.draft !== "boolean") {
          throw new Error("GitHub release list returned an invalid response");
        }
        if (release.tag_name === tag) {
          return classifyReleaseResponse(200, release, tag);
        }
      }
      if (payload.length < 100) return "missing";
    }
    throw new Error("GitHub release list exceeded the 1000-release safety bound");
  } finally {
    clearTimeout(timer);
  }
}

if (import.meta.main) {
  const repository = process.argv[2] ?? "";
  const tag = process.argv[3] ?? "";
  // biome-ignore lint/suspicious/noUndeclaredEnvVars: this script runs directly in the release job, outside Turbo's cache.
  const state = await checkReleaseRerun(repository, tag, process.env.GITHUB_TOKEN ?? "");
  if (state === "published") {
    console.error(`Release ${tag} is already published; refusing a release-workflow rerun.`);
    process.exit(1);
  }
  console.log(
    state === "draft"
      ? `Release ${tag} is a draft; recovery may continue.`
      : `Release ${tag} does not exist; first publication may continue.`,
  );
}
