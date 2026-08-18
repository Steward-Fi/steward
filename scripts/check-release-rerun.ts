const REPOSITORY_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const TAG_PATTERN = /^v[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

export type ReleaseState = "missing" | "draft" | "published";

type ReleasePayload = {
  draft?: unknown;
  tag_name?: unknown;
};

async function readBoundedJson(response: Response): Promise<unknown> {
  const contentLength = Number(response.headers.get("content-length") ?? "0");
  if (Number.isFinite(contentLength) && contentLength > 64 * 1024) {
    throw new Error("GitHub release lookup response exceeded 64 KiB");
  }
  const body = await response.text();
  if (new TextEncoder().encode(body).byteLength > 64 * 1024) {
    throw new Error("GitHub release lookup response exceeded 64 KiB");
  }
  try {
    return JSON.parse(body) as unknown;
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
      if (!Array.isArray(payload)) throw new Error("GitHub release list returned an invalid response");
      for (const item of payload) {
        if (!item || typeof item !== "object") {
          throw new Error("GitHub release list returned an invalid response");
        }
        const release = item as ReleasePayload;
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
