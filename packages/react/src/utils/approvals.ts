import type { ApprovalQueueEntry, StewardClient } from "@stwd/sdk";

const APPROVAL_PAGE_SIZE = 200;
// Bound an unexpectedly large queue instead of polling without limit.
const MAX_APPROVAL_PAGES = 51;

/**
 * Load an agent's complete pending approval queue through the credentialed SDK.
 *
 * Keyset pagination follows the stable (requestedAt, id) ordering. Concurrent
 * inserts, resolutions, and deletions cannot shift an unseen row across an
 * offset boundary.
 */
export async function getAllPendingApprovals(
  client: Pick<StewardClient, "listApprovals">,
  agentId: string,
): Promise<ApprovalQueueEntry[]> {
  const approvals: ApprovalQueueEntry[] = [];
  const seen = new Set<string>();
  let cursorRequestedAt: string | undefined;
  let cursorId: string | undefined;

  for (let pageNumber = 0; pageNumber < MAX_APPROVAL_PAGES; pageNumber++) {
    const page = await client.listApprovals({
      status: "pending",
      agentId,
      limit: APPROVAL_PAGE_SIZE,
      ...(cursorRequestedAt && cursorId ? { cursorRequestedAt, cursorId } : {}),
    });
    for (const approval of page) {
      if (seen.has(approval.id)) {
        throw new Error("Approval server returned a duplicate keyset page entry");
      }
      seen.add(approval.id);
      approvals.push(approval);
    }
    if (page.length < APPROVAL_PAGE_SIZE) return approvals;

    const last = page.at(-1);
    if (!last) return approvals;
    const requestedAt =
      last.requestedAt instanceof Date ? last.requestedAt : new Date(last.requestedAt);
    if (Number.isNaN(requestedAt.getTime())) {
      throw new Error("Approval server returned an invalid pagination timestamp");
    }
    cursorRequestedAt = requestedAt.toISOString();
    cursorId = last.id;
  }

  throw new Error("Approval queue exceeds the supported pagination bound");
}
