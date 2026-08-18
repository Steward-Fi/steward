import type { ApprovalQueueEntry, StewardClient } from "@stwd/sdk";

const APPROVAL_PAGE_SIZE = 200;
// The API accepts offsets through 10,000, so pages starting at 0..10,000 are
// the largest complete snapshot an offset client can request.
const MAX_APPROVAL_PAGES = 51;

/**
 * Load an agent's complete pending approval queue through the credentialed SDK.
 *
 * Offset pagination over a newest-first queue can shift while it is read. Each
 * page after the first deliberately overlaps the preceding page by one row.
 * A changed boundary detects both forward shifts (inserts) and backward shifts
 * (resolutions/deletes), so retry once rather than showing a partial
 * security-sensitive queue.
 */
export async function getAllPendingApprovals(
  client: Pick<StewardClient, "listApprovals">,
  agentId: string,
): Promise<ApprovalQueueEntry[]> {
  for (let snapshotAttempt = 0; snapshotAttempt < 2; snapshotAttempt++) {
    const approvals: ApprovalQueueEntry[] = [];
    const seen = new Set<string>();
    let offset = 0;
    let shifted = false;

    for (let pageNumber = 0; pageNumber < MAX_APPROVAL_PAGES; pageNumber++) {
      const page = await client.listApprovals({
        status: "pending",
        agentId,
        limit: APPROVAL_PAGE_SIZE,
        offset,
      });
      let pageStart = 0;
      if (pageNumber > 0) {
        const expectedBoundaryId = approvals.at(-1)?.id;
        if (!expectedBoundaryId || page[0]?.id !== expectedBoundaryId) {
          shifted = true;
          break;
        }
        pageStart = 1;
      }
      for (const approval of page.slice(pageStart)) {
        if (seen.has(approval.id)) {
          shifted = true;
          break;
        }
        seen.add(approval.id);
        approvals.push(approval);
      }
      if (shifted) break;
      if (page.length < APPROVAL_PAGE_SIZE) return approvals;
      // Keep the final row as an overlap sentinel for the next page. Without
      // this, a resolved row before the offset can shift an unseen approval
      // backward and make it disappear from the assembled queue.
      offset += page.length - 1;
    }

    if (!shifted) {
      throw new Error("Approval queue exceeds the supported pagination bound");
    }
  }

  throw new Error("Approval queue changed during pagination; retry the request");
}
