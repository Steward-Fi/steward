import type { StewardClient, TxRecord } from "@stwd/sdk";

const TRANSACTION_PAGE_SIZE = 200;
const MAX_TRANSACTION_PAGES = 500;

/** Load the complete credentialed transaction history without the legacy
 * history endpoint's 100-row default truncating analytics or pagination. */
export async function getAllTransactions(
  client: Pick<StewardClient, "listTransactions">,
  agentId: string,
): Promise<TxRecord[]> {
  // Offset pagination over a newest-first feed can shift while it is being
  // read. A duplicate ID proves that happened; retry once from a clean
  // snapshot rather than double-counting spend or returning duplicate rows.
  for (let snapshotAttempt = 0; snapshotAttempt < 2; snapshotAttempt++) {
    const transactions: TxRecord[] = [];
    const seen = new Set<string>();
    let offset = 0;
    let shifted = false;

    for (let pageNumber = 0; pageNumber < MAX_TRANSACTION_PAGES; pageNumber++) {
      const page = await client.listTransactions(agentId, {
        limit: TRANSACTION_PAGE_SIZE,
        offset,
      });
      for (const transaction of page.transactions) {
        if (seen.has(transaction.id)) {
          shifted = true;
          break;
        }
        seen.add(transaction.id);
        transactions.push(transaction);
      }
      if (shifted) break;
      if (page.transactions.length < TRANSACTION_PAGE_SIZE) return transactions;
      offset += page.transactions.length;
    }
    if (!shifted) throw new Error("Transaction history exceeds the supported pagination bound");
  }
  throw new Error("Transaction history changed during pagination; retry the request");
}
