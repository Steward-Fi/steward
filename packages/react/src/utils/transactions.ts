import type { StewardClient, TxRecord } from "@stwd/sdk";

const TRANSACTION_PAGE_SIZE = 200;

/** Load the complete credentialed transaction history without the legacy
 * history endpoint's 100-row default truncating analytics or pagination. */
export async function getAllTransactions(
  client: Pick<StewardClient, "listTransactions">,
  agentId: string,
): Promise<TxRecord[]> {
  const transactions: TxRecord[] = [];
  let offset = 0;

  for (;;) {
    const page = await client.listTransactions(agentId, {
      limit: TRANSACTION_PAGE_SIZE,
      offset,
    });
    transactions.push(...page.transactions);
    if (page.transactions.length < TRANSACTION_PAGE_SIZE) return transactions;
    offset += page.transactions.length;
  }
}
