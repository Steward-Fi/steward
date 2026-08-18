// Stub Steward API for signer tests: records every request (method, path,
// headers, body) and plays the vault's documented response shapes for the two
// routes the signer touches. `mode` switches the sign route between a real
// stub signature and the refusal envelopes the API emits.

import {
  Keypair,
  MessageV0,
  PublicKey,
  SystemProgram,
  Transaction,
  VersionedTransaction,
} from "@solana/web3.js";

export interface RecordedRequest {
  method: string;
  path: string;
  headers: Record<string, string>;
  body: unknown;
}

export type StubMode =
  | "sign"
  | "reject"
  | "pending"
  | "forbidden"
  | "invalid-signature"
  | "changed-cosigner"
  | "injected-cosigner"
  | "malformed-addresses"
  | "malformed-sign-result"
  | "slow-sign"
  | "trailing-response-bytes"
  | "missing-broadcast-proof"
  | "wrong-chain";

export interface StubSteward {
  url: string;
  requests: RecordedRequest[];
  setMode(mode: StubMode): void;
  stop(): void;
}

// Same detection the real vault uses: skip the compact-u16 signature count and
// the signature slots, then check the message version byte's high bit.
function isVersionedTransactionBytes(bytes: Uint8Array): boolean {
  let sigCount = 0;
  let bytesRead = 0;
  for (let shift = 0; ; shift += 7) {
    const byte = bytes[bytesRead];
    if (byte === undefined) return false;
    bytesRead += 1;
    sigCount |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) break;
  }
  const firstMessageByte = bytes[bytesRead + sigCount * 64];
  return firstMessageByte !== undefined && (firstMessageByte & 0x80) !== 0;
}

function json(body: object, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export function startStubSteward(kp: Keypair): StubSteward {
  const requests: RecordedRequest[] = [];
  let mode: StubMode = "sign";

  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch: async (req) => {
      const url = new URL(req.url);
      const headers: Record<string, string> = {};
      req.headers.forEach((value, key) => {
        headers[key.toLowerCase()] = value;
      });
      const body = req.method === "POST" ? await req.json() : undefined;
      requests.push({ method: req.method, path: url.pathname, headers, body });

      if (req.method === "GET" && /^\/vault\/[^/]+\/addresses$/.test(url.pathname)) {
        if (mode === "malformed-addresses") {
          return json({ ok: true, data: { addresses: null } });
        }
        return json({
          ok: true,
          data: {
            agentId: url.pathname.split("/")[2],
            addresses: [
              { chainFamily: "evm", address: "0x1111111111111111111111111111111111111111" },
              { chainFamily: "solana", address: kp.publicKey.toBase58() },
            ],
          },
        });
      }

      if (req.method === "POST" && /^\/vault\/[^/]+\/sign-solana$/.test(url.pathname)) {
        if (mode === "malformed-sign-result") {
          return json({ ok: true, data: null });
        }
        if (mode === "slow-sign") await Bun.sleep(25);
        if (mode === "forbidden") {
          return json({ ok: false, error: "Forbidden: token scope does not match agent" }, 403);
        }
        if (mode === "reject") {
          return json(
            {
              ok: false,
              error: "Transaction rejected by policy",
              data: {
                txId: "tx-reject-1",
                results: [
                  {
                    policyId: "policy-spend",
                    type: "spending-limit",
                    passed: false,
                    reason: "daily cap 0.5 SOL exceeded",
                  },
                ],
              },
            },
            403,
          );
        }
        if (mode === "pending") {
          return json(
            {
              ok: false,
              error: "Transaction requires manual approval",
              data: {
                txId: "tx-pending-1",
                status: "pending_approval",
                results: [
                  {
                    policyId: "policy-threshold",
                    type: "auto-approve-threshold",
                    passed: false,
                    reason: "above the auto-approve threshold",
                  },
                ],
              },
            },
            202,
          );
        }
        const { transaction, chainId } = body as { transaction: string; chainId?: number };
        const bytes = Uint8Array.from(Buffer.from(transaction, "base64"));
        let signed: Uint8Array;
        // Same version-byte branch the real vault uses.
        if (isVersionedTransactionBytes(bytes)) {
          const vtx = VersionedTransaction.deserialize(bytes);
          vtx.sign([kp]);
          if (mode === "changed-cosigner" && vtx.signatures[1]) {
            vtx.signatures[1][0] ^= 1;
          }
          if (mode === "injected-cosigner" && vtx.signatures[1]) {
            vtx.signatures[1] = new Uint8Array(64).fill(1);
          }
          signed = vtx.serialize();
        } else {
          const tx = Transaction.from(bytes);
          tx.partialSign(kp);
          if (mode === "invalid-signature" && tx.signatures[0]?.signature) {
            tx.signatures[0].signature[0] ^= 1;
          }
          if (mode === "changed-cosigner" && tx.signatures[1]?.signature) {
            tx.signatures[1].signature[0] ^= 1;
          }
          if (mode === "injected-cosigner" && tx.signatures[1]) {
            tx.signatures[1].signature = new Uint8Array(64).fill(1);
          }
          signed = new Uint8Array(
            tx.serialize({ requireAllSignatures: false, verifySignatures: false }),
          );
        }
        if (mode === "trailing-response-bytes") {
          signed = new Uint8Array([...signed, 0xa5]);
        }
        const data: Record<string, unknown> = {
          txId: crypto.randomUUID(),
          signature: Buffer.from(signed).toString("base64"),
          broadcast: false,
          chainId: mode === "wrong-chain" ? 102 : (chainId ?? 101),
        };
        if (mode === "missing-broadcast-proof") delete data.broadcast;
        return json({
          ok: true,
          data,
        });
      }

      return json({ ok: false, error: "not found" }, 404);
    },
  });

  return {
    url: `http://127.0.0.1:${server.port}`,
    requests,
    setMode(next: StubMode) {
      mode = next;
    },
    stop() {
      server.stop(true);
    },
  };
}

// Deterministic blockhash-shaped base58 string for offline tx building.
export const STUB_BLOCKHASH = new PublicKey(new Uint8Array(32).fill(7)).toBase58();

export const SINK = new PublicKey(new Uint8Array(32).fill(9));

export function legacyTransfer(from: PublicKey): Transaction {
  const tx = new Transaction();
  tx.add(SystemProgram.transfer({ fromPubkey: from, toPubkey: SINK, lamports: 1_000 }));
  tx.recentBlockhash = STUB_BLOCKHASH;
  tx.feePayer = from;
  return tx;
}

export function versionedTransfer(from: PublicKey): VersionedTransaction {
  const message = MessageV0.compile({
    payerKey: from,
    recentBlockhash: STUB_BLOCKHASH,
    instructions: [SystemProgram.transfer({ fromPubkey: from, toPubkey: SINK, lamports: 1_000 })],
  });
  return new VersionedTransaction(message);
}
