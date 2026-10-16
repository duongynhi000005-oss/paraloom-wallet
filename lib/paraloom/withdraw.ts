// Shielded → Solana withdrawal. Computes the note's commitment, fetches its
// Merkle path from a validator node, builds the Groth16 proof in the browser,
// and submits it to the validator ingress for BFT verification + on-chain
// settlement. The note secret never leaves the wallet.

import { noteCommitmentV2, proveWithdrawalV2 } from "~lib/prover"

import { INGRESS_URL, PATH_SERVER_URL } from "./constants"
import { solanaAddressToBytes } from "./bridge"
import type { ShieldedNote } from "./notes"
import { serializeWithdrawalBodyJson } from "./proverSerialize"

interface MerklePathResponse {
  root: string
  path: string[]
  indices: boolean[]
}

export interface WithdrawResult {
  requestId: string
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")
}

// Withdraw a deposited note to a Solana address. `spendPrivkeyHex` is the
// account's circuit-v2 spend key. Throws with a readable message if the note is
// not yet indexed or the node is unreachable.
export async function withdraw(
  note: ShieldedNote,
  toSolanaAddress: string,
  spendPrivkeyHex: string
): Promise<WithdrawResult> {
  if (note.spent) {
    throw new Error("Cannot withdraw an already-spent note")
  }
  const amount = BigInt(note.amount)
  if (amount <= 0n) {
    throw new Error("Withdrawal amount must be > 0")
  }

  const commitment = await noteCommitmentV2(amount, spendPrivkeyHex, note.blinding, note.assetId)

  const pathRes = await fetch(`${PATH_SERVER_URL}/merkle/path/${commitment}`)
  if (pathRes.status === 404) {
    throw new Error("Note not indexed by the validators yet — try again shortly")
  }
  if (!pathRes.ok) {
    throw new Error(`Path server error (${pathRes.status})`)
  }
  const { root, path, indices } = (await pathRes.json()) as MerklePathResponse

  // The on-chain program binds the proof to this destination via
  // ext_data_hash = sha256(recipient || amount); the body's recipient must
  // match exactly, so the payout cannot be redirected (#293 finding D).
  const destRecipientHex = toHex(solanaAddressToBytes(toSolanaAddress))

  const { nullifier, proof } = await proveWithdrawalV2({
    root,
    amount,
    blinding: note.blinding,
    privkey: spendPrivkeyHex,
    assetId: note.assetId,
    destRecipient: destRecipientHex,
    path,
    indices
  })

  const bodyJson = serializeWithdrawalBodyJson({
    nullifier,
    recipient: destRecipientHex,
    proof,
    amount,
    fee: 0n
  })

  const res = await fetch(`${INGRESS_URL}/withdrawal/submit`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: bodyJson
  })
  if (!res.ok) {
    throw new Error(`Ingress rejected the withdrawal (${res.status})`)
  }
  const { request_id } = (await res.json()) as { request_id: string }
  return { requestId: request_id }
}
