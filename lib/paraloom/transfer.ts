// Shielded → shielded transfer (#197). Spends two notes the wallet owns and
// creates two outputs — one to the recipient, one change back to self — proving
// the TransferCircuit in the browser (#195) and encrypting each output to its
// recipient's shielded address (#196) so only they can discover and spend it.
// The spend secrets never leave the wallet.

import { isValidShieldedAddress } from "~lib/crypto/addressChecksum"
import { addressBoxPubHex, addressSpendPubHex } from "~lib/crypto/keyManagement"
import { NATIVE_ASSET_HEX, noteCommitmentV2, proveTransferV2 } from "~lib/prover"

import { PATH_SERVER_URL, TRANSFER_INGRESS_URL } from "./constants"
import { encryptNote } from "./noteCrypto"
import {
  addDiscoveredNote,
  markNoteSpentByIdentity,
  type ShieldedNote
} from "./notes"
import { randomBn254BlindingHex } from "./proverSerialize"

interface MerklePathResponse {
  root: string
  path: string[]
  indices: boolean[]
}

export interface TransferResult {
  requestId: string
  changeCommitment: string
}

async function fetchPath(commitment: string): Promise<MerklePathResponse> {
  const res = await fetch(`${PATH_SERVER_URL}/merkle/path/${commitment}`)
  if (res.status === 404) {
    throw new Error("An input note is not indexed by the validators yet — try again shortly")
  }
  if (!res.ok) {
    throw new Error(`Path server error (${res.status})`)
  }
  return (await res.json()) as MerklePathResponse
}

// Send `amount` lamports from two owned input notes to `recipientShieldedAddress`,
// with the remainder as change back to this wallet. `inputs` must be exactly two
// unspent notes the wallet owns whose values sum to at least `amount` (the
// circuit is fixed 2-in/2-out and every input must be a real tree member).
export async function transfer(
  account: string,
  ownShieldedAddress: string,
  recipientShieldedAddress: string,
  amount: bigint,
  inputs: [ShieldedNote, ShieldedNote],
  spendPrivkeyHex: string
): Promise<TransferResult> {
  if (!isValidShieldedAddress(recipientShieldedAddress)) {
    throw new Error("Invalid recipient shielded address")
  }
  if (recipientShieldedAddress === ownShieldedAddress) {
    throw new Error("Cannot transfer to your own shielded address")
  }
  if (amount <= 0n) {
    throw new Error("Transfer amount must be > 0")
  }
  if (inputs.length !== 2) {
    throw new Error("Transfer requires exactly 2 input notes")
  }
  for (const n of inputs) {
    if (n.spent) {
      throw new Error("Cannot spend an already-spent note")
    }
    if (n.assetId && n.assetId !== NATIVE_ASSET_HEX) {
      throw new Error("All input notes must be native SOL notes")
    }
  }
  const sameNote =
    (inputs[0].signature &&
      inputs[1].signature &&
      inputs[0].signature === inputs[1].signature) ||
    (inputs[0].commitment &&
      inputs[1].commitment &&
      inputs[0].commitment === inputs[1].commitment) ||
    (inputs[0].blinding === inputs[1].blinding &&
      inputs[0].amount === inputs[1].amount &&
      inputs[0].createdAt === inputs[1].createdAt)
  if (sameNote) {
    throw new Error("Transfer inputs must be two distinct notes")
  }

  const inputTotal = inputs.reduce((sum, n) => sum + BigInt(n.amount), 0n)
  if (inputTotal < amount) {
    throw new Error("Selected notes do not cover the transfer amount")
  }
  const change = inputTotal - amount

  // v2 (#293): an output binds the recipient's spend pubkey (so only they can
  // spend it) and is encrypted to their box pubkey (so only they can read it).
  const recipientSpendPub = addressSpendPubHex(recipientShieldedAddress)
  const recipientBoxPub = addressBoxPubHex(recipientShieldedAddress)
  const ownSpendPub = addressSpendPubHex(ownShieldedAddress)
  const ownBoxPub = addressBoxPubHex(ownShieldedAddress)

  // Pull each input's Merkle path. Both must prove against the same root.
  let root = ""
  const proofInputs = []
  const commitments: string[] = []
  for (const note of inputs) {
    const noteAmt = BigInt(note.amount)
    const commitment = await noteCommitmentV2(
      noteAmt,
      spendPrivkeyHex,
      note.blinding,
      note.assetId || NATIVE_ASSET_HEX
    )
    if (commitments.includes(commitment)) {
      throw new Error("Transfer inputs must have distinct commitments")
    }
    commitments.push(commitment)
    const pathRes = await fetchPath(commitment)
    if (root && pathRes.root !== root) {
      throw new Error(
        "Merkle root changed between input path lookups — please retry"
      )
    }
    root = pathRes.root
    proofInputs.push({
      amount: noteAmt,
      blinding_hex: note.blinding,
      privkey_hex: spendPrivkeyHex,
      path_hex: pathRes.path,
      indices: pathRes.indices
    })
  }

  // Output 0 → recipient, output 1 → change back to self. Fresh canonical
  // BN254 blinding (< BN254_SCALAR_MODULUS) each.
  const outBlind0 = randomBn254BlindingHex()
  const outBlind1 = randomBn254BlindingHex()
  const outputs = [
    { amount, blinding_hex: outBlind0, pubkey_hex: recipientSpendPub },
    { amount: change, blinding_hex: outBlind1, pubkey_hex: ownSpendPub }
  ]

  const { nullifiers, output_commitments, proof } = await proveTransferV2(
    root,
    NATIVE_ASSET_HEX,
    proofInputs,
    outputs
  )

  // Encrypt each output note to its recipient's box pubkey so they can discover
  // and spend it (they recompute the commitment with their own spend key).
  const ciphertexts = [
    encryptNote(recipientBoxPub, {
      amount,
      blindingHex: outBlind0,
      assetIdHex: NATIVE_ASSET_HEX
    }),
    encryptNote(ownBoxPub, {
      amount: change,
      blindingHex: outBlind1,
      assetIdHex: NATIVE_ASSET_HEX
    })
  ]

  const body = {
    nullifiers,
    output_commitments,
    // The node recomputes the authoritative post-state root from its own pool;
    // we send the current root (advisory). L2 verification uses the pool root.
    new_merkle_root: root,
    proof,
    ciphertexts
  }

  const res = await fetch(`${TRANSFER_INGRESS_URL}/transfer/submit`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  })
  if (!res.ok) {
    throw new Error(`Transfer ingress rejected the transfer (${res.status})`)
  }
  const { request_id } = (await res.json()) as { request_id: string }

  // Mark the spent inputs by identity and store the change note locally only
  // when change > 0n (avoid polluting storage with a zero-value note).
  for (const note of inputs) {
    await markNoteSpentByIdentity(account, note)
  }
  const changeCommitment = output_commitments[1]
  if (change > 0n) {
    await addDiscoveredNote(account, {
      amount: change.toString(),
      blinding: outBlind1,
      assetId: NATIVE_ASSET_HEX,
      signature: "",
      createdAt: Date.now(),
      spent: false,
      commitment: changeCommitment,
      source: "transfer"
    })
  }

  return { requestId: request_id, changeCommitment }
}
