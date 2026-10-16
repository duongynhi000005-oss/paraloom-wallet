// Loads the WASM Groth16 prover and the v2 (spend-key, #293) ceremony proving
// keys, then builds proofs entirely in the extension — the spend key never
// leaves the wallet. The proving keys and wasm are bundled as assets.

import init, {
  mint_to_asset,
  note_commitment_v2,
  prove_transact,
  prove_transfer_v2,
  prove_withdrawal_v2,
  spend_pubkey,
  v3_merkle_path,
  v3_note_commitment,
  v3_note_commitment_asset,
  v3_note_pubkey
} from "./paraloom_prover_wasm.js"
import wasmUrl from "url:./paraloom_prover_wasm_bg.wasm"
import keyUrl from "url:./withdraw_v2_proving.key"
import transferKeyUrl from "url:./transfer_v2_proving.key"
import transactKeyUrl from "url:./transact_v3_proving.key"

// Native-SOL asset id (#235): all-zero 32 bytes, hex. SPL assets use the mint.
export const NATIVE_ASSET_HEX = "00".repeat(32)

// The shielded-asset id for an SPL `mint` (#779): Poseidon(2) over the mint's
// two 16-byte halves, matching the on-chain `merkle_tree::mint_to_asset`. Use
// this as the `assetId` for a shielded SPL note or transact. `mintHex` is the
// 32-byte mint pubkey, hex.
export async function assetIdForMint(mintHex: string): Promise<string> {
  await ensureInit()
  return mint_to_asset(mintHex)
}

let initialized = false
let provingKey: Uint8Array | null = null
let transferProvingKey: Uint8Array | null = null

async function ensureInit(): Promise<void> {
  if (!initialized) {
    await init(wasmUrl)
    initialized = true
  }
}

async function ensureReady(): Promise<Uint8Array> {
  await ensureInit()
  if (!provingKey) {
    const res = await fetch(keyUrl)
    provingKey = new Uint8Array(await res.arrayBuffer())
  }
  return provingKey
}

async function ensureTransferReady(): Promise<Uint8Array> {
  await ensureInit()
  if (!transferProvingKey) {
    const res = await fetch(transferKeyUrl)
    transferProvingKey = new Uint8Array(await res.arrayBuffer())
  }
  return transferProvingKey
}

let transactProvingKey: Uint8Array | null = null

async function ensureTransactReady(): Promise<Uint8Array> {
  await ensureInit()
  if (!transactProvingKey) {
    const res = await fetch(transactKeyUrl)
    transactProvingKey = new Uint8Array(await res.arrayBuffer())
  }
  return transactProvingKey
}

// Derive the spend public key (`Poseidon(privkey)`) bound into note commitments;
// it is half of the wallet's shielded address.
export async function spendPubkey(privkeyHex: string): Promise<string> {
  await ensureInit()
  return spend_pubkey(privkeyHex)
}

// Spend-key commitment of a note, hex — used to look up its Merkle path.
export async function noteCommitmentV2(
  amount: bigint,
  privkeyHex: string,
  blindingHex: string,
  assetIdHex: string
): Promise<string> {
  await ensureInit()
  return note_commitment_v2(amount, privkeyHex, blindingHex, assetIdHex)
}

export interface WithdrawalProofInput {
  root: string // hex, 32 bytes
  amount: bigint // lamports
  blinding: string // hex, 32 bytes (the note's blinding)
  privkey: string // hex, 32 bytes (the wallet's spend key)
  assetId: string // hex, 32 bytes (all-zero = native SOL)
  destRecipient: string // hex, 32 bytes (the on-chain Solana destination)
  path: string[] // hex sibling hashes
  indices: boolean[] // sibling directions
}

export interface WithdrawalProof {
  nullifier: string // hex
  proof: string // hex
}

// Generate the withdrawal proof. CPU-heavy (Groth16 in wasm), so expect a few
// seconds to tens of seconds. `destRecipient` is bound into the proof's
// ext_data_hash, so the on-chain payout cannot be redirected.
export async function proveWithdrawalV2(input: WithdrawalProofInput): Promise<WithdrawalProof> {
  const key = await ensureReady()
  const json = prove_withdrawal_v2(
    key,
    input.root,
    input.amount,
    input.blinding,
    input.privkey,
    input.assetId,
    input.destRecipient,
    JSON.stringify(input.path),
    JSON.stringify(input.indices)
  )
  return JSON.parse(json) as WithdrawalProof
}

// One spent input note + its Merkle path (mirrors core's `TransferInputV2`).
export interface TransferProofInputNote {
  amount: number // lamports (JSON number; serde u64)
  blinding_hex: string
  privkey_hex: string
  path_hex: string[]
  indices: boolean[]
}

// One created output note (mirrors core's `TransferOutputV2`). `pubkey_hex` is
// the recipient's spend public key, so only they can later spend the note.
export interface TransferProofOutputNote {
  amount: number
  blinding_hex: string
  pubkey_hex: string
}

export interface TransferProof {
  nullifiers: string[] // 2 hex
  output_commitments: string[] // 2 hex
  proof: string // hex
}

// Build a shielded → shielded transfer proof in the browser. Fixed 2-in/2-out;
// all notes share one `assetId` (all-zero = native SOL).
export async function proveTransferV2(
  root: string,
  assetIdHex: string,
  inputs: TransferProofInputNote[],
  outputs: TransferProofOutputNote[]
): Promise<TransferProof> {
  const key = await ensureTransferReady()
  const json = prove_transfer_v2(
    key,
    root,
    assetIdHex,
    JSON.stringify(inputs),
    JSON.stringify(outputs)
  )
  return JSON.parse(json) as TransferProof
}


// ===== circuit v3 (#350): unified transact =====

// v3 spend public key (`Poseidon1(privkey)`, circom Poseidon).
export async function v3NotePubkey(privkeyHex: string): Promise<string> {
  await ensureInit()
  return v3_note_pubkey(privkeyHex)
}

// v3 note commitment `Poseidon4(amount, pubkey, blinding, 0)` — the exact
// leaf `deposit_note` appends on-chain.
export async function v3NoteCommitment(
  amount: bigint,
  pubkeyHex: string,
  blindingHex: string
): Promise<string> {
  await ensureInit()
  return v3_note_commitment(amount, pubkeyHex, blindingHex)
}

// Asset-aware v3 commitment (#779): pass the note's assetId (all-zero for native
// SOL, or `assetIdForMint(mint)` for a shielded SPL note) to locate its leaf.
export async function v3NoteCommitmentAsset(
  amount: bigint,
  pubkeyHex: string,
  blindingHex: string,
  assetIdHex: string
): Promise<string> {
  await ensureInit()
  return v3_note_commitment_asset(amount, pubkeyHex, blindingHex, assetIdHex)
}

// Rebuild the v3 tree from the ordered leaf list (public on-chain events) and
// return `{ path: string[32], root: string }` for `leafIndex` — computed
// locally so no validator learns which leaf is ours.
export async function v3MerklePath(
  leavesHex: string[],
  leafIndex: number
): Promise<{ path: string[]; root: string }> {
  await ensureInit()
  return JSON.parse(v3_merkle_path(JSON.stringify(leavesHex), leafIndex))
}

export interface TransactProofInput {
  amount: bigint
  privkeyHex: string
  blindingHex: string
  leafIndex: number
  pathHex: string[]
}

export interface TransactProofOutput {
  amount: bigint
  pubkeyHex: string
  blindingHex: string
}

function formatU64Literal(amount: bigint): string {
  const v = BigInt(amount)
  if (v < 0n || v > 0xffffffffffffffffn) {
    throw new RangeError("note amount out of u64 range")
  }
  return v.toString(10)
}

export function serializeTransactInputsJson(
  inputs: [TransactProofInput, TransactProofInput]
): string {
  return `[${inputs
    .map(
      (i) =>
        `{"amount":${formatU64Literal(i.amount)},"privkey_hex":${JSON.stringify(
          i.privkeyHex
        )},"blinding_hex":${JSON.stringify(i.blindingHex)},"leaf_index":${JSON.stringify(
          i.leafIndex
        )},"path_hex":${JSON.stringify(i.pathHex)}}`
    )
    .join(",")}]`
}

export function serializeTransactOutputsJson(
  outputs: [TransactProofOutput, TransactProofOutput]
): string {
  return `[${outputs
    .map(
      (o) =>
        `{"amount":${formatU64Literal(o.amount)},"pubkey_hex":${JSON.stringify(
          o.pubkeyHex
        )},"blinding_hex":${JSON.stringify(o.blindingHex)}}`
    )
    .join(",")}]`
}

// Build the v3 transact proof in the extension (fixed 2-in/2-out; a padding
// input has amount 0). Returns the raw prover JSON
// ({ nullifiers, output_commitments, proof }) that `submitTransact` wraps
// into the ingress body.
export async function proveTransact(
  rootHex: string,
  extAmount: bigint,
  recipientHex: string,
  assetIdHex: string,
  inputs: [TransactProofInput, TransactProofInput],
  outputs: [TransactProofOutput, TransactProofOutput]
): Promise<string> {
  const pk = await ensureTransactReady()
  const inputsJson = serializeTransactInputsJson(inputs)
  const outputsJson = serializeTransactOutputsJson(outputs)
  return prove_transact(
    pk,
    rootHex,
    BigInt(extAmount),
    recipientHex,
    assetIdHex,
    inputsJson,
    outputsJson
  )
}

