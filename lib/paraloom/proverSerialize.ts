// Exact 64-bit integer JSON serialization and input validation helpers for the
// browser prover (`lib/prover/index.ts`), v2 transfer/withdraw flows
// (`lib/paraloom/transfer.ts`, `lib/paraloom/withdraw.ts`), and popup SOL
// amount parsing (`src/popup/Home.tsx`). Kept free of `.wasm` asset imports so
// it can be unit-tested directly under Vitest.

const MAX_U64 = (1n << 64n) - 1n
const MAX_U32 = 0xffffffff

// BN254 scalar field modulus r.
export const BN254_SCALAR_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n

// Minimum transparent SOL lamports reserved to pay the base transaction fee
// when submitting a `deposit_note` transaction from the wallet.
export const SOL_DEPOSIT_FEE_RESERVE_LAMPORTS = 10_000n

export function assertU64(value: bigint | number, label = "amount"): bigint {
  let bi: bigint
  if (typeof value === "bigint") {
    bi = value
  } else if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error(`${label} must be a non-negative safe integer or bigint`)
    }
    bi = BigInt(value)
  } else {
    throw new Error(`${label} must be a bigint`)
  }
  if (bi < 0n || bi > MAX_U64) {
    throw new Error(`${label} out of u64 range: ${bi.toString()}`)
  }
  return bi
}

export function assertU32(value: number, label = "leafIndex"): number {
  if (!Number.isInteger(value) || value < 0 || value > MAX_U32) {
    throw new Error(`${label} out of u32 range: ${String(value)}`)
  }
  return value
}

export interface RawTransactInput {
  amount: bigint
  privkeyHex: string
  blindingHex: string
  leafIndex: number
  pathHex: string[]
}

export interface RawTransactOutput {
  amount: bigint
  pubkeyHex: string
  blindingHex: string
}

/**
 * Serialize v3 `TransactProofInput[]` to JSON with exact 64-bit integer
 * `amount` tokens instead of `Number(i.amount)` (which silently rounds any
 * amount above `Number.MAX_SAFE_INTEGER = 2^53 - 1` and causes the circuit
 * commitment to diverge from `v3NoteCommitment(amount: bigint)`).
 */
export function serializeTransactInputsJson(
  inputs: readonly RawTransactInput[]
): string {
  const items = inputs.map((i, idx) => {
    const amt = assertU64(i.amount, `inputs[${idx}].amount`)
    const leafIdx = assertU32(i.leafIndex, `inputs[${idx}].leafIndex`)
    return `{"amount":${amt.toString()},"privkey_hex":${JSON.stringify(
      i.privkeyHex
    )},"blinding_hex":${JSON.stringify(
      i.blindingHex
    )},"leaf_index":${leafIdx},"path_hex":${JSON.stringify(i.pathHex)}}`
  })
  return `[${items.join(",")}]`
}

/**
 * Serialize v3 `TransactProofOutput[]` to JSON with exact 64-bit integer
 * `amount` tokens instead of `Number(o.amount)`.
 */
export function serializeTransactOutputsJson(
  outputs: readonly RawTransactOutput[]
): string {
  const items = outputs.map((o, idx) => {
    const amt = assertU64(o.amount, `outputs[${idx}].amount`)
    return `{"amount":${amt.toString()},"pubkey_hex":${JSON.stringify(
      o.pubkeyHex
    )},"blinding_hex":${JSON.stringify(o.blindingHex)}}`
  })
  return `[${items.join(",")}]`
}

export interface RawTransferInputV2 {
  amount: bigint | number
  blinding_hex: string
  privkey_hex: string
  path_hex: string[]
  indices: boolean[]
}

export interface RawTransferOutputV2 {
  amount: bigint | number
  blinding_hex: string
  pubkey_hex: string
}

export function serializeTransferInputsJson(
  inputs: readonly RawTransferInputV2[]
): string {
  const items = inputs.map((i, idx) => {
    const amt = assertU64(i.amount, `inputs[${idx}].amount`)
    return `{"amount":${amt.toString()},"blinding_hex":${JSON.stringify(
      i.blinding_hex
    )},"privkey_hex":${JSON.stringify(
      i.privkey_hex
    )},"path_hex":${JSON.stringify(i.path_hex)},"indices":${JSON.stringify(
      i.indices
    )}}`
  })
  return `[${items.join(",")}]`
}

export function serializeTransferOutputsJson(
  outputs: readonly RawTransferOutputV2[]
): string {
  const items = outputs.map((o, idx) => {
    const amt = assertU64(o.amount, `outputs[${idx}].amount`)
    return `{"amount":${amt.toString()},"blinding_hex":${JSON.stringify(
      o.blinding_hex
    )},"pubkey_hex":${JSON.stringify(o.pubkey_hex)}}`
  })
  return `[${items.join(",")}]`
}

export function serializeWithdrawalBodyJson(params: {
  nullifier: string
  recipient: string
  proof: string
  amount: bigint
  fee?: bigint
}): string {
  const amt = assertU64(params.amount, "withdraw.amount")
  if (amt <= 0n) {
    throw new Error("withdraw.amount must be > 0")
  }
  const fee = assertU64(params.fee ?? 0n, "withdraw.fee")
  return `{"nullifier":${JSON.stringify(
    params.nullifier
  )},"recipient":${JSON.stringify(params.recipient)},"proof":${JSON.stringify(
    params.proof
  )},"amount":${amt.toString()},"fee":${fee.toString()}}`
}

/**
 * Generate a 32-byte random blinding scalar in canonical BN254 range
 * (`< BN254_SCALAR_MODULUS`) by masking the top 3 bits of byte 31 (`0x1f`).
 */
export function randomBn254BlindingHex(): string {
  const b = new Uint8Array(32)
  crypto.getRandomValues(b)
  b[31] &= 0x1f
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("")
}

/**
 * Parse a user-entered decimal SOL string (up to 9 fractional digits) directly
 * into a positive `bigint` lamport count without IEEE-754 floating-point
 * multiplication (`Math.round(Number(s) * 1e9)`), avoiding both float64
 * precision loss and unhandled `BigInt(Infinity)` RangeErrors.
 */
export function parseSolInputToLamports(input: string): bigint | null {
  const trimmed = input.trim()
  if (!/^\d+(?:\.\d{1,9})?$/.test(trimmed)) return null
  const [wholePart, fracPart = ""] = trimmed.split(".")
  const paddedFrac = fracPart.padEnd(9, "0")
  const lamports = BigInt(wholePart) * 1_000_000_000n + BigInt(paddedFrac)
  if (lamports <= 0n || lamports > MAX_U64) return null
  return lamports
}
