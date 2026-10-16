// Pure classification for the swap reconciler, split out so it carries no heavy
// imports (prover / wasm) and can be unit-tested in isolation. See
// swapReconcile.ts for how each verdict is acted on.

// A swap younger than this may still be in flight; do not touch it. Matches the
// page-side swap timeout budget with headroom.
export const RESUME_GRACE_MS = 120_000
// Below this the fresh address never received the withdraw (only rent dust), so
// the input note is still unspent and safe in the pool. Mirrors the swap
// overhead reserve in privateSwap.
export const RESUME_MIN_LAMPORTS = 6_000_000n

/** Wrapped-SOL mint. The swaps app sends this as `outputMint` for a SOL output
 *  (not the literal "SOL"), and Jupiter unwraps it to native SOL on the way out.
 *  Both spellings must count as native SOL so a token->SOL round trip re-shields
 *  a native note (and displays as SOL) instead of mis-handling it as an SPL. */
export const WSOL_MINT = "So11111111111111111111111111111111111111112"

/** True when `outputMint` denotes native SOL (the literal "SOL" or the wrapped
 *  mint). Kept here (no heavy imports) so it is unit-testable. */
export function isNativeSolOutput(mint: string): boolean {
  return mint === "SOL" || mint === WSOL_MINT
}

export type StrandAction = "skip" | "resume" | "landed" | "unresolved"

/// Decide what to do with a stranded swap row from its on-chain footprint.
///  - skip:       already recorded, or still inside the in-flight grace window.
///  - resume:     the fresh address holds swappable SOL → finish the swap leg.
///  - landed:     SOL is gone but the bought token sits there → record it done.
///  - unresolved: nothing recoverable → leave for the user to dismiss manually.
export function classifyStrand(args: {
  hasSignature: boolean
  ageMs: number
  solLamports: bigint
  tokenAmount: bigint
}): StrandAction {
  if (args.hasSignature) return "skip"
  if (args.ageMs < RESUME_GRACE_MS) return "skip"
  if (args.solLamports > RESUME_MIN_LAMPORTS) return "resume"
  if (args.tokenAmount > 0n) return "landed"
  return "unresolved"
}

export const DEFAULT_SWAP_SLIPPAGE_BPS = 100
export const MAX_SWAP_SLIPPAGE_BPS = 5000
export const MAX_U64 = (1n << 64n) - 1n
const B58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

function isValidBase58Pubkey(s: string): boolean {
  if (typeof s !== "string" || s.length < 32 || s.length > 44) return false
  const bytes: number[] = []
  for (const ch of s) {
    const v = B58_ALPHABET.indexOf(ch)
    if (v < 0) return false
    let carry = v
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58
      bytes[j] = carry & 0xff
      carry >>= 8
    }
    while (carry > 0) {
      bytes.push(carry & 0xff)
      carry >>= 8
    }
  }
  let leadingZeros = 0
  while (leadingZeros < s.length && s[leadingZeros] === "1") {
    leadingZeros++
  }
  return leadingZeros + bytes.length === 32
}

export function isValidSwapMint(mint: string): boolean {
  return mint === "SOL" || isValidBase58Pubkey(mint)
}

export interface ValidatedSwapRequestParams {
  outputMint: string
  inputMint?: string
  amountLamports: string
  amount: bigint
  slippageBps: number
  reshield?: boolean
}

/**
 * Validate page-supplied `PRIVATE_SWAP` parameters before opening the approval
 * popup or executing a spend. Rejects non-canonical or out-of-range u64 amounts,
 * malformed base58 mints, identical input/output assets, and out-of-bounds
 * slippage tolerances (`1..=5000` bps).
 */
export function validateSwapRequestParams(
  raw: unknown
): ValidatedSwapRequestParams {
  if (!raw || typeof raw !== "object") {
    throw new Error("invalid swap params")
  }
  const p = raw as Record<string, unknown>
  if (typeof p.outputMint !== "string" || !isValidSwapMint(p.outputMint)) {
    throw new Error("invalid outputMint")
  }
  let inputMint: string | undefined
  if (p.inputMint !== undefined) {
    if (typeof p.inputMint !== "string" || !isValidSwapMint(p.inputMint)) {
      throw new Error("invalid inputMint")
    }
    inputMint = p.inputMint
  }
  const inputIsSol = !inputMint || isNativeSolOutput(inputMint)
  const outputIsSol = isNativeSolOutput(p.outputMint)
  if ((inputIsSol && outputIsSol) || (inputMint && inputMint === p.outputMint)) {
    throw new Error("inputMint and outputMint must be different assets")
  }
  if (typeof p.amountLamports !== "string" || !/^\d+$/.test(p.amountLamports)) {
    throw new Error("invalid amountLamports")
  }
  const amount = BigInt(p.amountLamports)
  if (amount <= 0n || amount > MAX_U64) {
    throw new Error("amountLamports out of u64 range")
  }
  let slippageBps = DEFAULT_SWAP_SLIPPAGE_BPS
  if (p.slippageBps !== undefined) {
    if (
      typeof p.slippageBps !== "number" ||
      !Number.isInteger(p.slippageBps) ||
      p.slippageBps < 1 ||
      p.slippageBps > MAX_SWAP_SLIPPAGE_BPS
    ) {
      throw new Error(`slippageBps must be an integer in 1..=${MAX_SWAP_SLIPPAGE_BPS}`)
    }
    slippageBps = p.slippageBps
  }
  if (p.reshield !== undefined && typeof p.reshield !== "boolean") {
    throw new Error("invalid reshield flag")
  }
  return {
    outputMint: p.outputMint,
    inputMint: p.inputMint as string | undefined,
    amountLamports: amount.toString(),
    amount,
    slippageBps,
    reshield: p.reshield as boolean | undefined
  }
}

/**
 * Format a base-unit decimal integer string using exact `BigInt` arithmetic so
 * large `u64` amounts (`> 2^53 - 1`) never suffer IEEE-754 precision loss and
 * small non-zero amounts (e.g. `< 500` lamports of 9-decimal SOL) never round
 * down to `"0"` on the swap approval consent screen.
 */
export function formatSwapAmount(amount: string, decimals: number): string {
  if (typeof amount !== "string" || !/^\d+$/.test(amount.trim())) {
    return amount
  }
  const raw = BigInt(amount.trim())
  if (decimals <= 0) {
    return raw.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",")
  }
  const base = 10n ** BigInt(decimals)
  const whole = raw / base
  const frac = raw % base
  const wholeFormatted = whole.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",")
  if (frac === 0n) {
    return wholeFormatted
  }
  const fracPadded = frac.toString().padStart(decimals, "0").replace(/0+$/, "")
  return `${wholeFormatted}.${fracPadded}`
}

