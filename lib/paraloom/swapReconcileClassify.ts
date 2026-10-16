// Pure classification and swap-transaction validation helpers, split out so they
// carry no wasm/prover imports and can be unit-tested in isolation. See
// swapReconcile.ts and privateSwap.ts for how each helper is used.

import { PublicKey, VersionedTransaction } from "@solana/web3.js"

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

export const JUPITER_V6_PROGRAM_ID = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"
export const JUPITER_V4_PROGRAM_ID = "JUP4Fb2cqiRUcaTHdrPC8h2gNsA2ETXiPDD33WcGuJB"
const COMPUTE_BUDGET_PROGRAM_ID = "ComputeBudget111111111111111111111111111111"
const SYSTEM_PROGRAM_ID = "11111111111111111111111111111111"
const TOKEN_PROGRAM_ID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
const TOKEN_2022_PROGRAM_ID = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
const ASSOCIATED_TOKEN_PROGRAM_ID = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
const MEMO_V2_PROGRAM_ID = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
const MEMO_V1_PROGRAM_ID = "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo"

const ALLOWED_SWAP_TOP_LEVEL_PROGRAMS = new Set([
  JUPITER_V6_PROGRAM_ID,
  JUPITER_V4_PROGRAM_ID,
  COMPUTE_BUDGET_PROGRAM_ID,
  SYSTEM_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
  TOKEN_2022_PROGRAM_ID,
  ASSOCIATED_TOKEN_PROGRAM_ID,
  MEMO_V2_PROGRAM_ID,
  MEMO_V1_PROGRAM_ID
])

// Top-level SPL Token tags that must never appear outside Jupiter's CPI:
// Transfer(3), Approve(4), SetAuthority(6), Burn(8), TransferChecked(12),
// ApproveChecked(13), BurnChecked(15).
const FORBIDDEN_TOP_LEVEL_TOKEN_TAGS = new Set([3, 4, 6, 8, 12, 13, 15])

// SystemProgram instruction tags that reassign ownership or transfer with seeds:
// Assign(1), CreateAccountWithSeed(3), Allocate(8), AllocateWithSeed(9),
// AssignWithSeed(10), TransferWithSeed(11), UpgradeNonceAccount(12).
const FORBIDDEN_SYSTEM_TAGS = new Set([1, 3, 8, 9, 10, 11, 12])

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

export function validateSwapRouteResponse(raw: unknown): {
  out_amount: number
  swap_transaction: string
} {
  if (!raw || typeof raw !== "object") {
    throw new Error("swap router returned an invalid response body")
  }
  const candidate = raw as { out_amount?: unknown; swap_transaction?: unknown }
  if (
    typeof candidate.out_amount !== "number" ||
    !Number.isFinite(candidate.out_amount) ||
    candidate.out_amount <= 0
  ) {
    throw new Error("swap router returned an invalid or non-positive out_amount")
  }
  if (
    typeof candidate.swap_transaction !== "string" ||
    candidate.swap_transaction.trim().length === 0
  ) {
    throw new Error("swap router returned an empty swap_transaction")
  }
  return {
    out_amount: candidate.out_amount,
    swap_transaction: candidate.swap_transaction
  }
}

/**
 * Deserialize and validate a router-built unsigned swap transaction before
 * signing it with `expectedSigner` (`fresh.publicKey`). Enforces the
 * non-custodial invariant documented in `privateSwap.ts`:
 *   1. `expectedSigner` is the sole required signer and fee payer (`staticAccountKeys[0]`),
 *      and the transaction carries no pre-filled signatures.
 *   2. Every top-level instruction targets an allowlisted swap/setup program and
 *      at least one instruction invokes the Jupiter aggregator (`JUP6` / `JUP4`).
 *   3. Top-level `SystemProgram` transfers/creates only target `expectedSigner` or
 *      its WSOL ATA (never an external drain address), and ownership-reassignment
 *      or top-level SPL Token `Transfer` / `Approve` / `SetAuthority` instructions
 *      are rejected.
 */
export function validateAndDeserializeSwapTransaction(
  swapTransactionBase64: string,
  expectedSigner: PublicKey
): VersionedTransaction {
  if (typeof swapTransactionBase64 !== "string" || swapTransactionBase64.trim().length === 0) {
    throw new Error("swap transaction payload is empty")
  }
  const rawBytes = Uint8Array.from(Buffer.from(swapTransactionBase64, "base64"))
  if (rawBytes.length === 0) {
    throw new Error("swap transaction base64 decoded to empty bytes")
  }
  const tx = VersionedTransaction.deserialize(rawBytes)
  const msg = tx.message

  if (msg.header.numRequiredSignatures !== 1) {
    throw new Error(
      `swap transaction requires ${msg.header.numRequiredSignatures} signers; expected sole signer ${expectedSigner.toBase58()}`
    )
  }
  if (msg.staticAccountKeys.length === 0 || !msg.staticAccountKeys[0].equals(expectedSigner)) {
    throw new Error("swap transaction fee payer / signer does not match fresh address")
  }
  if (tx.signatures.length !== 1 || tx.signatures[0].some((b) => b !== 0)) {
    throw new Error("swap transaction must be unsigned before local signing")
  }

  const expectedWsolAta = PublicKey.findProgramAddressSync(
    [
      expectedSigner.toBytes(),
      new PublicKey(TOKEN_PROGRAM_ID).toBytes(),
      new PublicKey(WSOL_MINT).toBytes()
    ],
    new PublicKey(ASSOCIATED_TOKEN_PROGRAM_ID)
  )[0]

  let hasJupiterIx = false
  for (const ix of msg.compiledInstructions) {
    const programKey = msg.staticAccountKeys[ix.programIdIndex]
    if (!programKey) {
      throw new Error("swap transaction instruction references non-static programIdIndex")
    }
    const prog = programKey.toBase58()
    if (!ALLOWED_SWAP_TOP_LEVEL_PROGRAMS.has(prog)) {
      throw new Error(`swap transaction invokes unauthorized program: ${prog}`)
    }
    if (prog === JUPITER_V6_PROGRAM_ID || prog === JUPITER_V4_PROGRAM_ID) {
      hasJupiterIx = true
      continue
    }
    if (prog === SYSTEM_PROGRAM_ID) {
      if (ix.data.length < 4) {
        throw new Error("swap transaction contains truncated SystemProgram instruction")
      }
      const sysTag = new DataView(
        ix.data.buffer,
        ix.data.byteOffset,
        ix.data.byteLength
      ).getUint32(0, true)
      if (FORBIDDEN_SYSTEM_TAGS.has(sysTag)) {
        throw new Error(`swap transaction contains forbidden SystemProgram instruction (${sysTag})`)
      }
      if (sysTag === 0 || sysTag === 2) {
        const destIdx = ix.accountKeyIndexes[1]
        const destKey =
          destIdx !== undefined && destIdx < msg.staticAccountKeys.length
            ? msg.staticAccountKeys[destIdx]
            : undefined
        if (!destKey || (!destKey.equals(expectedWsolAta) && !destKey.equals(expectedSigner))) {
          throw new Error(
            "swap transaction SystemProgram transfer/create targets an unauthorized destination"
          )
        }
      }
    } else if (prog === TOKEN_PROGRAM_ID || prog === TOKEN_2022_PROGRAM_ID) {
      if (ix.data.length < 1) {
        throw new Error("swap transaction contains empty SPL Token instruction")
      }
      const tokTag = ix.data[0]
      if (FORBIDDEN_TOP_LEVEL_TOKEN_TAGS.has(tokTag)) {
        throw new Error(
          `swap transaction contains forbidden top-level SPL Token instruction (${tokTag})`
        )
      }
      if (tokTag === 9) {
        // CloseAccount: accountKeyIndexes[1] receives the reclaimed rent/WSOL lamports
        const destIdx = ix.accountKeyIndexes[1]
        const destKey =
          destIdx !== undefined && destIdx < msg.staticAccountKeys.length
            ? msg.staticAccountKeys[destIdx]
            : undefined
        if (!destKey || !destKey.equals(expectedSigner)) {
          throw new Error(
            "swap transaction CloseAccount destination must be the fresh address"
          )
        }
      }
    }
  }

  if (!hasJupiterIx) {
    throw new Error("swap transaction does not invoke a Jupiter aggregator program")
  }

  return tx
}

