// Private swap-out outputs. A private swap leaves the bought token at a FRESH,
// unlinkable address whose key the wallet generated. That key never leaves the
// wallet, so it must be persisted here or the token would be unrecoverable.
// Stored in extension-local storage (not synced).

export interface SwapOutput {
  /** The fresh, unlinkable address holding the swapped token. */
  freshAddress: string
  /** Secret key (hex) of the fresh address — needed to move the token later. */
  freshSecretKeyHex: string
  /** Output mint (base58) or "SOL". */
  outputMint: string
  /** Optional input mint (base58) or "SOL" so token-input swaps are not resumed as SOL-input swaps. */
  inputMint?: string
  /** Optional owning shielded address so multi-account wallets isolate swap outputs and recovery. */
  shieldedAddress?: string
  /** Output amount the route reported, in the out mint's base units. */
  outAmount: number
  /** The swap transaction signature. Empty until the swap leg completes; a
   *  non-empty value marks the swap done (used to find resumable strands). */
  swapSignature: string
  /** Whether the user asked to re-shield the bought token (a round trip). Saved
   *  so a resumed/recovered swap honors the original intent. */
  reshield?: boolean
  /** Set once the re-shield note has been persisted (either normally or via the
   *  recovery scan), so recovery does not re-scan a settled reshield each connect. */
  reshieldRecovered?: boolean
  createdAt: number
}

const KEY = "paraloom_swap_outputs"

let swapOutputsLock: Promise<void> = Promise.resolve()

function withSwapOutputsLock<T>(fn: () => Promise<T>): Promise<T> {
  const run = swapOutputsLock.then(fn, fn)
  swapOutputsLock = run.then(
    () => undefined,
    () => undefined
  )
  return run
}

// Upsert by freshAddress: the key is saved early (before the withdraw) so it can
// never be lost, then the same entry is updated with the realized amount +
// signature once the swap lands. Keyed on the address so the two writes collapse
// to one row.
export async function saveSwapOutput(output: SwapOutput): Promise<void> {
  return withSwapOutputsLock(async () => {
    const stored = await chrome.storage.local.get(KEY)
    const current = (stored[KEY] as SwapOutput[]) ?? []
    const i = current.findIndex((o) => o.freshAddress === output.freshAddress)
    if (i >= 0) {
      current[i] = {
        ...current[i],
        ...output,
        createdAt: current[i].createdAt || output.createdAt
      }
    } else {
      current.push(output)
    }
    await chrome.storage.local.set({ [KEY]: current })
  })
}

export async function listSwapOutputs(
  shieldedAddress?: string
): Promise<SwapOutput[]> {
  await swapOutputsLock
  const stored = await chrome.storage.local.get(KEY)
  const all = (stored[KEY] as SwapOutput[]) ?? []
  if (!shieldedAddress) return all
  return all.filter(
    (o) => !o.shieldedAddress || o.shieldedAddress === shieldedAddress
  )
}

// Drop a swap row by its fresh address. Used to clear a stale "pending" row the
// reconciler could not positively account for — the funds are already safe (the
// swap either re-shielded into the pool or its input note was never spent), so
// this only removes the misleading Activity entry, never any money.
export async function dismissSwapOutput(freshAddress: string): Promise<void> {
  return withSwapOutputsLock(async () => {
    const stored = await chrome.storage.local.get(KEY)
    const current = (stored[KEY] as SwapOutput[]) ?? []
    const next = current.filter((o) => o.freshAddress !== freshAddress)
    await chrome.storage.local.set({ [KEY]: next })
  })
}
