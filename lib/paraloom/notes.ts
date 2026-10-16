// Local record of the shielded notes this wallet has deposited. Until the
// extension can scan the pool for its own notes (a viewing-key feature), the
// shielded balance is tracked here: the sum of unspent deposits. Each note
// keeps the randomness needed to spend it in a later withdrawal.

// Spend-key note (circuit v2, #293). The note is bound to the account's spend
// public key (derived from the account seed, not stored here); to spend it the
// wallet supplies that account spend privkey plus this note's `blinding`. The
// nullifier is a signature over the commitment — no per-note secret.
export interface ShieldedNote {
  amount: string // lamports, bigint serialized
  blinding: string // hex, 32 bytes (per-note randomizer)
  assetId: string // hex, 32 bytes (all-zero = native SOL)
  // The SPL mint (base58) for a shielded-token note (#779). Absent for native
  // SOL. Kept alongside `assetId` because assetId = mint_to_asset(mint) is a
  // one-way hash, and spending the note must send the mint to the ingress.
  mint?: string
  signature: string // deposit transaction (empty for discovered transfer notes)
  createdAt: number
  spent: boolean
  // Set for notes discovered by scanning transfer ciphertexts (#196). The
  // commitment is the stable identity for received notes (which have no
  // deposit signature) and the de-dup key when re-scanning.
  commitment?: string
  source?: "deposit" | "transfer"
  // Circuit v3 (#350): the note's position in the on-chain incremental tree,
  // recorded at deposit (from DepositNoteEvent) or located by commitment for
  // received notes. Spending needs it for the membership path.
  leafIndex?: number
}

const NOTES_KEY = "paraloom_notes"

type NotesByAccount = Record<string, ShieldedNote[]>

async function readAll(): Promise<NotesByAccount> {
  const stored = await chrome.storage.local.get(NOTES_KEY)
  return (stored[NOTES_KEY] as NotesByAccount) ?? {}
}

async function writeAll(all: NotesByAccount): Promise<void> {
  await chrome.storage.local.set({ [NOTES_KEY]: all })
}

export async function getNotes(account: string): Promise<ShieldedNote[]> {
  const all = await readAll()
  return all[account] ?? []
}

export async function addNote(account: string, note: ShieldedNote): Promise<void> {
  const all = await readAll()
  const existing = all[account] ?? []
  // Idempotent by (non-empty) deposit signature or commitment: the same
  // shielded note can be persisted more than once — the early on-submit persist
  // AND the end-of-flow persist AND the recovery/transfer scan all target the
  // same note — so dedupe here rather than double-counting the balance.
  if (note.signature && existing.some((n) => n.signature === note.signature)) {
    return
  }
  if (note.commitment && existing.some((n) => n.commitment === note.commitment)) {
    return
  }
  all[account] = [...existing, note]
  await writeAll(all)
}

// Mark the note with this deposit signature as spent (after a withdrawal
// settles), so it no longer counts toward the shielded balance.
export async function markNoteSpent(account: string, signature: string): Promise<void> {
  const all = await readAll()
  const notes = all[account] ?? []
  all[account] = notes.map((n) => (n.signature === signature ? { ...n, spent: true } : n))
  await writeAll(all)
}

// Add a note discovered by scanning transfer ciphertexts (#196), de-duplicated
// by commitment so re-scanning is idempotent.
export async function addDiscoveredNote(account: string, note: ShieldedNote): Promise<void> {
  const all = await readAll()
  const notes = all[account] ?? []
  if (notes.some((n) => n.commitment && n.commitment === note.commitment)) {
    return
  }
  all[account] = [...notes, note]
  await writeAll(all)
}

// Fill in a deposit note's on-chain leaf index once it is known. The note is
// persisted at submit time (before the index can be resolved) so its blinding is
// never orphaned (#791); this finalizes it by commitment. A no-op if the note is
// gone. Only writes when the index actually changes, to avoid a redundant store.
export async function setNoteLeafIndex(
  account: string,
  commitment: string,
  leafIndex: number
): Promise<void> {
  const all = await readAll()
  const notes = all[account] ?? []
  let changed = false
  all[account] = notes.map((n) => {
    if (n.commitment === commitment && n.leafIndex !== leafIndex) {
      changed = true
      return { ...n, leafIndex }
    }
    return n
  })
  if (changed) await writeAll(all)
}

// Mark a note spent by its commitment (used for transfer inputs/outputs, which
// are identified by commitment rather than a deposit signature).
export async function markNoteSpentByCommitment(account: string, commitment: string): Promise<void> {
  const all = await readAll()
  const notes = all[account] ?? []
  all[account] = notes.map((n) => (n.commitment === commitment ? { ...n, spent: true } : n))
  await writeAll(all)
}

// Mark exactly the given note spent, by whichever identity is unique to it
// (#718). Deposit notes carry a non-empty `signature` and no `commitment`;
// received and change notes carry a `commitment` and an empty `signature`.
// Matching on `signature` alone flips every empty-signature note at once —
// received and change notes vanish from the balance and re-scan does not bring
// them back — so prefer the commitment, and never match on an empty string.
export async function markNoteSpentByIdentity(account: string, note: ShieldedNote): Promise<void> {
  if (note.commitment) {
    await markNoteSpentByCommitment(account, note.commitment)
  } else if (note.signature) {
    await markNoteSpent(account, note.signature)
  }
  // A note with neither identity cannot be addressed; leaving it is safe (the
  // on-chain nullifier set is the authoritative double-spend gate) and is not
  // reachable from the current note-creation paths, which always set one.
}

// Native SOL shielded balance, in lamports. SPL notes (#779) are EXCLUDED:
// their `amount` is in the token's own base units (e.g. 6-decimal USDC), so
// summing them as lamports would corrupt the SOL figure. A note is native iff
// it carries no `mint`. Use shieldedTokenBalances() for the SPL side.
export async function shieldedBalance(account: string): Promise<bigint> {
  const notes = await getNotes(account)
  return notes
    .filter((n) => !n.spent && !n.mint)
    .reduce((sum, n) => sum + BigInt(n.amount), 0n)
}

// Unspent shielded SPL balances keyed by base58 mint (#779). Each amount is in
// that mint's own base units, kept separate from the native lamports sum.
export async function shieldedTokenBalances(
  account: string
): Promise<Record<string, bigint>> {
  const notes = await getNotes(account)
  const byMint: Record<string, bigint> = {}
  for (const n of notes) {
    if (n.spent || !n.mint) continue
    byMint[n.mint] = (byMint[n.mint] ?? 0n) + BigInt(n.amount)
  }
  return byMint
}

// Pre-confirmation record of a submitted v3 spend. Persisted before/upon
// submitTransact so that if the popup closes, the MV3 worker is evicted, or the
// quorum settles after the client poll timeout, the wallet still knows which
// inputs were committed to the spend and retains the freshly generated change
// blinding secret (`changeNote.blinding`).
export interface PendingSpend {
  // First output commitment (`outputs[0]`) of the submitted transact. On-chain
  // `transact` / `transact_spl` atomically records both input nullifiers and
  // appends both output commitments (`oc0`, `oc1`), so `settleCommitmentHex`
  // appearing in `fetchV3Leaves` is authoritative proof that `inputs` were
  // consumed and `changeNote` (if any) landed on-chain.
  settleCommitmentHex: string
  inputs: ShieldedNote[]
  changeNote?: ShieldedNote
  createdAt: number
}

const PENDING_SPENDS_KEY = "paraloom_pending_spends"
export const PENDING_SPEND_EXPIRY_MS = 300_000

type PendingSpendsByAccount = Record<string, PendingSpend[]>

async function readAllPendingSpends(): Promise<PendingSpendsByAccount> {
  const stored = await chrome.storage.local.get(PENDING_SPENDS_KEY)
  return (stored[PENDING_SPENDS_KEY] as PendingSpendsByAccount) ?? {}
}

async function writeAllPendingSpends(all: PendingSpendsByAccount): Promise<void> {
  await chrome.storage.local.set({ [PENDING_SPENDS_KEY]: all })
}

export async function getPendingSpends(account: string): Promise<PendingSpend[]> {
  const all = await readAllPendingSpends()
  return all[account] ?? []
}

export async function savePendingSpend(
  account: string,
  pending: PendingSpend
): Promise<void> {
  const all = await readAllPendingSpends()
  const existing = (all[account] ?? []).filter(
    (p) => p.settleCommitmentHex !== pending.settleCommitmentHex
  )
  all[account] = [...existing, pending]
  await writeAllPendingSpends(all)
}

export async function removePendingSpend(
  account: string,
  settleCommitmentHex: string
): Promise<void> {
  const all = await readAllPendingSpends()
  const existing = all[account] ?? []
  const next = existing.filter((p) => p.settleCommitmentHex !== settleCommitmentHex)
  if (next.length !== existing.length) {
    all[account] = next
    await writeAllPendingSpends(all)
  }
}

export async function finalizePendingSpend(
  account: string,
  settleCommitmentHex: string
): Promise<boolean> {
  const all = await readAllPendingSpends()
  const existing = all[account] ?? []
  const target = existing.find((p) => p.settleCommitmentHex === settleCommitmentHex)
  if (!target) return false
  for (const input of target.inputs) {
    await markNoteSpentByIdentity(account, input)
  }
  if (target.changeNote) {
    await addNote(account, target.changeNote)
  }
  await removePendingSpend(account, settleCommitmentHex)
  return true
}

// Reconcile pending spends against the authoritative on-chain leaf set.
// - If `settleCommitmentHex` is present in `onchainCommitments`, the spend
//   settled on-chain (regardless of how long ago it was submitted): mark its
//   inputs spent, book its change note (preserving `changeBlind`), and remove
//   the pending entry.
// - If `settleCommitmentHex` is NOT on-chain and the entry is older than
//   `PENDING_SPEND_EXPIRY_MS`, the spend never landed: drop the expired pending
//   entry and leave the input notes unspent so they remain spendable (#792).
export async function reconcilePendingSpends(
  account: string,
  onchainCommitments: Set<string>,
  now = Date.now()
): Promise<number> {
  const pendingList = await getPendingSpends(account)
  if (pendingList.length === 0) return 0

  let reconciled = 0
  const remaining: PendingSpend[] = []

  for (const pending of pendingList) {
    if (onchainCommitments.has(pending.settleCommitmentHex)) {
      for (const input of pending.inputs) {
        await markNoteSpentByIdentity(account, input)
      }
      if (pending.changeNote) {
        await addNote(account, pending.changeNote)
      }
      reconciled++
    } else if (now - pending.createdAt <= PENDING_SPEND_EXPIRY_MS) {
      remaining.push(pending)
    }
  }

  if (remaining.length !== pendingList.length) {
    const all = await readAllPendingSpends()
    all[account] = remaining
    await writeAllPendingSpends(all)
  }

  return reconciled
}

