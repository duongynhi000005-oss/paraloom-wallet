import {
  addDiscoveredNote,
  addNote,
  finalizePendingSpend,
  getNotes,
  getPendingSpends,
  markNoteSpentByIdentity,
  PENDING_SPEND_EXPIRY_MS,
  reconcilePendingSpends,
  removePendingSpend,
  savePendingSpend,
  shieldedBalance,
  shieldedTokenBalances,
  type ShieldedNote
} from "~lib/paraloom/notes"
import { beforeEach, describe, expect, it } from "vitest"
import { installFakeChrome } from "./support/chromeStorage"

const ACCOUNT = "paraloom1" + "11".repeat(64)
const OTHER_ACCOUNT = "paraloom1" + "22".repeat(64)

function deposit(overrides: Partial<ShieldedNote> = {}): ShieldedNote {
  return {
    amount: "1000",
    blinding: "aa".repeat(32),
    assetId: "00".repeat(32),
    signature: "sig-deposit",
    createdAt: 1,
    spent: false,
    source: "deposit",
    ...overrides
  }
}

function received(commitment: string, overrides: Partial<ShieldedNote> = {}): ShieldedNote {
  return {
    amount: "2000",
    blinding: "bb".repeat(32),
    assetId: "00".repeat(32),
    signature: "", // received notes have no deposit signature
    createdAt: 2,
    spent: false,
    commitment,
    source: "transfer",
    ...overrides
  }
}

beforeEach(() => {
  installFakeChrome()
})

describe("markNoteSpentByIdentity (#718)", () => {
  it("spends only the named received note, leaving the other received notes alone", async () => {
    // The bug: received and change notes all carry `signature: ""`, so
    // matching on signature flipped every one of them at once. Both notes
    // below are indistinguishable by signature and must not share a fate.
    const a = received("c0".repeat(32))
    const b = received("c1".repeat(32))
    await addDiscoveredNote(ACCOUNT, a)
    await addDiscoveredNote(ACCOUNT, b)

    await markNoteSpentByIdentity(ACCOUNT, a)

    const notes = await getNotes(ACCOUNT)
    expect(notes.find((n) => n.commitment === a.commitment)!.spent).toBe(true)
    expect(notes.find((n) => n.commitment === b.commitment)!.spent).toBe(false)
  })

  it("keeps the balance of the surviving notes", async () => {
    // The user-visible symptom was notes vanishing from the balance and not
    // coming back on re-scan, so assert the number, not just the flag.
    await addDiscoveredNote(ACCOUNT, received("c0".repeat(32)))
    await addDiscoveredNote(ACCOUNT, received("c1".repeat(32)))
    await addNote(ACCOUNT, deposit())

    await markNoteSpentByIdentity(ACCOUNT, received("c0".repeat(32)))

    expect(await shieldedBalance(ACCOUNT)).toBe(3000n)
  })

  it("spends a deposit note by signature when it has no commitment", async () => {
    await addNote(ACCOUNT, deposit({ signature: "sig-a" }))
    await addNote(ACCOUNT, deposit({ signature: "sig-b" }))

    await markNoteSpentByIdentity(ACCOUNT, deposit({ signature: "sig-a" }))

    const notes = await getNotes(ACCOUNT)
    expect(notes.find((n) => n.signature === "sig-a")!.spent).toBe(true)
    expect(notes.find((n) => n.signature === "sig-b")!.spent).toBe(false)
  })

  it("prefers the commitment when a note carries both identities", async () => {
    // A change note that also happens to carry a signature must not fall
    // through to the signature branch and take its siblings with it.
    await addDiscoveredNote(ACCOUNT, received("c0".repeat(32), { signature: "shared" }))
    await addDiscoveredNote(ACCOUNT, received("c1".repeat(32), { signature: "shared" }))

    await markNoteSpentByIdentity(ACCOUNT, received("c0".repeat(32), { signature: "shared" }))

    // Naming both notes, not just counting: a count of one is also what
    // spending the wrong note produces.
    const notes = await getNotes(ACCOUNT)
    expect(notes.find((n) => n.commitment === "c0".repeat(32))!.spent).toBe(true)
    expect(notes.find((n) => n.commitment === "c1".repeat(32))!.spent).toBe(false)
  })

  it("is a no-op for a note with neither identity", async () => {
    await addNote(ACCOUNT, deposit({ signature: "" }))
    await markNoteSpentByIdentity(ACCOUNT, deposit({ signature: "" }))
    expect((await getNotes(ACCOUNT)).every((n) => !n.spent)).toBe(true)
  })
})

describe("shielded token notes (#779)", () => {
  // Native and SPL notes live in one list and are told apart only by `mint`.
  // A note counted on the wrong side is a silent balance error, in a number
  // the user acts on.
  const USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"

  it("keeps an SPL note out of the native balance", async () => {
    await addNote(ACCOUNT, deposit({ signature: "s1" }))
    await addNote(ACCOUNT, deposit({ signature: "s2", mint: USDC, amount: "500" }))
    expect(await shieldedBalance(ACCOUNT)).toBe(1000n)
  })

  it("keeps a native note out of the token balances", async () => {
    await addNote(ACCOUNT, deposit({ signature: "s1" }))
    expect(await shieldedTokenBalances(ACCOUNT)).toEqual({})
  })

  it("sums each mint separately", async () => {
    await addNote(ACCOUNT, deposit({ signature: "s1", mint: USDC, amount: "500" }))
    await addNote(ACCOUNT, deposit({ signature: "s2", mint: USDC, amount: "250" }))
    await addNote(
      ACCOUNT,
      deposit({ signature: "s3", mint: "So11111111111111111111111111111111111111112", amount: "7" })
    )
    expect(await shieldedTokenBalances(ACCOUNT)).toEqual({
      [USDC]: 750n,
      So11111111111111111111111111111111111111112: 7n
    })
  })

  it("drops a mint once its last note is spent", async () => {
    // An empty entry reads as a token the wallet still holds.
    await addNote(ACCOUNT, deposit({ signature: "s1", mint: USDC, amount: "500", spent: true }))
    expect(await shieldedTokenBalances(ACCOUNT)).toEqual({})
  })

  it("spends an SPL note without touching a native one of the same amount", async () => {
    const spl = received("c0".repeat(32), { mint: USDC })
    await addDiscoveredNote(ACCOUNT, spl)
    await addDiscoveredNote(ACCOUNT, received("c1".repeat(32)))

    await markNoteSpentByIdentity(ACCOUNT, spl)

    expect(await shieldedTokenBalances(ACCOUNT)).toEqual({})
    expect(await shieldedBalance(ACCOUNT)).toBe(2000n)
  })
})

describe("note storage", () => {
  it("de-duplicates discovered notes by commitment, keeping the first copy", async () => {
    // Which copy survives is the part that matters, not just the count:
    // first-wins, last-wins and field-merge all keep the length at one, and
    // #718 is about spent state surviving a re-scan. First-wins means a
    // re-delivered note cannot quietly overwrite `spent` either.
    const note = received("c0".repeat(32))
    await addDiscoveredNote(ACCOUNT, note)
    await addDiscoveredNote(ACCOUNT, { ...note, createdAt: 99, amount: "5000" })

    const notes = await getNotes(ACCOUNT)
    expect(notes).toHaveLength(1)
    expect(notes[0].createdAt).toBe(2)
    expect(notes[0].amount).toBe("2000")
  })

  it("does not resurrect a spent note on re-scan", async () => {
    const note = received("c0".repeat(32))
    await addDiscoveredNote(ACCOUNT, note)
    await markNoteSpentByIdentity(ACCOUNT, note)
    await addDiscoveredNote(ACCOUNT, note) // the node delivers it again

    expect((await getNotes(ACCOUNT))[0].spent).toBe(true)
    expect(await shieldedBalance(ACCOUNT)).toBe(0n)
  })

  it("keeps accounts separate", async () => {
    await addNote(ACCOUNT, deposit())
    expect(await getNotes(OTHER_ACCOUNT)).toEqual([])
    expect(await shieldedBalance(OTHER_ACCOUNT)).toBe(0n)
  })

  it("sums lamports as bigint, not as a float", async () => {
    // Above 2^53 a Number sum silently loses precision; these two amounts
    // differ by 1 lamport and must not collapse to the same total.
    await addNote(ACCOUNT, deposit({ amount: "9007199254740993", signature: "s1" }))
    await addNote(ACCOUNT, deposit({ amount: "1", signature: "s2" }))
    expect(await shieldedBalance(ACCOUNT)).toBe(9007199254740994n)
  })

  it("excludes spent notes from the balance", async () => {
    await addNote(ACCOUNT, deposit({ signature: "s1" }))
    await addNote(ACCOUNT, deposit({ signature: "s2", spent: true }))
    expect(await shieldedBalance(ACCOUNT)).toBe(1000n)
  })

  it("de-duplicates addNote by commitment so scanForNotes + spendV3 never double-book change", async () => {
    const change = received("c9".repeat(32), { amount: "750" })
    await addDiscoveredNote(ACCOUNT, change)
    await addNote(ACCOUNT, change)

    const notes = await getNotes(ACCOUNT)
    expect(notes).toHaveLength(1)
    expect(await shieldedBalance(ACCOUNT)).toBe(750n)
  })
})

describe("pending spend persistence and reconciliation", () => {
  it("reconciles a settled pending spend by marking inputs spent and booking the change note", async () => {
    const input = deposit({ signature: "sig-parent", amount: "5000", commitment: "a0".repeat(32) })
    const change = received("b0".repeat(32), { amount: "3500", blinding: "cc".repeat(32) })
    await addNote(ACCOUNT, input)
    await savePendingSpend(ACCOUNT, {
      settleCommitmentHex: "b0".repeat(32),
      inputs: [input],
      changeNote: change,
      createdAt: 100
    })

    // Before settlement lands on-chain, inputs stay unspent and change is not booked (#792).
    const preReconciled = await reconcilePendingSpends(
      ACCOUNT,
      new Set(["a0".repeat(32)]),
      1_000
    )
    expect(preReconciled).toBe(0)
    expect(await shieldedBalance(ACCOUNT)).toBe(5000n)
    expect(await getPendingSpends(ACCOUNT)).toHaveLength(1)

    // Once the output commitment lands on-chain (even after PENDING_SPEND_EXPIRY_MS),
    // the parent input is marked spent and the change note with its blinding is booked.
    const postReconciled = await reconcilePendingSpends(
      ACCOUNT,
      new Set(["a0".repeat(32), "b0".repeat(32)]),
      100 + PENDING_SPEND_EXPIRY_MS + 60_000
    )
    expect(postReconciled).toBe(1)
    expect(await getPendingSpends(ACCOUNT)).toEqual([])
    expect(await shieldedBalance(ACCOUNT)).toBe(3500n)

    const notes = await getNotes(ACCOUNT)
    expect(notes.find((n) => n.signature === "sig-parent")!.spent).toBe(true)
    const bookedChange = notes.find((n) => n.commitment === "b0".repeat(32))!
    expect(bookedChange.spent).toBe(false)
    expect(bookedChange.blinding).toBe("cc".repeat(32))
  })

  it("expires an unsettled pending spend after PENDING_SPEND_EXPIRY_MS while keeping inputs spendable", async () => {
    const input = deposit({ signature: "sig-parent", amount: "5000" })
    await addNote(ACCOUNT, input)
    await savePendingSpend(ACCOUNT, {
      settleCommitmentHex: "d0".repeat(32),
      inputs: [input],
      changeNote: received("d0".repeat(32), { amount: "2000" }),
      createdAt: 100
    })

    const reconciled = await reconcilePendingSpends(
      ACCOUNT,
      new Set(),
      100 + PENDING_SPEND_EXPIRY_MS + 1
    )
    expect(reconciled).toBe(0)
    expect(await getPendingSpends(ACCOUNT)).toEqual([])
    expect(await shieldedBalance(ACCOUNT)).toBe(5000n)
    expect((await getNotes(ACCOUNT))[0].spent).toBe(false)
  })

  it("supports removePendingSpend and finalizePendingSpend directly", async () => {
    const input = deposit({ signature: "sig-direct", amount: "4000" })
    const change = received("e0".repeat(32), { amount: "1500" })
    await addNote(ACCOUNT, input)
    await savePendingSpend(ACCOUNT, {
      settleCommitmentHex: "e0".repeat(32),
      inputs: [input],
      changeNote: change,
      createdAt: 1
    })
    await savePendingSpend(ACCOUNT, {
      settleCommitmentHex: "f0".repeat(32),
      inputs: [input],
      createdAt: 1
    })

    await removePendingSpend(ACCOUNT, "f0".repeat(32))
    expect(await getPendingSpends(ACCOUNT)).toHaveLength(1)

    expect(await finalizePendingSpend(ACCOUNT, "e0".repeat(32))).toBe(true)
    expect(await getPendingSpends(ACCOUNT)).toEqual([])
    expect(await shieldedBalance(ACCOUNT)).toBe(1500n)
  })
})

