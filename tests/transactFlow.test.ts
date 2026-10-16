import { Keypair, type Connection } from "@solana/web3.js"
import { beforeEach, describe, expect, it, vi } from "vitest"
import {
  addNote,
  getNotes,
  getPendingSpends,
  shieldedBalance,
  type ShieldedNote
} from "~lib/paraloom/notes"
import { depositV3, spendV3 } from "~lib/paraloom/transactFlow"
import { installFakeChrome } from "./support/chromeStorage"

const mockLeaves: { index: number; commitmentHex: string }[] = []
let mockSubmitError: Error | null = null
let mockSendDepositSig = "sig-deposit-v3"

vi.mock("~lib/prover", () => ({
  NATIVE_ASSET_HEX: "00".repeat(32),
  v3NotePubkey: vi.fn(async (priv: string) => priv.slice(0, 64).padEnd(64, "1")),
  v3NoteCommitment: vi.fn(
    async (amount: bigint, _pub: string, blinding: string) =>
      `${amount.toString(16).padStart(16, "0")}${blinding.slice(16, 64)}`
  ),
  v3NoteCommitmentAsset: vi.fn(
    async (amount: bigint, _pub: string, blinding: string, asset: string) =>
      `${amount.toString(16).padStart(16, "0")}${asset.slice(0, 16)}${blinding.slice(32, 64)}`
  ),
  v3MerklePath: vi.fn(async (_leaves: string[], leafIndex: number) => ({
    path: Array(20).fill("00".repeat(32)),
    root: `aa${leafIndex.toString(16).padStart(62, "0")}`
  })),
  proveTransact: vi.fn(async () =>
    JSON.stringify({
      nullifiers: ["11".repeat(32), "22".repeat(32)],
      output_commitments: ["33".repeat(32), "44".repeat(32)],
      proof: "00".repeat(128)
    })
  )
}))

vi.mock("~lib/paraloom/transact", () => ({
  fetchV3Leaves: vi.fn(async () => [...mockLeaves]),
  sendDepositNote: vi.fn(
    async (
      _conn: unknown,
      _payer: unknown,
      _lamports: bigint,
      _pub: Uint8Array,
      _blind: Uint8Array,
      onSubmitted?: (sig: string) => Promise<void>
    ) => {
      if (onSubmitted) await onSubmitted(mockSendDepositSig)
      return mockSendDepositSig
    }
  ),
  submitTransact: vi.fn(async () => {
    if (mockSubmitError) throw mockSubmitError
    return { requestId: "req-1234567890" }
  })
}))

const ACCOUNT = "paraloom1" + "11".repeat(64) + "deadbeef"
const SPEND_PRIV = "22".repeat(32)
const OWN_BOX_PUB = "11".repeat(32)

beforeEach(() => {
  installFakeChrome()
  mockLeaves.length = 0
  mockSubmitError = null
  mockSendDepositSig = "sig-deposit-v3"
})

describe("spendV3 pending-spend persistence and late-settlement reconciliation", () => {
  it("persists the pending spend before confirmation and reconciles inputs + change when settled after timeout", async () => {
    const inputBlind = "ab".repeat(32)
    const inputCommitment = `${5000n.toString(16).padStart(16, "0")}${inputBlind.slice(16, 64)}`
    const parentNote: ShieldedNote = {
      amount: "5000",
      blinding: inputBlind,
      assetId: "00".repeat(32),
      signature: "sig-parent",
      createdAt: 10,
      spent: false,
      source: "deposit",
      commitment: inputCommitment,
      leafIndex: 0
    }
    await addNote(ACCOUNT, parentNote)
    mockLeaves.push({ index: 0, commitmentHex: inputCommitment })

    // Simulate a withdraw where the client poll times out (or popup closes) before
    // the 2-of-2 quorum settles the transaction on-chain.
    const res = await spendV3(
      {} as unknown as Connection,
      ACCOUNT,
      SPEND_PRIV,
      OWN_BOX_PUB,
      [parentNote],
      2000n,
      { kind: "withdraw", recipientSolanaHex: "99".repeat(32) },
      { confirmSettled: async () => false }
    )
    expect(res.settled).toBe(false)
    expect(res.changeLamports).toBe(3000n)

    // The pending spend (including the change note's blinding secret) is saved in storage.
    const pending = await getPendingSpends(ACCOUNT)
    expect(pending).toHaveLength(1)
    expect(pending[0].changeNote?.amount).toBe("3000")
    expect(pending[0].changeNote?.blinding).toMatch(/^[0-9a-f]{64}$/)

    // Now the quorum lands the transaction on-chain: outputs[0] (`settleCommitmentHex`)
    // is appended to the on-chain Merkle tree.
    mockLeaves.push({ index: 1, commitmentHex: pending[0].settleCommitmentHex })

    // If a stale caller tries to re-spend `parentNote` before refreshing UI state,
    // spendV3 reconciles pending spends against the fresh tree, marks `parentNote`
    // spent, books the 3000-lamport change note, and rejects the stale input before
    // proving a duplicate nullifier.
    await expect(
      spendV3(
        {} as unknown as Connection,
        ACCOUNT,
        SPEND_PRIV,
        OWN_BOX_PUB,
        [parentNote],
        1000n,
        { kind: "withdraw", recipientSolanaHex: "99".repeat(32) },
        { confirmSettled: async () => true }
      )
    ).rejects.toThrow(/already spent in a prior settled transaction/)

    expect(await getPendingSpends(ACCOUNT)).toEqual([])
    expect(await shieldedBalance(ACCOUNT)).toBe(3000n)

    const notes = await getNotes(ACCOUNT)
    expect(notes.find((n) => n.signature === "sig-parent")?.spent).toBe(true)
    const changeNote = notes.find((n) => n.commitment === pending[0].settleCommitmentHex)
    expect(changeNote?.spent).toBe(false)
    expect(changeNote?.amount).toBe("3000")
  })

  it("removes the pending spend record if submitTransact fails before ingress acceptance", async () => {
    const inputBlind = "cd".repeat(32)
    const inputCommitment = `${4000n.toString(16).padStart(16, "0")}${inputBlind.slice(16, 64)}`
    const parentNote: ShieldedNote = {
      amount: "4000",
      blinding: inputBlind,
      assetId: "00".repeat(32),
      signature: "sig-parent-2",
      createdAt: 10,
      spent: false,
      source: "deposit",
      commitment: inputCommitment,
      leafIndex: 0
    }
    await addNote(ACCOUNT, parentNote)
    mockLeaves.push({ index: 0, commitmentHex: inputCommitment })
    mockSubmitError = new Error("transact ingress rejected: 503 busy")

    await expect(
      spendV3(
        {} as unknown as Connection,
        ACCOUNT,
        SPEND_PRIV,
        OWN_BOX_PUB,
        [parentNote],
        1500n,
        { kind: "withdraw", recipientSolanaHex: "99".repeat(32) }
      )
    ).rejects.toThrow(/503 busy/)

    expect(await getPendingSpends(ACCOUNT)).toEqual([])
    expect(await shieldedBalance(ACCOUNT)).toBe(4000n)
  })
})

describe("depositV3 post-confirmation leaf index resolution", () => {
  it("retries getTransaction when RPC transaction indexing lags behind signature confirmation", async () => {
    const wallet = Keypair.generate()
    let attempts = 0
    const connection = {
      getTransaction: vi.fn(async () => {
        attempts++
        if (attempts < 3) return null
        return {
          meta: {
            logMessages: ["Program log: Deposit note appended at leaf 7"]
          }
        }
      })
    } as unknown as Connection

    const res = await depositV3(connection, wallet, ACCOUNT, SPEND_PRIV, 2500n)
    expect(res.leafIndex).toBe(7)
    expect(attempts).toBe(3)
    const notes = await getNotes(ACCOUNT)
    expect(notes).toHaveLength(1)
    expect(notes[0].leafIndex).toBe(7)
  })

  it("does not throw after a confirmed deposit when RPC indexing still lags, and resolves leafIndex at spend time", async () => {
    const wallet = Keypair.generate()
    const connection = {
      getTransaction: vi.fn(async () => null)
    } as unknown as Connection

    const res = await depositV3(connection, wallet, ACCOUNT, SPEND_PRIV, 6000n)
    expect(res.signature).toBe("sig-deposit-v3")
    expect(res.leafIndex).toBe(-1)

    const notesBeforeSpend = await getNotes(ACCOUNT)
    expect(notesBeforeSpend).toHaveLength(1)
    expect(notesBeforeSpend[0].leafIndex).toBeUndefined()
    expect(notesBeforeSpend[0].commitment).toBeDefined()

    // Once the deposit leaf appears in the contiguous tree (at slot 4), spending
    // the note resolves and backfills its leafIndex via ensureLeafIndex.
    for (let i = 0; i < 4; i++) {
      mockLeaves.push({ index: i, commitmentHex: `0${i}`.repeat(32) })
    }
    mockLeaves.push({ index: 4, commitmentHex: notesBeforeSpend[0].commitment! })
    const spendRes = await spendV3(
      connection,
      ACCOUNT,
      SPEND_PRIV,
      OWN_BOX_PUB,
      [notesBeforeSpend[0]],
      6000n,
      { kind: "withdraw", recipientSolanaHex: "88".repeat(32) },
      { confirmSettled: async () => true }
    )
    expect(spendRes.settled).toBe(true)

    const notesAfterSpend = await getNotes(ACCOUNT)
    expect(notesAfterSpend[0].leafIndex).toBe(4)
    expect(notesAfterSpend[0].spent).toBe(true)
  })
})
