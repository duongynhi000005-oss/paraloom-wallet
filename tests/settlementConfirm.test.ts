import { Keypair, PublicKey, type Connection } from "@solana/web3.js"
import { describe, expect, it, vi } from "vitest"

vi.mock("~lib/prover", () => ({
  NATIVE_ASSET_HEX: "00".repeat(32),
  assetIdForMint: async () => "00".repeat(32)
}))

import { base58Decode, recoverReshieldedNote } from "../lib/paraloom/bridge"
import {
  DEPOSIT_NOTE_SPL_DISCRIMINATOR,
  PROGRAM_ID
} from "../lib/paraloom/constants"
import {
  waitForFunding,
  waitForSwapConfirmation
} from "../lib/paraloom/privateSwap"
import {
  confirmCommitmentInTree,
  type LeafRef
} from "../lib/paraloom/settlementConfirm"

const TARGET = "aa".repeat(32)
const OTHER = "bb".repeat(32)

// A deterministic clock: `now()` advances by `pollMs` on every `sleep`, so a
// timeout is reached in a fixed number of polls with no real waiting.
function fakeClock(pollMs: number) {
  let t = 0
  return {
    now: () => t,
    sleep: async (ms: number) => {
      t += ms
    },
    _pollMs: pollMs
  }
}

describe("confirmCommitmentInTree", () => {
  it("returns true when the commitment is already in the tree", async () => {
    const clock = fakeClock(1000)
    const settled = await confirmCommitmentInTree(
      async () => [{ commitmentHex: OTHER }, { commitmentHex: TARGET }],
      TARGET,
      10_000,
      1000,
      clock
    )
    expect(settled).toBe(true)
  })

  it("returns true once the commitment appears on a later poll", async () => {
    let calls = 0
    const clock = fakeClock(1000)
    const settled = await confirmCommitmentInTree(
      async (): Promise<LeafRef[]> => {
        calls += 1
        // Not there for the first two rebuilds, then it lands.
        return calls >= 3 ? [{ commitmentHex: TARGET }] : [{ commitmentHex: OTHER }]
      },
      TARGET,
      10_000,
      1000,
      clock
    )
    expect(settled).toBe(true)
    expect(calls).toBe(3)
  })

  it("returns false when the commitment never lands before the timeout", async () => {
    let calls = 0
    const clock = fakeClock(1000)
    const settled = await confirmCommitmentInTree(
      async () => {
        calls += 1
        return [{ commitmentHex: OTHER }]
      },
      TARGET,
      3000,
      1000,
      clock
    )
    // The core guard: a spend that never settles must report NOT settled, so the
    // caller leaves the inputs spendable instead of hiding them (#792).
    expect(settled).toBe(false)
    // Polls at t=0,1000,2000,3000 — the t=3000 check hits the deadline and stops.
    expect(calls).toBe(4)
  })

  it("treats a transient fetch error as a retry, not a settlement failure", async () => {
    let calls = 0
    const clock = fakeClock(1000)
    const settled = await confirmCommitmentInTree(
      async () => {
        calls += 1
        if (calls === 1) throw new Error("RPC 500")
        return [{ commitmentHex: TARGET }]
      },
      TARGET,
      10_000,
      1000,
      clock
    )
    expect(settled).toBe(true)
    expect(calls).toBe(2)
  })
})

describe("waitForFunding and waitForSwapConfirmation transient RPC resilience", () => {
  it("waitForFunding survives a transient getBalance RPC error and resolves once funded", async () => {
    let calls = 0
    const pk = Keypair.generate().publicKey
    const bal = await waitForFunding(
      {
        getBalance: async () => {
          calls += 1
          if (calls === 1) throw new Error("RPC 502 Bad Gateway")
          if (calls === 2) return 0
          return 15_000_000
        }
      },
      pk,
      5_000,
      1
    )
    expect(bal).toBe(15_000_000n)
    expect(calls).toBe(3)
  })

  it("waitForSwapConfirmation survives a transient getSignatureStatus error but throws on on-chain err", async () => {
    let calls = 0
    await expect(
      waitForSwapConfirmation(
        {
          getSignatureStatus: (async () => {
            calls += 1
            if (calls === 1) throw new Error("fetch failed")
            return { value: { err: null, confirmationStatus: "confirmed" } }
          }) as unknown as Connection["getSignatureStatus"]
        },
        "sig-ok",
        5_000,
        1
      )
    ).resolves.toBeUndefined()
    expect(calls).toBe(2)

    await expect(
      waitForSwapConfirmation(
        {
          getSignatureStatus: (async () => ({
            value: { err: { InstructionError: [0, "Custom"] }, confirmationStatus: "confirmed" }
          })) as unknown as Connection["getSignatureStatus"]
        },
        "sig-err",
        5_000,
        1
      )
    ).rejects.toThrow(/swap transaction failed on-chain/)
  })
})

describe("base58Decode and recoverReshieldedNote", () => {
  it("base58Decode handles empty and leading-'1' inputs without prepending a spurious 0x00 byte", () => {
    expect(Array.from(base58Decode(""))).toEqual([])
    expect(Array.from(base58Decode("1"))).toEqual([0])
    expect(Array.from(base58Decode("111"))).toEqual([0, 0, 0])
  })

  it("recoverReshieldedNote resolves programId via v0 loadedAddresses and inspects innerInstructions", async () => {
    const fresh = Keypair.generate().publicKey
    const progPk = new PublicKey(PROGRAM_ID)
    const ixData = new Uint8Array(80)
    ixData.set(DEPOSIT_NOTE_SPL_DISCRIMINATOR, 0)
    new DataView(ixData.buffer).setBigUint64(8, 2_500_000n, true)
    ixData.fill(0xcd, 48, 80)

    const conn = {
      getSignaturesForAddress: async () => [{ signature: "sig-v0-inner" }],
      getTransaction: async () => ({
        meta: {
          err: null,
          loadedAddresses: {
            writable: [],
            readonly: [progPk]
          },
          innerInstructions: [
            {
              index: 0,
              instructions: [
                {
                  programIdIndex: 1, // index 0 is staticAccountKeys[0], index 1 is loadedAddresses.readonly[0]
                  data: ixData
                }
              ]
            }
          ]
        },
        transaction: {
          message: {
            staticAccountKeys: [fresh],
            compiledInstructions: []
          }
        }
      })
    } as unknown as Connection

    const recovered = await recoverReshieldedNote(conn, fresh.toBase58())
    expect(recovered).toEqual({
      amount: "2500000",
      blindingHex: "cd".repeat(32),
      signature: "sig-v0-inner"
    })
  })
})
