import { describe, expect, it } from "vitest"

import {
  classifyStrand,
  isNativeSolOutput,
  RESUME_GRACE_MS,
  RESUME_MIN_LAMPORTS,
  WSOL_MINT
} from "../lib/paraloom/swapReconcileClassify"

const OLD = RESUME_GRACE_MS + 1

describe("classifyStrand", () => {
  it("skips a row that already has a signature (done)", () => {
    expect(
      classifyStrand({
        hasSignature: true,
        ageMs: OLD,
        solLamports: 10_000_000n,
        tokenAmount: 0n
      })
    ).toBe("skip")
  })

  it("skips a row still inside the in-flight grace window", () => {
    expect(
      classifyStrand({
        hasSignature: false,
        ageMs: RESUME_GRACE_MS - 1,
        solLamports: 10_000_000n,
        tokenAmount: 5_000_000n
      })
    ).toBe("skip")
  })

  it("resumes when the fresh address still holds swappable SOL", () => {
    expect(
      classifyStrand({
        hasSignature: false,
        ageMs: OLD,
        solLamports: RESUME_MIN_LAMPORTS + 1n,
        tokenAmount: 0n
      })
    ).toBe("resume")
  })

  it("marks landed when SOL is gone but the bought token sits at the address", () => {
    expect(
      classifyStrand({
        hasSignature: false,
        ageMs: OLD,
        solLamports: RESUME_MIN_LAMPORTS,
        tokenAmount: 597_800n
      })
    ).toBe("landed")
  })

  it("leaves a strand unresolved when nothing is recoverable on-chain", () => {
    expect(
      classifyStrand({
        hasSignature: false,
        ageMs: OLD,
        solLamports: 0n,
        tokenAmount: 0n
      })
    ).toBe("unresolved")
  })

  it("prefers resume over landed when both SOL and token are present", () => {
    // A partially-funded address that also holds dust token: finishing the swap
    // of the remaining SOL is the correct move, not treating it as already done.
    expect(
      classifyStrand({
        hasSignature: false,
        ageMs: OLD,
        solLamports: RESUME_MIN_LAMPORTS + 1n,
        tokenAmount: 100n
      })
    ).toBe("resume")
  })

  it("does not resume on exactly the reserve threshold (nothing left to swap)", () => {
    expect(
      classifyStrand({
        hasSignature: false,
        ageMs: OLD,
        solLamports: RESUME_MIN_LAMPORTS,
        tokenAmount: 0n
      })
    ).toBe("unresolved")
  })
})

describe("isNativeSolOutput", () => {
  it("treats the wrapped-SOL mint as native SOL (the app sends this, not 'SOL')", () => {
    expect(isNativeSolOutput(WSOL_MINT)).toBe(true)
  })

  it("treats the literal 'SOL' as native SOL", () => {
    expect(isNativeSolOutput("SOL")).toBe(true)
  })

  it("treats USDC (any SPL mint) as NOT native SOL", () => {
    expect(isNativeSolOutput("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")).toBe(false)
  })
})

import { Keypair, type Connection } from "@solana/web3.js"
import { vi } from "vitest"

vi.mock("~lib/prover", () => ({
  NATIVE_ASSET_HEX: "00".repeat(32),
  assetIdForMint: async () => "11".repeat(32)
}))

import { recoverReshields } from "../lib/paraloom/reshieldRecovery"
import {
  dismissSwapOutput,
  listSwapOutputs,
  saveSwapOutput,
  type SwapOutput
} from "../lib/paraloom/swapOutputs"
import { reconcileSwapOutputs } from "../lib/paraloom/swapReconcile"

function installFakeChromeStorage() {
  const store: Record<string, unknown> = {}
  ;(globalThis as unknown as { chrome: unknown }).chrome = {
    storage: {
      local: {
        get: async (key: string) => {
          await new Promise((r) => setTimeout(r, 2))
          return { [key]: store[key] ? JSON.parse(JSON.stringify(store[key])) : undefined }
        },
        set: async (items: Record<string, unknown>) => {
          await new Promise((r) => setTimeout(r, 2))
          for (const [k, v] of Object.entries(items)) {
            store[k] = JSON.parse(JSON.stringify(v))
          }
        }
      }
    }
  }
}

describe("swapOutputs concurrency, createdAt preservation, and account isolation", () => {
  it("serializes concurrent saveSwapOutput and dismissSwapOutput calls without losing keys and preserves original createdAt", async () => {
    installFakeChromeStorage()
    const a1 = Keypair.generate().publicKey.toBase58()
    const a2 = Keypair.generate().publicKey.toBase58()
    const a3 = Keypair.generate().publicKey.toBase58()

    await Promise.all([
      saveSwapOutput({
        freshAddress: a1,
        freshSecretKeyHex: "aa".repeat(64),
        outputMint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        shieldedAddress: "paraloom1acct1",
        outAmount: 0,
        swapSignature: "",
        createdAt: 1000
      }),
      saveSwapOutput({
        freshAddress: a2,
        freshSecretKeyHex: "bb".repeat(64),
        outputMint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        shieldedAddress: "paraloom1acct2",
        outAmount: 0,
        swapSignature: "",
        createdAt: 2000
      }),
      saveSwapOutput({
        freshAddress: a3,
        freshSecretKeyHex: "cc".repeat(64),
        outputMint: "SOL",
        outAmount: 0,
        swapSignature: "",
        createdAt: 3000
      })
    ])

    await Promise.all([
      saveSwapOutput({
        freshAddress: a1,
        freshSecretKeyHex: "aa".repeat(64),
        outputMint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        shieldedAddress: "paraloom1acct1",
        outAmount: 500_000,
        swapSignature: "sig-a1",
        createdAt: 9999
      }),
      dismissSwapOutput(a2)
    ])

    const acct1 = await listSwapOutputs("paraloom1acct1")
    expect(acct1.map((o) => o.freshAddress)).toEqual([a1, a3])
    expect(acct1[0].createdAt).toBe(1000)
    expect(acct1[0].swapSignature).toBe("sig-a1")

    const acct2 = await listSwapOutputs("paraloom1acct2")
    expect(acct2.map((o) => o.freshAddress)).toEqual([a3])
  })
})

describe("reconcileSwapOutputs and recoverReshields", () => {
  it("does not resume a token-input swap's gas SOL as a native SOL swap, and skips failed signatures when recording landed swaps", async () => {
    installFakeChromeStorage()
    const fresh = Keypair.generate()
    const usdcMint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
    const bonkMint = "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263"

    const row: SwapOutput = {
      freshAddress: fresh.publicKey.toBase58(),
      freshSecretKeyHex: Buffer.from(fresh.secretKey).toString("hex"),
      inputMint: usdcMint,
      outputMint: bonkMint,
      shieldedAddress: "paraloom1owner",
      outAmount: 0,
      swapSignature: "",
      createdAt: Date.now() - (RESUME_GRACE_MS + 10_000)
    }
    await saveSwapOutput(row)

    const conn = {
      // Fresh address still holds 6.95M lamports of leftover gas (> RESUME_MIN_LAMPORTS = 6M)
      getBalance: async () => 6_950_000,
      getParsedTokenAccountsByOwner: async () => ({
        value: [
          {
            account: {
              data: {
                parsed: {
                  info: { tokenAmount: { amount: "42000000" } }
                }
              }
            }
          }
        ]
      }),
      getSignaturesForAddress: async () => [
        { signature: "sig-failed-attempt", err: { InstructionError: [0, "Custom"] } },
        { signature: "sig-valid-landed", err: null }
      ]
    } as unknown as Connection

    const resolved = await reconcileSwapOutputs(conn, "paraloom1owner")
    expect(resolved).toBe(1)

    const updated = await listSwapOutputs("paraloom1owner")
    expect(updated[0].swapSignature).toBe("sig-valid-landed")
    expect(updated[0].outAmount).toBe(42_000_000)
  })

  it("recoverReshields skips WSOL_MINT outputs and other accounts' swap outputs", async () => {
    installFakeChromeStorage()
    const fresh1 = Keypair.generate()
    const fresh2 = Keypair.generate()

    await saveSwapOutput({
      freshAddress: fresh1.publicKey.toBase58(),
      freshSecretKeyHex: Buffer.from(fresh1.secretKey).toString("hex"),
      outputMint: WSOL_MINT,
      shieldedAddress: "paraloom1acct1",
      outAmount: 100_000_000,
      swapSignature: "sig-wsol",
      reshield: true,
      createdAt: Date.now()
    })
    await saveSwapOutput({
      freshAddress: fresh2.publicKey.toBase58(),
      freshSecretKeyHex: Buffer.from(fresh2.secretKey).toString("hex"),
      outputMint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
      shieldedAddress: "paraloom1acct2",
      outAmount: 5_000_000,
      swapSignature: "sig-usdc",
      reshield: true,
      createdAt: Date.now()
    })

    let rpcCalls = 0
    const conn = {
      getSignaturesForAddress: async () => {
        rpcCalls += 1
        return []
      },
      getTokenAccountBalance: async () => {
        rpcCalls += 1
        return { value: { amount: "0" } }
      }
    } as unknown as Connection

    const count = await recoverReshields(conn, "paraloom1acct1")
    expect(count).toBe(0)
    expect(rpcCalls).toBe(0)
  })
})
