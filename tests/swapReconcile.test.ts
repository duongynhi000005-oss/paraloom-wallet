import { describe, expect, it } from "vitest"

import {
  classifyStrand,
  formatSwapAmount,
  isNativeSolOutput,
  MAX_SWAP_SLIPPAGE_BPS,
  MAX_U64,
  RESUME_GRACE_MS,
  RESUME_MIN_LAMPORTS,
  validateSwapRequestParams,
  WSOL_MINT
} from "../lib/paraloom/swapReconcileClassify"

const OLD = RESUME_GRACE_MS + 1
const USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"

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
    expect(isNativeSolOutput(USDC_MINT)).toBe(false)
  })
})

describe("validateSwapRequestParams", () => {
  it("accepts valid SOL -> SPL and SPL -> SOL swap requests", () => {
    const solToSpl = validateSwapRequestParams({
      outputMint: USDC_MINT,
      amountLamports: "1000000000",
      slippageBps: 50
    })
    expect(solToSpl).toEqual({
      inputMint: undefined,
      outputMint: USDC_MINT,
      amountLamports: "1000000000",
      amount: 1_000_000_000n,
      slippageBps: 50,
      reshield: undefined
    })

    const splToSol = validateSwapRequestParams({
      inputMint: USDC_MINT,
      outputMint: WSOL_MINT,
      amountLamports: MAX_U64.toString(),
      slippageBps: MAX_SWAP_SLIPPAGE_BPS
    })
    expect(splToSol.amount).toBe(MAX_U64)
  })

  it("rejects non-base58 or missing mints before opening consent popup", () => {
    expect(() =>
      validateSwapRequestParams({
        outputMint: "not-a-valid-mint!!!",
        amountLamports: "1000000"
      })
    ).toThrow(/invalid outputMint/)

    expect(() =>
      validateSwapRequestParams({
        inputMint: "bad-input-mint",
        outputMint: USDC_MINT,
        amountLamports: "1000000"
      })
    ).toThrow(/invalid inputMint/)
  })

  it("rejects swapping an asset into itself (including SOL <-> WSOL)", () => {
    expect(() =>
      validateSwapRequestParams({
        inputMint: "SOL",
        outputMint: WSOL_MINT,
        amountLamports: "1000000"
      })
    ).toThrow(/different assets/)

    expect(() =>
      validateSwapRequestParams({
        inputMint: USDC_MINT,
        outputMint: USDC_MINT,
        amountLamports: "1000000"
      })
    ).toThrow(/different assets/)
  })

  it("rejects zero, negative, non-canonical, or > u64::MAX amounts", () => {
    expect(() =>
      validateSwapRequestParams({ outputMint: USDC_MINT, amountLamports: "0" })
    ).toThrow(/u64 range/)
    expect(() =>
      validateSwapRequestParams({ outputMint: USDC_MINT, amountLamports: "-100" })
    ).toThrow(/invalid amountLamports/)
    expect(() =>
      validateSwapRequestParams({ outputMint: USDC_MINT, amountLamports: "1e9" })
    ).toThrow(/invalid amountLamports/)
    expect(() =>
      validateSwapRequestParams({
        outputMint: USDC_MINT,
        amountLamports: (MAX_U64 + 1n).toString()
      })
    ).toThrow(/u64 range/)
  })

  it("rejects out-of-range or non-integer slippageBps", () => {
    expect(() =>
      validateSwapRequestParams({
        outputMint: USDC_MINT,
        amountLamports: "1000000",
        slippageBps: 0
      })
    ).toThrow(/slippageBps/)
    expect(() =>
      validateSwapRequestParams({
        outputMint: USDC_MINT,
        amountLamports: "1000000",
        slippageBps: MAX_SWAP_SLIPPAGE_BPS + 1
      })
    ).toThrow(/slippageBps/)
    expect(() =>
      validateSwapRequestParams({
        outputMint: USDC_MINT,
        amountLamports: "1000000",
        slippageBps: 12.5
      })
    ).toThrow(/slippageBps/)
  })
})

describe("formatSwapAmount", () => {
  it("formats sub-micro SOL amounts accurately without rounding to '0'", () => {
    // Previously `(Number(lamports) / 1e9).toFixed(6)` turned < 500 lamports into "0".
    expect(formatSwapAmount("1", 9)).toBe("0.000000001")
    expect(formatSwapAmount("499", 9)).toBe("0.000000499")
    expect(formatSwapAmount("1500000000", 9)).toBe("1.5")
  })

  it("preserves exact integer precision above Number.MAX_SAFE_INTEGER", () => {
    // 18_446_744_073_709_551_615 lamports = 18,446,744,073.709551615 SOL
    expect(formatSwapAmount(MAX_U64.toString(), 9)).toBe("18,446,744,073.709551615")
  })
})
