import { describe, expect, it, vi } from "vitest"

vi.mock("~lib/prover", () => ({
  v3NotePubkey: vi.fn(async (spendPrivHex: string) => spendPrivHex)
}))

import {
  isValidShieldedAddress,
  parseShieldedAddress,
  shieldedChecksum,
  withChecksum
} from "../lib/crypto/addressChecksum"
import {
  deriveKeypairFromSeed,
  normalizeSeedPhrase,
  pickDecoys,
  validateSeedPhrase
} from "../lib/crypto/keyManagement"

// A representative 128-hex body: box pubkey (64) + spend pubkey (64).
const BODY128 = "0123456789abcdef".repeat(8)
const ADDR = `paraloom1${withChecksum(BODY128)}`

describe("shielded address checksum (#781)", () => {
  it("accepts a correctly checksummed address and returns its body", () => {
    expect(isValidShieldedAddress(ADDR)).toBe(true)
    expect(parseShieldedAddress(ADDR)).toBe(BODY128)
  })

  it("rejects a one-character substitution in the body (the core #781 case)", () => {
    // Flip the first body hex digit; length is unchanged.
    const flipped = (BODY128[0] === "1" ? "2" : "1") + BODY128.slice(1)
    const bad = `paraloom1${flipped}${shieldedChecksum(BODY128)}`
    expect(bad.length).toBe(ADDR.length) // same length, only a typo
    expect(isValidShieldedAddress(bad)).toBe(false)
  })

  it("rejects two transposed characters in the body", () => {
    const arr = BODY128.split("")
    ;[arr[10], arr[11]] = [arr[11], arr[10]]
    const swapped = arr.join("")
    // Only swap if it actually changed something.
    if (swapped !== BODY128) {
      const bad = `paraloom1${swapped}${shieldedChecksum(BODY128)}`
      expect(isValidShieldedAddress(bad)).toBe(false)
    }
  })

  it("rejects a legacy checksum-less address (128-hex body, no checksum)", () => {
    expect(isValidShieldedAddress(`paraloom1${BODY128}`)).toBe(false)
  })

  it("rejects a wrong prefix and non-hex", () => {
    expect(isValidShieldedAddress(`solana1${withChecksum(BODY128)}`)).toBe(false)
    expect(isValidShieldedAddress(`paraloom1${"z".repeat(136)}`)).toBe(false)
  })

  it("round-trips: withChecksum then parse returns the same body", () => {
    expect(parseShieldedAddress(`paraloom1${withChecksum(BODY128)}`)).toBe(BODY128)
  })
})

describe("seed phrase normalization & onboarding decoy selection", () => {
  const CANONICAL =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

  it("normalizes multi-line, uppercase, and irregular whitespace mnemonics", () => {
    const messy =
      "  Abandon\nABANDON\r\nabandon\t\tabandon   abandon abandon\nabandon abandon abandon abandon abandon ABOUT  "
    expect(normalizeSeedPhrase(messy)).toBe(CANONICAL)
    expect(validateSeedPhrase(messy)).toBe(true)
  })

  it("derives the exact same Solana and shielded keys regardless of input whitespace or casing", async () => {
    const messy =
      "  Abandon\nABANDON\r\nabandon\t\tabandon   abandon abandon\nabandon abandon abandon abandon abandon ABOUT  "
    const cleanKeys = await deriveKeypairFromSeed(CANONICAL, 0)
    const messyKeys = await deriveKeypairFromSeed(messy, 0)
    expect(Buffer.from(messyKeys.publicKey).toString("hex")).toBe(
      Buffer.from(cleanKeys.publicKey).toString("hex")
    )
    expect(Buffer.from(messyKeys.secretKey).toString("hex")).toBe(
      Buffer.from(cleanKeys.secretKey).toString("hex")
    )
    expect(messyKeys.shieldedAddress).toBe(cleanKeys.shieldedAddress)
  })

  it("returns 3 distinct decoy words even when the 12-word phrase repeats words", () => {
    // CANONICAL has only 2 unique words ("abandon" x11 and "about" x1).
    // Previously `pickDecoys("about", words, 3)` returned `["abandon", "abandon", "abandon"]`.
    const words = CANONICAL.split(" ")
    const decoysForAbout = pickDecoys("about", words, 3)
    expect(decoysForAbout).toHaveLength(3)
    expect(new Set([decoysForAbout[0], decoysForAbout[1], decoysForAbout[2], "about"]).size).toBe(4)

    const decoysForAbandon = pickDecoys("abandon", words, 3)
    expect(decoysForAbandon).toHaveLength(3)
    expect(
      new Set([decoysForAbandon[0], decoysForAbandon[1], decoysForAbandon[2], "abandon"]).size
    ).toBe(4)
  })
})
