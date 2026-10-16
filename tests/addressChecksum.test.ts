import { describe, expect, it, vi } from "vitest"

vi.mock("~lib/prover", () => ({}))

import {
  BN254_SCALAR_MODULUS,
  isCanonicalSpendPubHex,
  isContributoryBoxPubHex,
  isValidShieldedAddress,
  parseShieldedAddress,
  shieldedChecksum,
  withChecksum
} from "../lib/crypto/addressChecksum"
import { addressBoxPubHex, addressSpendPubHex } from "../lib/crypto/keyManagement"

// A representative 128-hex body: box pubkey (64) + spend pubkey (64).
const VALID_BOX_PUB = "7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13"
const VALID_SPEND_PUB = "0123456789abcdef".repeat(4)
const BODY128 = `${VALID_BOX_PUB}${VALID_SPEND_PUB}`
const ADDR = `paraloom1${withChecksum(BODY128)}`

// Low-order X25519 / twist points (RFC 7748 / SafeCurves) that force
// X25519(k, P) == 0^32 for every clamped secret key k.
const LOW_ORDER_X25519_POINTS = [
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
  "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880"
]

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

describe("cryptographic component validation in shielded addresses", () => {
  it("rejects non-canonical BN254 spendPub (>= Fr::MODULUS) and zero spendPub even with valid checksum", () => {
    const modulusHex = BN254_SCALAR_MODULUS.toString(16).padStart(64, "0")
    const aboveModulusHex = (BN254_SCALAR_MODULUS + 42n).toString(16).padStart(64, "0")
    const maxSpendPubHex = (BN254_SCALAR_MODULUS - 1n).toString(16).padStart(64, "0")
    const zeroSpendPubHex = "00".repeat(32)

    expect(isCanonicalSpendPubHex(maxSpendPubHex)).toBe(true)
    expect(isCanonicalSpendPubHex(modulusHex)).toBe(false)
    expect(isCanonicalSpendPubHex(aboveModulusHex)).toBe(false)
    expect(isCanonicalSpendPubHex(zeroSpendPubHex)).toBe(false)

    const validMaxAddr = `paraloom1${withChecksum(`${VALID_BOX_PUB}${maxSpendPubHex}`)}`
    const nonCanonicalModulusAddr = `paraloom1${withChecksum(`${VALID_BOX_PUB}${modulusHex}`)}`
    const nonCanonicalAliasAddr = `paraloom1${withChecksum(`${VALID_BOX_PUB}${aboveModulusHex}`)}`
    const zeroSpendAddr = `paraloom1${withChecksum(`${VALID_BOX_PUB}${zeroSpendPubHex}`)}`

    expect(isValidShieldedAddress(validMaxAddr)).toBe(true)
    expect(isValidShieldedAddress(nonCanonicalModulusAddr)).toBe(false)
    expect(isValidShieldedAddress(nonCanonicalAliasAddr)).toBe(false)
    expect(isValidShieldedAddress(zeroSpendAddr)).toBe(false)
  })

  it.each(LOW_ORDER_X25519_POINTS)(
    "rejects low-order Curve25519 boxPub (%s) even with valid checksum",
    (lowOrderBoxHex) => {
      expect(isContributoryBoxPubHex(lowOrderBoxHex)).toBe(false)
      const forgedAddr = `paraloom1${withChecksum(`${lowOrderBoxHex}${VALID_SPEND_PUB}`)}`
      expect(isValidShieldedAddress(forgedAddr)).toBe(false)
      expect(parseShieldedAddress(forgedAddr)).toBeNull()
    }
  )

  it("enforces checksum and key validation in addressBoxPubHex and addressSpendPubHex", () => {
    expect(addressBoxPubHex(ADDR)).toBe(VALID_BOX_PUB)
    expect(addressSpendPubHex(ADDR)).toBe(VALID_SPEND_PUB)

    // Corrupted checksum must throw instead of slicing unverified hex
    const badChecksumAddr = `${ADDR.slice(0, -1)}${ADDR.endsWith("0") ? "1" : "0"}`
    expect(() => addressBoxPubHex(badChecksumAddr)).toThrow(/Invalid shielded address/)
    expect(() => addressSpendPubHex(badChecksumAddr)).toThrow(/Invalid shielded address/)

    // Non-canonical spendPub or low-order boxPub must throw even in legacy 128-hex or checksummed form
    const modulusHex = BN254_SCALAR_MODULUS.toString(16).padStart(64, "0")
    expect(() =>
      addressSpendPubHex(`paraloom1${withChecksum(`${VALID_BOX_PUB}${modulusHex}`)}`)
    ).toThrow(/Invalid shielded address/)
    expect(() =>
      addressBoxPubHex(`paraloom1${withChecksum(`${LOW_ORDER_X25519_POINTS[2]}${VALID_SPEND_PUB}`)}`)
    ).toThrow(/Invalid shielded address/)
  })
})

