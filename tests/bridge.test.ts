import { Keypair, PublicKey } from "@solana/web3.js"
import type { Connection } from "@solana/web3.js"
import {
  assertCanonicalBn254FieldElement,
  BN254_FR_MODULUS,
  buildDepositSplInstruction,
  depositSpl,
  isCanonicalBn254FieldElement,
  leBytesToBigInt,
  randomFieldElement32
} from "~lib/paraloom/bridge"
import { DEPOSIT_NOTE_SPL_DISCRIMINATOR } from "~lib/paraloom/constants"
import { depositNoteInstruction } from "~lib/paraloom/transact"
import { afterEach, describe, expect, it, vi } from "vitest"

vi.mock("~lib/prover", () => ({ NATIVE_ASSET_HEX: "00".repeat(32) }))

function bigIntToLeBytes32(value: bigint): Uint8Array {
  const out = new Uint8Array(32)
  let v = value
  for (let i = 0; i < 32; i++) {
    out[i] = Number(v & 0xffn)
    v >>= 8n
  }
  return out
}

describe("BN254 canonical field element blinding (#1131)", () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it("samples canonical 32-byte LE field elements strictly below BN254 modulus p", () => {
    for (let i = 0; i < 1000; i++) {
      const sample = randomFieldElement32()
      expect(sample).toHaveLength(32)
      expect(sample[31] & 0xe0).toBe(0)
      expect(leBytesToBigInt(sample) < BN254_FR_MODULUS).toBe(true)
      expect(isCanonicalBn254FieldElement(sample)).toBe(true)
    }
  })

  it("masks 0xff high bits from crypto.getRandomValues into canonical range", () => {
    vi.spyOn(globalThis.crypto, "getRandomValues").mockImplementation((arr) => {
      if (arr instanceof Uint8Array) {
        arr.fill(0xff)
      }
      return arr
    })
    const sample = randomFieldElement32()
    expect(sample[31]).toBe(0x1f)
    expect(isCanonicalBn254FieldElement(sample)).toBe(true)
  })

  it("accepts p - 1 and rejects >= p in assertCanonicalBn254FieldElement and instruction builders", () => {
    const validPubkey = new Uint8Array(32)
    validPubkey[0] = 7
    const maxCanonical = bigIntToLeBytes32(BN254_FR_MODULUS - 1n)
    const exactModulus = bigIntToLeBytes32(BN254_FR_MODULUS)
    const unreduced = new Uint8Array(32).fill(0xff)

    expect(() =>
      assertCanonicalBn254FieldElement(maxCanonical, "blinding")
    ).not.toThrow()
    expect(() =>
      assertCanonicalBn254FieldElement(exactModulus, "blinding")
    ).toThrow(/not a canonical BN254 field element/)
    expect(() =>
      assertCanonicalBn254FieldElement(unreduced, "blinding")
    ).toThrow(/not a canonical BN254 field element/)

    const depositor = Keypair.generate().publicKey
    const mint = Keypair.generate().publicKey
    const ata = Keypair.generate().publicKey

    const ix = buildDepositSplInstruction(
      depositor,
      mint,
      ata,
      1_000_000n,
      validPubkey,
      maxCanonical
    )
    expect(Array.from(ix.data.subarray(0, 8))).toEqual(
      Array.from(DEPOSIT_NOTE_SPL_DISCRIMINATOR)
    )

    expect(() =>
      buildDepositSplInstruction(
        depositor,
        mint,
        ata,
        1_000_000n,
        validPubkey,
        exactModulus
      )
    ).toThrow(/blinding is not a canonical BN254 field element/)

    expect(() =>
      depositNoteInstruction(depositor, 1_000_000n, validPubkey, unreduced)
    ).toThrow(/blinding is not a canonical BN254 field element/)
  })

  it("depositSpl always serializes a canonical BN254 blinding even when RNG draws >= 0x30 in byte 31", async () => {
    vi.spyOn(globalThis.crypto, "getRandomValues").mockImplementation((arr) => {
      if (arr instanceof Uint8Array) {
        arr.fill(0xff)
      }
      return arr
    })

    const depositor = Keypair.generate()
    const mint = new PublicKey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
    const boxPubHex = "11".repeat(32)
    const spendPubHex = "02".repeat(32) // canonical LE field element (top byte 0x02 < 0x30)
    const shieldedAddress = `paraloom1${boxPubHex}${spendPubHex}deadbeef`

    const fakeConnection = {
      async getLatestBlockhash() {
        return {
          blockhash: "11111111111111111111111111111111",
          lastValidBlockHeight: 100
        }
      },
      async sendRawTransaction() {
        return "5wHu1qwD7q2ggb1X7sH8hV3k6yQp1n2m3k4j5h6g7f8d9s0a1q2w3e4r5t6y7u8i"
      },
      async getSignatureStatus() {
        return { value: { err: null, confirmationStatus: "confirmed" } }
      }
    } as unknown as Connection

    let submittedBlinding: Uint8Array | undefined
    const res = await depositSpl(
      fakeConnection,
      depositor,
      shieldedAddress,
      mint,
      500_000n,
      "aa".repeat(32),
      undefined,
      async (r) => {
        submittedBlinding = r.blinding
      }
    )

    expect(res.blinding[31]).toBe(0x1f)
    expect(isCanonicalBn254FieldElement(res.blinding)).toBe(true)
    expect(submittedBlinding).toEqual(res.blinding)
  })
})
