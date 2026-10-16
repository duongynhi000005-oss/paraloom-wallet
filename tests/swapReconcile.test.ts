import { describe, expect, it, vi } from "vitest"

vi.mock("~lib/prover", () => ({ NATIVE_ASSET_HEX: "00".repeat(32) }))

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

import {
  ComputeBudgetProgram,
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  TransactionInstruction,
  TransactionMessage,
  VersionedTransaction
} from "@solana/web3.js"

import {
  associatedTokenAddress,
  base58Decode,
  buildDepositSplInstruction,
  recoverReshieldedNote
} from "../lib/paraloom/bridge"
import { TOKEN_PROGRAM_ID } from "../lib/paraloom/constants"
import {
  JUPITER_V6_PROGRAM_ID,
  validateAndDeserializeSwapTransaction,
  validateSwapRouteResponse
} from "../lib/paraloom/swapReconcileClassify"

function serializeV0TxBase64(
  payer: PublicKey,
  instructions: TransactionInstruction[],
  signers: Keypair[] = []
): string {
  const msg = new TransactionMessage({
    payerKey: payer,
    recentBlockhash: "11111111111111111111111111111111",
    instructions
  }).compileToV0Message()
  const tx = new VersionedTransaction(msg)
  if (signers.length > 0) {
    tx.sign(signers)
  }
  return Buffer.from(tx.serialize()).toString("base64")
}

function dummyJupiterIx(signer: PublicKey): TransactionInstruction {
  return new TransactionInstruction({
    programId: new PublicKey(JUPITER_V6_PROGRAM_ID),
    keys: [{ pubkey: signer, isSigner: true, isWritable: true }],
    data: Buffer.from([1, 2, 3, 4])
  })
}

describe("validateSwapRouteResponse", () => {
  it("accepts a valid swap route response with positive out_amount", () => {
    const res = validateSwapRouteResponse({
      swap_transaction: "AQAB",
      out_amount: 123_456
    })
    expect(res.out_amount).toBe(123_456)
    expect(res.swap_transaction).toBe("AQAB")
  })

  it("rejects non-positive or non-finite out_amount and empty swap_transaction", () => {
    expect(() =>
      validateSwapRouteResponse({ swap_transaction: "AQAB", out_amount: 0 })
    ).toThrow(/positive out_amount/i)
    expect(() =>
      validateSwapRouteResponse({ swap_transaction: "AQAB", out_amount: -5 })
    ).toThrow(/positive out_amount/i)
    expect(() =>
      validateSwapRouteResponse({ swap_transaction: "AQAB", out_amount: Number.NaN })
    ).toThrow(/positive out_amount/i)
    expect(() =>
      validateSwapRouteResponse({ swap_transaction: "", out_amount: 100 })
    ).toThrow(/empty swap_transaction/i)
  })
})

describe("validateAndDeserializeSwapTransaction", () => {
  const fresh = Keypair.generate()
  const attacker = Keypair.generate()
  const wsolAta = associatedTokenAddress(
    fresh.publicKey,
    new PublicKey(WSOL_MINT),
    new PublicKey(TOKEN_PROGRAM_ID)
  )

  it("accepts a valid unsigned Jupiter swap transaction with WSOL wrap and CloseAccount to fresh", () => {
    const closeAccountIx = new TransactionInstruction({
      programId: new PublicKey(TOKEN_PROGRAM_ID),
      keys: [
        { pubkey: wsolAta, isSigner: false, isWritable: true },
        { pubkey: fresh.publicKey, isSigner: false, isWritable: true },
        { pubkey: fresh.publicKey, isSigner: true, isWritable: false }
      ],
      data: Buffer.from([9]) // SPL Token CloseAccount
    })
    const b64 = serializeV0TxBase64(fresh.publicKey, [
      ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 }),
      SystemProgram.transfer({
        fromPubkey: fresh.publicKey,
        toPubkey: wsolAta,
        lamports: 10_000_000
      }),
      dummyJupiterIx(fresh.publicKey),
      closeAccountIx
    ])
    const tx = validateAndDeserializeSwapTransaction(b64, fresh.publicKey)
    expect(tx.message.staticAccountKeys[0].equals(fresh.publicKey)).toBe(true)
  })

  it("rejects a swap transaction with a mismatched fee payer or extra required signers", () => {
    const wrongPayerB64 = serializeV0TxBase64(attacker.publicKey, [
      dummyJupiterIx(attacker.publicKey)
    ])
    expect(() =>
      validateAndDeserializeSwapTransaction(wrongPayerB64, fresh.publicKey)
    ).toThrow(/fee payer/i)

    const twoSignerIx = new TransactionInstruction({
      programId: new PublicKey(JUPITER_V6_PROGRAM_ID),
      keys: [
        { pubkey: fresh.publicKey, isSigner: true, isWritable: true },
        { pubkey: attacker.publicKey, isSigner: true, isWritable: false }
      ],
      data: Buffer.from([1])
    })
    const twoSignerB64 = serializeV0TxBase64(fresh.publicKey, [twoSignerIx])
    expect(() =>
      validateAndDeserializeSwapTransaction(twoSignerB64, fresh.publicKey)
    ).toThrow(/sole signer/i)
  })

  it("rejects a pre-signed transaction or a transaction without a Jupiter instruction", () => {
    const preSignedB64 = serializeV0TxBase64(
      fresh.publicKey,
      [dummyJupiterIx(fresh.publicKey)],
      [fresh]
    )
    expect(() =>
      validateAndDeserializeSwapTransaction(preSignedB64, fresh.publicKey)
    ).toThrow(/unsigned/i)

    const noJupiterB64 = serializeV0TxBase64(fresh.publicKey, [
      ComputeBudgetProgram.setComputeUnitLimit({ units: 100_000 })
    ])
    expect(() =>
      validateAndDeserializeSwapTransaction(noJupiterB64, fresh.publicKey)
    ).toThrow(/Jupiter/i)
  })

  it("rejects external SystemProgram transfers, Assign, and unauthorized programs", () => {
    const drainSolB64 = serializeV0TxBase64(fresh.publicKey, [
      SystemProgram.transfer({
        fromPubkey: fresh.publicKey,
        toPubkey: attacker.publicKey,
        lamports: 50_000_000
      }),
      dummyJupiterIx(fresh.publicKey)
    ])
    expect(() =>
      validateAndDeserializeSwapTransaction(drainSolB64, fresh.publicKey)
    ).toThrow(/unauthorized destination/i)

    const assignB64 = serializeV0TxBase64(fresh.publicKey, [
      SystemProgram.assign({
        accountPubkey: fresh.publicKey,
        programId: attacker.publicKey
      }),
      dummyJupiterIx(fresh.publicKey)
    ])
    expect(() =>
      validateAndDeserializeSwapTransaction(assignB64, fresh.publicKey)
    ).toThrow(/SystemProgram instruction/i)

    const rogueProgIx = new TransactionInstruction({
      programId: attacker.publicKey,
      keys: [{ pubkey: fresh.publicKey, isSigner: true, isWritable: true }],
      data: Buffer.from([0])
    })
    const rogueProgB64 = serializeV0TxBase64(fresh.publicKey, [
      rogueProgIx,
      dummyJupiterIx(fresh.publicKey)
    ])
    expect(() =>
      validateAndDeserializeSwapTransaction(rogueProgB64, fresh.publicKey)
    ).toThrow(/unauthorized program/i)
  })

  it("rejects top-level SPL Token Transfer/Approve/SetAuthority and CloseAccount to an external recipient", () => {
    const directTokenTransferIx = new TransactionInstruction({
      programId: new PublicKey(TOKEN_PROGRAM_ID),
      keys: [
        { pubkey: wsolAta, isSigner: false, isWritable: true },
        { pubkey: attacker.publicKey, isSigner: false, isWritable: true },
        { pubkey: fresh.publicKey, isSigner: true, isWritable: false }
      ],
      data: Buffer.from([3, 1, 0, 0, 0, 0, 0, 0, 0]) // SPL Token Transfer (tag 3)
    })
    const tokenDrainB64 = serializeV0TxBase64(fresh.publicKey, [
      directTokenTransferIx,
      dummyJupiterIx(fresh.publicKey)
    ])
    expect(() =>
      validateAndDeserializeSwapTransaction(tokenDrainB64, fresh.publicKey)
    ).toThrow(/SPL Token instruction/i)

    const closeToAttackerIx = new TransactionInstruction({
      programId: new PublicKey(TOKEN_PROGRAM_ID),
      keys: [
        { pubkey: wsolAta, isSigner: false, isWritable: true },
        { pubkey: attacker.publicKey, isSigner: false, isWritable: true },
        { pubkey: fresh.publicKey, isSigner: true, isWritable: false }
      ],
      data: Buffer.from([9]) // CloseAccount to attacker
    })
    const closeDrainB64 = serializeV0TxBase64(fresh.publicKey, [
       dummyJupiterIx(fresh.publicKey),
      closeToAttackerIx
    ])
    expect(() =>
      validateAndDeserializeSwapTransaction(closeDrainB64, fresh.publicKey)
    ).toThrow(/CloseAccount destination must be the fresh address/i)
  })
})

describe("base58Decode and recoverReshieldedNote", () => {
  it("decodes leading '1's (zero bytes) to exact length without a spurious extra byte", () => {
    expect(Array.from(base58Decode(""))).toEqual([])
    expect(Array.from(base58Decode("1"))).toEqual([0])
    expect(Array.from(base58Decode("1111"))).toEqual([0, 0, 0, 0])
  })

  it("accepts a genuine reshield deposit and rejects third-party / wrong-mint / wrong-recipient poisoning", async () => {
    const fresh = Keypair.generate()
    const attacker = Keypair.generate()
    const usdcMint = new PublicKey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
    const fakeMint = Keypair.generate().publicKey
    const victimSpendPub = new Uint8Array(32).fill(0x11)
    const victimSpendPubHex = Buffer.from(victimSpendPub).toString("hex")
    const otherSpendPub = new Uint8Array(32).fill(0x22)
    const realBlinding = new Uint8Array(32).fill(0xaa)
    const fakeBlinding = new Uint8Array(32).fill(0xbb)

    const freshAta = associatedTokenAddress(fresh.publicKey, usdcMint)
    const attackerAta = associatedTokenAddress(attacker.publicKey, fakeMint)

    // 1. Third-party spoofed deposit referencing `fresh` as a read-only account
    const spoofedIx = buildDepositSplInstruction(
      attacker.publicKey,
      fakeMint,
      attackerAta,
      999_999n,
      victimSpendPub,
      fakeBlinding
    )
    spoofedIx.keys.push({
      pubkey: fresh.publicKey,
      isSigner: false,
      isWritable: false
    })
    const spoofedMsg = new TransactionMessage({
      payerKey: attacker.publicKey,
      recentBlockhash: "11111111111111111111111111111111",
      instructions: [spoofedIx]
    }).compileToV0Message()

    // 2. Deposit signed by fresh but for the wrong mint (fakeMint)
    const wrongMintIx = buildDepositSplInstruction(
      fresh.publicKey,
      fakeMint,
      freshAta,
      888_888n,
      victimSpendPub,
      fakeBlinding
    )
    const wrongMintMsg = new TransactionMessage({
      payerKey: fresh.publicKey,
      recentBlockhash: "11111111111111111111111111111111",
      instructions: [wrongMintIx]
    }).compileToV0Message()

    // 3. Deposit signed by fresh for USDC but crediting a different recipient spendPub
    const wrongRecipientIx = buildDepositSplInstruction(
      fresh.publicKey,
      usdcMint,
      freshAta,
      777_777n,
      otherSpendPub,
      fakeBlinding
    )
    const wrongRecipientMsg = new TransactionMessage({
      payerKey: fresh.publicKey,
      recentBlockhash: "11111111111111111111111111111111",
      instructions: [wrongRecipientIx]
    }).compileToV0Message()

    // 4. Authentic reshield deposit signed by fresh for USDC and victimSpendPub
    const validIx = buildDepositSplInstruction(
      fresh.publicKey,
      usdcMint,
      freshAta,
      500_000n,
      victimSpendPub,
      realBlinding
    )
    const validMsg = new TransactionMessage({
      payerKey: fresh.publicKey,
      recentBlockhash: "11111111111111111111111111111111",
      instructions: [validIx]
    }).compileToV0Message()

    const txBySig: Record<string, unknown> = {
      "sig-spoofed": { meta: { err: null }, transaction: { message: spoofedMsg } },
      "sig-wrong-mint": { meta: { err: null }, transaction: { message: wrongMintMsg } },
      "sig-wrong-recipient": {
        meta: { err: null },
        transaction: { message: wrongRecipientMsg }
      },
      "sig-valid": { meta: { err: null }, transaction: { message: validMsg } }
    }

    const mockConn = {
      getSignaturesForAddress: async () => [
        { signature: "sig-spoofed" },
        { signature: "sig-wrong-mint" },
        { signature: "sig-wrong-recipient" },
        { signature: "sig-valid" }
      ],
      getTransaction: async (sig: string) => txBySig[sig] ?? null
    } as unknown as Connection

    const recovered = await recoverReshieldedNote(
      mockConn,
      fresh.publicKey.toBase58(),
      {
        expectedMint: usdcMint.toBase58(),
        expectedSpendPubHex: victimSpendPubHex
      }
    )

    expect(recovered).toEqual({
      amount: "500000",
      blindingHex: Buffer.from(realBlinding).toString("hex"),
      signature: "sig-valid"
    })
  })
})

