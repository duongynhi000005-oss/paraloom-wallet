import { beforeEach, describe, expect, it, vi } from "vitest"

vi.mock("~lib/prover", () => ({
  NATIVE_ASSET_HEX: "00".repeat(32),
  noteCommitmentV2: vi.fn(
    async (amount: bigint, _priv: string, blind: string, asset: string) =>
      `cm:${amount.toString()}:${blind.slice(0, 8)}:${asset.slice(0, 8)}`
  ),
  proveTransferV2: vi.fn(async () => ({
    nullifiers: ["11".repeat(32), "22".repeat(32)],
    output_commitments: ["aa".repeat(32), "bb".repeat(32)],
    proof: "cc".repeat(64)
  })),
  proveWithdrawalV2: vi.fn(async () => ({
    nullifier: "dd".repeat(32),
    proof: "ee".repeat(64)
  })),
  v3NotePubkey: vi.fn(async (priv: string) => priv)
}))

import { withChecksum } from "~lib/crypto/addressChecksum"
import {
  decryptSeedPhrase,
  encryptSeedPhrase,
  encryptWallet,
  KDF_VERSION_SCRYPT,
  type WalletKeyPair
} from "~lib/crypto/keyManagement"
import { getNotes, type ShieldedNote } from "~lib/paraloom/notes"
import {
  BN254_SCALAR_MODULUS,
  parseSolInputToLamports,
  randomBn254BlindingHex,
  serializeTransactInputsJson,
  serializeTransactOutputsJson,
  serializeTransferInputsJson,
  serializeTransferOutputsJson,
  serializeWithdrawalBodyJson
} from "~lib/paraloom/proverSerialize"
import { transfer } from "~lib/paraloom/transfer"
import { withdraw } from "~lib/paraloom/withdraw"
import {
  BASE_LOCKOUT_SECONDS,
  clearUnlockLockout,
  getStoredWallet,
  getUnlockLockoutState,
  MAX_UNLOCK_ATTEMPTS,
  migrateWalletToScrypt,
  recordFailedUnlockAttempt,
  saveEncryptedWallet
} from "~lib/storage/secure"
import { installFakeChrome } from "./support/chromeStorage"

function makeShieldedAddr(boxHex: string, spendHex: string): string {
  return `paraloom1${withChecksum(boxHex + spendHex)}`
}

function leHexToBigInt(hex: string): bigint {
  const bytes = Buffer.from(hex, "hex")
  let out = 0n
  for (let i = bytes.length - 1; i >= 0; i--) {
    out = (out << 8n) | BigInt(bytes[i])
  }
  return out
}

describe("proverSerialize exact 64-bit u64 JSON serialization", () => {
  it("preserves exact u64 integer tokens above Number.MAX_SAFE_INTEGER in proveTransact inputs and outputs", () => {
    const unsafeAmount = 9_007_199_254_740_993n // 2^53 + 1 (Number() rounds to 9007199254740992)
    const maxU64 = (1n << 64n) - 1n

    const inputsJson = serializeTransactInputsJson([
      {
        amount: unsafeAmount,
        privkeyHex: "11".repeat(32),
        blindingHex: "22".repeat(32),
        leafIndex: 42,
        pathHex: ["33".repeat(32)]
      },
      {
        amount: 0n,
        privkeyHex: "44".repeat(32),
        blindingHex: "55".repeat(32),
        leafIndex: 0,
        pathHex: ["33".repeat(32)]
      }
    ])
    expect(inputsJson).toContain(`"amount":9007199254740993`)
    expect(inputsJson).not.toContain("9007199254740992")

    const outputsJson = serializeTransactOutputsJson([
      {
        amount: maxU64,
        pubkeyHex: "66".repeat(32),
        blindingHex: "77".repeat(32)
      },
      {
        amount: unsafeAmount,
        pubkeyHex: "88".repeat(32),
        blindingHex: "99".repeat(32)
      }
    ])
    expect(outputsJson).toContain(`"amount":18446744073709551615`)
    expect(outputsJson).toContain(`"amount":9007199254740993`)
  })

  it("rejects out-of-range u64 amounts or out-of-range u32 leafIndex", () => {
    expect(() =>
      serializeTransactInputsJson([
        {
          amount: -1n,
          privkeyHex: "11".repeat(32),
          blindingHex: "22".repeat(32),
          leafIndex: 0,
          pathHex: []
        }
      ])
    ).toThrow(/out of u64 range/i)

    expect(() =>
      serializeTransactInputsJson([
        {
          amount: 1n << 64n,
          privkeyHex: "11".repeat(32),
          blindingHex: "22".repeat(32),
          leafIndex: 0,
          pathHex: []
        }
      ])
    ).toThrow(/out of u64 range/i)

    expect(() =>
      serializeTransactInputsJson([
        {
          amount: 100n,
          privkeyHex: "11".repeat(32),
          blindingHex: "22".repeat(32),
          leafIndex: 0x1_0000_0000,
          pathHex: []
        }
      ])
    ).toThrow(/out of u32 range/i)
  })

  it("preserves exact u64 integer tokens in v2 transfer and withdrawal JSON bodies", () => {
    const unsafeAmount = 9_007_199_254_740_995n
    const transferIn = serializeTransferInputsJson([
      {
        amount: unsafeAmount,
        blinding_hex: "aa".repeat(32),
        privkey_hex: "bb".repeat(32),
        path_hex: ["cc".repeat(32)],
        indices: [false]
      }
    ])
    expect(transferIn).toContain(`"amount":9007199254740995`)

    const transferOut = serializeTransferOutputsJson([
      {
        amount: unsafeAmount,
        blinding_hex: "dd".repeat(32),
        pubkey_hex: "ee".repeat(32)
      }
    ])
    expect(transferOut).toContain(`"amount":9007199254740995`)

    const withdrawJson = serializeWithdrawalBodyJson({
      nullifier: "11".repeat(32),
      recipient: "22".repeat(32),
      proof: "33".repeat(64),
      amount: unsafeAmount,
      fee: 0n
    })
    expect(withdrawJson).toContain(`"amount":9007199254740995,"fee":0`)
  })
})

describe("randomBn254BlindingHex and parseSolInputToLamports", () => {
  it("always produces canonical BN254 blindings strictly below BN254_SCALAR_MODULUS", () => {
    for (let i = 0; i < 64; i++) {
      const hex = randomBn254BlindingHex()
      expect(hex).toMatch(/^[0-9a-f]{64}$/)
      expect(leHexToBigInt(hex) < BN254_SCALAR_MODULUS).toBe(true)
    }
  })

  it("parses decimal SOL strings to exact lamports without float64 rounding or Infinity crashes", () => {
    expect(parseSolInputToLamports("1")).toBe(1_000_000_000n)
    expect(parseSolInputToLamports("0.000000001")).toBe(1n)
    expect(parseSolInputToLamports("18.012345679")).toBe(18_012_345_679n)
    expect(parseSolInputToLamports("9007199.254740993")).toBe(
      9_007_199_254_740_993n
    )

    expect(parseSolInputToLamports("")).toBeNull()
    expect(parseSolInputToLamports("0")).toBeNull()
    expect(parseSolInputToLamports("-1")).toBeNull()
    expect(parseSolInputToLamports("Infinity")).toBeNull()
    expect(parseSolInputToLamports("NaN")).toBeNull()
    expect(parseSolInputToLamports("1e9")).toBeNull()
    expect(parseSolInputToLamports("1.1234567891")).toBeNull()
  })
})

describe("v2 transfer and withdraw hardening", () => {
  const senderAddr = makeShieldedAddr("11".repeat(32), "01".repeat(32))
  const recipientAddr = makeShieldedAddr("22".repeat(32), "02".repeat(32))
  const spendPriv = "03".repeat(32)

  beforeEach(() => {
    installFakeChrome()
    vi.restoreAllMocks()
  })

  const makeNote = (overrides: Partial<ShieldedNote> = {}): ShieldedNote => ({
    amount: "5000000000",
    blinding: "04".repeat(32),
    assetId: "00".repeat(32),
    signature: "sig-1",
    createdAt: 1000,
    spent: false,
    source: "deposit",
    ...overrides
  })

  it("rejects self-transfer, invalid recipient, duplicate inputs, spent inputs, and cross-root Merkle path mismatch", async () => {
    const n1 = makeNote({ signature: "sig-1", blinding: "04".repeat(32) })
    const n2 = makeNote({ signature: "sig-2", blinding: "05".repeat(32) })

    await expect(
      transfer(senderAddr, senderAddr, "paraloom1invalid", 100n, [n1, n2], spendPriv)
    ).rejects.toThrow(/Invalid recipient/i)

    await expect(
      transfer(senderAddr, senderAddr, senderAddr, 100n, [n1, n2], spendPriv)
    ).rejects.toThrow(/own shielded address/i)

    await expect(
      transfer(senderAddr, senderAddr, recipientAddr, 100n, [n1, n1], spendPriv)
    ).rejects.toThrow(/two distinct notes/i)

    await expect(
      transfer(
        senderAddr,
        senderAddr,
        recipientAddr,
        100n,
        [{ ...n1, spent: true }, n2],
        spendPriv
      )
    ).rejects.toThrow(/already-spent/i)

    // Cross-root mismatch between input 0 and input 1
    let callCount = 0
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        callCount++
        return {
          ok: true,
          status: 200,
          json: async () => ({
            root: callCount === 1 ? "aa".repeat(32) : "bb".repeat(32),
            path: ["00".repeat(32)],
            indices: [false]
          })
        }
      })
    )

    await expect(
      transfer(senderAddr, senderAddr, recipientAddr, 100n, [n1, n2], spendPriv)
    ).rejects.toThrow(/Merkle root changed/i)
  })

  it("does not record a zero-value change note when transfer spends exact total", async () => {
    const n1 = makeNote({
      amount: "3000000000",
      signature: "sig-1",
      blinding: "04".repeat(32)
    })
    const n2 = makeNote({
      amount: "2000000000",
      signature: "sig-2",
      blinding: "05".repeat(32)
    })

    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url.includes("/merkle/path/")) {
          return {
            ok: true,
            status: 200,
            json: async () => ({
              root: "aa".repeat(32),
              path: ["00".repeat(32)],
              indices: [false]
            })
          }
        }
        return {
          ok: true,
          status: 200,
          json: async () => ({ request_id: "req-exact" })
        }
      })
    )

    const res = await transfer(
      senderAddr,
      senderAddr,
      recipientAddr,
      5_000_000_000n,
      [n1, n2],
      spendPriv
    )
    expect(res.requestId).toBe("req-exact")
    const storedNotes = await getNotes(senderAddr)
    expect(storedNotes.length).toBe(0)
  })

  it("serializes exact u64 amount in withdraw and rejects spent/zero notes", async () => {
    const spentNote = makeNote({ spent: true })
    await expect(
      withdraw(spentNote, "11111111111111111111111111111111", spendPriv)
    ).rejects.toThrow(/already-spent/i)

    let submittedBody = ""
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        if (url.includes("/merkle/path/")) {
          return {
            ok: true,
            status: 200,
            json: async () => ({
              root: "aa".repeat(32),
              path: ["00".repeat(32)],
              indices: [false]
            })
          }
        }
        submittedBody = String(init?.body ?? "")
        return {
          ok: true,
          status: 200,
          json: async () => ({ request_id: "wd-1" })
        }
      })
    )

    const largeNote = makeNote({ amount: "9007199254740993" })
    const out = await withdraw(
      largeNote,
      "11111111111111111111111111111111",
      spendPriv
    )
    expect(out.requestId).toBe("wd-1")
    expect(submittedBody).toContain(`"amount":9007199254740993`)
  })
})

describe("scrypt migration safety and persistent unlock brute-force lockout", () => {
  beforeEach(() => {
    installFakeChrome()
  })

  const dummyKp: WalletKeyPair = {
    publicKey: new Uint8Array(32).fill(1),
    secretKey: new Uint8Array(64).fill(2),
    shieldedAddress: makeShieldedAddr("11".repeat(32), "01".repeat(32)),
    boxPublicKey: new Uint8Array(32).fill(3),
    boxSecretKey: new Uint8Array(32).fill(4),
    spendPrivkey: new Uint8Array(32).fill(5)
  }

  it("refuses to bump kdfVersion to scrypt when encryptedSeedPhrase exists on disk but seedPhrase is undefined", async () => {
    const password = "correct-horse-battery-staple"
    const phrase =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    const encWallet = encryptWallet(dummyKp, password)
    await saveEncryptedWallet(
      encWallet,
      dummyKp.shieldedAddress,
      phrase,
      password
    )

    // Simulate a legacy vault (no kdfVersion, legacy-encrypted seed phrase)
    const raw = await chrome.storage.local.get("paraloom_wallet")
    raw.paraloom_wallet.wallet.kdfVersion = undefined
    await chrome.storage.local.set(raw)

    // Calling migrateWalletToScrypt with undefined seedPhrase must NOT bump kdfVersion
    await migrateWalletToScrypt(encWallet, undefined, password)
    const afterSkipped = await getStoredWallet()
    expect(afterSkipped?.kdfVersion).toBeUndefined()

    // Calling migrateWalletToScrypt with the plaintext seedPhrase upgrades both and sets kdfVersion
    await migrateWalletToScrypt(encWallet, phrase, password)
    const afterMigrated = await getStoredWallet()
    expect(afterMigrated?.kdfVersion).toBe(KDF_VERSION_SCRYPT)
    expect(
      decryptSeedPhrase(afterMigrated!.encryptedSeedPhrase!, password, false)
    ).toBe(phrase)
  })

  it("persists failed unlock attempts and enforces exponential backoff lockout across popup reloads", async () => {
    const password = "secret-password"
    const encWallet = encryptWallet(dummyKp, password)
    await saveEncryptedWallet(encWallet, dummyKp.shieldedAddress)

    const t0 = 1_700_000_000_000
    for (let i = 1; i < MAX_UNLOCK_ATTEMPTS; i++) {
      const r = await recordFailedUnlockAttempt(t0 + i * 100)
      expect(r.lockedOut).toBe(false)
      expect(r.attempts).toBe(i)
    }

    // 5th attempt triggers tier-1 lockout (30s)
    const lock1 = await recordFailedUnlockAttempt(t0 + 500)
    expect(lock1.lockedOut).toBe(true)
    expect(lock1.lockoutSeconds).toBe(BASE_LOCKOUT_SECONDS)
    expect(lock1.lockedUntil).toBe(t0 + 500 + BASE_LOCKOUT_SECONDS * 1000)

    // Reopening the popup mid-lockout still reads the persisted lockout
    const persisted = await getUnlockLockoutState()
    expect(persisted.lockedUntil).toBe(lock1.lockedUntil)
    expect(persisted.tier).toBe(1)

    // Failing another 5 times after the first lockout expires doubles the lockout to 60s (tier 2)
    const tAfterLock1 = lock1.lockedUntil + 1000
    for (let i = 1; i < MAX_UNLOCK_ATTEMPTS; i++) {
      await recordFailedUnlockAttempt(tAfterLock1 + i * 100)
    }
    const lock2 = await recordFailedUnlockAttempt(tAfterLock1 + 500)
    expect(lock2.lockedOut).toBe(true)
    expect(lock2.lockoutSeconds).toBe(BASE_LOCKOUT_SECONDS * 2)

    // Clearing lockout on successful unlock resets attempts, lockedUntil, and tier
    await clearUnlockLockout()
    const cleared = await getUnlockLockoutState()
    expect(cleared).toEqual({ attempts: 0, lockedUntil: 0, tier: 0 })
  })
})
