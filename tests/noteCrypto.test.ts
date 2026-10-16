// The encrypted-note bundle is a cross-repository contract: paraloom-core
// carries these bytes and other wallets open them, and nothing at runtime
// tells either side it disagrees — a mismatch looks like "no notes for you",
// which is also what a correct trial-decrypt of someone else's note looks
// like. That silence is why the format is pinned here rather than left to a
// round-trip test.
//
// Layout, canonical since core #697 and adopted here in #6:
//
//     tag(1) || epk(32) || nonce(24) || ct     (v1 tag = 0x01)
//
// Two properties are load-bearing and neither is visible from a round trip:
//
//   1. The leading tag must be 0x01. Core's `/transact/submit` runs
//      `check_relayable` on every ciphertext and rejects the reserved tag 0.
//      Before #6 the wallet wrote `epk[0]` into that position, so a transact
//      failed whenever an ephemeral key started with 0x00 — about 0.78% of
//      2-output transacts, and it worked on retry.
//   2. The offsets must match core's, which is checked below against core's
//      own vector file rather than against `encryptNote`.

import { encryptNote, tryDecryptNote, type NotePlaintext } from "~lib/paraloom/noteCrypto"
import * as nacl from "tweetnacl"
import { describe, expect, it } from "vitest"
import vectors from "./vectors/note_envelope_v1.json"

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex")
const bytes = (h: string) => Uint8Array.from(Buffer.from(h, "hex"))

const TAG_V1 = 0x01
const TAG_RESERVED = 0x00

// Fixed keys and nonce — the point is that nothing here is random.
const RECIPIENT_SECRET = new Uint8Array(32).fill(0x11)
const RECIPIENT_PUB_HEX = "7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13"
const BLINDING_HEX = "aa".repeat(32)
const NATIVE_ASSET_HEX = "00".repeat(32)

const NOTE: NotePlaintext = {
  amount: 1234567890n,
  blindingHex: BLINDING_HEX,
  assetIdHex: NATIVE_ASSET_HEX
}

// Sealed with ephemeral secret 0x22*32 and nonce 0x33*24 to RECIPIENT_PUB_HEX.
// The remainder is byte-identical to the pre-#6 untagged encoding, so the two
// vectors below differ only in the leading tag.
const V1_REMAINDER_HEX =
  "0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20" +
  "333333333333333333333333333333333333333333333333" +
  "6657adb272f3800d58851114481b7608e41e58d0bee9ed5c0a18b189335e6cef" +
  "57bd9b705bac7b0fc26b247d35b956fd4011fa597059f2e9c705051ec899540d" +
  "cdc20cb008b544b77d4f068ccd7b731dffd7c96488fea449"
const V1_BUNDLE_HEX = "01" + V1_REMAINDER_HEX
const LEGACY_BUNDLE_HEX = V1_REMAINDER_HEX

// A pre-#6 untagged bundle whose ephemeral public key happens to start with
// 0x01, so its first byte is indistinguishable from a v1 tag. Sealed to
// RECIPIENT_SECRET with ephemeral secret 0x08c8 (LE) and nonce 0x44*24, over
// amount=987654321 / blinding=0xcc*32 / asset=0x00*32.
const LEGACY_AMBIGUOUS_HEX =
  "0109b13faa0aae2a5e8bcf04ac725f2d10188bcaeb68722cabc86bcea7fb1f48" +
  "444444444444444444444444444444444444444444444444" +
  "e2c3d332456d45a2faee7a02f66d8f823835ab8e1c042f3010d49ff738f408ca" +
  "682fe6df381656fca6fae776dcb7ed824397ef9be2f8bb9d1d6b6cf742d94f84" +
  "428bef7783e9d4815b38cd23dfce431a63a5840ac8261c80"

describe("v1 envelope tag (#6)", () => {
  it("prefixes every bundle with the v1 tag", () => {
    // The single assertion that would have caught #6. Deterministic, because
    // the tag no longer depends on the ephemeral key.
    expect(bytes(encryptNote(RECIPIENT_PUB_HEX, NOTE))[0]).toBe(TAG_V1)
  })

  it("never emits a bundle core's ingress would reject", () => {
    // `check_relayable` in core: empty and the reserved tag are refused, a v1
    // tag is handed to the v1 parser, anything else is relayed untouched.
    // Sampling matters here only because the pre-#6 failure was probabilistic
    // — one ephemeral key in 256 started with 0x00.
    for (let i = 0; i < 512; i++) {
      const bundle = bytes(encryptNote(RECIPIENT_PUB_HEX, NOTE))
      expect(bundle.length).toBeGreaterThan(0)
      expect(bundle[0]).not.toBe(TAG_RESERVED)
      expect(bundle.length).toBeGreaterThanOrEqual(1 + 32 + 24 + 16) // v1 minimum
    }
  })

  it("is 145 bytes for a 72-byte plaintext", () => {
    // 1 (tag) + 32 (epk) + 24 (nonce) + 16 (Poly1305) + 72 (plaintext).
    expect(bytes(encryptNote(RECIPIENT_PUB_HEX, NOTE))).toHaveLength(145)
    expect(bytes(V1_BUNDLE_HEX)).toHaveLength(145)
  })

  it("opens the fixed v1 vector", () => {
    expect(tryDecryptNote(RECIPIENT_SECRET, V1_BUNDLE_HEX)).toEqual(NOTE)
  })

  it("places epk/nonce/ct at 1/33/57", () => {
    // Opened with NaCl directly at the documented offsets, not with
    // `tryDecryptNote` — this is what catches encrypt and decrypt agreeing on
    // a wrong offset.
    const bundle = bytes(encryptNote(RECIPIENT_PUB_HEX, NOTE))
    const pt = nacl.box.open(
      bundle.slice(57),
      bundle.slice(33, 57),
      bundle.slice(1, 33),
      RECIPIENT_SECRET
    )
    expect(pt).not.toBeNull()
    expect(pt).toHaveLength(72)

    // amount is u64 little-endian at 0, blinding at 8, asset at 40.
    expect(new DataView(pt!.buffer, pt!.byteOffset, 72).getBigUint64(0, true)).toBe(1234567890n)
    expect(hex(pt!.slice(8, 40))).toBe(BLINDING_HEX)
    expect(hex(pt!.slice(40, 72))).toBe(NATIVE_ASSET_HEX)
  })

  it("uses a fresh ephemeral key per note", () => {
    // Reusing an ephemeral key across two outputs links them to the same
    // sender for anyone watching the pool.
    const a = bytes(encryptNote(RECIPIENT_PUB_HEX, NOTE)).slice(1, 33)
    const b = bytes(encryptNote(RECIPIENT_PUB_HEX, NOTE)).slice(1, 33)
    expect(hex(a)).not.toBe(hex(b))
  })
})

describe("offsets against core's canonical vectors", () => {
  // `tests/vectors/note_envelope_v1.json` is a copy of core's
  // `vectors/note_envelope_v1.json`. The bytes there are structural rather
  // than real crypto, so they cannot be decrypted — but they do pin where each
  // field sits, which is the part the two repos have to agree on. Refresh the
  // copy when core's file changes.

  it("agrees with the tag constants", () => {
    expect(vectors.tags.v1).toBe(TAG_V1)
    expect(vectors.tags.reserved).toBe(TAG_RESERVED)
  })

  it.each(vectors.encode.map((v) => [v.name, v] as const))(
    "splits the %s vector into the fields core named",
    (_name, v) => {
      const bundle = bytes(v.bytes)
      expect(bundle[0]).toBe(TAG_V1)
      expect(hex(bundle.slice(1, 33))).toBe(v.epk)
      expect(hex(bundle.slice(33, 57))).toBe(v.nonce)
      expect(hex(bundle.slice(57))).toBe(v.ct)
    }
  )

  it("emits nothing that matches a reject vector", () => {
    // Not a test of the wallet's parser — a check that what the wallet writes
    // cannot look like one of the shapes core refuses. The reserved-tag case
    // is #6 itself.
    const emitted = hex(bytes(encryptNote(RECIPIENT_PUB_HEX, NOTE)))
    for (const v of vectors.reject) {
      expect(emitted).not.toBe(v.bytes)
    }
    expect(vectors.reject.map((v) => v.error)).toContain("ReservedTag")
  })
})

describe("legacy untagged bundles", () => {
  // #6 kept the untagged reader so notes delivered before the change still
  // open. This is a read-only concession: nothing writes the old form. If the
  // legacy path is ever dropped, these three go with it.

  it("still opens a pre-#6 bundle", () => {
    expect(tryDecryptNote(RECIPIENT_SECRET, LEGACY_BUNDLE_HEX)).toEqual(NOTE)
  })

  it("resolves a legacy bundle whose epk starts with the v1 tag byte", () => {
    // The ambiguous case: the first byte is 0x01, so the tagged parse is tried
    // first and fails authentication, and the legacy parse then succeeds.
    // Getting this wrong loses exactly 1/256 of pre-#6 notes.
    expect(bytes(LEGACY_AMBIGUOUS_HEX)[0]).toBe(TAG_V1)
    expect(bytes(LEGACY_AMBIGUOUS_HEX)).toHaveLength(144)
    expect(tryDecryptNote(RECIPIENT_SECRET, LEGACY_AMBIGUOUS_HEX)).toEqual({
      amount: 987654321n,
      blindingHex: "cc".repeat(32),
      assetIdHex: NATIVE_ASSET_HEX
    })
  })

  it("does not open a legacy bundle addressed to someone else", () => {
    // The fallback widens what is parsed, not what authenticates.
    const stranger = nacl.box.keyPair()
    const legacy = bytes(encryptNote(hex(stranger.publicKey), NOTE)).slice(1)
    expect(tryDecryptNote(RECIPIENT_SECRET, hex(legacy))).toBeNull()
  })
})

describe("trial decryption", () => {
  it("round-trips a note sealed to this wallet", () => {
    const boxKeys = nacl.box.keyPair()
    expect(tryDecryptNote(boxKeys.secretKey, encryptNote(hex(boxKeys.publicKey), NOTE))).toEqual(
      NOTE
    )
  })

  it("returns null, not a throw, for a note sealed to someone else", () => {
    // Scanning calls this on every ciphertext the node delivers; a throw on a
    // stranger's note would abort the scan at the first one.
    const stranger = nacl.box.keyPair()
    expect(tryDecryptNote(RECIPIENT_SECRET, encryptNote(hex(stranger.publicKey), NOTE))).toBeNull()
  })

  it.each([
    ["empty", ""],
    ["tag alone", "01"],
    ["header only", "01" + "ab".repeat(56)],
    ["one byte short of the v1 minimum", "01" + "ab".repeat(71)]
  ])("returns null for a truncated bundle (%s)", (_label, bundleHex) => {
    expect(tryDecryptNote(RECIPIENT_SECRET, bundleHex)).toBeNull()
  })

  it("rejects a tampered ciphertext", () => {
    const flipped = bytes(V1_BUNDLE_HEX)
    flipped[100] ^= 0x01
    expect(tryDecryptNote(RECIPIENT_SECRET, hex(flipped))).toBeNull()
  })

  it("rejects a substituted ephemeral key", () => {
    // The epk is outside the AEAD, so pin that swapping it breaks the open
    // rather than silently changing the derived key.
    const swapped = bytes(V1_BUNDLE_HEX)
    swapped.set(nacl.box.keyPair().publicKey, 1)
    expect(tryDecryptNote(RECIPIENT_SECRET, hex(swapped))).toBeNull()
  })

  it("rejects an unknown version tag", () => {
    // Core relays unknown tags untouched, so the wallet will be handed them.
    // v2 bytes must not be read as v1 with a coincidentally valid shape.
    const v2 = bytes(V1_BUNDLE_HEX)
    v2[0] = 0x02
    expect(tryDecryptNote(RECIPIENT_SECRET, hex(v2))).toBeNull()
  })

  it("rejects a well-sealed payload of the wrong length", () => {
    // Authenticated, addressed to us, but not 72 bytes — a valid NaCl box is
    // not on its own a valid note.
    const eph = nacl.box.keyPair()
    const nonce = new Uint8Array(24).fill(7)
    const ct = nacl.box(new Uint8Array(71), nonce, bytes(RECIPIENT_PUB_HEX), eph.secretKey)
    const bundle = new Uint8Array(57 + ct.length)
    bundle[0] = TAG_V1
    bundle.set(eph.publicKey, 1)
    bundle.set(nonce, 33)
    bundle.set(ct, 57)
    expect(tryDecryptNote(RECIPIENT_SECRET, hex(bundle))).toBeNull()
  })

  it.each([
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880"
  ])(
    "refuses low-order Curve25519 public key %s in both encryptNote and tryDecryptNote",
    (lowOrderHex) => {
      // Sender side: refuses to seal under the public all-zero shared secret
      expect(() => encryptNote(lowOrderHex, NOTE)).toThrow(/low-order|non-contributory/)

      // Recipient side: refuses a bundle forged with a low-order epk and HSalsa20(0^32, 0)
      const lowOrderEpk = bytes(lowOrderHex)
      const sharedKey = nacl.box.before(lowOrderEpk, RECIPIENT_SECRET)
      const nonce = new Uint8Array(24).fill(0x55)
      const pt = new Uint8Array(72)
      new DataView(pt.buffer).setBigUint64(0, 5_000_000_000n, true)
      const ct = nacl.box.after(pt, nonce, sharedKey)

      const v1Forged = new Uint8Array(57 + ct.length)
      v1Forged[0] = TAG_V1
      v1Forged.set(lowOrderEpk, 1)
      v1Forged.set(nonce, 33)
      v1Forged.set(ct, 57)
      expect(tryDecryptNote(RECIPIENT_SECRET, hex(v1Forged))).toBeNull()

      const legacyForged = new Uint8Array(56 + ct.length)
      legacyForged.set(lowOrderEpk, 0)
      legacyForged.set(nonce, 32)
      legacyForged.set(ct, 56)
      expect(tryDecryptNote(RECIPIENT_SECRET, hex(legacyForged))).toBeNull()
    }
  )

  it("preserves exact u64 amounts above 2^53 - 1 and rejects out-of-range amounts", () => {
    const boxKeys = nacl.box.keyPair()
    const largeAmount = 9_007_199_254_740_993n // 2^53 + 1 (unsafe for IEEE-754 Number)
    const ctHex = encryptNote(hex(boxKeys.publicKey), {
      ...NOTE,
      amount: largeAmount
    })
    const opened = tryDecryptNote(boxKeys.secretKey, ctHex)
    expect(opened?.amount).toBe(largeAmount)

    expect(() =>
      encryptNote(hex(boxKeys.publicKey), {
        ...NOTE,
        amount: -1n
      })
    ).toThrow(/u64 range/)
    expect(() =>
      encryptNote(hex(boxKeys.publicKey), {
        ...NOTE,
        amount: 1n << 64n
      })
    ).toThrow(/u64 range/)
  })
})

