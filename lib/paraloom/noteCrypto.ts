// Encrypted note delivery (#196), the wallet side of paraloom-core's
// `note_crypto`. A transfer's output note is encrypted to the recipient's
// shielded address (their X25519 box public key) so only they can discover and
// spend it. NaCl `box` (X25519 + XSalsa20-Poly1305) with a fresh ephemeral
// sender key per output — byte-compatible with core's `crypto_box` (pinned by
// core's tweetnacl interop test).
//
// Wire format (matches core's canonical `EncryptedNote`, tagged since #697):
//   bundle = tag(1) || epk(32) || nonce(24) || ct   (v1 tag = 0x01;
//            ct = tag(16) || ciphertext, NaCl)
//   NotePlaintext = amount(8, LE) || blinding(32) || assetId(32)  = 72 bytes (v2)
//
// The version tag is REQUIRED: core's `/transact/submit` runs `check_relayable`
// on every ciphertext and rejects the reserved tag 0. An untagged bundle put
// `epk[0]` where the tag byte is read, so a transact was rejected whenever an
// ephemeral key happened to start with 0x00 (~0.78% per 2-output transact) and
// only succeeded on retry (paraloom-wallet#6).

// v1 envelope tag: `crypto_box` (X25519 + XSalsa20-Poly1305). The remainder is
// byte-identical to the pre-tag encoding.
const ENVELOPE_TAG_V1 = 0x01

import { randomBytes } from "@noble/hashes/utils"
import * as nacl from "tweetnacl"

// Spend-key note plaintext (#293): the recipient recomputes the commitment with
// their OWN spend key, so the plaintext only needs the value, blinding and asset
// — no recipient field.
export interface NotePlaintext {
  amount: bigint
  blindingHex: string
  assetIdHex: string
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")
}

function encodePlaintext(note: NotePlaintext): Uint8Array {
  if (note.amount < 0n || note.amount > 0xffffffffffffffffn) {
    throw new RangeError("Note amount out of u64 range")
  }
  const pt = new Uint8Array(72)
  new DataView(pt.buffer).setBigUint64(0, note.amount, true) // amount, little-endian
  pt.set(hexToBytes(note.blindingHex), 8)
  pt.set(hexToBytes(note.assetIdHex), 40)
  return pt
}

/**
 * Constant-time check that the X25519 Diffie-Hellman shared point is not the
 * all-zero output produced by the 8 low-order Curve25519/twist points
 * (paraloom-core#814). Without this check:
 *  - `encryptNote` seals the note under the public constant key `HSalsa20(0^32, 0)`,
 *    leaking the plaintext to any observer on `/transact/scan` while burning the
 *    funds to an unspendable box key;
 *  - `tryDecryptNote` accepts low-order ephemeral public keys (`epk`), allowing
 *    universal MAC forgery across wallets.
 */
export function hasContributorySharedSecret(
  secretKey: Uint8Array,
  publicKey: Uint8Array
): boolean {
  if (secretKey.length !== 32 || publicKey.length !== 32) return false
  const shared = nacl.scalarMult(secretKey, publicKey)
  let diff = 0
  for (let i = 0; i < shared.length; i++) {
    diff |= shared[i]
  }
  return diff !== 0
}

/**
 * Encrypt `note` to `recipientBoxPubHex` (a 32-byte X25519 public key, i.e. the
 * recipient's shielded address bytes) under a fresh ephemeral key. Returns the
 * hex bundle to carry in the transfer's `ciphertexts`.
 */
export function encryptNote(recipientBoxPubHex: string, note: NotePlaintext): string {
  const cleanPub = recipientBoxPubHex.startsWith("0x")
    ? recipientBoxPubHex.slice(2)
    : recipientBoxPubHex
  if (!/^[0-9a-fA-F]{64}$/.test(cleanPub)) {
    throw new Error("Invalid recipient box public key hex")
  }
  const recipientPub = hexToBytes(cleanPub)
  const ephemeral = nacl.box.keyPair()
  if (!hasContributorySharedSecret(ephemeral.secretKey, recipientPub)) {
    throw new Error("Invalid or low-order recipient box public key")
  }
  const nonce = randomBytes(nacl.box.nonceLength) // 24
  const ct = nacl.box(encodePlaintext(note), nonce, recipientPub, ephemeral.secretKey)

  const bundle = new Uint8Array(1 + 32 + 24 + ct.length)
  bundle[0] = ENVELOPE_TAG_V1
  bundle.set(ephemeral.publicKey, 1)
  bundle.set(nonce, 33)
  bundle.set(ct, 57)
  return bytesToHex(bundle)
}

/**
 * Try to decrypt a delivered ciphertext bundle with the wallet's box secret.
 * Returns the note on success, `null` otherwise (trial-decrypt: callers scan
 * every delivered note and silently skip the ones not for them).
 */
export function tryDecryptNote(boxSecretKey: Uint8Array, bundleHex: string): NotePlaintext | null {
  if (typeof bundleHex !== "string") return null
  const clean = bundleHex.startsWith("0x") ? bundleHex.slice(2) : bundleHex
  if (clean.length === 0 || clean.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(clean)) {
    return null
  }
  const bundle = hexToBytes(clean)

  // Parse the v1-tagged envelope (epk at offset 1) and, for notes delivered
  // before the tag was added, the legacy untagged one (epk at offset 0). When
  // the first byte is 0x01 both are possible (a legacy epk can start with 0x01),
  // so try tagged first then legacy; `box.open` authenticates, so only the
  // correct parse decrypts. Otherwise it can only be legacy.
  const offsets = bundle[0] === ENVELOPE_TAG_V1 ? [1, 0] : [0]
  for (const off of offsets) {
    if (bundle.length < off + 56 + 16) continue
    const epk = bundle.slice(off, off + 32)
    if (!hasContributorySharedSecret(boxSecretKey, epk)) continue
    const nonce = bundle.slice(off + 32, off + 56)
    const ct = bundle.slice(off + 56)
    const pt = nacl.box.open(ct, nonce, epk, boxSecretKey)
    if (pt && pt.length === 72) {
      return {
        amount: new DataView(pt.buffer, pt.byteOffset, 72).getBigUint64(0, true),
        blindingHex: bytesToHex(pt.slice(8, 40)),
        assetIdHex: bytesToHex(pt.slice(40, 72))
      }
    }
  }
  return null
}

