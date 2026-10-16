import { sha256 } from "@noble/hashes/sha256"
import * as nacl from "tweetnacl"

// A v2 shielded address is `paraloom1` + a 128-hex body (box pubkey 64 hex +
// spend pubkey 64 hex) + an 8-hex checksum. The checksum closes #781: the body
// carries no self-describing structure, so a length-preserving typo (one wrong
// character, or two swapped) used to pass a length-only check and strand the
// transfer at an address that decrypts to nothing spendable, with no recovery.
// The checksum makes such a typo fail validation before anything is sent.
export const SHIELDED_BODY_HEX = 128
export const SHIELDED_CHECKSUM_HEX = 8

// BN254 scalar field modulus r (big-endian interpretation used by v3_note_pubkey
// and v3_note_commitment in paraloom-prover-wasm). Every valid spend public key
// derived by Poseidon over BN254 Fr is strictly in [1, BN254_SCALAR_MODULUS - 1].
export const BN254_SCALAR_MODULUS =
  0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n

// Fixed clamped X25519 scalar `8 * (2^251 + 1)` used to reject all 8 low-order
// Curve25519/twist points. Because `0 < 2^251 + 1 < min(l, l')` and both group
// prime orders `l` and `l'` are prime, `scalarMult(PROBE_SCALAR, P)` is all-zero
// if and only if `8 * P = O` (i.e. `P` is a low-order point).
const X25519_LOW_ORDER_PROBE_SCALAR = (() => {
  const s = new Uint8Array(32)
  s[0] = 8
  s[31] = 0x40
  return s
})()

export function isCanonicalSpendPubHex(spendPubHex: string): boolean {
  if (spendPubHex.length !== 64 || !/^[0-9a-fA-F]{64}$/.test(spendPubHex)) {
    return false
  }
  const scalar = BigInt(`0x${spendPubHex}`)
  return scalar > 0n && scalar < BN254_SCALAR_MODULUS
}

export function isContributoryBoxPubHex(boxPubHex: string): boolean {
  if (boxPubHex.length !== 64 || !/^[0-9a-fA-F]{64}$/.test(boxPubHex)) {
    return false
  }
  const pubBytes = Uint8Array.from(Buffer.from(boxPubHex, "hex"))
  if (pubBytes.length !== 32) return false
  const shared = nacl.scalarMult(X25519_LOW_ORDER_PROBE_SCALAR, pubBytes)
  let diff = 0
  for (let i = 0; i < shared.length; i++) {
    diff |= shared[i]
  }
  return diff !== 0
}

// 8-hex checksum over the 64 raw payload bytes (box || spend): the first 4 bytes
// of their SHA-256, Bitcoin-style. 32 bits, so a random corruption slips through
// only ~1 in 4 billion.
export function shieldedChecksum(bodyHex: string): string {
  const bytes = Uint8Array.from(Buffer.from(bodyHex, "hex"))
  return Buffer.from(sha256(bytes).slice(0, 4)).toString("hex")
}

// Append the checksum to a 128-hex body, producing the address suffix after the
// `paraloom1` prefix.
export function withChecksum(bodyHex: string): string {
  return bodyHex + shieldedChecksum(bodyHex)
}

// Validate a full `paraloom1…` address and return its 128-hex body, or null if
// the prefix, length, hex, checksum, box pubkey, or spend pubkey is invalid.
// A checksum-less legacy address (128-hex body, no checksum) is rejected by
// design: accepting it would let the exact typo this guards against back in.
export function parseShieldedAddress(addr: string): string | null {
  if (!addr.startsWith("paraloom1")) return null
  const rest = addr.slice("paraloom1".length)
  if (rest.length !== SHIELDED_BODY_HEX + SHIELDED_CHECKSUM_HEX) return null
  if (!/^[0-9a-fA-F]+$/.test(rest)) return null
  const body = rest.slice(0, SHIELDED_BODY_HEX)
  const csum = rest.slice(SHIELDED_BODY_HEX).toLowerCase()
  if (shieldedChecksum(body) !== csum) return null
  const boxPubHex = body.slice(0, 64)
  const spendPubHex = body.slice(64, 128)
  if (!isContributoryBoxPubHex(boxPubHex) || !isCanonicalSpendPubHex(spendPubHex)) {
    return null
  }
  return body
}

export function isValidShieldedAddress(addr: string): boolean {
  return parseShieldedAddress(addr) !== null
}

