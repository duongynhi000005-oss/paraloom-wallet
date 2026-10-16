import * as bip39 from "bip39"
import { sha256 } from "@noble/hashes/sha256"
import { scrypt } from "@noble/hashes/scrypt"
import { randomBytes } from "@noble/hashes/utils"

import {
  isCanonicalSpendPubHex,
  isContributoryBoxPubHex,
  parseShieldedAddress,
  SHIELDED_BODY_HEX,
  SHIELDED_CHECKSUM_HEX,
  withChecksum
} from "./addressChecksum"
import * as nacl from "tweetnacl"

// Circuit v3 (#350): the address carries the circom-Poseidon spend pubkey the
// v3 note commitments bind to. Addresses derived before the v3 cutover used
// the old sponge Poseidon and died with the pool reset.
import { v3NotePubkey as deriveSpendPub } from "~lib/prover"

// scrypt parameters for password-based key derivation.
// N=2^15 / r=8 / p=1 → ~100ms in-popup, 32 MiB memory-hard work factor.
// Memory-hardness is what makes this resist the GPU/ASIC brute-force that
// the old plain-SHA-256 chain was wide open to.
const SCRYPT_PARAMS = { N: 2 ** 15, r: 8, p: 1, dkLen: 32 } as const

// KDF version stored alongside the wallet so old vaults stay decryptable.
// 1 = scrypt (current). Absence / undefined = legacy SHA-256 chain.
export const KDF_VERSION_SCRYPT = 1

export interface WalletKeyPair {
  publicKey: Uint8Array
  secretKey: Uint8Array
  shieldedAddress: string
  // X25519 box keypair for encrypted note delivery (#196). Derived from the
  // ed25519 secret (its first 32 bytes are the account seed), so it is not
  // stored in the vault — it is reconstructed on every unlock.
  boxPublicKey: Uint8Array
  boxSecretKey: Uint8Array
  // Spend private key for circuit v2 (#293): binds note commitments and signs
  // nullifiers. Derived from the account seed, reconstructed on every unlock.
  spendPrivkey: Uint8Array
}

/**
 * Derive the X25519 (NaCl box) keypair from an ed25519 secret key. The first
 * 32 bytes of a tweetnacl sign secret key are the account seed; box keys are
 * derived from it so the seed phrase alone recovers everything (#196).
 */
export function deriveBoxKeypair(ed25519SecretKey: Uint8Array): nacl.BoxKeyPair {
  return nacl.box.keyPair.fromSecretKey(ed25519SecretKey.slice(0, 32))
}

/**
 * Derive the circuit-v2 spend private key from an ed25519 secret key, domain-
 * separated so it is independent of the sign and box keys (#293). The first 32
 * bytes of the sign secret key are the account seed, so the seed phrase alone
 * recovers it.
 */
export function deriveSpendPrivkey(ed25519SecretKey: Uint8Array): Uint8Array {
  const accountSeed = ed25519SecretKey.slice(0, 32)
  const tag = new TextEncoder().encode("paraloom-spend-v2")
  const input = new Uint8Array(tag.length + accountSeed.length)
  input.set(tag)
  input.set(accountSeed, tag.length)
  return sha256(input)
}

/**
 * The v2 shielded address (#293), `paraloom1<boxPub(64hex)><spendPub(64hex)>`:
 * the box public key for encrypted note delivery and the spend public key a
 * sender binds an output note to. Async because the spend pubkey is a Poseidon
 * hash computed in the wasm prover.
 */
export async function deriveShieldedAddress(
  boxPublicKey: Uint8Array,
  spendPrivkey: Uint8Array
): Promise<string> {
  const boxHex = Buffer.from(boxPublicKey).toString("hex")
  const spendHex = await deriveSpendPub(Buffer.from(spendPrivkey).toString("hex"))
  const body = `${boxHex}${spendHex}`
  return `paraloom1${withChecksum(body)}`
}

function extractValidatedShieldedBody(shieldedAddress: string): string {
  if (!shieldedAddress.startsWith("paraloom1")) {
    throw new Error("Invalid shielded address: missing paraloom1 prefix")
  }
  const rest = shieldedAddress.slice("paraloom1".length)
  if (rest.length === SHIELDED_BODY_HEX + SHIELDED_CHECKSUM_HEX) {
    const body = parseShieldedAddress(shieldedAddress)
    if (!body) {
      throw new Error("Invalid shielded address")
    }
    return body.toLowerCase()
  }
  if (rest.length === SHIELDED_BODY_HEX && /^[0-9a-fA-F]{128}$/.test(rest)) {
    const boxPubHex = rest.slice(0, 64)
    const spendPubHex = rest.slice(64, 128)
    if (!isContributoryBoxPubHex(boxPubHex) || !isCanonicalSpendPubHex(spendPubHex)) {
      throw new Error("Invalid shielded address: non-canonical or low-order public key")
    }
    return rest.toLowerCase()
  }
  throw new Error("Invalid shielded address")
}

/** The box (encryption) public key half of a v2 shielded address, hex. */
export function addressBoxPubHex(shieldedAddress: string): string {
  return extractValidatedShieldedBody(shieldedAddress).slice(0, 64)
}

/** The spend (commitment-binding) public key half of a v2 shielded address, hex. */
export function addressSpendPubHex(shieldedAddress: string): string {
  return extractValidatedShieldedBody(shieldedAddress).slice(64, 128)
}

export interface EncryptedWallet {
  encrypted: string
  nonce: string
  salt: string
}

/**
 * Generate a new seed phrase (12 words)
 */
export function generateSeedPhrase(): string {
  const entropy = randomBytes(16) // 128 bits = 12 words
  return bip39.entropyToMnemonic(Buffer.from(entropy))
}

/**
 * Validate seed phrase
 */
export function validateSeedPhrase(seedPhrase: string): boolean {
  return bip39.validateMnemonic(seedPhrase)
}

/**
 * Derive an ed25519 keypair from a BIP39 mnemonic and account index.
 *
 * NOTE: this is a Paraloom-specific derivation, NOT the standard Solana
 * BIP44/SLIP-0010 path `m/44'/501'/{accountIndex}'/0'`. The account seed is
 * `SHA-256(bip39_seed || u32be(accountIndex))`, fed straight into
 * `nacl.sign.keyPair.fromSeed` — no chain code, no per-component hardened child
 * derivation. It is deterministic and reproduces the same accounts across
 * installs, but a mnemonic exported from a standard-path wallet (e.g. Phantom)
 * derives DIFFERENT accounts here, and vice versa. An offline recovery tool must
 * reproduce THIS exact mapping, not the SLIP-0010 path.
 *
 * Switching to the standard path is a breaking migration, not an edit: the
 * primary wallet's keys are stored directly in the encrypted vault while the
 * account list is reconstructed from index on unlock, so a silent change would
 * leave the two on different algorithms. Any such change must ship a
 * derivation-version marker (#3).
 */
export async function deriveKeypairFromSeed(
  seedPhrase: string,
  accountIndex: number = 0
): Promise<WalletKeyPair> {
  if (!validateSeedPhrase(seedPhrase)) {
    throw new Error("Invalid seed phrase")
  }

  // Convert seed to bytes
  const seed = bip39.mnemonicToSeedSync(seedPhrase)

  // Derive account-specific seed by hashing with account index
  const accountIndexBytes = new Uint8Array(4)
  new DataView(accountIndexBytes.buffer).setUint32(0, accountIndex, false)

  const combined = new Uint8Array(seed.length + accountIndexBytes.length)
  combined.set(seed)
  combined.set(accountIndexBytes, seed.length)

  const accountSeed = sha256(combined)

  // Derive Ed25519 keypair from account seed
  const keypair = nacl.sign.keyPair.fromSeed(accountSeed)

  // X25519 box keypair (encrypted note delivery, #196) + spend keypair (v2
  // commitment binding, #293). The shielded address carries both pubkeys.
  const box = deriveBoxKeypair(keypair.secretKey)
  const spendPrivkey = deriveSpendPrivkey(keypair.secretKey)
  const shieldedAddress = await deriveShieldedAddress(box.publicKey, spendPrivkey)

  return {
    publicKey: keypair.publicKey,
    secretKey: keypair.secretKey,
    shieldedAddress,
    boxPublicKey: box.publicKey,
    boxSecretKey: box.secretKey,
    spendPrivkey
  }
}

/**
 * Derive encryption key from password using scrypt (memory-hard).
 * Used for all newly written vaults.
 */
function deriveKeyScrypt(password: string, salt: Uint8Array): Uint8Array {
  return scrypt(new TextEncoder().encode(password), salt, SCRYPT_PARAMS)
}

/**
 * Legacy key derivation: a plain iterated-SHA-256 chain (NOT real PBKDF2).
 * GPU-parallelizable and weak — retained ONLY to decrypt vaults written
 * before the scrypt migration. Never use this to encrypt new data.
 */
function deriveKeyLegacy(password: string, salt: Uint8Array): Uint8Array {
  let key = new TextEncoder().encode(password)

  for (let i = 0; i < 100000; i++) {
    const combined = new Uint8Array(key.length + salt.length)
    combined.set(key)
    combined.set(salt, key.length)
    key = sha256(combined)
  }

  return key
}

/**
 * Select the KDF for a given vault version.
 * legacy=true → old SHA-256 chain; otherwise scrypt.
 */
function deriveKey(password: string, salt: Uint8Array, legacy: boolean): Uint8Array {
  return legacy ? deriveKeyLegacy(password, salt) : deriveKeyScrypt(password, salt)
}

/**
 * Encrypt wallet with password.
 * Key derivation: scrypt. Cipher: NaCl secretbox (XSalsa20-Poly1305).
 */
export function encryptWallet(
  keypair: WalletKeyPair,
  password: string
): EncryptedWallet {
  // Generate random salt
  const salt = randomBytes(32)

  // Derive encryption key from password (scrypt)
  const encryptionKey = deriveKeyScrypt(password, salt)

  // Generate random nonce
  const nonce = randomBytes(nacl.secretbox.nonceLength)

  // Serialize keypair
  const walletData = JSON.stringify({
    publicKey: Buffer.from(keypair.publicKey).toString("hex"),
    secretKey: Buffer.from(keypair.secretKey).toString("hex"),
    shieldedAddress: keypair.shieldedAddress
  })

  // Encrypt with NaCl secretbox (XSalsa20-Poly1305)
  const message = new TextEncoder().encode(walletData)
  const encrypted = nacl.secretbox(message, nonce, encryptionKey)

  return {
    encrypted: Buffer.from(encrypted).toString("hex"),
    nonce: Buffer.from(nonce).toString("hex"),
    salt: Buffer.from(salt).toString("hex")
  }
}

/**
 * Decrypt wallet with password
 */
export async function decryptWallet(
  encryptedWallet: EncryptedWallet,
  password: string,
  legacy: boolean = false
): Promise<WalletKeyPair> {
  // Parse hex strings
  const encrypted = Buffer.from(encryptedWallet.encrypted, "hex")
  const nonce = Buffer.from(encryptedWallet.nonce, "hex")
  const salt = Buffer.from(encryptedWallet.salt, "hex")

  // Derive encryption key from password (scrypt, or legacy chain for old vaults)
  const encryptionKey = deriveKey(password, salt, legacy)

  // Decrypt
  const decrypted = nacl.secretbox.open(encrypted, nonce, encryptionKey)

  if (!decrypted) {
    throw new Error("Invalid password")
  }

  // Parse wallet data
  const walletData = JSON.parse(new TextDecoder().decode(decrypted))

  // Derive the box keypair from the stored ed25519 secret and recompute the
  // shielded address from the box public key (#196). This overrides any
  // address stored by a pre-#196 vault (which used sha256(pubkey)), migrating
  // existing wallets to the box-pubkey address with no re-onboarding.
  const secretKey = Buffer.from(walletData.secretKey, "hex")
  const box = deriveBoxKeypair(secretKey)
  const spendPrivkey = deriveSpendPrivkey(secretKey)

  return {
    publicKey: Buffer.from(walletData.publicKey, "hex"),
    secretKey,
    shieldedAddress: await deriveShieldedAddress(box.publicKey, spendPrivkey),
    boxPublicKey: box.publicKey,
    boxSecretKey: box.secretKey,
    spendPrivkey
  }
}

/**
 * Sign message with secret key
 */
export function signMessage(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
  return nacl.sign.detached(message, secretKey)
}

/**
 * Verify signature
 */
export function verifySignature(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array
): boolean {
  return nacl.sign.detached.verify(message, signature, publicKey)
}

/**
 * Encrypt seed phrase with password
 */
export function encryptSeedPhrase(seedPhrase: string, password: string): string {
  const salt = randomBytes(32)
  const encryptionKey = deriveKeyScrypt(password, salt)
  const nonce = randomBytes(nacl.secretbox.nonceLength)
  const message = new TextEncoder().encode(seedPhrase)
  const encrypted = nacl.secretbox(message, nonce, encryptionKey)

  // Combine salt + nonce + encrypted and encode as hex
  const combined = new Uint8Array(salt.length + nonce.length + encrypted.length)
  combined.set(salt)
  combined.set(nonce, salt.length)
  combined.set(encrypted, salt.length + nonce.length)

  return Buffer.from(combined).toString("hex")
}

/**
 * Decrypt seed phrase with password
 */
export function decryptSeedPhrase(
  encryptedData: string,
  password: string,
  legacy: boolean = false
): string {
  const combined = Buffer.from(encryptedData, "hex")

  // Extract salt, nonce, and encrypted data
  const salt = combined.subarray(0, 32)
  const nonce = combined.subarray(32, 32 + nacl.secretbox.nonceLength)
  const encrypted = combined.subarray(32 + nacl.secretbox.nonceLength)

  const encryptionKey = deriveKey(password, salt, legacy)
  const decrypted = nacl.secretbox.open(encrypted, nonce, encryptionKey)

  if (!decrypted) {
    throw new Error("Invalid password")
  }

  return new TextDecoder().decode(decrypted)
}
