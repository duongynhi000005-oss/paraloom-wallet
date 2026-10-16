import type { EncryptedWallet } from "~lib/crypto/keyManagement"
import { encryptSeedPhrase, KDF_VERSION_SCRYPT } from "~lib/crypto/keyManagement"
import type { Account } from "~lib/store/walletStore"

export interface SerializableAccount {
  index: number
  name: string
  address: string
  balance: string
}

export interface StoredWallet {
  encryptedData: EncryptedWallet
  address: string
  createdAt: number
  encryptedSeedPhrase?: string
  accounts?: SerializableAccount[]
  // KDF used for encryptedData + encryptedSeedPhrase. Both blobs are always
  // written together, so one marker covers both. Absent = legacy SHA-256 chain.
  kdfVersion?: number
}

export interface WalletStorage {
  wallet?: StoredWallet
  locked: boolean
  autoLockMinutes: number
  network?: "mainnet-beta" | "devnet"
  failedUnlockAttempts?: number
  unlockLockedUntil?: number
  unlockLockoutTier?: number
}

const STORAGE_KEY = "paraloom_wallet"
export const MAX_UNLOCK_ATTEMPTS = 5
export const BASE_LOCKOUT_SECONDS = 30
const MAX_LOCKOUT_SECONDS = 900

export async function saveEncryptedWallet(
  encryptedWallet: EncryptedWallet,
  address: string,
  seedPhrase?: string,
  password?: string,
  accounts?: Account[]
): Promise<void> {
  const data: StoredWallet = {
    encryptedData: encryptedWallet,
    address,
    createdAt: Date.now(),
    kdfVersion: KDF_VERSION_SCRYPT
  }

  // Encrypt and save seed phrase if provided
  if (seedPhrase && password) {
    data.encryptedSeedPhrase = encryptSeedPhrase(seedPhrase, password)
  }

  // Serialize accounts if provided (convert keypair to address, balance to string)
  if (accounts && accounts.length > 0) {
    data.accounts = accounts.map(acc => ({
      index: acc.index,
      name: acc.name,
      address: acc.keypair.shieldedAddress,
      balance: acc.balance.toString()
    }))
  }

  await chrome.storage.local.set({
    [STORAGE_KEY]: {
      wallet: data,
      locked: true,
      autoLockMinutes: 60
    }
  })
}

/**
 * Re-encrypt an already-unlocked wallet under the current (scrypt) KDF,
 * updating only the wallet blobs + kdfVersion and preserving every other
 * stored setting (lock state, auto-lock minutes, network).
 * Used to transparently upgrade legacy vaults on first unlock.
 */
export async function migrateWalletToScrypt(
  encryptedWallet: EncryptedWallet,
  seedPhrase: string | undefined,
  password: string
): Promise<void> {
  const result = await chrome.storage.local.get(STORAGE_KEY)
  const storage = result[STORAGE_KEY] as WalletStorage | undefined
  if (!storage?.wallet) return

  // Both `encryptedData` and `encryptedSeedPhrase` share the single `kdfVersion`
  // marker. If the vault has a stored `encryptedSeedPhrase` but the caller did
  // not supply the plaintext `seedPhrase` to re-encrypt under scrypt, refuse to
  // bump `kdfVersion` — otherwise `encryptedSeedPhrase` remains encrypted under
  // the legacy SHA-256 KDF while `kdfVersion` is set to scrypt, permanently
  // orphaning the user's seed phrase and multi-account derivation.
  if (storage.wallet.encryptedSeedPhrase && !seedPhrase) {
    return
  }

  storage.wallet.encryptedData = encryptedWallet
  storage.wallet.kdfVersion = KDF_VERSION_SCRYPT
  if (seedPhrase) {
    storage.wallet.encryptedSeedPhrase = encryptSeedPhrase(seedPhrase, password)
  }

  await chrome.storage.local.set({ [STORAGE_KEY]: storage })
}

export interface UnlockLockoutState {
  attempts: number
  lockedUntil: number
  tier: number
}

export async function getUnlockLockoutState(): Promise<UnlockLockoutState> {
  const result = await chrome.storage.local.get(STORAGE_KEY)
  const storage = result[STORAGE_KEY] as WalletStorage | undefined
  return {
    attempts: storage?.failedUnlockAttempts ?? 0,
    lockedUntil: storage?.unlockLockedUntil ?? 0,
    tier: storage?.unlockLockoutTier ?? 0
  }
}

export async function recordFailedUnlockAttempt(
  now = Date.now()
): Promise<{
  attempts: number
  lockedUntil: number
  lockedOut: boolean
  lockoutSeconds: number
}> {
  const result = await chrome.storage.local.get(STORAGE_KEY)
  const storage = result[STORAGE_KEY] as WalletStorage | undefined
  if (!storage) {
    return { attempts: 0, lockedUntil: 0, lockedOut: false, lockoutSeconds: 0 }
  }
  const currentLockedUntil = storage.unlockLockedUntil ?? 0
  if (now < currentLockedUntil) {
    return {
      attempts: storage.failedUnlockAttempts ?? 0,
      lockedUntil: currentLockedUntil,
      lockedOut: true,
      lockoutSeconds: Math.ceil((currentLockedUntil - now) / 1000)
    }
  }
  const newAttempts = (storage.failedUnlockAttempts ?? 0) + 1
  if (newAttempts >= MAX_UNLOCK_ATTEMPTS) {
    const newTier = (storage.unlockLockoutTier ?? 0) + 1
    const lockoutSeconds = Math.min(
      MAX_LOCKOUT_SECONDS,
      BASE_LOCKOUT_SECONDS * 2 ** (newTier - 1)
    )
    const lockedUntil = now + lockoutSeconds * 1000
    storage.failedUnlockAttempts = 0
    storage.unlockLockedUntil = lockedUntil
    storage.unlockLockoutTier = newTier
    await chrome.storage.local.set({ [STORAGE_KEY]: storage })
    return {
      attempts: 0,
      lockedUntil,
      lockedOut: true,
      lockoutSeconds
    }
  }
  storage.failedUnlockAttempts = newAttempts
  await chrome.storage.local.set({ [STORAGE_KEY]: storage })
  return {
    attempts: newAttempts,
    lockedUntil: 0,
    lockedOut: false,
    lockoutSeconds: 0
  }
}

export async function clearUnlockLockout(): Promise<void> {
  const result = await chrome.storage.local.get(STORAGE_KEY)
  const storage = result[STORAGE_KEY] as WalletStorage | undefined
  if (!storage) return
  if (
    storage.failedUnlockAttempts ||
    storage.unlockLockedUntil ||
    storage.unlockLockoutTier
  ) {
    storage.failedUnlockAttempts = 0
    storage.unlockLockedUntil = 0
    storage.unlockLockoutTier = 0
    await chrome.storage.local.set({ [STORAGE_KEY]: storage })
  }
}

export async function getStoredWallet(): Promise<StoredWallet | null> {
  const result = await chrome.storage.local.get(STORAGE_KEY)
  const storage = result[STORAGE_KEY] as WalletStorage | undefined
  return storage?.wallet || null
}

export async function clearWallet(): Promise<void> {
  await chrome.storage.local.remove(STORAGE_KEY)
}

export async function isWalletLocked(): Promise<boolean> {
  const result = await chrome.storage.local.get(STORAGE_KEY)
  const storage = result[STORAGE_KEY] as WalletStorage | undefined
  return storage?.locked ?? true
}

export async function setLockState(locked: boolean): Promise<void> {
  const result = await chrome.storage.local.get(STORAGE_KEY)
  const storage = result[STORAGE_KEY] as WalletStorage

  if (storage) {
    storage.locked = locked
    await chrome.storage.local.set({ [STORAGE_KEY]: storage })
  }
}

export async function getAutoLockMinutes(): Promise<number> {
  const result = await chrome.storage.local.get(STORAGE_KEY)
  const storage = result[STORAGE_KEY] as WalletStorage | undefined
  return storage?.autoLockMinutes ?? 60
}

export async function setAutoLockMinutes(minutes: number): Promise<void> {
  const result = await chrome.storage.local.get(STORAGE_KEY)
  const storage = result[STORAGE_KEY] as WalletStorage

  if (storage) {
    storage.autoLockMinutes = minutes
    await chrome.storage.local.set({ [STORAGE_KEY]: storage })
  }
}

export async function updateAccounts(accounts: Account[]): Promise<void> {
  const result = await chrome.storage.local.get(STORAGE_KEY)
  const storage = result[STORAGE_KEY] as WalletStorage

  if (storage?.wallet) {
    storage.wallet.accounts = accounts.map(acc => ({
      index: acc.index,
      name: acc.name,
      address: acc.keypair.shieldedAddress,
      balance: acc.balance.toString()
    }))
    await chrome.storage.local.set({ [STORAGE_KEY]: storage })
  }
}

export async function getNetwork(): Promise<"mainnet-beta" | "devnet"> {
  // Mainnet is live (capped beta). New installs default to mainnet-beta;
  // a previously stored choice (e.g. devnet for testing) is honoured.
  const result = await chrome.storage.local.get(STORAGE_KEY)
  const storage = result[STORAGE_KEY] as WalletStorage | undefined
  return storage?.network ?? "mainnet-beta"
}

export async function setNetwork(network: "mainnet-beta" | "devnet"): Promise<void> {
  const result = await chrome.storage.local.get(STORAGE_KEY)
  const storage = result[STORAGE_KEY] as WalletStorage

  if (storage) {
    storage.network = network
    await chrome.storage.local.set({ [STORAGE_KEY]: storage })
  }
}
