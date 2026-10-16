import { useEffect, useState } from "react"
import {
  decryptWallet,
  decryptSeedPhrase,
  deriveKeypairFromSeed,
  encryptWallet,
  KDF_VERSION_SCRYPT
} from "~lib/crypto/keyManagement"
import {
  clearUnlockLockout,
  getStoredWallet,
  getUnlockLockoutState,
  MAX_UNLOCK_ATTEMPTS,
  migrateWalletToScrypt,
  recordFailedUnlockAttempt,
  setLockState
} from "~lib/storage/secure"
import { saveSession } from "~lib/storage/session"
import { useWalletStore } from "~lib/store/walletStore"
import type { Account } from "~lib/store/walletStore"
import logoImg from "data-base64:~/../assets/icon.png"

interface UnlockProps {
  onUnlock: () => void
}

export function Unlock({ onUnlock }: UnlockProps) {
  const [password, setPassword] = useState("")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)
  const [attempts, setAttempts] = useState(0)
  const [lockedUntil, setLockedUntil] = useState(0)
  const [, setTick] = useState(0)
  const { unlock, addAccount } = useWalletStore()

  useEffect(() => {
    getUnlockLockoutState()
      .then((st) => {
        setAttempts(st.attempts)
        setLockedUntil(st.lockedUntil)
        if (st.lockedUntil > Date.now()) {
          const secs = Math.ceil((st.lockedUntil - Date.now()) / 1000)
          setError(`Too many attempts. Try again in ${secs}s`)
        }
      })
      .catch(() => {})
  }, [])

  useEffect(() => {
    if (lockedUntil <= Date.now()) return
    const timer = setInterval(() => {
      if (Date.now() >= lockedUntil) {
        setLockedUntil(0)
        setError("")
      } else {
        setTick((t) => t + 1)
      }
    }, 1000)
    return () => clearInterval(timer)
  }, [lockedUntil])

  const isLockedOut = Date.now() < lockedUntil
  const remainingSeconds = isLockedOut
    ? Math.ceil((lockedUntil - Date.now()) / 1000)
    : 0

  async function handleUnlock() {
    const preLock = await getUnlockLockoutState().catch(() => ({
      attempts,
      lockedUntil,
      tier: 0
    }))
    if (Date.now() < preLock.lockedUntil) {
      setLockedUntil(preLock.lockedUntil)
      const secs = Math.ceil((preLock.lockedUntil - Date.now()) / 1000)
      setError(`Too many attempts. Try again in ${secs}s`)
      return
    }
    setError("")
    setLoading(true)

    try {
      const stored = await getStoredWallet()
      if (!stored) {
        setError("No wallet found")
        setLoading(false)
        return
      }

      // Vaults written before the scrypt migration have no kdfVersion and
      // must be decrypted with the legacy SHA-256 KDF.
      const isLegacy = (stored.kdfVersion ?? 0) < KDF_VERSION_SCRYPT
      const wallet = await decryptWallet(stored.encryptedData, password, isLegacy)

      let seedPhrase: string | undefined
      if (stored.encryptedSeedPhrase) {
        try {
          seedPhrase = decryptSeedPhrase(stored.encryptedSeedPhrase, password, isLegacy)
        } catch {
          try {
            seedPhrase = decryptSeedPhrase(stored.encryptedSeedPhrase, password, !isLegacy)
          } catch {}
        }
      }

      // Transparently upgrade legacy vaults to scrypt now that the password
      // is confirmed correct, but only when any stored encryptedSeedPhrase was
      // also decrypted so both blobs stay under the same KDF version.
      if (isLegacy && (!stored.encryptedSeedPhrase || !!seedPhrase)) {
        try {
          const upgraded = encryptWallet(wallet, password)
          await migrateWalletToScrypt(upgraded, seedPhrase, password)
        } catch {}
      }

      if (stored.accounts && stored.accounts.length > 0 && seedPhrase) {
        for (const storedAccount of stored.accounts) {
          const keypair = await deriveKeypairFromSeed(seedPhrase, storedAccount.index)
          const account: Account = {
            index: storedAccount.index,
            name: storedAccount.name,
            keypair,
            balance: BigInt(storedAccount.balance)
          }
          addAccount(account)
        }
      }

      unlock(wallet, seedPhrase)
      await setLockState(false)
      await clearUnlockLockout()
      setAttempts(0)
      setLockedUntil(0)

      // Persist the decrypted session in memory-only storage so reopening the
      // popup doesn't force a re-unlock (the idle auto-lock timer still applies).
      const st = useWalletStore.getState()
      await saveSession({
        wallet,
        accounts: st.accounts,
        currentAccountIndex: st.currentAccountIndex,
        seedPhrase: seedPhrase ?? st.seedPhrase
      })

      chrome.runtime.sendMessage({ type: "ACTIVITY" })
      onUnlock()
    } catch {
      const res = await recordFailedUnlockAttempt().catch(() => ({
        attempts: attempts + 1,
        lockedUntil: 0,
        lockedOut: false,
        lockoutSeconds: 0
      }))
      setAttempts(res.attempts)

      if (res.lockedOut) {
        setLockedUntil(res.lockedUntil)
        setError(`Too many attempts. Try again in ${res.lockoutSeconds}s`)
      } else {
        setError(
          `Invalid password (${MAX_UNLOCK_ATTEMPTS - res.attempts} attempts remaining)`
        )
      }

      setPassword("")
      setLoading(false)
    }
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Enter") {
      handleUnlock()
    }
  }

  return (
    <div className="unlock-layout">
      <div className="unlock-hero">
        <img src={logoImg} alt="paraloom" className="unlock-logo" />
        <div className="unlock-brand">
          <span className="unlock-wordmark">paraloom</span>
          <span className="unlock-greeting">Welcome back</span>
        </div>
      </div>

      <div className="unlock-form">
        <div className="unlock-input-group">
          <label className="unlock-label">Enter your password</label>
          <input
            type="password"
            className={`input unlock-input ${error ? 'input-error shake' : ''}`}
            placeholder="••••••••"
            value={password}
            onChange={(e) => {
              setPassword(e.target.value)
              if (error) setError("")
            }}
            onKeyDown={handleKeyDown}
            autoFocus
            disabled={isLockedOut}
          />
          {error && <div className="unlock-attempts">{error}</div>}
        </div>

        <button className="button" onClick={handleUnlock} disabled={loading || isLockedOut || !password}>
          {loading ? (
            <><span className="spinner" /> Unlocking...</>
          ) : isLockedOut ? (
            `Locked (${remainingSeconds}s)`
          ) : (
            "Unlock"
          )}
        </button>
      </div>

      <div className="unlock-footer">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        </svg>
        <span>Your wallet is encrypted locally</span>
      </div>
    </div>
  )
}
