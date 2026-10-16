import { useState, useMemo } from "react"
import {
  deriveKeypairFromSeed,
  encryptWallet,
  generateSeedPhrase,
  normalizeSeedPhrase,
  pickDecoys,
  validateSeedPhrase
} from "~lib/crypto/keyManagement"
import { saveEncryptedWallet, setLockState } from "~lib/storage/secure"
import { useWalletStore } from "~lib/store/walletStore"
import type { Account } from "~lib/store/walletStore"
import logoImg from "data-base64:~/../assets/icon.png"

interface OnboardingProps {
  onComplete: () => void
}

// Pick N random unique indices from 0..max-1
function pickRandom(count: number, max: number): number[] {
  const indices = Array.from({ length: max }, (_, i) => i)
  for (let i = indices.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [indices[i], indices[j]] = [indices[j], indices[i]]
  }
  return indices.slice(0, count).sort((a, b) => a - b)
}

export function Onboarding({ onComplete }: OnboardingProps) {
  const [step, setStep] = useState<"welcome" | "create" | "import">("welcome")
  const [createStep, setCreateStep] = useState<1 | 2 | 3>(1)
  const [seedPhrase, setSeedPhrase] = useState("")
  const [seedRevealed, setSeedRevealed] = useState(false)
  const [password, setPassword] = useState("")
  const [confirmPassword, setConfirmPassword] = useState("")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)
  const [verifyAnswers, setVerifyAnswers] = useState<Record<number, string>>({})
  const [verifyError, setVerifyError] = useState("")
  const [activeQuestionIdx, setActiveQuestionIdx] = useState(0)
  const { unlock, addAccount, setSeedPhrase: setSeedPhraseStore } = useWalletStore()

  const words = seedPhrase ? seedPhrase.split(" ") : []

  // Pick 3 random word indices to quiz on (memoized per seed phrase)
  const hiddenIndices = useMemo(() => {
    if (words.length !== 12) return []
    return pickRandom(3, 12)
  }, [seedPhrase])

  // Generate shuffled options for each hidden word
  const verifyOptions = useMemo(() => {
    if (words.length !== 12 || hiddenIndices.length === 0) return {}
    const opts: Record<number, string[]> = {}
    for (const idx of hiddenIndices) {
      const correct = words[idx]
      const decoys = pickDecoys(correct, words, 3)
      const choices = [correct, ...decoys]
      // Shuffle
      for (let i = choices.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [choices[i], choices[j]] = [choices[j], choices[i]]
      }
      opts[idx] = choices
    }
    return opts
  }, [seedPhrase, hiddenIndices])

  function handleCreateWallet() {
    try {
      const seed = generateSeedPhrase()
      setSeedPhrase(seed)
      setStep("create")
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to generate seed phrase")
    }
  }

  function handleSelectWord(wordIdx: number, selected: string) {
    const correct = words[wordIdx]
    if (selected === correct) {
      // Correct — save and auto-advance
      const newAnswers = { ...verifyAnswers, [wordIdx]: selected }
      setVerifyAnswers(newAnswers)
      setVerifyError("")

      // Check if all answered
      const answeredCount = Object.keys(newAnswers).length
      if (answeredCount >= hiddenIndices.length) {
        // All correct — auto-advance to password after brief delay
        setTimeout(() => setCreateStep(3), 600)
      } else {
        // Move to next unanswered question
        const nextIdx = hiddenIndices.findIndex(
          (idx) => !newAnswers[idx]
        )
        if (nextIdx !== -1) {
          setTimeout(() => setActiveQuestionIdx(nextIdx), 300)
        }
      }
    } else {
      // Wrong — shake + reset all
      setVerifyError("Wrong word! Try again from the beginning.")
      setVerifyAnswers({})
      setActiveQuestionIdx(0)
    }
  }

  async function handleSaveWallet(seed: string) {
    setError("")

    if (password.length < 8) {
      setError("Password must be at least 8 characters")
      return
    }

    if (password !== confirmPassword) {
      setError("Passwords do not match")
      return
    }

    const normalizedSeed = normalizeSeedPhrase(seed)
    if (!validateSeedPhrase(normalizedSeed)) {
      setError("Invalid seed phrase")
      return
    }

    setLoading(true)

    try {
      const keypair = await deriveKeypairFromSeed(normalizedSeed, 0)

      const initialAccount: Account = {
        index: 0,
        name: "Account 1",
        keypair,
        balance: 0n
      }

      const encrypted = encryptWallet(keypair, password)
      await saveEncryptedWallet(
        encrypted,
        keypair.shieldedAddress,
        normalizedSeed,
        password,
        [initialAccount]
      )

      unlock(keypair, normalizedSeed)
      setSeedPhraseStore(normalizedSeed)
      addAccount(initialAccount)
      await setLockState(false)

      await new Promise(resolve => setTimeout(resolve, 100))
      onComplete()
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create wallet")
    } finally {
      setLoading(false)
    }
  }

  // ─── Welcome Screen ───
  if (step === "welcome") {
    return (
      <div className="onboarding-layout">
        <div className="onboarding-hero">
          <img src={logoImg} alt="paraloom" className="hero-logo" />
          <div className="wordmark">
            <span className="wordmark-text">paraloom</span>
          </div>
          <p className="onboarding-tagline">Privacy-first shielded wallet</p>
        </div>

        <div className="onboarding-features">
          <div className="feature-item">
            <div className="feature-icon">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </div>
            <span>Zero-knowledge privacy</span>
          </div>
          <div className="feature-item">
            <div className="feature-icon">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                <path d="M7 11V7a5 5 0 0 1 10 0v4" />
              </svg>
            </div>
            <span>Encrypted local storage</span>
          </div>
          <div className="feature-item">
            <div className="feature-icon">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
              </svg>
            </div>
            <span>Shielded transactions</span>
          </div>
        </div>

        <div className="onboarding-actions">
          <button className="button" onClick={handleCreateWallet}>
            Create New Wallet
          </button>
          <button className="button button-secondary" onClick={() => setStep("import")}>
            Import Existing Wallet
          </button>
        </div>
      </div>
    )
  }

  // ─── Create Wallet ───
  if (step === "create") {
    return (
      <div className="onboarding-layout">
        <div className="onboarding-mini-header">
          <img src={logoImg} alt="paraloom" className="mini-header-logo" />
          <div className="mini-header-text">
            <span className="mini-header-title">Create Wallet</span>
            <span className="mini-header-step">Step {createStep} of 3</span>
          </div>
        </div>

        <div className="step-indicator">
          <div className={`step-item ${createStep >= 1 ? 'active' : ''}`}></div>
          <div className={`step-item ${createStep >= 2 ? 'active' : ''}`}></div>
          <div className={`step-item ${createStep >= 3 ? 'active' : ''}`}></div>
        </div>

        <div className="onboarding-body">
          {/* ── Step 1: Show Seed Phrase ── */}
          {createStep === 1 && (
            <>
              <p className="section-description">
                Write down these 12 words in order. Keep them safe — this is your only backup.
              </p>

              <div className="card seed-card">
                <div className={`seed-grid ${!seedRevealed ? 'blurred' : ''}`}>
                  {words.map((word, i) => (
                    <div key={i} className="seed-word">
                      <span className="seed-index">{i + 1}</span>
                      <span className="seed-text">{word}</span>
                    </div>
                  ))}
                </div>

                {!seedRevealed && (
                  <button
                    className="reveal-button"
                    onClick={() => setSeedRevealed(true)}>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                      <circle cx="12" cy="12" r="3" />
                    </svg>
                    Reveal Seed Phrase
                  </button>
                )}
              </div>

              <div className="seed-warning">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                  <line x1="12" y1="9" x2="12" y2="13" />
                  <line x1="12" y1="17" x2="12.01" y2="17" />
                </svg>
                <span>Never share your seed phrase with anyone</span>
              </div>

              {seedRevealed && (
                <button className="button" onClick={() => setCreateStep(2)}>
                  I've Saved It — Verify
                </button>
              )}
            </>
          )}

          {/* ── Step 2: Verify Seed Phrase ── */}
          {createStep === 2 && (() => {
            const allDone = hiddenIndices.every(idx => verifyAnswers[idx])
            const currentWordIdx = hiddenIndices[activeQuestionIdx]
            const progress = Object.keys(verifyAnswers).length

            return (
              <>
                <p className="section-description">
                  Confirm your seed phrase. Select the correct word for each blank.
                </p>

                {/* Progress dots */}
                <div className="verify-progress">
                  {hiddenIndices.map((idx, i) => (
                    <div
                      key={idx}
                      className={`verify-dot ${verifyAnswers[idx] ? 'done' : i === activeQuestionIdx ? 'active' : ''}`}
                    >
                      {verifyAnswers[idx] ? (
                        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
                          <polyline points="20 6 9 17 4 12" />
                        </svg>
                      ) : (
                        <span>{i + 1}</span>
                      )}
                    </div>
                  ))}
                </div>

                {verifyError && <div className="error shake">{verifyError}</div>}

                {/* Seed grid — compact preview */}
                <div className="card seed-card">
                  <div className="seed-grid">
                    {words.map((word, i) => {
                      const isHidden = hiddenIndices.includes(i)
                      const isAnswered = verifyAnswers[i] !== undefined
                      const isCurrent = i === currentWordIdx && !isAnswered

                      if (isHidden) {
                        return (
                          <div
                            key={i}
                            className={`seed-word ${isAnswered ? 'seed-word-correct' : isCurrent ? 'seed-word-active' : 'seed-word-blank'}`}
                          >
                            <span className="seed-index">{i + 1}</span>
                            <span className="seed-text">
                              {isAnswered ? verifyAnswers[i] : '?'}
                            </span>
                          </div>
                        )
                      }

                      return (
                        <div key={i} className="seed-word seed-word-visible">
                          <span className="seed-index">{i + 1}</span>
                          <span className="seed-text">{word}</span>
                        </div>
                      )
                    })}
                  </div>
                </div>

                {/* Active question — one at a time */}
                {!allDone && currentWordIdx !== undefined && (
                  <div className="verify-single-question">
                    <div className="verify-label">
                      Select word <span className="verify-label-num">#{currentWordIdx + 1}</span>
                      <span className="verify-label-progress">{progress}/{hiddenIndices.length}</span>
                    </div>
                    <div className="verify-options">
                      {(verifyOptions[currentWordIdx] || []).map((option) => (
                        <button
                          key={option}
                          className="verify-option"
                          onClick={() => handleSelectWord(currentWordIdx, option)}
                        >
                          {option}
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                {/* All done — success message */}
                {allDone && (
                  <div className="verify-success">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
                      <polyline points="22 4 12 14.01 9 11.01" />
                    </svg>
                    <span>Seed phrase verified!</span>
                  </div>
                )}

                <button
                  className="button button-ghost"
                  onClick={() => {
                    setCreateStep(1)
                    setVerifyAnswers({})
                    setVerifyError("")
                    setActiveQuestionIdx(0)
                  }}>
                  Back to Seed Phrase
                </button>
              </>
            )
          })()}

          {/* ── Step 3: Password ── */}
          {createStep === 3 && (
            <>
              <p className="section-description">
                Create a strong password to encrypt your wallet locally.
              </p>

              {error && <div className="error">{error}</div>}

              <div className="form-stack">
                <div className="input-group">
                  <label className="label">Password</label>
                  <input
                    type="password"
                    className="input"
                    placeholder="Min 8 characters"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    autoFocus
                  />
                </div>

                <div className="input-group">
                  <label className="label">Confirm Password</label>
                  <input
                    type="password"
                    className="input"
                    placeholder="Re-enter password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                  />
                </div>

                {password.length > 0 && (
                  <div className="password-strength">
                    <div className={`strength-bar ${password.length >= 12 ? 'strong' : password.length >= 8 ? 'medium' : 'weak'}`}>
                      <div className="strength-fill" style={{ width: `${Math.min(100, (password.length / 16) * 100)}%` }} />
                    </div>
                    <span className="strength-label">
                      {password.length < 8 ? 'Too short' : password.length >= 12 ? 'Strong' : 'Good'}
                    </span>
                  </div>
                )}

                <button className="button" onClick={() => handleSaveWallet(seedPhrase)} disabled={loading}>
                  {loading ? <><span className="spinner" /> Creating...</> : "Create Wallet"}
                </button>

                <button
                  className="button button-ghost"
                  onClick={() => setCreateStep(2)}>
                  Back
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    )
  }

  // ─── Import Wallet ───
  if (step === "import") {
    return (
      <div className="onboarding-layout">
        <div className="onboarding-mini-header">
          <img src={logoImg} alt="paraloom" className="mini-header-logo" />
          <div className="mini-header-text">
            <span className="mini-header-title">Import Wallet</span>
            <span className="mini-header-step">Recovery phrase</span>
          </div>
        </div>

        <div className="onboarding-body">
          <p className="section-description">
            Enter your 12-word Paraloom recovery phrase to restore your wallet.
            Paraloom uses its own key derivation, so a phrase from another wallet
            (such as Phantom) will restore different accounts.
          </p>

          {error && <div className="error">{error}</div>}

          <div className="form-stack">
            <div className="input-group">
              <label className="label">Seed Phrase</label>
              <textarea
                className="input seed-input"
                placeholder="word1 word2 word3 ..."
                value={seedPhrase}
                onChange={(e) => setSeedPhrase(e.target.value)}
                rows={3}
              />
            </div>

            <div className="input-group">
              <label className="label">Create Password</label>
              <input
                type="password"
                className="input"
                placeholder="Min 8 characters"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>

            <div className="input-group">
              <label className="label">Confirm Password</label>
              <input
                type="password"
                className="input"
                placeholder="Re-enter password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
              />
            </div>

            <button className="button" onClick={() => handleSaveWallet(seedPhrase)} disabled={loading}>
              {loading ? <><span className="spinner" /> Importing...</> : "Import Wallet"}
            </button>

            <button className="button button-ghost" onClick={() => setStep("welcome")}>
              Back
            </button>
          </div>
        </div>
      </div>
    )
  }

  return null
}
