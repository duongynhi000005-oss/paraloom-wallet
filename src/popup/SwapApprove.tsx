import { useState } from "react"
import logoImg from "data-base64:~/../assets/icon.png"
import { DEFAULT_SWAP_SLIPPAGE_BPS, formatSwapAmount } from "~lib/paraloom/swapReconcileClassify"

interface SwapParams {
  outputMint: string
  inputMint?: string
  amountLamports: string
  slippageBps?: number
  reshield?: boolean
}

interface SwapApproveProps {
  id: number
  origin: string
  params: SwapParams
  onResolved: () => void
}

type Status = "idle" | "approved" | "rejected"

const USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"

function sendMessage(message: Record<string, unknown>): Promise<unknown> {
  return new Promise((resolve) => chrome.runtime.sendMessage(message, resolve))
}

function tokenLabel(mint: string): string {
  if (mint === "SOL") return "SOL"
  if (mint === USDC_MINT) return "USDC"
  return `${mint.slice(0, 4)}…${mint.slice(-4)}`
}

// Decimals + symbol for the input side. Only native SOL and USDC are spendable
// inputs today; an unknown mint falls back to showing raw base units.
function inputInfo(inputMint?: string): { decimals: number; symbol: string } {
  if (!inputMint || inputMint === "SOL") return { decimals: 9, symbol: "SOL" }
  if (inputMint === USDC_MINT) return { decimals: 6, symbol: "USDC" }
  return { decimals: 0, symbol: tokenLabel(inputMint) }
}

export function SwapApprove({ id, origin, params, onResolved }: SwapApproveProps) {
  const [status, setStatus] = useState<Status>("idle")

  let host = origin
  try {
    host = new URL(origin).host
  } catch {}

  async function decide(approved: boolean) {
    if (status !== "idle") return
    setStatus(approved ? "approved" : "rejected")
    await sendMessage({ type: approved ? "APPROVE_SWAP" : "REJECT_SWAP", id })
    // The swap runs in the background after approval; the window just closes.
    setTimeout(() => {
      window.close()
      setTimeout(onResolved, 400)
    }, approved ? 900 : 350)
  }

  if (status !== "idle") {
    const approved = status === "approved"
    return (
      <div className="connect-approve">
        <div className="connect-result">
          <div className={`connect-badge ${approved ? "ok" : "no"}`}>
            {approved ? (
              <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="20 6 9 17 4 12" />
              </svg>
            ) : (
              <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round">
                <line x1="18" y1="6" x2="6" y2="18" />
                <line x1="6" y1="6" x2="18" y2="18" />
              </svg>
            )}
          </div>
          <h2 className="connect-title">{approved ? "Swapping…" : "Rejected"}</h2>
          <div className="connect-origin">{host}</div>
        </div>
      </div>
    )
  }

  return (
    <div className="connect-approve">
      <img src={logoImg} alt="paraloom" className="connect-logo" />
      <h2 className="connect-title">Approve private swap</h2>
      <div className="connect-origin">{host}</div>
      <p className="connect-desc">
        This spends{" "}
        <strong>
          {formatSwapAmount(params.amountLamports, inputInfo(params.inputMint).decimals)}{" "}
          {inputInfo(params.inputMint).symbol}
        </strong>{" "}
        from your shielded balance, exits to a fresh unlinkable address, and swaps
        to <strong>{tokenLabel(params.outputMint)}</strong> there (max slippage{" "}
        <strong>{((params.slippageBps ?? DEFAULT_SWAP_SLIPPAGE_BPS) / 100).toFixed(2)}%</strong>).{" "}
        {params.reshield
          ? "The result is re-shielded back into your Paraloom balance."
          : "The result stays at that address (it is not re-shielded)."}{" "}
        Only approve swaps you started.
      </p>
      <div className="connect-actions">
        <button className="button button-secondary" onClick={() => decide(false)}>
          Reject
        </button>
        <button className="button" onClick={() => decide(true)}>
          Approve
        </button>
      </div>
    </div>
  )
}
