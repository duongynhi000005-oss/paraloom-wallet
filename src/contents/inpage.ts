import type { PlasmoCSConfig } from "plasmo"

const DEV_MATCHES =
  process.env.NODE_ENV === "development"
    ? ["http://localhost/*", "http://127.0.0.1/*"]
    : []

// Runs in the page's MAIN world so the dapp can see `window.paraloom`. A
// MAIN-world content script is injected by the browser itself (not via a
// <script> tag), so unlike an inline injection it is NOT subject to the page's
// CSP — which is what blocked the previous approach on app.paraloom.io. It has
// no chrome.* access, so every call is relayed to the isolated relay.ts over
// window.postMessage.
//
// NOTE: Plasmo 0.89.4 builds this file but drops the world:"MAIN" entry from the
// generated manifest, so scripts/patch-manifest.mjs re-adds it after the build.
export const config: PlasmoCSConfig = {
  matches: ["https://*.paraloom.io/*", "https://paraloom.io/*", ...DEV_MATCHES],
  run_at: "document_start",
  world: "MAIN"
}

const REQ = "paraloom:request"
const RES = "paraloom:response"

let counter = 0

const DEFAULT_RELAY_TIMEOUT_MS = 240_000
const FAST_RELAY_TIMEOUT_MS = 30_000

function relay(
  type: string,
  payload?: Record<string, unknown>,
  timeoutMs = DEFAULT_RELAY_TIMEOUT_MS
): Promise<any> {
  return new Promise((resolve, reject) => {
    const id = ++counter
    let timer: ReturnType<typeof setTimeout> | undefined
    const cleanup = () => {
      window.removeEventListener("message", onMessage)
      if (timer !== undefined) clearTimeout(timer)
    }
    const onMessage = (event: MessageEvent) => {
      if (event.source !== window) return
      const data = event.data
      if (!data || data.channel !== RES || data.id !== id) return
      cleanup()
      if (data.error) reject(new Error(data.error))
      else resolve(data.result)
    }
    if (timeoutMs > 0) {
      timer = setTimeout(() => {
        cleanup()
        reject(new Error(`Wallet request timed out (${type})`))
      }, timeoutMs)
    }
    window.addEventListener("message", onMessage)
    window.postMessage({ channel: REQ, id, type, payload }, window.location.origin)
  })
}

if (!(window as any).paraloom) {
  ;(window as any).paraloom = {
    // Version marker so we can confirm from the page console which build is
    // actually injected (two extensions or a stale one caused confusion).
    __version: "1.5.6",
    connect: async () => {
      // Trigger the approval flow, but do NOT depend on this call's held
      // response. The background holds it across the user's approval; an MV3
      // worker eviction mid-wait can silently drop it (no error), hanging
      // connect() forever. So FIRE it without awaiting (it opens the approval
      // popup for a new origin), then poll isConnected() — which reflects the
      // DURABLE approval recorded when the user approves. The first poll also
      // covers the already-approved fast path (returns immediately, no popup).
      void relay("CONNECT_WALLET", undefined, FAST_RELAY_TIMEOUT_MS).catch(() => {})
      for (let i = 0; i < 180; i++) {
        const c = await relay("IS_CONNECTED", undefined, FAST_RELAY_TIMEOUT_MS).catch(() => null)
        if (c?.connected) {
          const a = await relay("GET_ADDRESS", undefined, FAST_RELAY_TIMEOUT_MS).catch(() => null)
          if (a?.address) return { address: a.address, publicKey: a.address }
        }
        await new Promise((res) => setTimeout(res, 700))
      }
      throw new Error("Connection request timed out")
    },
    disconnect: async () => {
      await relay("DISCONNECT_WALLET", undefined, FAST_RELAY_TIMEOUT_MS)
    },
    signMessage: async (message: string) => {
      const r = await relay("SIGN_MESSAGE", { message })
      if (r?.success) return r.signature
      throw new Error(r?.error || "Failed to sign")
    },
    sendPrivateTransfer: async (params: unknown) => {
      const r = await relay("SEND_PRIVATE_TRANSFER", { params })
      if (r?.success) return r.txHash
      throw new Error(r?.error || "Transfer failed")
    },
    // Private swap-out: spend a shielded note, exit at a fresh unlinkable
    // address, and buy `outputMint` there. `params.amountLamports` is a decimal
    // string. Requires the user to approve the exact amount + token in the
    // wallet popup; resolves to { freshAddress, swapSignature, outAmount }.
    privateSwap: async (params: {
      outputMint: string
      inputMint?: string
      amountLamports: string
      slippageBps?: number
      reshield?: boolean
    }) => {
      // Kick off the swap job (opens the approval popup), then POLL its status.
      // The polling keeps the MV3 worker alive through the approval + the
      // ~2-3 min swap; a single held response could not (worker eviction dropped
      // it as "message channel closed").
      const ack = await relay("PRIVATE_SWAP", { params }, FAST_RELAY_TIMEOUT_MS)
      if (!ack || ack.success !== true) {
        throw new Error(ack?.error || "Private swap failed")
      }
      const expectedStartedAt =
        typeof ack.startedAt === "number" ? ack.startedAt : undefined
      for (let i = 0; i < 200; i++) {
        await new Promise((res) => setTimeout(res, 1500))
        const st = await relay("GET_SWAP_STATUS", undefined, FAST_RELAY_TIMEOUT_MS).catch(
          () => null
        )
        if (
          expectedStartedAt !== undefined &&
          typeof st?.startedAt === "number" &&
          st.startedAt !== expectedStartedAt
        ) {
          continue
        }
        if (st?.status === "done") return st.result
        if (st?.status === "error") {
          throw new Error(st.error || "Private swap failed")
        }
      }
      throw new Error("Private swap timed out")
    },
    getAddress: async () => {
      const r = await relay("GET_ADDRESS")
      return r?.address ?? null
    },
    // The wallet's transparent Solana address (for reading public holdings).
    getPublicAddress: async () => {
      const r = await relay("GET_PUBLIC_ADDRESS")
      return r?.address ?? null
    },
    // Shielded SOL balance in lamports, as a decimal string (avoids BigInt
    // serialization across the message bridge). null if unavailable/locked.
    getShieldedBalance: async () => {
      const r = await relay("GET_SHIELDED_BALANCE")
      return r?.lamports ?? null
    },
    // Shielded SPL balances (#779) as { base58Mint: baseUnitsString }, e.g.
    // re-shielded USDC. Empty object if none / unavailable / locked.
    getShieldedTokenBalances: async () => {
      const r = await relay("GET_SHIELDED_TOKEN_BALANCES")
      return r?.balances ?? {}
    },
    isConnected: async () => {
      const r = await relay("IS_CONNECTED")
      return r?.connected ?? false
    },
    // Whether the connected wallet is currently locked (auto-locked after idle).
    // The dapp uses this to show "locked, unlock to swap" instead of a
    // misleading "ready" state while the origin stays approved. False when not
    // connected.
    isLocked: async () => {
      const r = await relay("IS_CONNECTED")
      return r?.locked ?? false
    },
    // Surface the wallet's own unlock screen (opens the extension popup on the
    // password prompt). The password is entered in the extension, never here.
    // No-op if already unlocked. The dapp then polls isLocked() to see the
    // result. Resolves to the lock state the wallet observed when asked.
    unlock: async () => {
      const r = await relay("REQUEST_UNLOCK").catch(() => null)
      return r?.locked ?? false
    },
    // Finish any earlier private swap whose withdraw settled but whose swap leg
    // never completed (funds stranded at the fresh address). Safe to call on
    // connect; resolves to the number recovered (0 if nothing to do).
    resumeSwaps: async () => {
      const r = await relay("RESUME_SWAPS").catch(() => null)
      return r?.recovered ?? 0
    }
  }
  console.log("[paraloom] wallet bridge ready (main world)")
}

export {}
