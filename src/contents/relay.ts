import type { PlasmoCSConfig } from "plasmo"

const DEV_MATCHES =
  process.env.NODE_ENV === "development"
    ? ["http://localhost/*", "http://127.0.0.1/*"]
    : []

// Runs in the ISOLATED world (has chrome.*). It bridges window.paraloom calls
// posted from the page's MAIN world (inpage.ts) to the background service
// worker, then posts the background's reply back to the page.
export const config: PlasmoCSConfig = {
  matches: ["https://*.paraloom.io/*", "https://paraloom.io/*", ...DEV_MATCHES],
  run_at: "document_start"
}

const REQ = "paraloom:request"
const RES = "paraloom:response"

// The only message types the page provider (`inpage.ts`) ever sends. The relay
// forwards nothing else, so the popup-only connection-approval types cannot be
// reached from the page even if this were the only guard. It is not — the
// background refuses those by sender — but keeping the surface here to exactly
// the provider API means a new page-reachable type has to be added in two
// places on purpose, not leaked by the relay passing through whatever it gets.
const ALLOWED_TYPES = new Set([
  "CONNECT_WALLET",
  "DISCONNECT_WALLET",
  "SIGN_MESSAGE",
  "SEND_PRIVATE_TRANSFER",
  "PRIVATE_SWAP",
  "GET_SWAP_STATUS",
  "GET_ADDRESS",
  "GET_PUBLIC_ADDRESS",
  "GET_SHIELDED_BALANCE",
  "GET_SHIELDED_TOKEN_BALANCES",
  "IS_CONNECTED",
  "REQUEST_UNLOCK",
  "RESUME_SWAPS"
])

window.addEventListener("message", (event: MessageEvent) => {
  if (event.source !== window) return
  const data = event.data
  if (!data || data.channel !== REQ || typeof data.id !== "number") return
  if (typeof data.type !== "string" || !ALLOWED_TYPES.has(data.type)) return

  const reply = (result?: unknown, error?: string) => {
    const targetOrigin =
      event.origin && event.origin !== "null" ? event.origin : "*"
    window.postMessage({ channel: RES, id: data.id, result, error }, targetOrigin)
  }

  try {
    // Pin the allowlisted `type` AFTER spreading the page-controlled payload, so
    // a `type` key smuggled inside `payload` cannot override the one we just
    // validated against ALLOWED_TYPES and cross the privilege boundary as a
    // different message (#736.2).
    chrome.runtime.sendMessage(
      { ...(data.payload || {}), type: data.type },
      (response) => {
        const err = chrome.runtime.lastError
        if (err) reply(undefined, err.message)
        else reply(response)
      }
    )
  } catch (e) {
    reply(undefined, e instanceof Error ? e.message : String(e))
  }
})

export {}
