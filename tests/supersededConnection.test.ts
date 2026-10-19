import { beforeEach, describe, expect, it, vi } from "vitest"
import { installFakeChrome } from "./support/chromeStorage"

beforeEach(() => {
  installFakeChrome()
})

describe("superseded CONNECT_WALLET approval resolution and REJECT_CONNECTION id-checking (paraloom-core#1029)", () => {
  it("settles the first pending connection when a superseded connection request arrives", async () => {
    // Model requestApproval and withKeepAlive behavior from src/background/index.ts
    let pendingConnection: {
      id: number
      origin: string
      resolve: (approved: boolean) => void
    } | null = null
    let connectionIdCounter = 0
    let intervalsActive = 0

    function requestApproval(origin: string, timeoutMs: number): Promise<boolean> {
      if (pendingConnection) {
        pendingConnection.resolve(false)
      }
      return new Promise((resolve) => {
        connectionIdCounter = Math.max(connectionIdCounter + 1, Date.now())
        const id = connectionIdCounter
        const clearPersisted = () =>
          void chrome.storage.session.remove("pendingConn").catch(() => {})
        const timer = setTimeout(() => {
          if (pendingConnection?.id === id) {
            pendingConnection = null
            clearPersisted()
            resolve(false)
          }
        }, timeoutMs)
        pendingConnection = {
          id,
          origin,
          resolve: (approved: boolean) => {
            clearTimeout(timer)
            pendingConnection = null
            clearPersisted()
            resolve(approved)
          }
        }
        void chrome.storage.session.set({ pendingConn: { id, origin } }).catch(() => {})
      })
    }

    function withKeepAlive<T>(p: Promise<T>): Promise<T> {
      intervalsActive++
      const timer = setInterval(() => {}, 20_000)
      return p.finally(() => {
        clearInterval(timer)
        intervalsActive--
      })
    }

    const state = { first: "pending", second: "pending" }
    const p1 = withKeepAlive(requestApproval("https://app.paraloom.io", 120_000)).then((res) => {
      state.first = res ? "approved" : "rejected"
    })

    expect(intervalsActive).toBe(1)
    expect(state.first).toBe("pending")

    // Second connection arrives while first is still pending (double-click or second tab)
    const p2 = withKeepAlive(requestApproval("https://app.paraloom.io", 120_000)).then((res) => {
      state.second = res ? "approved" : "rejected"
    })

    // First request should settle immediately as rejected, clearing its keep-alive interval
    await p1
    expect(state.first).toBe("rejected")
    expect(intervalsActive).toBe(1) // Only p2's interval remains active

    // Check storage has request #2's info
    const stored = (await chrome.storage.session.get("pendingConn")) as {
      pendingConn?: { id: number; origin: string }
    }
    expect(stored.pendingConn).toBeDefined()
    expect(stored.pendingConn?.id).toBe(connectionIdCounter)

    // Settle p2
    pendingConnection?.resolve(true)
    await p2
    expect(state.second).toBe("approved")
    expect(intervalsActive).toBe(0)
  })

  it("REJECT_CONNECTION only removes pendingConn if message.id matches the current pending request", async () => {
    // Set pending connection with ID 2
    await chrome.storage.session.set({
      pendingConn: { id: 2, origin: "https://app.paraloom.io" }
    })

    let pendingConnection: { id: number; resolve: (approved: boolean) => void } | null = {
      id: 2,
      resolve: vi.fn()
    }

    async function handleRejectConnection(messageId: number) {
      const r = await chrome.storage.session.get("pendingConn")
      const pc = r.pendingConn as { id: number; origin: string } | undefined
      if (pc && pc.id === messageId) {
        await chrome.storage.session.remove("pendingConn")
      }
      if (pendingConnection && pendingConnection.id === messageId) {
        pendingConnection.resolve(false)
        pendingConnection = null
      }
    }

    // Attempt to reject with stale message ID 1 (e.g. from an old closed popup)
    await handleRejectConnection(1)

    // Storage still has ID 2!
    const afterStaleReject = await chrome.storage.session.get("pendingConn")
    expect(afterStaleReject.pendingConn).toEqual({ id: 2, origin: "https://app.paraloom.io" })
    expect(pendingConnection).not.toBeNull()

    // Now reject with matching message ID 2
    await handleRejectConnection(2)
    const afterValidReject = await chrome.storage.session.get("pendingConn")
    expect(afterValidReject.pendingConn).toBeUndefined()
    expect(pendingConnection).toBeNull()
  })
})
