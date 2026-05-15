/**
 * Test helpers and mock factories for opencode-adversary tests
 */

// @ts-ignore - JSON import
import defaultConfig from "../../defaults/config.json"
import type { PatternRule, SecurityConfig } from "../index"

/**
 * Creates a mock OpenCode client with spy functions
 */
export function makeClient() {
  const logs: Array<{ level: string; message: string; extra?: any }> = []
  const toasts: Array<{ title: string; message: string; variant: string }> = []

  return {
    logs,
    toasts,
    app: {
      log: async ({ body }: { body: { level: string; message: string; extra?: any } }) => {
        logs.push(body)
      },
    },
    tui: {
      showToast: async ({
        body,
      }: {
        body: { title: string; message: string; variant: string }
      }) => {
        toasts.push(body)
      },
    },
    session: {
      messages: async () => ({ data: [] }),
      create: async () => ({ data: { id: "ses_test_review" } }),
      prompt: async () => ({ data: { parts: [{ type: "text", text: "ALLOW" }] } }),
      delete: async () => ({}),
    },
  }
}

/**
 * Creates a tool input object
 */
export function makeToolInput(tool: string, sessionID = "ses_test", callID = "call_test") {
  return { tool, sessionID, callID }
}

/**
 * Creates a tool output object with args
 */
export function makeToolOutput(args: Record<string, unknown>) {
  return { args }
}

/**
 * Returns all pattern rules from default config
 */
export function getRules(): PatternRule[] {
  return (defaultConfig as SecurityConfig).patterns.rules
}

/**
 * Finds a rule by reason substring
 */
export function findRule(reasonSubstring: string): PatternRule | undefined {
  return getRules().find((r) => r.reason.toLowerCase().includes(reasonSubstring.toLowerCase()))
}

/**
 * Creates a minimal security config for testing
 */
export function makeConfig(overrides: Partial<SecurityConfig> = {}): SecurityConfig {
  return {
    enabled: true,
    patterns: {
      enabled: true,
      rules: [],
    },
    adversary: {
      enabled: false,
      tools: [],
      model: null,
      policy: "",
    },
    ...overrides,
  }
}

/**
 * Creates a single pattern rule
 */
export function makeRule(
  pattern: string,
  action: "block" | "ask" = "block",
  reason = "Test rule",
): PatternRule {
  return { pattern, action, reason }
}
