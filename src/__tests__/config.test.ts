import { describe, expect, test } from "bun:test"
import { deepMerge, loadConfig } from "../index"

describe("loadConfig", () => {
  test("returns config with enabled flag", () => {
    const config = loadConfig()
    expect(typeof config.enabled).toBe("boolean")
  })

  test("returns config with patterns section", () => {
    const config = loadConfig()
    expect(config.patterns).toBeDefined()
    expect(typeof config.patterns.enabled).toBe("boolean")
    expect(Array.isArray(config.patterns.rules)).toBe(true)
  })

  test("returns config with adversary section", () => {
    const config = loadConfig()
    expect(config.adversary).toBeDefined()
    expect(typeof config.adversary.enabled).toBe("boolean")
    expect(Array.isArray(config.adversary.tools)).toBe(true)
    expect(typeof config.adversary.policy).toBe("string")
  })

  test("patterns rules have required fields", () => {
    const config = loadConfig()
    for (const rule of config.patterns.rules) {
      expect(typeof rule.pattern).toBe("string")
      expect(["block", "ask"]).toContain(rule.action)
      expect(typeof rule.reason).toBe("string")
    }
  })

  test("loads default config with multiple rules", () => {
    const config = loadConfig()
    expect(config.patterns.rules.length).toBeGreaterThan(10)
  })
})

describe("config merging with deepMerge", () => {
  test("user config can disable patterns", () => {
    const defaults = {
      enabled: true,
      patterns: { enabled: true, rules: [] },
    }
    const userConfig = { patterns: { enabled: false } }
    const merged = deepMerge(defaults, userConfig)
    expect(merged.patterns.enabled).toBe(false)
    expect(merged.enabled).toBe(true)
  })

  test("user config can add custom policy", () => {
    const defaults = {
      adversary: { enabled: true, policy: "default policy" },
    }
    const userConfig = { adversary: { policy: "custom policy" } }
    const merged = deepMerge(defaults, userConfig)
    expect(merged.adversary.policy).toBe("custom policy")
    expect(merged.adversary.enabled).toBe(true)
  })

  test("user config can override tools array", () => {
    const defaults = {
      adversary: { tools: ["bash"] },
    }
    const userConfig = { adversary: { tools: ["bash", "edit", "write"] } }
    const merged = deepMerge(defaults, userConfig)
    expect(merged.adversary.tools).toEqual(["bash", "edit", "write"])
  })
})
