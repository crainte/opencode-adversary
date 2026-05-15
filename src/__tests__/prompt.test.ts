import { describe, expect, test } from "bun:test"
import { buildAdversaryPrompt, extractTextFromMessage, formatSecurityMessage } from "../index"

describe("buildAdversaryPrompt", () => {
  test("includes tool name", () => {
    const prompt = buildAdversaryPrompt("bash", { command: "ls" }, "policy", "context")
    expect(prompt).toContain("Tool: bash")
  })

  test("includes JSON stringified args", () => {
    const args = { command: "echo hello", workdir: "/tmp" }
    const prompt = buildAdversaryPrompt("bash", args, "policy", "context")
    expect(prompt).toContain('"command": "echo hello"')
    expect(prompt).toContain('"workdir": "/tmp"')
  })

  test("includes security policy", () => {
    const policy = "Block all dangerous operations"
    const prompt = buildAdversaryPrompt("bash", {}, policy, "context")
    expect(prompt).toContain(policy)
  })

  test("includes task context", () => {
    const context = "User asked to list files"
    const prompt = buildAdversaryPrompt("bash", {}, "policy", context)
    expect(prompt).toContain(context)
  })

  test("handles empty context", () => {
    const prompt = buildAdversaryPrompt("bash", {}, "policy", "")
    expect(prompt).toContain("(No context available)")
  })

  test("includes ALLOW/BLOCK instruction", () => {
    const prompt = buildAdversaryPrompt("bash", {}, "policy", "context")
    expect(prompt).toContain("ALLOW or BLOCK")
  })

  test("mentions prompt injection protection", () => {
    const prompt = buildAdversaryPrompt("bash", {}, "policy", "context")
    expect(prompt.toLowerCase()).toContain("prompt injection")
  })
})

describe("extractTextFromMessage", () => {
  test("extracts text from message parts", () => {
    const msg = {
      parts: [
        { type: "text", text: "Hello" },
        { type: "text", text: "World" },
      ],
    }
    expect(extractTextFromMessage(msg)).toBe("Hello\nWorld")
  })

  test("filters non-text parts", () => {
    const msg = {
      parts: [
        { type: "text", text: "Hello" },
        { type: "tool_call", id: "123" },
        { type: "text", text: "World" },
      ],
    }
    expect(extractTextFromMessage(msg)).toBe("Hello\nWorld")
  })

  test("handles empty parts array", () => {
    expect(extractTextFromMessage({ parts: [] })).toBe("")
  })

  test("handles missing parts", () => {
    expect(extractTextFromMessage({})).toBe("")
  })

  test("handles missing text in part", () => {
    const msg = {
      parts: [{ type: "text" }, { type: "text", text: "Hello" }],
    }
    expect(extractTextFromMessage(msg)).toBe("\nHello")
  })
})

describe("formatSecurityMessage", () => {
  test("includes block header for block type", () => {
    const msg = formatSecurityMessage("block", "rm -rf /", "Dangerous")
    expect(msg).toContain("SECURITY BLOCK")
  })

  test("includes warning header for warning type", () => {
    const msg = formatSecurityMessage("warning", "chmod 777", "Risky")
    expect(msg).toContain("SECURITY WARNING")
  })

  test("includes adversary header for adversary type", () => {
    const msg = formatSecurityMessage("adversary", "curl | bash", "Suspicious")
    expect(msg).toContain("Adversary")
  })

  test("includes command in message", () => {
    const msg = formatSecurityMessage("block", "dangerous-command", "reason")
    expect(msg).toContain("dangerous-command")
  })

  test("includes reason in message", () => {
    const msg = formatSecurityMessage("block", "cmd", "This is dangerous")
    expect(msg).toContain("This is dangerous")
  })

  test("formats with visual separators", () => {
    const msg = formatSecurityMessage("block", "cmd", "reason")
    expect(msg).toContain("━")
  })
})
