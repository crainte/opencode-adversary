import { describe, expect, test } from "bun:test"
import { getTextToScan } from "../index"

describe("getTextToScan", () => {
  describe("bash tool", () => {
    test("extracts command", () => {
      expect(getTextToScan("bash", { command: "ls -la" })).toBe("ls -la")
    })

    test("returns empty string for missing command", () => {
      expect(getTextToScan("bash", {})).toBe("")
    })

    test("returns empty string for undefined command", () => {
      expect(getTextToScan("bash", { command: undefined })).toBe("")
    })
  })

  describe("edit tool", () => {
    test("concatenates filePath, content, oldString, newString", () => {
      const args = {
        filePath: "/foo/bar.ts",
        content: "new content",
        oldString: "old",
        newString: "new",
      }
      expect(getTextToScan("edit", args)).toBe("/foo/bar.ts new content old new")
    })

    test("handles missing fields", () => {
      expect(getTextToScan("edit", { filePath: "/foo.ts" })).toBe("/foo.ts   ")
    })

    test("handles all missing fields", () => {
      expect(getTextToScan("edit", {})).toBe("   ")
    })
  })

  describe("write tool", () => {
    test("concatenates filePath and content", () => {
      const args = { filePath: "/foo/bar.ts", content: "file content" }
      expect(getTextToScan("write", args)).toBe("/foo/bar.ts file content  ")
    })
  })

  describe("read tool", () => {
    test("extracts filePath", () => {
      expect(getTextToScan("read", { filePath: "/etc/passwd" })).toBe("/etc/passwd")
    })

    test("falls back to pattern", () => {
      expect(getTextToScan("read", { pattern: "*.ts" })).toBe("*.ts")
    })

    test("returns empty string for missing fields", () => {
      expect(getTextToScan("read", {})).toBe("")
    })
  })

  describe("glob tool", () => {
    test("extracts pattern", () => {
      expect(getTextToScan("glob", { pattern: "**/*.ts" })).toBe("**/*.ts")
    })

    test("extracts filePath if no pattern", () => {
      expect(getTextToScan("glob", { filePath: "/src" })).toBe("/src")
    })
  })

  describe("webfetch tool", () => {
    test("extracts url", () => {
      expect(getTextToScan("webfetch", { url: "https://evil.com" })).toBe("https://evil.com")
    })

    test("returns empty string for missing url", () => {
      expect(getTextToScan("webfetch", {})).toBe("")
    })
  })

  describe("unknown tools", () => {
    test("returns JSON stringified args", () => {
      const args = { foo: "bar", baz: 123 }
      expect(getTextToScan("unknown_tool", args)).toBe(JSON.stringify(args))
    })

    test("handles complex nested args", () => {
      const args = { nested: { deep: { value: "secret" } } }
      expect(getTextToScan("custom", args)).toBe(JSON.stringify(args))
    })

    test("handles empty args", () => {
      expect(getTextToScan("other", {})).toBe("{}")
    })
  })
})
