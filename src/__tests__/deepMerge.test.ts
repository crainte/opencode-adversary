import { describe, expect, test } from "bun:test"
import { deepMerge } from "../index"

describe("deepMerge", () => {
  test("merges flat objects", () => {
    const target = { a: 1, b: 2 }
    const source = { b: 3, c: 4 }
    expect(deepMerge(target, source)).toEqual({ a: 1, b: 3, c: 4 })
  })

  test("merges nested objects", () => {
    const target = { a: { x: 1, y: 2 }, b: 3 }
    const source = { a: { y: 5, z: 6 } }
    expect(deepMerge(target, source)).toEqual({ a: { x: 1, y: 5, z: 6 }, b: 3 })
  })

  test("deeply nested objects", () => {
    const target = { a: { b: { c: { d: 1 } } } }
    const source = { a: { b: { c: { e: 2 } } } }
    expect(deepMerge(target, source)).toEqual({ a: { b: { c: { d: 1, e: 2 } } } })
  })

  test("source arrays replace target arrays", () => {
    const target = { arr: [1, 2, 3] }
    const source = { arr: [4, 5] }
    expect(deepMerge(target, source)).toEqual({ arr: [4, 5] })
  })

  test("ignores undefined values in source", () => {
    const target = { a: 1, b: 2 }
    const source = { a: undefined, b: 3 }
    expect(deepMerge(target, source)).toEqual({ a: 1, b: 3 })
  })

  test("null in source replaces target", () => {
    const target = { a: { x: 1 } }
    const source = { a: null }
    expect(deepMerge(target, source as any)).toEqual({ a: null })
  })

  test("handles empty source", () => {
    const target = { a: 1, b: 2 }
    expect(deepMerge(target, {})).toEqual({ a: 1, b: 2 })
  })

  test("handles empty target", () => {
    const target = {}
    const source = { a: 1, b: 2 }
    expect(deepMerge(target, source)).toEqual({ a: 1, b: 2 })
  })

  test("does not mutate original objects", () => {
    const target = { a: { x: 1 } }
    const source = { a: { y: 2 } }
    const targetCopy = JSON.parse(JSON.stringify(target))
    const sourceCopy = JSON.parse(JSON.stringify(source))

    deepMerge(target, source)

    expect(target).toEqual(targetCopy)
    expect(source).toEqual(sourceCopy)
  })

  test("primitive source values overwrite target objects", () => {
    const target = { a: { x: 1 } }
    const source = { a: 5 }
    expect(deepMerge(target, source as any)).toEqual({ a: 5 })
  })

  test("object source values overwrite target primitives", () => {
    const target = { a: 5 }
    const source = { a: { x: 1 } }
    expect(deepMerge(target, source as any)).toEqual({ a: { x: 1 } })
  })

  test("handles mixed nested structures", () => {
    const target = {
      enabled: true,
      patterns: { enabled: true, rules: [{ a: 1 }] },
      adversary: { enabled: false, tools: ["bash"] },
    }
    const source = {
      patterns: { enabled: false },
      adversary: { tools: ["edit"] },
    }
    expect(deepMerge(target, source)).toEqual({
      enabled: true,
      patterns: { enabled: false, rules: [{ a: 1 }] },
      adversary: { enabled: false, tools: ["edit"] },
    })
  })
})
