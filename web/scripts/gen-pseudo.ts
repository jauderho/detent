#!/usr/bin/env bun
/**
 * gen-pseudo — generates `locales/qps-ploc/web.ftl` from `locales/en-US/web.ftl`.
 *
 * Every simple message value is wrapped in `[...]` markers. Fluent select
 * blocks and their variants are left untouched — the markers catch
 * untranslated prose and overflow without duplicating the selector syntax.
 *
 * Usage: bun scripts/gen-pseudo.ts
 *   generates locales/qps-ploc/web.ftl (relative to repo root)
 */

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const WEB_ROOT = new URL('..', import.meta.url).pathname
const SRC_PATH = join(WEB_ROOT, '..', 'locales', 'en-US', 'web.ftl')
const OUT_DIR = join(WEB_ROOT, '..', 'locales', 'qps-ploc')
const OUT_PATH = join(OUT_DIR, 'web.ftl')

function generate(src: string): string {
  const lines = src.split('\n')
  const out: string[] = []
  let currentKey: string | null = null
  let valueLines: string[] = []

  function flush() {
    if (currentKey !== null && valueLines.length > 0) {
      const hasSelect = valueLines.some((l) => /^\s+[*]?\s*\[/.test(l) || /^\s+\S+\s+\{/.test(l))
      if (hasSelect) {
        // Fluent select blocks — pass through unwrapped so the selector
        // syntax stays parseable. The variant strings inside are short enough
        // that wrapping them individually is not worth the complexity.
        out.push(`${currentKey} = ${valueLines.join('\n')}`)
      } else {
        out.push(`${currentKey} = [${valueLines.join('\n')}]`)
      }
    }
    currentKey = null
    valueLines = []
  }

  function isSelectVariant(line: string): boolean {
    // Indented line with a variant pattern: "    [one] ..." or "   *[other] ..."
    return /^\s+\[/.test(line) || /^\s+\*\s/.test(line)
  }

  for (const line of lines) {
    // Comment or blank line: flush any pending message, then pass through.
    if (line.startsWith('##') || line.trim() === '') {
      flush()
      out.push(line)
      continue
    }

    // New message definition: "key = value" or "key = " (multiline).
    const m = /^([a-zA-Z][a-zA-Z0-9_-]*)\s*=\s*(.*)$/.exec(line)
    if (m) {
      flush()
      currentKey = m[1]
      const rest = m[2]
      if (rest.length > 0) {
        valueLines = [rest]
      } else {
        valueLines = []
      }
      continue
    }

    // Fluent select variant line — pass through unwrapped.
    if (currentKey !== null && isSelectVariant(line)) {
      valueLines.push(line)
      continue
    }

    // Continuation or closing brace inside a message — pass through.
    if (currentKey !== null) {
      valueLines.push(line)
      continue
    }

    // Outside any message — pass through as-is.
    out.push(line)
  }

  flush()
  return `${out.join('\n')}\n`
}

const src = readFileSync(SRC_PATH, 'utf8')
mkdirSync(OUT_DIR, { recursive: true })
writeFileSync(OUT_PATH, generate(src))
console.log(`gen-pseudo: wrote ${OUT_PATH} (${src.split('\n').length} lines from en-US)`)
