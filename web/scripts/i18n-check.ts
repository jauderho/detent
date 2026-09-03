#!/usr/bin/env bun
/**
 * i18n-check — verifies every Fluent message id referenced from src/ exists
 * in locales/en-US/web.ftl, and flags hardcoded JSX text literals that
 * should be Fluent ids instead.
 *
 * Usage: bun run i18n:check   (invoked via package.json script "i18n:check")
 *
 * Checks:
 *   1. Every `<Localized id="…">` / `l10n.getString("…")` id used under
 *      src/ is defined in locales/en-US/web.ftl.
 *   2. No JSX text node containing a letter appears outside test files and
 *      outside the fallback children of a <Localized> element (which
 *      intentionally mirror the message text per @fluent/react convention).
 *
 * Exits non-zero and prints violations if either check fails.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

const WEB_ROOT = new URL('..', import.meta.url).pathname
const SRC_DIR = join(WEB_ROOT, 'src')
const FTL_PATH = join(WEB_ROOT, '..', 'locales', 'en-US', 'web.ftl')

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry)
    const stat = statSync(full)
    if (stat.isDirectory()) {
      walk(full, out)
    } else if (/\.(tsx?|jsx?)$/.test(entry)) {
      out.push(full)
    }
  }
  return out
}

function isTestFile(path: string): boolean {
  return /(__tests__\/|\.test\.[tj]sx?$|\/test\/)/.test(path)
}

function loadFtlIds(path: string): Set<string> {
  const text = readFileSync(path, 'utf8')
  const ids = new Set<string>()
  for (const line of text.split('\n')) {
    const m = /^([a-zA-Z][a-zA-Z0-9_-]*)\s*=/.exec(line)
    if (m?.[1]) ids.add(m[1])
  }
  return ids
}

function findReferencedIds(text: string): string[] {
  const ids: string[] = []
  const localizedRe = /<Localized\s+id=["']([^"']+)["']/g
  const getStringRe = /l10n\.getString\(\s*["']([^"']+)["']/g
  for (const m of text.matchAll(localizedRe)) {
    const id = m[1]
    if (id) ids.push(id)
  }
  for (const m of text.matchAll(getStringRe)) {
    const id = m[1]
    if (id) ids.push(id)
  }
  return ids
}

/** Strips <Localized>…</Localized> fallback-children blocks (non-nesting, sufficient for this codebase). */
function stripLocalizedBlocks(text: string): string {
  return text.replace(/<Localized\b[^>]*>[\s\S]*?<\/Localized>/g, '<Localized />')
}

function findHardcodedJsxText(text: string): string[] {
  const stripped = stripLocalizedBlocks(text)
  const violations: string[] = []
  // JSX text nodes: content between `>` and `<` on the same logical run,
  // ignoring script/style-free .tsx source. Skip pure whitespace/symbols.
  const jsxTextRe = />([^<>{}\n]*[a-zA-Z][^<>{}]*)</g
  for (const m of stripped.matchAll(jsxTextRe)) {
    const raw = m[1]?.trim()
    if (!raw) continue
    // Ignore stray closing-tag artifacts and JS expressions leaking through.
    if (raw.startsWith('//')) continue
    violations.push(raw)
  }
  return violations
}

function main(): number {
  const ftlIds = loadFtlIds(FTL_PATH)
  const files = walk(SRC_DIR)

  let failed = false
  const missingIds: { file: string; id: string }[] = []
  const hardcodedText: { file: string; text: string }[] = []

  for (const file of files) {
    const text = readFileSync(file, 'utf8')
    const rel = relative(WEB_ROOT, file)

    for (const id of findReferencedIds(text)) {
      if (!ftlIds.has(id)) {
        missingIds.push({ file: rel, id })
      }
    }

    if (!isTestFile(file) && /\.tsx$/.test(file)) {
      for (const raw of findHardcodedJsxText(text)) {
        hardcodedText.push({ file: rel, text: raw })
      }
    }
  }

  if (missingIds.length > 0) {
    failed = true
    console.error(
      'i18n-check: Fluent ids referenced in src/ but missing from locales/en-US/web.ftl:',
    )
    for (const { file, id } of missingIds) {
      console.error(`  ${file}: "${id}"`)
    }
  }

  if (hardcodedText.length > 0) {
    failed = true
    console.error(
      'i18n-check: hardcoded JSX text literals found outside <Localized> fallback children:',
    )
    for (const { file, text } of hardcodedText) {
      console.error(`  ${file}: "${text}"`)
    }
  }

  if (failed) {
    return 1
  }

  console.log(`i18n-check: OK — ${ftlIds.size} message ids defined, all references resolved.`)
  return 0
}

process.exit(main())
