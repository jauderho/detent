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
 *   2. Every id defined in web.ftl is referenced from src/. The bundle is
 *      compiled into the binary (`vite` `?raw` import → rust-embed), and
 *      detent targets SBCs where every byte is argued for, so a message no
 *      code can reach is dead weight. It is also the usual shape of a
 *      rename gone half-done: the new id is referenced, the old one lingers.
 *   3. No JSX text node containing a letter appears outside test files and
 *      outside the fallback children of a <Localized> element (which
 *      intentionally mirror the message text per @fluent/react convention).
 *
 * Exits non-zero and prints violations if any check fails.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

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

export function loadFtlIdsFrom(text: string): Set<string> {
  const ids = new Set<string>()
  for (const line of text.split('\n')) {
    const m = /^([a-zA-Z][a-zA-Z0-9_-]*)\s*=/.exec(line)
    if (m?.[1]) ids.add(m[1])
  }
  return ids
}

export function findReferencedIds(text: string): string[] {
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

/**
 * Every quoted string literal in `text` that spells out one of `known`.
 *
 * Check 1 asks "is this id defined?" and so must only look where an id is
 * unambiguously being *rendered* — `<Localized id>` and `getString`. Check 2
 * asks the opposite question, "can any code reach this id?", and the honest
 * answer is broader: `validate.ts` pushes `'forms-error-min-length'` through
 * an `issue()` helper, and `messages.ts` lists every server-sent id in the
 * `API_MESSAGE_IDS` array. Both are real references that the narrow patterns
 * cannot see, and calling them dead would delete messages an operator does
 * read.
 *
 * Matching against ids that are already defined is what keeps this from
 * drowning in ordinary strings: a literal has to spell a real message id
 * exactly before it counts.
 */
export function findIdLiterals(text: string, known: ReadonlySet<string>): string[] {
  const found: string[] = []
  for (const m of text.matchAll(/["'`]([a-zA-Z][a-zA-Z0-9_-]*)["'`]/g)) {
    const id = m[1]
    if (id !== undefined && known.has(id)) found.push(id)
  }
  return found
}

/** Strips <Localized>…</Localized> fallback-children blocks (non-nesting, sufficient for this codebase). */
function stripLocalizedBlocks(text: string): string {
  return text.replace(/<Localized\b[^>]*>[\s\S]*?<\/Localized>/g, '<Localized />')
}

/**
 * Punctuation that says "this is code, not prose".
 *
 * The scan below is a regex over `>…<` runs, not a parser, so it cannot tell a
 * JSX text node from a fragment of an expression that merely sits between a
 * `>` and a `<` — `foo ?? bar()` inside a `{…}` container matched happily and
 * reported itself as untranslated copy. A false failure here is worse than a
 * missed one: it trains the reader to ignore the check, or worse, to reshape
 * working code to appease it. So anything carrying these characters is treated
 * as code and skipped, at the cost of missing a hardcoded string that contains
 * one.
 */
const CODE_PUNCTUATION = /[(){};=?|&`$\\]|=>|\.\w/

export function findHardcodedJsxText(text: string): string[] {
  const stripped = stripLocalizedBlocks(text)
  const violations: string[] = []
  // A JSX text node lives between `>` and `<` with no intervening angle
  // bracket, brace or newline — real copy is written on one line.
  const jsxTextRe = />([^<>{}\n]*[a-zA-Z][^<>{}\n]*)</g
  for (const m of stripped.matchAll(jsxTextRe)) {
    const raw = m[1]?.trim()
    if (!raw) continue
    if (raw.startsWith('//')) continue
    if (CODE_PUNCTUATION.test(raw)) continue
    // Prose has at least two adjacent letters; `x` or `a b` is an artifact.
    if (!/[a-zA-Z]{2}/.test(raw)) continue
    violations.push(raw)
  }
  return violations
}

function main(): number {
  const ftlIds = loadFtlIdsFrom(readFileSync(FTL_PATH, 'utf8'))
  const files = walk(SRC_DIR)

  let failed = false
  const missingIds: { file: string; id: string }[] = []
  const hardcodedText: { file: string; text: string }[] = []
  const referenced = new Set<string>()

  for (const file of files) {
    const text = readFileSync(file, 'utf8')
    const rel = relative(WEB_ROOT, file)

    for (const id of findReferencedIds(text)) {
      referenced.add(id)
      if (!ftlIds.has(id)) {
        missingIds.push({ file: rel, id })
      }
    }
    for (const id of findIdLiterals(text, ftlIds)) {
      referenced.add(id)
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

  const unused = [...ftlIds].filter((id) => !referenced.has(id)).sort()
  if (unused.length > 0) {
    failed = true
    console.error(
      'i18n-check: message ids defined in locales/en-US/web.ftl but referenced nowhere in src/:',
    )
    for (const id of unused) {
      console.error(`  "${id}"`)
    }
    console.error(
      '  Delete them, or reference them. The bundle ships inside the binary, so an ' +
        'unreachable message is bytes on an SBC that nothing can ever print.',
    )
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

  console.log(
    `i18n-check: OK — ${ftlIds.size} message ids defined, all referenced, all references resolved.`,
  )
  return 0
}

const entry = process.argv[1]
if (entry !== undefined && import.meta.url.startsWith('file:')) {
  if (fileURLToPath(import.meta.url) === entry) {
    process.exit(main())
  }
}
