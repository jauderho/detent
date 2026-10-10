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
 *   4. Every translation that exists (locales/<lang>/web.ftl for each
 *      directory under locales/ other than en-US and the pseudo-locale)
 *      defines exactly the ids en-US defines, and every message uses exactly
 *      the placeables (`{$var}`) its en-US source uses. A missing id silently
 *      falls back to English; a missing or misspelled placeable renders as a
 *      literal `{$var}` to the operator. A locale with no directory yet is not
 *      a failure (translators add them), but a directory that is not one of the
 *      SHIPPED_LOCALES in src/i18n/locales.ts is, and so is one with no web.ftl.
 *
 * Exits non-zero and prints violations if any check fails.
 */

import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import { DEFAULT_LOCALE, PSEUDO_LOCALE, SHIPPED_LOCALES } from '../src/i18n/locales.ts'

const WEB_ROOT = new URL('..', import.meta.url).pathname
const SRC_DIR = join(WEB_ROOT, 'src')
const LOCALES_DIR = join(WEB_ROOT, '..', 'locales')
const FTL_PATH = join(LOCALES_DIR, 'en-US', 'web.ftl')
/**
 * The translations that exist: every directory under `localesDir` except the
 * source locale, the generated pseudo-locale and hidden entries. Sorted.
 */
export function findTranslatedLocales(localesDir: string): string[] {
  return readdirSync(localesDir)
    .filter(
      (name) =>
        !name.startsWith('.') &&
        name !== DEFAULT_LOCALE &&
        name !== PSEUDO_LOCALE &&
        statSync(join(localesDir, name)).isDirectory(),
    )
    .sort()
}

/** The shipped locales that have no directory yet. Informational, never a failure. */
export function pendingLocales(found: readonly string[]): string[] {
  return SHIPPED_LOCALES.filter((tag) => tag !== DEFAULT_LOCALE && !found.includes(tag))
}

/** The directories that are not a shipped locale, so would never be offered. */
export function unknownLocales(found: readonly string[]): string[] {
  return found.filter((tag) => !(SHIPPED_LOCALES as readonly string[]).includes(tag))
}

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

/**
 * The set of placeable variable names (`{$var}`, including selector heads such
 * as `{$count ->`) each message uses, keyed by message id, sorted. A message's
 * text runs from its `id =` line through the indented or closing-brace lines
 * that follow it.
 */
export function loadPlaceablesFrom(text: string): Map<string, string[]> {
  const blocks = new Map<string, string[]>()
  let current: string | null = null
  for (const line of text.split('\n')) {
    const m = /^([a-zA-Z][a-zA-Z0-9_-]*)\s*=/.exec(line)
    if (m?.[1]) {
      current = m[1]
      blocks.set(current, [line])
    } else if (current !== null && /^(\s|\})/.test(line) && line.trim() !== '') {
      blocks.get(current)?.push(line)
    } else {
      current = null
    }
  }
  const out = new Map<string, string[]>()
  for (const [id, lines] of blocks) {
    const vars = new Set<string>()
    for (const v of lines.join('\n').matchAll(/\{\s*\$([a-zA-Z][a-zA-Z0-9_-]*)/g)) {
      if (v[1]) vars.add(v[1])
    }
    out.set(id, [...vars].sort())
  }
  return out
}

export interface LocaleDrift {
  missing: string[]
  extra: string[]
  placeables: { id: string; expected: string[]; actual: string[] }[]
}

/** How a translation differs from its en-US source: ids and placeables. */
export function compareLocale(source: string, translation: string): LocaleDrift {
  const want = loadPlaceablesFrom(source)
  const have = loadPlaceablesFrom(translation)
  const missing = [...want.keys()].filter((id) => !have.has(id)).sort()
  const extra = [...have.keys()].filter((id) => !want.has(id)).sort()
  const placeables: LocaleDrift['placeables'] = []
  for (const [id, expected] of want) {
    const actual = have.get(id)
    if (actual !== undefined && actual.join(',') !== expected.join(',')) {
      placeables.push({ id, expected, actual })
    }
  }
  return { missing, extra, placeables }
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

  const source = readFileSync(FTL_PATH, 'utf8')
  const translated = findTranslatedLocales(LOCALES_DIR)
  for (const lang of unknownLocales(translated)) {
    failed = true
    console.error(
      `i18n-check: locales/${lang} is not a shipped locale. Add the tag to SHIPPED_LOCALES in ` +
        'web/src/i18n/locales.ts (the owner decides which locales ship), or rename the directory.',
    )
  }
  for (const lang of translated) {
    const path = join(LOCALES_DIR, lang, 'web.ftl')
    if (!existsSync(path)) {
      failed = true
      console.error(
        `i18n-check: ${relative(WEB_ROOT, path)} does not exist (a locale needs web.ftl).`,
      )
      continue
    }
    const drift = compareLocale(source, readFileSync(path, 'utf8'))
    if (drift.missing.length + drift.extra.length + drift.placeables.length === 0) continue
    failed = true
    console.error(`i18n-check: ${relative(WEB_ROOT, path)} differs from locales/en-US/web.ftl:`)
    for (const id of drift.missing) console.error(`  missing: "${id}"`)
    for (const id of drift.extra) console.error(`  extra (absent from en-US): "${id}"`)
    for (const { id, expected, actual } of drift.placeables) {
      console.error(`  placeables of "${id}": expected [${expected}], found [${actual}]`)
    }
  }

  if (failed) {
    return 1
  }

  const pending = pendingLocales(translated)
  console.log(
    `i18n-check: OK — ${ftlIds.size} message ids defined, all referenced, all references resolved; ` +
      `${translated.length} translation(s) match en-US${translated.length > 0 ? ` (${translated.join(', ')})` : ''}.`,
  )
  if (pending.length > 0) {
    console.log(`i18n-check: no directory yet for ${pending.join(', ')} (shown in English).`)
  }
  return 0
}

const entry = process.argv[1]
if (entry !== undefined && import.meta.url.startsWith('file:')) {
  if (fileURLToPath(import.meta.url) === entry) {
    process.exit(main())
  }
}
