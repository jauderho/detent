#!/usr/bin/env bun
/**
 * api-check — verifies src/api/schema.d.ts is exactly what the checked-in
 * OpenAPI document generates.
 *
 * The Rust side already guarantees docs/openapi.json matches the running
 * server (crates/detent-web/src/api/openapi.rs diffs it byte for byte in a
 * test). This closes the other half: that the TypeScript the front end is
 * typed against matches that document. Without it, a backend response type
 * can change, the document can be regenerated, and the UI keeps compiling
 * against the old shape.
 *
 * Usage:
 *   bun run api:check              compare, exit non-zero on drift
 *   bun run api:check -- --verbose report byte counts and the paths compared
 *   bun run api:check -- --help    print this usage block
 *
 * CLI switches:
 *   --verbose, -v   Print the compared paths and their sizes.
 *   --help, -h      Print usage and exit 0.
 *
 * This script only reads; it never writes the generated file. Regenerate with
 * `bun run api:generate`.
 *
 * Exit codes:
 *   0  the committed types match the document
 *   1  they differ — run `bun run api:generate`
 *   2  the generator could not be run
 */

import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const EXIT_OK = 0
const EXIT_DRIFT = 1
const EXIT_GENERATOR_FAILED = 2

const GENERATED = 'src/api/schema.d.ts'
const DOCUMENT = '../docs/openapi.json'

function main(argv: readonly string[]): number {
  const verbose = argv.includes('--verbose') || argv.includes('-v')
  if (argv.includes('--help') || argv.includes('-h')) {
    console.log(
      [
        'api-check — verify src/api/schema.d.ts matches docs/openapi.json.',
        '',
        'Usage: bun run api:check [-- --verbose] [-- --help]',
        '',
        '  --verbose, -v  print the compared paths and their sizes',
        '  --help, -h     print this message',
        '',
        'On drift, regenerate with `bun run api:generate`.',
      ].join('\n'),
    )
    return EXIT_OK
  }

  const root = fileURLToPath(new URL('..', import.meta.url))

  // Generate to stdout rather than over the committed file: a check that
  // rewrites its own input can never fail twice in a row, which would hide
  // drift from anyone who ran it locally before pushing.
  const generated = spawnSync('bunx', ['openapi-typescript', DOCUMENT], {
    cwd: root,
    encoding: 'utf8',
  })
  if (generated.status !== 0) {
    console.error(`api-check: openapi-typescript failed:\n${generated.stderr}`)
    return EXIT_GENERATOR_FAILED
  }

  const committed = readFileSync(join(root, GENERATED), 'utf8')
  const fresh = generated.stdout

  if (verbose) {
    console.log(`api-check: ${DOCUMENT} → ${fresh.length} bytes`)
    console.log(`api-check: ${GENERATED} → ${committed.length} bytes`)
  }

  if (committed !== fresh) {
    console.error(
      `api-check: ${GENERATED} is not what ${DOCUMENT} generates.\n` +
        '  Run `bun run api:generate` and commit the result.',
    )
    return EXIT_DRIFT
  }

  console.log(`api-check: OK — ${GENERATED} matches ${DOCUMENT}.`)
  return EXIT_OK
}

process.exit(main(process.argv.slice(2)))
