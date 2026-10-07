/**
 * Dotted numeric version comparison, the same rules as `detent-core`'s
 * `version` module (crates/detent-core/src/version.rs): the numeric run at the
 * start of the text is the version, anything after it is ignored, and text with
 * no such run is unknown.
 */

/** The numeric components of `text`, or `undefined` when it is not a version. */
function components(text: string): readonly number[] | undefined {
  const run = (/^\s*([0-9.]*)/.exec(text)?.[1] ?? '').replace(/\.+$/, '')
  const names = run.split('.')
  if (names.includes('')) return undefined
  const parts = names.map((name) => Number(name))
  return parts.every((part) => Number.isSafeInteger(part)) ? parts : undefined
}

/**
 * `-1`, `0` or `1` as `left` is older than, equal to or newer than `right`.
 * Missing trailing components count as `0`. `undefined` when either side is not
 * a version.
 */
export function compareVersions(left: string, right: string): -1 | 0 | 1 | undefined {
  const a = components(left)
  const b = components(right)
  if (a === undefined || b === undefined) return undefined
  for (let index = 0; index < Math.max(a.length, b.length); index += 1) {
    const l = a[index] ?? 0
    const r = b[index] ?? 0
    if (l !== r) return l < r ? -1 : 1
  }
  return 0
}

/**
 * Whether an option that needs `since` is unsupported by `installed`. Only a
 * known, older version says so: an undetected or unparsable one does not
 * disable anything, the server reports it as a warning instead.
 */
export function isTooOld(installed: string | undefined, since: string): boolean {
  return installed !== undefined && compareVersions(installed, since) === -1
}
