/**
 * Teaches TypeScript about the jest-dom matchers `src/test/preload.ts` installs.
 *
 * `@testing-library/jest-dom` ships ready-made augmentations for Jest and for
 * Vitest, but not for `bun:test`, so the matchers work at run time and are
 * invisible to the type checker without this. Declaring it here rather than
 * reaching for `any` at each call site keeps `toBeInTheDocument()` and friends
 * type-checked, including a typo in one of their names.
 */

import type { TestingLibraryMatchers } from '@testing-library/jest-dom/matchers'

declare module 'bun:test' {
  interface Matchers<T> extends TestingLibraryMatchers<typeof expect.stringContaining, T> {}
  interface AsymmetricMatchers extends TestingLibraryMatchers<unknown, unknown> {}
}
