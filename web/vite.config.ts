import path from 'node:path'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'
import { themeScriptPlugin } from './vite-plugin-theme-script.ts'

/**
 * Build config for a bundle that ships *inside the Rust binary*.
 *
 * `vite build` output is embedded by `rust-embed` (see
 * `crates/detent-web/src/spa.rs`), and the binary is size-gated in CI against
 * `size-baseline.json` at 3% tolerance. Every byte here becomes a byte of
 * `detent`, so the build is tuned for size over build speed — this runs once
 * per release, not per keystroke.
 *
 * `scripts/postbuild.ts` finishes the job: it writes the pre-compressed
 * `.br`/`.gz` siblings `spa.rs` serves (it never compresses at request time)
 * and re-checks the CSP hash the Rust side pins.
 */
export default defineConfig({
  plugins: [react(), tailwindcss(), themeScriptPlugin()],
  resolve: {
    alias: {
      '@': path.resolve(import.meta.dirname, './src'),
    },
  },
  build: {
    // Matches tsconfig.app.json's `target`. A modern baseline avoids shipping
    // downlevel helpers for syntax every browser we support already has.
    target: 'es2023',

    // Terser rather than the default esbuild: slower, but consistently a few
    // percent smaller, and this build runs once per release.
    minify: 'terser',
    terserOptions: {
      compress: {
        // Repeat passes so that inlining performed by one pass exposes
        // further constant folding for the next.
        passes: 3,
        // The console is not a supported interface of a shipped admin panel,
        // and a stray log could echo a value that should not be retained.
        drop_console: true,
        drop_debugger: true,
        // React's production build is already guarded on this; stating it
        // lets terser drop the dev-only branches outright.
        global_defs: { 'process.env.NODE_ENV': 'production' },
      },
      format: {
        comments: false,
      },
      // Property mangling is deliberately NOT enabled: it renames object keys,
      // which would silently corrupt the JSON models exchanged with the API
      // and the Fluent message ids looked up by string.
      mangle: true,
    },

    // lightningcss beats esbuild on CSS, and Tailwind v4 emits a lot of it.
    cssMinify: 'lightningcss',

    // Print gzip sizes so a regression is visible in the build log, next to
    // the postbuild report.
    reportCompressedSize: true,

    // `spa.rs` serves anything under `assets/` with an immutable cache header
    // on the strength of the content hash in its name, so the hash must stay.
    rollupOptions: {
      output: {
        assetFileNames: 'assets/[name]-[hash][extname]',
        chunkFileNames: 'assets/[name]-[hash].js',
        entryFileNames: 'assets/[name]-[hash].js',
      },
    },
  },
  css: {
    lightningcss: {
      targets: {
        // Roughly "browsers with baseline ES2023" — kept in step with
        // `build.target` above.
        chrome: 120 << 16,
        firefox: 120 << 16,
        safari: (17 << 16) | (2 << 8),
      },
    },
  },
  server: {
    fs: {
      // allow importing locales/en-US/web.ftl from outside web/ as ?raw
      allow: ['..'],
    },
  },
})
