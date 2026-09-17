;(() => {
  let s
  try {
    s = localStorage.getItem('detent-theme')
    if (s !== 'light' && s !== 'dark') {
      // Dark is the documented default (AGENTS.md), not a fallback the OS gets
      // a say in. This must agree with `readTheme()` in src/lib/theme.ts: this
      // script paints the first frame and that function decides every frame
      // after it, so a disagreement is a visible flash of the wrong theme.
      s = 'dark'
    }
    document.documentElement.setAttribute('data-theme', s)
  } catch {
    document.documentElement.setAttribute('data-theme', 'dark')
  }
})()
