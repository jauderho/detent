;(() => {
  let s
  try {
    s = localStorage.getItem('detent-theme')
    if (!s) {
      s = window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
    }
    document.documentElement.setAttribute('data-theme', s)
  } catch {
    document.documentElement.setAttribute('data-theme', 'dark')
  }
})()
