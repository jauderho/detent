## qps-ploc — test fixture, NOT a real locale.
## Standard pseudo-locale tag (used by Microsoft and others for pseudo-localization
## QA). This file is deliberately incomplete: it translates a handful of the ids in
## `locales/en-US/core.ftl` and defines one id that `en-US` does not have. It exists
## solely so `detent-i18n`'s id-parity test (crates/detent-i18n/src/lib.rs) can prove,
## against real data, that the test catches ids missing from a locale and ids a
## locale adds that `en-US` does not define. It is not part of the compiled-in
## catalogue and is never reachable through `Localizer::new`/`for_env` — see the
## "i18n-embed substitution" note in `crates/detent-i18n/src/lib.rs` and
## `docs/TRANSLATING.md` for why it lives here instead of under `locales/`.

hosts-name = [hosts]
hosts-note-spoofing = [entries here override dns; a wrong or malicious entry silently redirects lookups.]
hosts-invalid-hostname = [`{ $name }` is not a valid hostname.]

## Deliberately not translated (present in en-US, absent here), to exercise the
## "missing" direction of the parity check: hosts-tip-entries, hosts-tip-ip,
## hosts-tip-hostnames, hosts-tip-comment, hosts-duplicate-canonical,
## hosts-no-hostnames, hosts-hostname-is-ip, hosts-ipv6-zone-unsupported,
## hosts-hostname-multiple-ips, hosts-localhost-not-loopback,
## hosts-missing-localhost, hosts-missing-ipv6-localhost, hosts-too-many-entries.

## Deliberately extra (absent from en-US, present here), to exercise the "extra"
## direction of the parity check.
qps-ploc-only-fixture-id = [this id does not exist in en-US]
