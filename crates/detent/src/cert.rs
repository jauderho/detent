//! `detent cert status` (PLAN §2.6).
//!
//! A read-only view of the served TLS certificate: what `serve` offers from
//! `tls.cert_dir`, without contacting any server or CA. The report math is
//! [`detent_web::api::system::cert_report_for_der`]'s — the same function the
//! `GET /api/v1/system/cert` handler answers with — so the shell and the API
//! cannot drift apart.

use detent_core::diag::MessageId;

use crate::cli::CertAction;
use crate::output::{Exit, Renderer};
use crate::run::{Settings, Streams, report_web_config_error};

/// `detent cert …`: dispatch on the action.
///
/// # Errors
///
/// Whatever the streams report.
pub fn status(
    action: &CertAction,
    settings: &Settings,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Exit> {
    match *action {
        CertAction::Status => cert_status(settings, renderer, streams),
    }
}

/// `detent cert status`: source, fingerprint, expiry, and lifetime used.
///
/// Exits [`Exit::Failed`] when the served certificate is expired or cannot
/// be parsed (owner decision, 2026-09-27), even though the report is still
/// printed in full; a certificate merely inside its renewal window exits
/// [`Exit::Ok`].
///
/// # Errors
///
/// Whatever the streams report.
fn cert_status(
    settings: &Settings,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Exit> {
    let config = match settings.load_web_config() {
        Ok(config) => config,
        Err(err) => return report_web_config_error(&err, settings, renderer, streams),
    };
    let cert_dir = &config.tls.cert_dir;
    let pair = match detent_web::serving_pair(cert_dir) {
        Ok(Some(pair)) => pair,
        Ok(None) => {
            renderer.line(
                streams.notes,
                MessageId::new("cli-cert-missing"),
                &[("path", &cert_dir.display().to_string())],
            )?;
            return Ok(Exit::Failed);
        }
        Err(err) => {
            return cert_unreadable(cert_dir, &err.to_string(), renderer, streams);
        }
    };
    // The served pair is an ACME one exactly when a usable ACME pair is
    // stored and is the pair served (`serving_pair` prefers ACME, so a
    // stored-but-unusable ACME file can never be what is served). A re-read
    // failure falls back to `bootstrap`: the pair is already in hand, so
    // status still succeeds.
    let source = match detent_web::load_acme(cert_dir) {
        Ok(Some(stored)) if stored.fingerprint() == pair.fingerprint() => "acme",
        _ => "bootstrap",
    };

    let report = detent_web::api::system::cert_report_for_der(pair.cert_der());
    // The certificate is bad (owner decision, 2026-09-27) when it cannot be
    // parsed (`not_after_unix` is `None`) or has already reached `not_after`.
    // "Now" is the system wall clock, as in `cert_report_for_der`. It comes
    // from `std`, because this crate enables `time` only with `update`.
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|since| i64::try_from(since.as_secs()).ok());
    let exit = match (report.not_after_unix, now_unix) {
        (Some(not_after_unix), Some(now_unix)) if now_unix < not_after_unix => Exit::Ok,
        _ => Exit::Failed,
    };
    let not_after = detent_web::api::system::not_after_rfc3339(report.not_after_unix);
    // The warning's wire names (`half`, `quarter`) are interpolated verbatim,
    // like every other enum wire name this CLI prints. No warning has its own
    // message, so no English word is interpolated for it.
    let warning = report.expiry_warning.map(|warning| match warning {
        detent_ops::ExpiryWarning::Half => "half",
        detent_ops::ExpiryWarning::Quarter => "quarter",
    });

    if renderer.json {
        let text = serde_json::to_string_pretty(&serde_json::json!({
            "source": source,
            "fingerprint": report.fingerprint,
            "not_after": not_after,
            "not_after_unix": report.not_after_unix,
            "lifetime_used_percent": report.lifetime_used_percent,
            "expiry_warning": report.expiry_warning,
            "renewal_due": report.renewal_due,
        }))
        .map_err(std::io::Error::other)?;
        writeln!(streams.out, "{text}")?;
        return Ok(exit);
    }
    renderer.line(
        streams.out,
        MessageId::new("cli-cert-source"),
        &[("source", source)],
    )?;
    renderer.line(
        streams.out,
        MessageId::new("cli-cert-fingerprint"),
        &[("fingerprint", report.fingerprint.as_str())],
    )?;
    match not_after {
        Some(stamp) => renderer.line(
            streams.out,
            MessageId::new("cli-cert-not-after"),
            &[("not_after", stamp.as_str())],
        )?,
        None => renderer.line(
            streams.out,
            MessageId::new("cli-cert-not-after-unknown"),
            &[],
        )?,
    }
    match report.lifetime_used_percent {
        Some(percent) => {
            let percent = format!("{percent}%");
            match warning {
                Some(warning) => renderer.line(
                    streams.out,
                    MessageId::new("cli-cert-lifetime"),
                    &[("percent", &percent), ("warning", warning)],
                )?,
                None => renderer.line(
                    streams.out,
                    MessageId::new("cli-cert-lifetime-no-warning"),
                    &[("percent", &percent)],
                )?,
            }
        }
        None => renderer.line(
            streams.out,
            MessageId::new("cli-cert-lifetime-unknown"),
            &[],
        )?,
    }
    Ok(exit)
}

/// The certificate directory cannot be read: say where, and why.
///
/// # Errors
///
/// Whatever the streams report.
fn cert_unreadable(
    cert_dir: &std::path::Path,
    reason: &str,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Exit> {
    renderer.line(
        streams.notes,
        MessageId::new("cli-cert-unreadable"),
        &[
            ("path", &cert_dir.display().to_string()),
            ("reason", reason),
        ],
    )?;
    Ok(Exit::Failed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::Messages;
    use crate::output::Renderer;

    type R = Result<(), Box<dyn std::error::Error>>;

    fn messages() -> Messages {
        Messages::new(Some("en-US"))
    }

    fn renderer(messages: &Messages, json: bool) -> Renderer<'_> {
        Renderer {
            messages,
            json,
            verbose: false,
        }
    }

    /// A config pointing at `cert_dir`; the main file holds only `[tls]`,
    /// so everything else is the documented default.
    fn fixture_settings(
        cert_dir: &std::path::Path,
    ) -> Result<Settings, Box<dyn std::error::Error>> {
        let dir = cert_dir.parent().unwrap_or(cert_dir);
        let path = cert_dir.display().to_string();
        std::fs::write(
            dir.join("detent.toml"),
            format!("[tls]\ncert_dir = {path:?}\n"),
        )?;
        Ok(Settings {
            state_root: dir.to_path_buf(),
            config_path: dir.join("detent.toml"),
        })
    }

    fn run(
        settings: &Settings,
        renderer: &Renderer<'_>,
    ) -> Result<(Exit, String, String), Box<dyn std::error::Error>> {
        let mut input = std::io::empty();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = status(
            &CertAction::Status,
            settings,
            renderer,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        Ok((exit, String::from_utf8(out)?, String::from_utf8(notes)?))
    }

    fn bootstrap_pair() -> Result<detent_web::CertifiedKeyPair, Box<dyn std::error::Error>> {
        Ok(detent_web::bootstrap_self_signed(&[
            "box.example".to_owned()
        ])?)
    }

    /// A pair spanning `from` to `to` (midnight UTC), so a test can slide a
    /// fixed-length window under the real clock.
    fn dated_pair(
        from: (i32, u8, u8),
        to: (i32, u8, u8),
    ) -> Result<detent_web::CertifiedKeyPair, Box<dyn std::error::Error>> {
        let key = rcgen::KeyPair::generate()?;
        let mut params = rcgen::CertificateParams::new(vec!["box.example".to_owned()])?;
        params.not_before = rcgen::date_time_ymd(from.0, from.1, from.2);
        params.not_after = rcgen::date_time_ymd(to.0, to.1, to.2);
        let chain_pem = params.self_signed(&key)?.pem();
        Ok(detent_web::CertifiedKeyPair::from_acme_pem(
            &chain_pem,
            &key.serialize_pem(),
        )?)
    }

    /// A ten-day pair whose lifetime is `percent` used at the real `now`.
    /// `not_after` lands on a midnight, one day early or late at most; the
    /// warning asserted below sits well inside its band either way.
    fn aged_pair(
        now_unix: i64,
        percent: i64,
    ) -> Result<detent_web::CertifiedKeyPair, Box<dyn std::error::Error>> {
        let lifetime = 10_i64 * 24 * 60 * 60;
        let used = lifetime.saturating_mul(percent).div_euclid(100);
        dated_pair(
            civil_from_unix(now_unix.saturating_sub(used))?,
            civil_from_unix(now_unix.saturating_sub(used).saturating_add(lifetime))?,
        )
    }

    /// Unix seconds to a UTC (year, month, day), by Howard Hinnant's
    /// `civil_from_days` algorithm.
    fn civil_from_unix(at: i64) -> Result<(i32, u8, u8), Box<dyn std::error::Error>> {
        let z = at.div_euclid(86_400).saturating_add(719_468);
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = doe
            .saturating_sub(doe / 1_460)
            .saturating_add(doe / 36_524)
            .saturating_sub(doe / 146_096)
            / 365;
        let doy = doe.saturating_sub(
            yoe.saturating_mul(365)
                .saturating_add(yoe / 4)
                .saturating_sub(yoe / 100),
        );
        let mp = doy.saturating_mul(5).saturating_add(2) / 153;
        let day = u8::try_from(
            doy.saturating_sub(mp.saturating_mul(153).saturating_add(2) / 5)
                .saturating_add(1),
        )?;
        let month = u8::try_from(if mp < 10 {
            mp.saturating_add(3)
        } else {
            mp.saturating_sub(9)
        })?;
        let year = i32::try_from(
            yoe.saturating_add(era.saturating_mul(400))
                .saturating_add(i64::from(month <= 2)),
        )?;
        Ok((year, month, day))
    }

    #[test]
    fn civil_from_unix_matches_known_dates() -> R {
        assert_eq!(civil_from_unix(0)?, (1970, 1, 1));
        assert_eq!(civil_from_unix(951_782_400)?, (2000, 2, 29));
        assert_eq!(civil_from_unix(1_790_726_400)?, (2026, 9, 30));
        assert_eq!(civil_from_unix(1_790_726_399)?, (2026, 9, 29));
        Ok(())
    }

    fn now_unix() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| {
                i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
            })
    }

    #[test]
    fn acme_and_bootstrap_pairs_render_text_and_json_without_key_material() -> R {
        for store in [
            detent_web::store_acme as fn(&std::path::Path, &detent_web::CertifiedKeyPair) -> _,
            detent_web::tls::store_bootstrap,
        ] {
            let dir = tempfile::TempDir::new()?;
            let cert_dir = dir.path().join("certs");
            store(&cert_dir, &bootstrap_pair()?)?;
            let settings = fixture_settings(&cert_dir)?;
            let messages = messages();
            let (exit, out, _) = run(&settings, &renderer(&messages, false))?;
            assert_eq!(exit, Exit::Ok, "{out}");
            assert!(out.contains("fingerprint"), "{out}");
            assert!(out.contains("(no warning)"), "{out}");
            assert!(!out.contains("PRIVATE KEY"), "{out}");

            let (exit, out, _) = run(&settings, &renderer(&messages, true))?;
            assert_eq!(exit, Exit::Ok, "{out}");
            let parsed: serde_json::Value = serde_json::from_str(&out)?;
            assert!(parsed.pointer("/fingerprint").is_some(), "{out}");
            assert!(!out.contains("PRIVATE KEY"), "{out}");
        }
        Ok(())
    }

    #[test]
    fn source_names_the_stored_pair() -> R {
        let dir = tempfile::TempDir::new()?;
        let cert_dir = dir.path().join("certs");
        detent_web::store_acme(&cert_dir, &bootstrap_pair()?)?;
        let cfg = fixture_settings(&cert_dir)?;
        let messages = messages();
        let (exit, out, _) = run(&cfg, &renderer(&messages, true))?;
        assert_eq!(exit, Exit::Ok, "{out}");
        let parsed: serde_json::Value = serde_json::from_str(&out)?;
        assert_eq!(
            parsed.pointer("/source").and_then(|v| v.as_str()),
            Some("acme")
        );
        let dir = tempfile::TempDir::new()?;
        let cert_dir = dir.path().join("cert");
        detent_web::tls::store_bootstrap(&cert_dir, &bootstrap_pair()?)?;
        let stored = fixture_settings(&cert_dir)?;
        let (exit, out, _) = run(&stored, &renderer(&messages, true))?;
        assert_eq!(exit, Exit::Ok, "{out}");
        let parsed: serde_json::Value = serde_json::from_str(&out)?;
        assert_eq!(
            parsed.pointer("/source").and_then(|v| v.as_str()),
            Some("bootstrap")
        );
        Ok(())
    }

    #[test]
    fn a_missing_directory_is_a_localized_failure() -> R {
        let dir = tempfile::TempDir::new()?;
        let cert_dir = dir.path().join("absent-certs");
        let cfg = fixture_settings(&cert_dir)?;
        let messages = messages();
        let (exit, out, notes) = run(&cfg, &renderer(&messages, false))?;
        assert_eq!(exit, Exit::Failed);
        assert!(out.is_empty(), "{out}");
        assert!(notes.contains("no certificate"), "{notes}");

        let (exit, out, _) = run(&cfg, &renderer(&messages, true))?;
        assert_eq!(exit, Exit::Failed);
        assert!(out.is_empty(), "{out}");
        Ok(())
    }

    #[test]
    fn a_bad_config_reports_the_path_and_fails() -> R {
        let dir = tempfile::TempDir::new()?;
        std::fs::write(dir.path().join("detent.toml"), b"[tls\n")?;
        let cfg = Settings {
            state_root: dir.path().to_path_buf(),
            config_path: dir.path().join("detent.toml"),
        };
        let messages = messages();
        let (exit, out, notes) = run(&cfg, &renderer(&messages, false))?;
        assert_eq!(exit, Exit::Failed);
        assert!(out.is_empty(), "{out}");
        assert!(notes.contains("detent.toml"), "{notes}");
        Ok(())
    }

    #[test]
    fn an_unreadable_directory_is_a_localized_failure() -> R {
        let dir = tempfile::TempDir::new()?;
        let blocker = dir.path().join("certs");
        std::fs::write(&blocker, b"not a directory")?;
        let cfg = fixture_settings(&blocker)?;
        let messages = messages();
        let (exit, out, notes) = run(&cfg, &renderer(&messages, false))?;
        assert_eq!(exit, Exit::Failed);
        assert!(out.is_empty(), "{out}");
        assert!(notes.contains("could not be read"), "{notes}");
        Ok(())
    }

    #[test]
    fn a_garbage_pair_renders_unknown_validity() -> R {
        let dir = tempfile::TempDir::new()?;
        let cert_dir = dir.path().join("certs");
        let key = rcgen::KeyPair::generate()?.serialize_der();
        let garbage = detent_web::CertifiedKeyPair::from_der_chain(
            b"not a certificate".to_vec(),
            vec![],
            key,
        );
        detent_web::tls::store_bootstrap(&cert_dir, &garbage)?;
        let cfg = fixture_settings(&cert_dir)?;
        let messages = messages();
        // Unparseable is a bad cert (owner decision, 2026-09-27): the report
        // still prints, but the exit status must say so.
        let (exit, out, _) = run(&cfg, &renderer(&messages, false))?;
        assert_eq!(exit, Exit::Failed, "{out}");
        assert!(out.contains("unknown"), "{out}");

        let (exit, out, _) = run(&cfg, &renderer(&messages, true))?;
        assert_eq!(exit, Exit::Failed, "{out}");
        let parsed: serde_json::Value = serde_json::from_str(&out)?;
        assert!(parsed.pointer("/not_after_unix").is_some(), "{out}");
        assert!(!out.contains("PRIVATE KEY"), "{out}");
        Ok(())
    }

    #[test]
    fn an_expired_pair_still_prints_but_fails() -> R {
        let dir = tempfile::TempDir::new()?;
        let cert_dir = dir.path().join("certs");
        detent_web::tls::store_bootstrap(&cert_dir, &dated_pair((2000, 1, 1), (2000, 2, 1))?)?;
        let cfg = fixture_settings(&cert_dir)?;
        let messages = messages();
        let (exit, out, _) = run(&cfg, &renderer(&messages, false))?;
        assert_eq!(exit, Exit::Failed, "{out}");
        assert!(out.contains("fingerprint"), "{out}");
        assert!(out.contains("2000"), "{out}");

        let (exit, out, _) = run(&cfg, &renderer(&messages, true))?;
        assert_eq!(exit, Exit::Failed, "{out}");
        let parsed: serde_json::Value = serde_json::from_str(&out)?;
        assert!(parsed.pointer("/fingerprint").is_some(), "{out}");
        Ok(())
    }

    #[test]
    fn warnings_trip_at_half_and_quarter_life() -> R {
        for (percent, warning) in [(55, "half"), (80, "quarter")] {
            let dir = tempfile::TempDir::new()?;
            let cert_dir = dir.path().join("certs");
            detent_web::tls::store_bootstrap(&cert_dir, &aged_pair(now_unix(), percent)?)?;
            let cfg = fixture_settings(&cert_dir)?;
            let messages = messages();
            let (exit, out, _) = run(&cfg, &renderer(&messages, false))?;
            assert_eq!(exit, Exit::Ok, "{out}");
            assert!(out.contains(warning), "{out}");

            let (exit, out, _) = run(&cfg, &renderer(&messages, true))?;
            assert_eq!(exit, Exit::Ok, "{out}");
            let parsed: serde_json::Value = serde_json::from_str(&out)?;
            assert_eq!(
                parsed.pointer("/expiry_warning").and_then(|v| v.as_str()),
                Some(warning),
                "{out}"
            );
            assert!(!out.contains("PRIVATE KEY"), "{out}");
        }
        Ok(())
    }
}
