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
    let not_after = detent_web::api::system::not_after_rfc3339(report.not_after_unix);
    // The warning's wire names (`half`, `quarter`) are interpolated verbatim,
    // like every other enum wire name this CLI prints.
    let warning = match report.expiry_warning {
        Some(detent_ops::ExpiryWarning::Half) => "half",
        Some(detent_ops::ExpiryWarning::Quarter) => "quarter",
        None => "none",
    };

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
        return Ok(Exit::Ok);
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
        Some(percent) => renderer.line(
            streams.out,
            MessageId::new("cli-cert-lifetime"),
            &[("percent", &format!("{percent}%")), ("warning", warning)],
        )?,
        None => renderer.line(
            streams.out,
            MessageId::new("cli-cert-lifetime-unknown"),
            &[],
        )?,
    }
    Ok(Exit::Ok)
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
        use time::OffsetDateTime;
        let lifetime = 10_i64 * 24 * 60 * 60;
        let used = lifetime.saturating_mul(percent).div_euclid(100);
        let to_ymd = |at: i64| {
            let date = OffsetDateTime::from_unix_timestamp(at)?.date();
            Ok::<(i32, u8, u8), Box<dyn std::error::Error>>((
                date.year(),
                date.month() as u8,
                date.day(),
            ))
        };
        dated_pair(
            to_ymd(now_unix.saturating_sub(used))?,
            to_ymd(now_unix.saturating_sub(used).saturating_add(lifetime))?,
        )
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
        let (exit, out, _) = run(&cfg, &renderer(&messages, false))?;
        assert_eq!(exit, Exit::Ok, "{out}");
        assert!(out.contains("unknown"), "{out}");

        let (exit, out, _) = run(&cfg, &renderer(&messages, true))?;
        assert_eq!(exit, Exit::Ok, "{out}");
        let parsed: serde_json::Value = serde_json::from_str(&out)?;
        assert!(parsed.pointer("/not_after_unix").is_some(), "{out}");
        assert!(!out.contains("PRIVATE KEY"), "{out}");
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
