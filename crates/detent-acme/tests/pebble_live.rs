//! Live spike: full dns-01 issuance against Pebble + challtestsrv.
//!
//! Ignored by default; run with Pebble up (see docs/spikes/acme-le.md).
//!
//! Env:
//! - `PEBBLE_URL` (required to run, e.g. `https://localhost:14000/dir`)
//! - `PEBBLE_CA` (optional, path to pebble.minica.pem for trust)
//! - `CHALLTESTSRV` (optional, default `http://localhost:8055`)
//!
//! Flow: `HookProvider` writes the 0600 challenge file into a temp
//! `state_dir`, a bridge reads that file back and POSTs it to challtestsrv's
//! management API (the hook contract is the file; challtestsrv is the
//! external responder), `dig` against challtestsrv's DNS port confirms
//! propagation, then the order flow drives to a certificate.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use detent_acme::{
    HookProvider, account_and_order, cleanup_challenges, finalize, present_challenges, wait_ready,
};
use instant_acme::{OrderStatus, RetryPolicy};

const TEST_DOMAIN: &str = "le.wtf";

/// Reads the challenge file `HookProvider` wrote and publishes it to
/// challtestsrv's management API: the external-responder half of the hook
/// contract. The file in `state_dir` is the interface; challtestsrv only
/// needs to learn what it says.
fn publish_to_challtestsrv(
    state_dir: &Path,
    record: &detent_acme::DnsRecord,
    challtestsrv: &str,
) -> Result<(), detent_acme::AcmeError> {
    let path = state_dir.join(format!("{}.txt", record.fqdn()));
    let value = std::fs::read_to_string(&path).map_err(detent_acme::AcmeError::Io)?;
    let out = Command::new("curl")
        .args([
            "-s",
            "-d",
            &format!(r#"{{"host":"{}", "value": "{value}"}}"#, record.fqdn()),
            &format!("{challtestsrv}/set-txt"),
        ])
        .output()
        .map_err(detent_acme::AcmeError::Io)?;
    if !out.status.success() {
        return Err(detent_acme::AcmeError::InvalidValue(format!(
            "challtestsrv set-txt failed: {}",
            out.status
        )));
    }
    Ok(())
}

/// Deletes the TXT record from challtestsrv after the order resolves.
fn unpublish_from_challtestsrv(fqdn: &str, challtestsrv: &str) {
    let _ = Command::new("curl")
        .args([
            "-s",
            "-d",
            &format!(r#"{{"host":"{fqdn}."}}"#),
            &format!("{challtestsrv}/clear-txt"),
        ])
        .status();
}

/// PEM to DER, std-only: strip armor, decode the std-alphabet base64 body.
fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    base64_decode(&body)
}

// Test-only decoder: short, fixed inputs (one leaf cert). Arithmetic and
// casts stay in-range by construction; allow the pedantic lints the
// workspace denies in non-test code rather than armoring a helper.
#[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for c in input.bytes() {
        if c == b'=' || c == b'\n' || c == b'\r' || c == b' ' {
            continue;
        }
        let v = TABLE.iter().position(|t| *t == c)? as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}

/// Proves a full dns-01 issuance against a live Pebble. Requires:
/// `PEBBLE_URL` (e.g. `https://localhost:14000/dir`), optional `PEBBLE_CA`
/// (path to `pebble.minica.pem`), optional `CHALLTESTSRV` (default
/// `http://localhost:8055`). The ignored test errors when `PEBBLE_URL` is absent.
///
/// Run: `PEBBLE_URL=... PEBBLE_CA=... cargo test -p detent-acme -- --ignored --nocapture`
#[test]
#[ignore = "needs a live Pebble: run with PEBBLE_URL (+PEBBLE_CA) set and `-- --ignored`"]
fn pebble_dns01_issuance() -> Result<(), Box<dyn std::error::Error>> {
    let directory = std::env::var("PEBBLE_URL")
        .map_err(|_| "PEBBLE_URL must be set when running the ignored Pebble live test")?;
    let ca = std::env::var("PEBBLE_CA").ok().map(PathBuf::from);
    let challtestsrv =
        std::env::var("CHALLTESTSRV").unwrap_or_else(|_| "http://localhost:8055".to_owned());
    let state_dir = std::env::temp_dir().join("detent-pebble-spike-challenges");
    let creds_path = std::env::temp_dir().join("detent-pebble-spike-account.json");
    let _ = std::fs::remove_file(&creds_path); // fresh account per full run

    let (issued, ari) = runtime()?.block_on(async {
        let (account, mut order) = account_and_order(
            &directory,
            &[TEST_DOMAIN],
            &creds_path,
            ca.as_deref(),
            None,
            &[],
            None,
        )
        .await?;
        println!("account: {}", account.id());
        println!("order:   {}", order.url());

        let hook = HookProvider::new(&state_dir);
        let bridge = |record: &detent_acme::DnsRecord| {
            publish_to_challtestsrv(&state_dir, record, &challtestsrv)?;
            Ok(())
        };
        let records = present_challenges(&mut order, &hook, &bridge).await?;
        println!("challenges presented and marked ready");

        // Caller-owned retry loop: no sleeps in the library.
        let policy = RetryPolicy::new()
            .initial_delay(Duration::from_millis(200))
            .timeout(Duration::from_secs(30));
        let status = wait_ready(&mut order, &policy).await?;
        println!("status:  {status:?}");
        if status != OrderStatus::Ready {
            return Err(detent_acme::AcmeError::InvalidOrder(status).into());
        }

        let issued = finalize(&mut order, &policy).await;
        cleanup_challenges(&hook, &records);
        let issued = issued?;
        println!(
            "chain:   {} PEM block(s)",
            issued.chain_pem.matches("BEGIN CERTIFICATE").count()
        );
        // ARI while the account is still alive: identifier out of the fresh
        // chain, suggested window back from Pebble, window-start sanity, and
        // the lifetime helper agreeing with a brand-new certificate.
        let id = detent_acme::ari_identifier(&issued.chain_pem)?;
        let (info, _) = account
            .renewal_info(&id)
            .await
            .map_err(detent_acme::AcmeError::from)?;
        let start = info.suggested_window.start.unix_timestamp();
        let end = info.suggested_window.end.unix_timestamp();
        assert!(start < end, "ARI window must be non-empty: {start}..{end}");
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let fresh = detent_acme::should_renew_ari(
            &account,
            &issued.chain_pem,
            now - 60,
            now + 576_000,
            now,
        )
        .await?;
        assert!(!fresh, "a just-issued certificate must not renew yet");
        Ok::<(String, (i64, i64)), Box<dyn std::error::Error>>((issued.chain_pem, (start, end)))
    })?;

    // Cleanup: withdraw the hook files and TXT records.
    let _ = std::fs::remove_dir_all(&state_dir);
    unpublish_from_challtestsrv(&format!("_acme-challenge.{TEST_DOMAIN}"), &challtestsrv);

    // Assertions: chain parses (PEM → DER, SEQUENCE tag) and the requested
    // domain appears in the leaf DER (SAN dNSName entries are IA5String, so
    // the raw domain bytes are embedded verbatim).
    let blocks: Vec<&str> = issued
        .split("-----END CERTIFICATE-----")
        .filter(|b| b.contains("BEGIN CERTIFICATE"))
        .collect();
    let der = pem_to_der(blocks.first().ok_or("no certificate in chain")?)
        .ok_or("leaf PEM did not decode")?;
    assert_eq!(
        der.first().copied(),
        Some(0x30),
        "DER must open with a SEQUENCE"
    );
    let domain_bytes = TEST_DOMAIN.as_bytes();
    assert!(
        der.windows(domain_bytes.len()).any(|w| w == domain_bytes),
        "requested domain missing from leaf DER SANs"
    );

    println!("done:    order valid, certificate downloaded");
    println!("ari:     suggested window {}..{}", ari.0, ari.1);
    // Spike convenience: the chain on disk for out-of-band inspection
    // (openssl x509 -serial/-fingerprint for the transcript).
    if let Ok(out) = std::env::var("PEBBLE_CHAIN_OUT") {
        let _ = std::fs::write(out, issued);
    }
    Ok(())
}
