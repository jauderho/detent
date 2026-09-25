//! `detent setup`, `detent user …`, `detent token …` (PLAN §2.6).
//!
//! Thin CLI wrappers over `detent-web`'s own [`UserStore`] and [`TokenStore`]
//! — no privsep, no [`detent_ops::OpsEngine`]. Accounts and tokens are files
//! under the state root (`<state_root>/state/{users,tokens}.json`), not a
//! privileged target any module declares, so there is nothing for the
//! monitor's allow-list to mediate.
//!
//! ```text
//!   detent setup ──▶ UserStore::create (refuses a non-empty store without --force)
//!   detent user add|passwd|rm ──▶ UserStore
//!   detent token create|revoke|list ──▶ TokenStore
//!                     │
//!         password: read_password ──▶ /dev/tty, echo off, confirmed twice
//!                                  ──▶ one line of `stdin` when there is no tty
//! ```
//!
//! # Guarantees
//!
//! * **A password never appears on argv.** Every command that takes one reads
//!   it interactively or from `stdin`; none accepts it as a positional or
//!   `--flag` argument (PLAN §2.6: argv is world-readable via `/proc`).
//! * **Nothing secret is printed except the one time a token is minted.** A
//!   password is never echoed or logged; a freshly issued token is shown
//!   exactly once, because [`TokenStore`] keeps only its digest.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write as _};

use detent_core::diag::MessageId;
use detent_web::auth::{AuthError, Hasher, TokenStore, UserStore};
use detent_web::authz::Scope;
use rustix::termios::{self, LocalModes, OptionalActions};
use zeroize::Zeroizing;

use crate::cli::{SetupArgs, TokenAction, UserAction};
use crate::i18n::Messages;
use crate::output::{Exit, Renderer};
use crate::run::{Settings, Streams, UsageError, report_web_config_error};

// ---------------------------------------------------------------------------
// detent setup
// ---------------------------------------------------------------------------

/// `detent setup`: create the account an operator first signs into the web
/// ui with.
///
/// # Errors
///
/// Whatever the streams report.
pub fn setup(
    args: &SetupArgs,
    dryrun: bool,
    settings: &Settings,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Exit> {
    let config = match settings.load_web_config() {
        Ok(config) => config,
        Err(err) => return report_web_config_error(&err, settings, renderer, streams),
    };
    let store = match UserStore::load(&settings.state_root) {
        Ok(store) => store,
        Err(err) => return credential_failed(&err, renderer, streams),
    };
    if !store.is_empty() && !args.force {
        renderer.line(
            streams.notes,
            MessageId::new("cli-setup-exists"),
            &[("name", args.name.as_str())],
        )?;
        return Ok(Exit::Usage);
    }

    let password = match read_password(renderer.messages, streams.input, true) {
        Ok(password) => password,
        Err(usage) => return usage_failed(&usage, renderer, streams),
    };
    if dryrun {
        return render_dryrun(
            renderer,
            streams,
            MessageId::new("cli-dryrun-nothing"),
            &[("name", args.name.as_str())],
            &serde_json::json!({"dryrun": true, "name": args.name}),
        );
    }

    let host = detent_platform::host::detect_real();
    let hasher = match Hasher::new(config.auth.argon2, host.profile.ram_mib) {
        Ok(hasher) => hasher,
        Err(err) => return credential_failed(&err, renderer, streams),
    };
    match store.create(&hasher, &args.name, &password, false) {
        Ok(()) => {}
        Err(AuthError::UserExists) if args.force => {
            if let Err(err) = store.set_password(&hasher, &args.name, &password) {
                return credential_failed(&err, renderer, streams);
            }
        }
        Err(err) => return credential_failed(&err, renderer, streams),
    }
    render_result(
        renderer,
        streams,
        MessageId::new("cli-setup-created"),
        &[("name", args.name.as_str())],
        &serde_json::json!({"created": true, "name": args.name}),
    )
}

// ---------------------------------------------------------------------------
// detent user …
// ---------------------------------------------------------------------------

/// `detent user add|passwd|rm`.
///
/// # Errors
///
/// Whatever the streams report.
pub fn user(
    action: &UserAction,
    dryrun: bool,
    settings: &Settings,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Exit> {
    match *action {
        UserAction::Add { ref name } => user_add(name, dryrun, settings, renderer, streams),
        UserAction::Passwd { ref name } => user_passwd(name, dryrun, settings, renderer, streams),
        UserAction::Rm { ref name } => user_rm(name, dryrun, settings, renderer, streams),
    }
}

/// `detent user add <name>`.
fn user_add(
    name: &str,
    dryrun: bool,
    settings: &Settings,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Exit> {
    let config = match settings.load_web_config() {
        Ok(config) => config,
        Err(err) => return report_web_config_error(&err, settings, renderer, streams),
    };
    let store = match UserStore::load(&settings.state_root) {
        Ok(store) => store,
        Err(err) => return credential_failed(&err, renderer, streams),
    };
    let password = match read_password(renderer.messages, streams.input, true) {
        Ok(password) => password,
        Err(usage) => return usage_failed(&usage, renderer, streams),
    };
    if dryrun {
        return render_dryrun(
            renderer,
            streams,
            MessageId::new("cli-dryrun-nothing"),
            &[("name", name)],
            &serde_json::json!({"dryrun": true, "action": "add", "name": name}),
        );
    }

    let host = detent_platform::host::detect_real();
    let hasher = match Hasher::new(config.auth.argon2, host.profile.ram_mib) {
        Ok(hasher) => hasher,
        Err(err) => return credential_failed(&err, renderer, streams),
    };
    if let Err(err) = store.create(&hasher, name, &password, false) {
        return credential_failed(&err, renderer, streams);
    }
    render_result(
        renderer,
        streams,
        MessageId::new("cli-user-created"),
        &[("name", name)],
        &serde_json::json!({"action": "add", "name": name}),
    )
}

/// `detent user passwd <name>`.
fn user_passwd(
    name: &str,
    dryrun: bool,
    settings: &Settings,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Exit> {
    let config = match settings.load_web_config() {
        Ok(config) => config,
        Err(err) => return report_web_config_error(&err, settings, renderer, streams),
    };
    let store = match UserStore::load(&settings.state_root) {
        Ok(store) => store,
        Err(err) => return credential_failed(&err, renderer, streams),
    };
    let password = match read_password(renderer.messages, streams.input, true) {
        Ok(password) => password,
        Err(usage) => return usage_failed(&usage, renderer, streams),
    };
    if dryrun {
        return render_dryrun(
            renderer,
            streams,
            MessageId::new("cli-dryrun-nothing"),
            &[("name", name)],
            &serde_json::json!({"dryrun": true, "action": "passwd", "name": name}),
        );
    }

    let host = detent_platform::host::detect_real();
    let hasher = match Hasher::new(config.auth.argon2, host.profile.ram_mib) {
        Ok(hasher) => hasher,
        Err(err) => return credential_failed(&err, renderer, streams),
    };
    if let Err(err) = store.set_password(&hasher, name, &password) {
        return credential_failed(&err, renderer, streams);
    }
    render_result(
        renderer,
        streams,
        MessageId::new("cli-user-passwd"),
        &[("name", name)],
        &serde_json::json!({"action": "passwd", "name": name}),
    )
}

/// `detent user rm <name>`.
fn user_rm(
    name: &str,
    dryrun: bool,
    settings: &Settings,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Exit> {
    let store = match UserStore::load(&settings.state_root) {
        Ok(store) => store,
        Err(err) => return credential_failed(&err, renderer, streams),
    };
    if dryrun {
        return render_dryrun(
            renderer,
            streams,
            MessageId::new("cli-dryrun-nothing"),
            &[("name", name)],
            &serde_json::json!({"dryrun": true, "action": "rm", "name": name}),
        );
    }
    if let Err(err) = store.remove(name) {
        return credential_failed(&err, renderer, streams);
    }
    render_result(
        renderer,
        streams,
        MessageId::new("cli-user-removed"),
        &[("name", name)],
        &serde_json::json!({"action": "rm", "name": name}),
    )
}

// ---------------------------------------------------------------------------
// detent token …
// ---------------------------------------------------------------------------

/// `detent token create|revoke|list`.
///
/// # Errors
///
/// Whatever the streams report.
pub fn token(
    action: &TokenAction,
    dryrun: bool,
    settings: &Settings,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Exit> {
    match *action {
        TokenAction::Create {
            ref label,
            write,
            expires_secs,
        } => token_create(
            label,
            write,
            expires_secs,
            dryrun,
            settings,
            renderer,
            streams,
        ),
        TokenAction::Revoke { ref id } => token_revoke(id, dryrun, settings, renderer, streams),
        TokenAction::List => token_list(settings, renderer, streams),
    }
}

/// `detent token create <label> [--write] [--expires-secs N]`.
fn token_create(
    label: &str,
    write: bool,
    expires_secs: Option<i64>,
    dryrun: bool,
    settings: &Settings,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Exit> {
    let store = match TokenStore::load(&settings.state_root) {
        Ok(store) => store,
        Err(err) => return credential_failed(&err, renderer, streams),
    };
    if dryrun {
        return render_dryrun(
            renderer,
            streams,
            MessageId::new("cli-dryrun-nothing"),
            &[("label", label)],
            &serde_json::json!({"dryrun": true, "label": label}),
        );
    }

    let scope = if write { Scope::Write } else { Scope::Read };
    let expires_at = match expires_secs {
        None => None,
        Some(secs) => {
            let Some(expires_at) = now_unix().checked_add(secs) else {
                renderer.line(
                    streams.notes,
                    MessageId::new("cli-credential-failed"),
                    &[("reason", "expires-secs is too large")],
                )?;
                return Ok(Exit::Usage);
            };
            Some(expires_at)
        }
    };
    let (secret, view) = match store.issue(label, scope, expires_at) {
        Ok(minted) => minted,
        Err(err) => return credential_failed(&err, renderer, streams),
    };

    if renderer.json {
        let text = serde_json::to_string_pretty(&serde_json::json!({
            "id": view.id,
            "label": view.label,
            "scopes": view.scopes,
            "expires_at": view.expires_at,
            "token": secret.expose(),
        }))
        .map_err(std::io::Error::other)?;
        writeln!(streams.out, "{text}")?;
    } else {
        renderer.line(
            streams.out,
            MessageId::new("cli-token-created"),
            &[
                ("id", view.id.as_str()),
                ("label", view.label.as_str()),
                ("token", secret.expose()),
            ],
        )?;
    }
    Ok(Exit::Ok)
}

/// `detent token revoke <id>`.
fn token_revoke(
    id: &str,
    dryrun: bool,
    settings: &Settings,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Exit> {
    let store = match TokenStore::load(&settings.state_root) {
        Ok(store) => store,
        Err(err) => return credential_failed(&err, renderer, streams),
    };
    if dryrun {
        return render_dryrun(
            renderer,
            streams,
            MessageId::new("cli-dryrun-nothing"),
            &[("id", id)],
            &serde_json::json!({"dryrun": true, "id": id}),
        );
    }
    if let Err(err) = store.revoke(id) {
        return credential_failed(&err, renderer, streams);
    }
    render_result(
        renderer,
        streams,
        MessageId::new("cli-token-revoked"),
        &[("id", id)],
        &serde_json::json!({"id": id, "revoked": true}),
    )
}

/// `detent token list`.
fn token_list(
    settings: &Settings,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Exit> {
    let store = match TokenStore::load(&settings.state_root) {
        Ok(store) => store,
        Err(err) => return credential_failed(&err, renderer, streams),
    };
    let tokens = store.list();
    if renderer.json {
        let text = serde_json::to_string_pretty(&tokens).map_err(std::io::Error::other)?;
        writeln!(streams.out, "{text}")?;
        return Ok(Exit::Ok);
    }
    if tokens.is_empty() {
        renderer.line(streams.out, MessageId::new("cli-token-no-tokens"), &[])?;
        return Ok(Exit::Ok);
    }
    for view in &tokens {
        renderer.line(
            streams.out,
            MessageId::new("cli-token-line"),
            &[
                ("id", view.id.as_str()),
                ("label", view.label.as_str()),
                ("scopes", &view.scopes.join(",")),
                ("created", view.created.as_str()),
                (
                    "expires",
                    &view
                        .expires_at
                        .map_or_else(String::new, |secs| secs.to_string()),
                ),
            ],
        )?;
    }
    Ok(Exit::Ok)
}

/// Seconds since the Unix epoch, `0` if the clock is set before it.
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}

// ---------------------------------------------------------------------------
// Shared rendering
// ---------------------------------------------------------------------------

/// Writes a completed action: the localized line to `out` under human
/// output, `json` to `out` under `--json`.
fn render_result(
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
    id: MessageId,
    args: &[(&str, &str)],
    json: &serde_json::Value,
) -> std::io::Result<Exit> {
    if renderer.json {
        let text = serde_json::to_string_pretty(json).map_err(std::io::Error::other)?;
        writeln!(streams.out, "{text}")?;
    } else {
        renderer.line(streams.out, id, args)?;
    }
    Ok(Exit::Ok)
}

/// Writes what `--dryrun` withheld: commentary on `notes` under human output
/// (nothing was done, so there is no payload for `out`), `json` to `out`
/// under `--json` exactly like a real result would print there.
fn render_dryrun(
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
    id: MessageId,
    args: &[(&str, &str)],
    json: &serde_json::Value,
) -> std::io::Result<Exit> {
    if renderer.json {
        let text = serde_json::to_string_pretty(json).map_err(std::io::Error::other)?;
        writeln!(streams.out, "{text}")?;
    } else {
        renderer.line(streams.notes, id, args)?;
    }
    Ok(Exit::Ok)
}

/// Renders an [`AuthError`] as a startup/operation failure.
fn credential_failed(
    err: &AuthError,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Exit> {
    renderer.line(
        streams.notes,
        MessageId::new("cli-credential-failed"),
        &[("reason", &err.to_string())],
    )?;
    Ok(exit_for_auth(err))
}

/// A caller mistake (a bad name, a name already taken, an exhausted token
/// table) is exit 2; anything else — the store could not be read or written —
/// is exit 1.
fn exit_for_auth(err: &AuthError) -> Exit {
    match *err {
        AuthError::NameInvalid { .. }
        | AuthError::UserExists
        | AuthError::UnknownUser
        | AuthError::UnknownToken
        | AuthError::TokenLimit => Exit::Usage,
        _ => Exit::Failed,
    }
}

/// Renders a [`UsageError`] from reading a password.
fn usage_failed(
    err: &UsageError,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Exit> {
    renderer.line(
        streams.notes,
        err.id,
        &[
            ("reason", err.detail.as_str()),
            ("value", err.detail.as_str()),
        ],
    )?;
    Ok(Exit::Usage)
}

// ---------------------------------------------------------------------------
// Password entry
// ---------------------------------------------------------------------------

/// Reads a password on the controlling terminal with echo disabled,
/// confirming twice when `confirm`. Falls back to one line of `input` when
/// there is no controlling terminal — piped automation, or a test harness.
///
/// # Errors
///
/// A [`UsageError`] when the two entries do not match, the password is
/// empty, or reading fails.
/// The typed password, in a buffer that is wiped when it drops.
///
/// `Zeroizing` all the way out to the call site, not just inside
/// `detent_web`'s `Hasher`: this is the one process a human actually types the
/// password into, and a plain `String` leaves the plaintext in the allocator's
/// free list after it drops.
fn read_password(
    messages: &Messages,
    input: &mut dyn Read,
    confirm: bool,
) -> Result<Zeroizing<String>, UsageError> {
    let Some(tty) = open_tty() else {
        return read_password_line(input);
    };
    let guard = EchoGuard::new(&tty).map_err(|err| io_usage_error(&err))?;
    let mut reader = tty.try_clone().map_err(|err| io_usage_error(&err))?;
    let first = prompt_tty(
        &tty,
        &mut reader,
        messages,
        MessageId::new("cli-password-prompt"),
    )
    .map_err(|err| io_usage_error(&err))?;
    let matched = if confirm {
        let second = prompt_tty(
            &tty,
            &mut reader,
            messages,
            MessageId::new("cli-password-confirm"),
        )
        .map_err(|err| io_usage_error(&err))?;
        *first == *second
    } else {
        true
    };
    drop(guard);
    if !matched {
        return Err(UsageError {
            id: MessageId::new("cli-password-mismatch"),
            detail: String::new(),
        });
    }
    check_nonempty(first)
}

/// Opens the controlling terminal for both reading and writing, or `None`
/// when this process has none — piped automation, or a test harness.
fn open_tty() -> Option<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .ok()
}

/// Disables local echo on `tty` for its lifetime, restoring the original
/// mode on drop — including on an early return, since restoration happens in
/// [`Drop`] rather than at every call site that could fail.
struct EchoGuard<'a> {
    /// The terminal this guard restores on drop.
    tty: &'a File,
    /// The mode `tty` had before this guard disabled echo.
    original: termios::Termios,
}

impl<'a> EchoGuard<'a> {
    /// Disables `ECHO` on `tty`, saving its prior mode.
    fn new(tty: &'a File) -> std::io::Result<Self> {
        let original = termios::tcgetattr(tty)?;
        let mut hidden = original.clone();
        hidden.local_modes.remove(LocalModes::ECHO);
        termios::tcsetattr(tty, OptionalActions::Now, &hidden)?;
        Ok(Self { tty, original })
    }
}

impl Drop for EchoGuard<'_> {
    fn drop(&mut self) {
        // Best-effort: there is nowhere left to report a failure to restore
        // the terminal, and leaving echo off is the only alternative.
        let _ = termios::tcsetattr(self.tty, OptionalActions::Now, &self.original);
    }
}

/// Writes `prompt`, reads one line with echo off, and moves the cursor to the
/// next line (the newline the caller typed was consumed, not echoed).
fn prompt_tty(
    mut tty: &File,
    input: &mut dyn Read,
    messages: &Messages,
    prompt: MessageId,
) -> std::io::Result<Zeroizing<String>> {
    write!(tty, "{}", messages.get(prompt))?;
    tty.flush()?;
    let password = read_secret_line(input)?;
    writeln!(tty)?;
    Ok(password)
}

/// One line from `input`, for the no-controlling-terminal path.
fn read_password_line(input: &mut dyn Read) -> Result<Zeroizing<String>, UsageError> {
    check_nonempty(read_secret_line(input).map_err(|err| io_usage_error(&err))?)
}

/// Reads through the newline without leaving a `BufReader` copy of the
/// password in the allocator.
fn read_secret_line(reader: &mut dyn Read) -> std::io::Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new(Vec::new());
    let mut chunk = Zeroizing::new([0_u8; 256]);
    loop {
        let read = reader.read(&mut chunk[..])?;
        if read == 0 {
            break;
        }
        let newline = chunk.iter().take(read).position(|byte| *byte == b'\n');
        let end = newline.map_or(read, |index| index.saturating_add(1));
        bytes.extend(chunk.iter().take(end));
        if newline.is_some() {
            break;
        }
    }
    let line = std::str::from_utf8(&bytes)
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "password is not valid UTF-8",
            )
        })?
        .to_owned();
    Ok(Zeroizing::new(trim_newline(line)))
}

/// Strips a trailing `\n` and, if present, the `\r` before it.
fn trim_newline(mut line: String) -> String {
    if line.ends_with('\n') {
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
    }
    line
}

/// Refuses an empty password.
fn check_nonempty(password: Zeroizing<String>) -> Result<Zeroizing<String>, UsageError> {
    if password.is_empty() {
        return Err(UsageError {
            id: MessageId::new("cli-password-empty"),
            detail: String::new(),
        });
    }
    Ok(password)
}

/// An I/O failure while prompting becomes the same usage error a broken
/// stdin already reports elsewhere in this crate.
fn io_usage_error(err: &std::io::Error) -> UsageError {
    UsageError {
        id: MessageId::new("cli-bad-stdin"),
        detail: err.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;
    use clap::Parser as _;

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

    fn settings(root: &std::path::Path) -> Settings {
        Settings {
            state_root: root.to_path_buf(),
            config_path: root.join("absent-detent.toml"),
        }
    }

    #[test]
    fn trim_newline_strips_lf_and_crlf() {
        assert_eq!(trim_newline("hi\n".to_owned()), "hi");
        assert_eq!(trim_newline("hi\r\n".to_owned()), "hi");
        assert_eq!(trim_newline("hi".to_owned()), "hi");
        assert_eq!(trim_newline(String::new()), "");
    }

    #[test]
    fn check_nonempty_refuses_the_empty_string() {
        assert!(check_nonempty(Zeroizing::new("x".to_owned())).is_ok());
        assert!(check_nonempty(Zeroizing::new(String::new())).is_err());
    }

    #[test]
    fn now_unix_is_positive_today() {
        assert!(now_unix() > 0);
    }

    /// `/dev/tty` is absent from this test harness, so `read_password` always
    /// takes the piped-input path, which is what makes it deterministically
    /// testable without a pseudo-terminal.
    #[test]
    fn read_password_falls_back_to_one_line_of_input_off_a_tty() -> R {
        let messages = messages();
        let mut input = b"hunter2\n".as_slice();
        let password = read_password(&messages, &mut input, true).map_err(|err| err.detail)?;
        assert_eq!(*password, "hunter2");
        Ok(())
    }

    #[test]
    fn invalid_utf8_password_bytes_are_refused() -> R {
        let mut input = b"\xff\n".as_slice();
        let err = read_password_line(&mut input)
            .err()
            .ok_or("invalid UTF-8 must be refused")?;
        assert_eq!(err.id, MessageId::new("cli-bad-stdin"));
        assert!(err.detail.contains("not valid UTF-8"), "{err:?}");
        Ok(())
    }

    #[test]
    fn an_empty_line_is_refused() -> R {
        let messages = messages();
        let mut input = b"\n".as_slice();
        let err = read_password(&messages, &mut input, false)
            .err()
            .ok_or("empty must be refused")?;
        assert_eq!(err.id, MessageId::new("cli-password-empty"));
        Ok(())
    }

    /// The whole `setup` path against a real (temporary) state root: refuses
    /// a second run without `--force`, honours `--dryrun`, and creates the
    /// account for real.
    #[test]
    fn setup_creates_once_and_then_refuses_without_force() -> R {
        let dir = tempfile::TempDir::new()?;
        let settings = settings(dir.path());
        let messages = messages();
        let renderer = renderer(&messages, false);
        let args = crate::cli::SetupArgs {
            name: "admin".to_owned(),
            force: false,
        };

        // Dry run: nothing written.
        let mut input = b"hunter22\nhunter22\n".as_slice();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = setup(
            &args,
            true,
            &settings,
            &renderer,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Ok);
        assert!(UserStore::load(&settings.state_root)?.is_empty());

        // A real run creates the account.
        let mut input = b"hunter22\nhunter22\n".as_slice();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = setup(
            &args,
            false,
            &settings,
            &renderer,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Ok, "{}", String::from_utf8_lossy(&notes));
        assert_eq!(
            UserStore::load(&settings.state_root)?
                .list()
                .into_iter()
                .map(|u| u.name)
                .collect::<Vec<_>>(),
            vec!["admin".to_owned()]
        );

        // Running it again without --force is refused before a password is
        // even asked for.
        let mut input = std::io::empty();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = setup(
            &args,
            false,
            &settings,
            &renderer,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Usage);
        assert!(!notes.is_empty());
        Ok(())
    }

    #[test]
    fn setup_with_force_overwrites_the_same_name() -> R {
        let dir = tempfile::TempDir::new()?;
        let settings = settings(dir.path());
        let messages = messages();
        let renderer = renderer(&messages, false);
        let args = crate::cli::SetupArgs {
            name: "admin".to_owned(),
            force: true,
        };

        for password in ["firstpass", "secondpass"] {
            let bytes = format!("{password}\n{password}\n").into_bytes();
            let mut input = bytes.as_slice();
            let mut out = Vec::new();
            let mut notes = Vec::new();
            let exit = setup(
                &args,
                false,
                &settings,
                &renderer,
                &mut Streams {
                    input: &mut input,
                    out: &mut out,
                    notes: &mut notes,
                },
            )?;
            assert_eq!(exit, Exit::Ok, "{}", String::from_utf8_lossy(&notes));
        }
        let store = UserStore::load(&settings.state_root)?;
        assert_eq!(store.list().len(), 1);
        Ok(())
    }

    #[test]
    fn user_add_passwd_and_rm_round_trip() -> R {
        let dir = tempfile::TempDir::new()?;
        let settings = settings(dir.path());
        let messages = messages();
        let renderer = renderer(&messages, true);

        let mut input = b"hunter22\nhunter22\n".as_slice();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = user(
            &UserAction::Add {
                name: "alice".to_owned(),
            },
            false,
            &settings,
            &renderer,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Ok, "{}", String::from_utf8_lossy(&notes));
        let parsed: serde_json::Value = serde_json::from_slice(&out)?;
        assert_eq!(
            parsed.pointer("/name").and_then(serde_json::Value::as_str),
            Some("alice")
        );

        let mut input = b"newpassword\nnewpassword\n".as_slice();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = user(
            &UserAction::Passwd {
                name: "alice".to_owned(),
            },
            false,
            &settings,
            &renderer,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Ok, "{}", String::from_utf8_lossy(&notes));

        let mut input = std::io::empty();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = user(
            &UserAction::Rm {
                name: "alice".to_owned(),
            },
            false,
            &settings,
            &renderer,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Ok, "{}", String::from_utf8_lossy(&notes));
        assert!(UserStore::load(&settings.state_root)?.is_empty());

        // Removing it again is a usage error, not a panic.
        let mut input = std::io::empty();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = user(
            &UserAction::Rm {
                name: "alice".to_owned(),
            },
            false,
            &settings,
            &renderer,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Usage);
        Ok(())
    }

    #[test]
    fn token_create_revoke_and_list_round_trip() -> R {
        let dir = tempfile::TempDir::new()?;
        let settings = settings(dir.path());
        let messages = messages();
        let renderer = renderer(&messages, true);

        let mut input = std::io::empty();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = token(
            &TokenAction::Create {
                label: "laptop".to_owned(),
                write: true,
                expires_secs: None,
            },
            false,
            &settings,
            &renderer,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Ok, "{}", String::from_utf8_lossy(&notes));
        let parsed: serde_json::Value = serde_json::from_slice(&out)?;
        let id = parsed
            .pointer("/id")
            .and_then(serde_json::Value::as_str)
            .ok_or("no id")?
            .to_owned();
        let minted = parsed
            .pointer("/token")
            .and_then(serde_json::Value::as_str)
            .ok_or("no token")?
            .to_owned();
        assert_eq!(minted.len(), 64);
        assert_eq!(
            parsed.pointer("/scopes"),
            Some(&serde_json::json!(["read", "write"]))
        );

        let mut input = std::io::empty();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = token(
            &TokenAction::List,
            false,
            &settings,
            &renderer,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Ok);
        let listed: serde_json::Value = serde_json::from_slice(&out)?;
        assert_eq!(listed.as_array().map(Vec::len), Some(1));
        // The digest and the token itself are nowhere in the listing.
        assert!(!out.windows(minted.len()).any(|w| w == minted.as_bytes()));

        let mut input = std::io::empty();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = token(
            &TokenAction::Revoke { id: id.clone() },
            false,
            &settings,
            &renderer,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Ok, "{}", String::from_utf8_lossy(&notes));
        assert!(TokenStore::load(&settings.state_root)?.list().is_empty());

        // Revoking an id that no longer exists is a usage error.
        let mut input = std::io::empty();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = token(
            &TokenAction::Revoke { id },
            false,
            &settings,
            &renderer,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Usage);
        Ok(())
    }
    #[test]
    fn an_empty_token_store_lists_nothing_in_human_output() -> R {
        // `token_list` JSON `[]` is covered by the round-trip above; the empty
        // human line (`cli-token-no-tokens`) only runs here.
        let dir = tempfile::TempDir::new()?;
        let settings = settings(dir.path());
        let messages = messages();
        let renderer = renderer(&messages, false);
        let mut input = std::io::empty();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = token(
            &TokenAction::List,
            false,
            &settings,
            &renderer,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Ok, "{}", String::from_utf8_lossy(&notes));
        let out = String::from_utf8(out)?;
        assert_eq!(
            out.trim(),
            messages.get(MessageId::new("cli-token-no-tokens"))
        );
        Ok(())
    }
    #[test]
    fn caller_mistakes_are_usage_and_store_failures_are_not() {
        use detent_web::auth::AuthError;
        assert_eq!(
            super::exit_for_auth(&AuthError::TokenLimit),
            crate::output::Exit::Usage
        );
        assert_eq!(
            super::exit_for_auth(&AuthError::StoreRead {
                path: std::path::PathBuf::from("/x"),
                source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "y"),
            }),
            crate::output::Exit::Failed
        );
    }

    #[test]
    fn token_create_honours_dryrun_and_expiry() -> R {
        let dir = tempfile::TempDir::new()?;
        let settings = settings(dir.path());
        let messages = messages();
        let renderer = renderer(&messages, false);

        let mut input = std::io::empty();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = token(
            &TokenAction::Create {
                label: "ci".to_owned(),
                write: false,
                expires_secs: Some(60),
            },
            true,
            &settings,
            &renderer,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Ok);
        assert!(TokenStore::load(&settings.state_root)?.list().is_empty());
        assert!(!notes.is_empty());

        let mut input = std::io::empty();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = token(
            &TokenAction::Create {
                label: "ci".to_owned(),
                write: false,
                expires_secs: Some(60),
            },
            false,
            &settings,
            &renderer,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Ok, "{}", String::from_utf8_lossy(&notes));
        let text = String::from_utf8(out)?;
        assert!(text.contains("ci"), "{text}");
        let listed = TokenStore::load(&settings.state_root)?.list();
        assert_eq!(listed.len(), 1);
        assert!(listed.first().is_some_and(|view| view.expires_at.is_some()));
        Ok(())
    }

    #[test]
    fn token_create_rejects_expiry_overflow_without_writing() -> R {
        let dir = tempfile::TempDir::new()?;
        let settings = settings(dir.path());
        let messages = messages();
        let renderer = renderer(&messages, false);
        let mut input = std::io::empty();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = token(
            &TokenAction::Create {
                label: "overflow".to_owned(),
                write: true,
                expires_secs: Some(i64::MAX),
            },
            false,
            &settings,
            &renderer,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;

        assert_eq!(exit, Exit::Usage);
        assert!(out.is_empty());
        assert!(String::from_utf8(notes)?.contains("expires-secs is too large"));
        assert!(TokenStore::load(&settings.state_root)?.list().is_empty());
        Ok(())
    }

    #[test]
    fn a_malformed_configuration_is_a_clean_startup_failure() -> R {
        let dir = tempfile::TempDir::new()?;
        std::fs::write(dir.path().join("detent.toml"), "not toml")?;
        let settings = Settings {
            state_root: dir.path().join("state"),
            config_path: dir.path().join("detent.toml"),
        };
        let messages = messages();
        let renderer = renderer(&messages, false);
        let mut input = std::io::empty();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = setup(
            &crate::cli::SetupArgs {
                name: "admin".to_owned(),
                force: false,
            },
            false,
            &settings,
            &renderer,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Failed);
        assert!(out.is_empty());
        assert!(!notes.is_empty());
        Ok(())
    }

    /// Every new command still parses through the real `Cli` tree.
    #[test]
    fn the_new_commands_parse() -> R {
        assert!(matches!(
            Cli::try_parse_from(["detent", "setup", "--name", "root", "--force"])?.command,
            Some(crate::cli::Command::Setup(crate::cli::SetupArgs { name, force: true })) if name == "root"
        ));
        assert!(matches!(
            Cli::try_parse_from(["detent", "user", "add", "alice"])?.command,
            Some(crate::cli::Command::User {
                action: UserAction::Add { name }
            }) if name == "alice"
        ));
        assert!(matches!(
            Cli::try_parse_from(["detent", "token", "create", "laptop", "--write"])?.command,
            Some(crate::cli::Command::Token {
                action: TokenAction::Create { label, write: true, expires_secs: None }
            }) if label == "laptop"
        ));
        assert!(matches!(
            Cli::try_parse_from(["detent", "token", "list"])?.command,
            Some(crate::cli::Command::Token {
                action: TokenAction::List
            })
        ));
        Ok(())
    }

    /// A store that cannot be opened (its directory is a file, not a
    /// directory) is `credential_failed` for every command that opens one
    /// before it would otherwise succeed.
    #[test]
    fn a_store_that_cannot_be_opened_is_a_credential_failure() -> R {
        let dir = tempfile::TempDir::new()?;
        // `UserStore`/`TokenStore::load` both confine `<state_root>/state`;
        // a file where that directory belongs makes `confine_state_dir` fail.
        std::fs::write(dir.path().join("state"), b"not a directory")?;
        let settings = settings(dir.path());
        let messages = messages();
        let renderer = renderer(&messages, false);

        for run in [
            "setup" as &str,
            "user_add",
            "user_passwd",
            "user_rm",
            "token_create",
            "token_revoke",
            "token_list",
        ] {
            let mut input = b"hunter22\nhunter22\n".as_slice();
            let mut out = Vec::new();
            let mut notes = Vec::new();
            let mut streams = Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            };
            let exit = match run {
                "setup" => setup(
                    &crate::cli::SetupArgs {
                        name: "admin".to_owned(),
                        force: false,
                    },
                    false,
                    &settings,
                    &renderer,
                    &mut streams,
                )?,
                "user_add" => user(
                    &UserAction::Add {
                        name: "alice".to_owned(),
                    },
                    false,
                    &settings,
                    &renderer,
                    &mut streams,
                )?,
                "user_passwd" => user(
                    &UserAction::Passwd {
                        name: "alice".to_owned(),
                    },
                    false,
                    &settings,
                    &renderer,
                    &mut streams,
                )?,
                "user_rm" => user(
                    &UserAction::Rm {
                        name: "alice".to_owned(),
                    },
                    false,
                    &settings,
                    &renderer,
                    &mut streams,
                )?,
                "token_create" => token(
                    &TokenAction::Create {
                        label: "laptop".to_owned(),
                        write: false,
                        expires_secs: None,
                    },
                    false,
                    &settings,
                    &renderer,
                    &mut streams,
                )?,
                "token_revoke" => token(
                    &TokenAction::Revoke {
                        id: "deadbeef".to_owned(),
                    },
                    false,
                    &settings,
                    &renderer,
                    &mut streams,
                )?,
                _ => token(
                    &TokenAction::List,
                    false,
                    &settings,
                    &renderer,
                    &mut streams,
                )?,
            };
            assert_eq!(exit, Exit::Failed, "{run}");
            assert!(!notes.is_empty(), "{run}");
        }
        Ok(())
    }

    /// Argon2 cost parameters that pass `Config::validate` but that the
    /// `argon2` crate itself refuses (memory too small for the requested
    /// parallelism) surface as a credential failure, not a panic.
    #[test]
    fn argon2_parameters_the_crate_itself_refuses_are_a_credential_failure() -> R {
        let dir = tempfile::TempDir::new()?;
        std::fs::write(
            dir.path().join("detent.toml"),
            "[auth.argon2]\nm_kib = 19456\nt = 3\np = 1000000\n",
        )?;
        let settings = Settings {
            state_root: dir.path().join("state"),
            config_path: dir.path().join("detent.toml"),
        };
        let messages = messages();
        let renderer = renderer(&messages, false);
        let mut input = b"hunter22\nhunter22\n".as_slice();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = setup(
            &crate::cli::SetupArgs {
                name: "admin".to_owned(),
                force: false,
            },
            false,
            &settings,
            &renderer,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Failed);
        assert!(!notes.is_empty());
        Ok(())
    }

    /// `token create`, `revoke` and `list` all render in human text too, not
    /// only under `--json`.
    #[test]
    fn token_commands_render_as_localized_text() -> R {
        let dir = tempfile::TempDir::new()?;
        let settings = settings(dir.path());
        let messages = messages();
        let renderer = renderer(&messages, false);

        let mut input = std::io::empty();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = token(
            &TokenAction::Create {
                label: "laptop".to_owned(),
                write: false,
                expires_secs: None,
            },
            false,
            &settings,
            &renderer,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Ok);
        let text = String::from_utf8(out)?;
        assert!(text.contains("laptop"), "{text}");
        let id = TokenStore::load(&settings.state_root)?
            .list()
            .first()
            .ok_or("no token")?
            .id
            .clone();

        let mut input = std::io::empty();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = token(
            &TokenAction::List,
            false,
            &settings,
            &renderer,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Ok);
        let text = String::from_utf8(out)?;
        assert!(text.contains("laptop") && text.contains(&id), "{text}");

        let mut input = std::io::empty();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = token(
            &TokenAction::Revoke { id },
            false,
            &settings,
            &renderer,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Ok);
        let text = String::from_utf8(out)?;
        assert!(text.contains("revoked") || !text.is_empty(), "{text}");

        // An empty listing says so, in text too.
        let mut input = std::io::empty();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = token(
            &TokenAction::List,
            false,
            &settings,
            &renderer,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Ok);
        assert!(!String::from_utf8(out)?.trim().is_empty());
        Ok(())
    }

    /// `--dryrun` on `user add|passwd|rm` and `token revoke` withholds the
    /// mutation and prints commentary to `notes` rather than `out` — the
    /// human-output branch of `render_dryrun` for the four commands whose
    /// round-trip tests above only ever exercise the non-dryrun path.
    #[test]
    fn dryrun_withholds_user_and_token_mutations_too() -> R {
        let dir = tempfile::TempDir::new()?;
        let settings = settings(dir.path());
        let messages = messages();
        let renderer = renderer(&messages, false);

        let mut input = b"hunter22\nhunter22\n".as_slice();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = user(
            &UserAction::Add {
                name: "alice".to_owned(),
            },
            true,
            &settings,
            &renderer,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Ok);
        assert!(out.is_empty());
        assert!(!notes.is_empty());
        assert!(UserStore::load(&settings.state_root)?.is_empty());

        let mut input = b"hunter22\nhunter22\n".as_slice();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = user(
            &UserAction::Passwd {
                name: "alice".to_owned(),
            },
            true,
            &settings,
            &renderer,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Ok);
        assert!(out.is_empty());
        assert!(!notes.is_empty());

        let mut input = std::io::empty();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = user(
            &UserAction::Rm {
                name: "alice".to_owned(),
            },
            true,
            &settings,
            &renderer,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Ok);
        assert!(out.is_empty());
        assert!(!notes.is_empty());

        let mut input = std::io::empty();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = token(
            &TokenAction::Revoke {
                id: "deadbeef".to_owned(),
            },
            true,
            &settings,
            &renderer,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Ok);
        assert!(out.is_empty());
        assert!(!notes.is_empty());
        Ok(())
    }

    /// The 65th token past `TokenStore::MAX_TOKENS` reaches `token_create`'s
    /// own `Err(err) => credential_failed(..)` arm for `store.issue` — the one
    /// failure of that call the round-trip tests above never provoke, since
    /// they only ever mint one or two tokens.
    #[test]
    fn a_full_token_store_is_a_credential_failure_not_a_panic() -> R {
        let dir = tempfile::TempDir::new()?;
        let settings = settings(dir.path());
        let messages = messages();
        let renderer = renderer(&messages, false);

        for index in 0..detent_web::auth::token::MAX_TOKENS {
            let mut input = std::io::empty();
            let mut out = Vec::new();
            let mut notes = Vec::new();
            let exit = token(
                &TokenAction::Create {
                    label: format!("t{index}"),
                    write: false,
                    expires_secs: None,
                },
                false,
                &settings,
                &renderer,
                &mut Streams {
                    input: &mut input,
                    out: &mut out,
                    notes: &mut notes,
                },
            )?;
            assert_eq!(exit, Exit::Ok, "{}", String::from_utf8_lossy(&notes));
        }

        let mut input = std::io::empty();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = token(
            &TokenAction::Create {
                label: "one-too-many".to_owned(),
                write: false,
                expires_secs: None,
            },
            false,
            &settings,
            &renderer,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Usage);
        assert!(!notes.is_empty());
        Ok(())
    }

    /// An empty name is refused by the store itself (`AuthError::NameInvalid`),
    /// which `setup` must surface through its general error arm — the one
    /// `store.create` failure this module's own tests do not otherwise reach,
    /// since every other case is either success or the `UserExists` arm.
    #[test]
    fn setup_refuses_a_name_the_store_itself_will_not_accept() -> R {
        let dir = tempfile::TempDir::new()?;
        let settings = settings(dir.path());
        let messages = messages();
        let renderer = renderer(&messages, false);
        let mut input = b"hunter22\nhunter22\n".as_slice();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = setup(
            &crate::cli::SetupArgs {
                name: String::new(),
                force: false,
            },
            false,
            &settings,
            &renderer,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Usage, "{}", String::from_utf8_lossy(&notes));
        assert!(UserStore::load(&settings.state_root)?.is_empty());
        Ok(())
    }

    /// An empty password read from a piped `stdin` reaches `setup` as a
    /// `UsageError` and renders through `usage_failed`, exit 2 — not a panic,
    /// and not a silently-accepted blank password.
    #[test]
    fn an_empty_password_is_a_usage_error_through_the_full_command() -> R {
        let dir = tempfile::TempDir::new()?;
        let settings = settings(dir.path());
        let messages = messages();
        let renderer = renderer(&messages, false);
        let mut input = b"\n".as_slice();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = setup(
            &crate::cli::SetupArgs {
                name: "admin".to_owned(),
                force: false,
            },
            false,
            &settings,
            &renderer,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Usage);
        assert!(!notes.is_empty());
        assert!(UserStore::load(&settings.state_root)?.is_empty());
        Ok(())
    }

    /// `--dryrun --json` prints the withheld action as JSON on `stdout`, the
    /// same shape a real result would use — the branch the other dry-run
    /// tests above (all `--json`-less) do not reach.
    #[test]
    fn a_json_dry_run_prints_to_stdout_not_notes() -> R {
        let dir = tempfile::TempDir::new()?;
        let settings = settings(dir.path());
        let messages = messages();
        let renderer = renderer(&messages, true);
        let mut input = std::io::empty();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = token(
            &TokenAction::Revoke {
                id: "deadbeef".to_owned(),
            },
            true,
            &settings,
            &renderer,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Ok);
        let parsed: serde_json::Value = serde_json::from_slice(&out)?;
        assert_eq!(
            parsed
                .pointer("/dryrun")
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert!(notes.is_empty());
        Ok(())
    }

    /// `user add` and `user passwd` load `detent.toml` exactly like `setup`
    /// does, and refuse the same malformed file — the `report_web_config_
    /// error` arm each command has of its own, which
    /// `a_malformed_configuration_is_a_clean_startup_failure` above only ever
    /// exercises for `setup`.
    #[test]
    fn user_add_and_passwd_report_a_malformed_configuration_too() -> R {
        let dir = tempfile::TempDir::new()?;
        std::fs::write(dir.path().join("detent.toml"), "not toml")?;
        let settings = Settings {
            state_root: dir.path().join("state"),
            config_path: dir.path().join("detent.toml"),
        };
        let messages = messages();
        let renderer = renderer(&messages, false);

        for action in [
            UserAction::Add {
                name: "alice".to_owned(),
            },
            UserAction::Passwd {
                name: "alice".to_owned(),
            },
        ] {
            let mut input = b"hunter22\nhunter22\n".as_slice();
            let mut out = Vec::new();
            let mut notes = Vec::new();
            let exit = user(
                &action,
                false,
                &settings,
                &renderer,
                &mut Streams {
                    input: &mut input,
                    out: &mut out,
                    notes: &mut notes,
                },
            )?;
            assert_eq!(exit, Exit::Failed, "{action:?}");
            assert!(out.is_empty(), "{action:?}");
            assert!(!notes.is_empty(), "{action:?}");
        }
        Ok(())
    }

    /// `user add` and `user passwd` build their own `Hasher` exactly like
    /// `setup` does, and refuse the same argon2 parameters the `argon2`
    /// crate itself will not accept — the `Hasher::new` failure arm each
    /// command has of its own, which
    /// `argon2_parameters_the_crate_itself_refuses_are_a_credential_failure`
    /// above only ever exercises for `setup`.
    #[test]
    fn user_add_and_passwd_report_the_crates_own_argon2_refusal_too() -> R {
        let dir = tempfile::TempDir::new()?;
        std::fs::write(
            dir.path().join("detent.toml"),
            "[auth.argon2]\nm_kib = 19456\nt = 3\np = 1000000\n",
        )?;
        let settings = Settings {
            state_root: dir.path().join("state"),
            config_path: dir.path().join("detent.toml"),
        };
        let messages = messages();
        let renderer = renderer(&messages, false);

        for action in [
            UserAction::Add {
                name: "alice".to_owned(),
            },
            UserAction::Passwd {
                name: "alice".to_owned(),
            },
        ] {
            let mut input = b"hunter22\nhunter22\n".as_slice();
            let mut out = Vec::new();
            let mut notes = Vec::new();
            let exit = user(
                &action,
                false,
                &settings,
                &renderer,
                &mut Streams {
                    input: &mut input,
                    out: &mut out,
                    notes: &mut notes,
                },
            )?;
            assert_eq!(exit, Exit::Failed, "{action:?}");
            assert!(!notes.is_empty(), "{action:?}");
        }
        Ok(())
    }

    /// An empty password piped in is a usage error for `user add` and `user
    /// passwd` too, not only for `setup` —
    /// `an_empty_password_is_a_usage_error_through_the_full_command` above
    /// only ever exercises `setup`'s own `read_password` call.
    #[test]
    fn an_empty_password_is_a_usage_error_for_user_add_and_passwd_too() -> R {
        let dir = tempfile::TempDir::new()?;
        let settings = settings(dir.path());
        let messages = messages();
        let renderer = renderer(&messages, false);

        for action in [
            UserAction::Add {
                name: "alice".to_owned(),
            },
            UserAction::Passwd {
                name: "alice".to_owned(),
            },
        ] {
            let mut input = b"\n".as_slice();
            let mut out = Vec::new();
            let mut notes = Vec::new();
            let exit = user(
                &action,
                false,
                &settings,
                &renderer,
                &mut Streams {
                    input: &mut input,
                    out: &mut out,
                    notes: &mut notes,
                },
            )?;
            assert_eq!(exit, Exit::Usage, "{action:?}");
            assert!(!notes.is_empty(), "{action:?}");
        }
        assert!(UserStore::load(&settings.state_root)?.is_empty());
        Ok(())
    }

    /// An empty name is refused by the store itself
    /// (`AuthError::NameInvalid`), which `user add` must surface through its
    /// general error arm too — `setup_refuses_a_name_the_store_itself_will_
    /// not_accept` above only ever exercises `setup`'s own `store.create`
    /// call.
    #[test]
    fn user_add_refuses_a_name_the_store_itself_will_not_accept() -> R {
        let dir = tempfile::TempDir::new()?;
        let settings = settings(dir.path());
        let messages = messages();
        let renderer = renderer(&messages, false);
        let mut input = b"hunter22\nhunter22\n".as_slice();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = user(
            &UserAction::Add {
                name: String::new(),
            },
            false,
            &settings,
            &renderer,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Usage, "{}", String::from_utf8_lossy(&notes));
        assert!(UserStore::load(&settings.state_root)?.is_empty());
        Ok(())
    }

    /// `user passwd` on a name no account holds reaches `store.set_password`'s
    /// own `AuthError::UnknownUser`, not `UserStore::load`'s — the one
    /// `credential_failed` arm inside `user_passwd` that
    /// `user_add_passwd_and_rm_round_trip` never provokes, since it only ever
    /// changes the password of a user it just created.
    #[test]
    fn user_passwd_on_an_unknown_user_is_a_credential_failure() -> R {
        let dir = tempfile::TempDir::new()?;
        let settings = settings(dir.path());
        let messages = messages();
        let renderer = renderer(&messages, false);
        let mut input = b"hunter22\nhunter22\n".as_slice();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = user(
            &UserAction::Passwd {
                name: "ghost".to_owned(),
            },
            false,
            &settings,
            &renderer,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Usage);
        assert!(!notes.is_empty());
        Ok(())
    }

    /// `setup --force` against an existing name reaches `store.create`'s
    /// `UserExists` arm purely from the in-memory record `UserStore::load`
    /// already parsed, so a state directory that has since gone read-only
    /// still lets that check pass — but the `store.set_password` call right
    /// after it must still write the file, and that is where this fails: the
    /// one `credential_failed` arm inside `setup`'s force branch that
    /// `setup_with_force_overwrites_the_same_name` never provokes, since the
    /// store is always writable there.
    #[test]
    fn setup_with_force_reports_a_write_failure_as_a_credential_failure() -> R {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::TempDir::new()?;
        let settings = settings(dir.path());
        let messages = messages();
        let renderer = renderer(&messages, false);
        let args = crate::cli::SetupArgs {
            name: "admin".to_owned(),
            force: true,
        };

        let mut input = b"hunter22\nhunter22\n".as_slice();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = setup(
            &args,
            false,
            &settings,
            &renderer,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Ok, "{}", String::from_utf8_lossy(&notes));

        let state_dir = settings.state_root.join("state");
        let original = std::fs::metadata(&state_dir)?.permissions();
        std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o500))?;

        let mut input = b"secondpass\nsecondpass\n".as_slice();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = setup(
            &args,
            false,
            &settings,
            &renderer,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        std::fs::set_permissions(&state_dir, original)?;
        assert_eq!(exit, Exit::Failed);
        assert!(!notes.is_empty());
        Ok(())
    }

    /// A fresh pseudo-terminal: the controller end and the terminal end.
    fn pty() -> Result<(File, File), Box<dyn std::error::Error>> {
        use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
        let controller = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY)?;
        grantpt(&controller)?;
        unlockpt(&controller)?;
        let name = ptsname(&controller, Vec::new())?;
        let terminal = OpenOptions::new()
            .read(true)
            .write(true)
            .open(<std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(name.as_bytes()))?;
        Ok((File::from(controller), terminal))
    }

    /// The guard turns local echo off for exactly its lifetime, so a typed
    /// password never appears on screen, and puts the terminal back as it
    /// found it when dropped.
    #[test]
    fn the_echo_guard_hides_input_and_restores_the_terminal() -> R {
        let (_controller, terminal) = pty()?;
        let echoing = |tty: &File| -> std::io::Result<bool> {
            Ok(termios::tcgetattr(tty)?
                .local_modes
                .contains(LocalModes::ECHO))
        };
        assert!(echoing(&terminal)?, "a fresh pty echoes");
        let guard = EchoGuard::new(&terminal)?;
        assert!(!echoing(&terminal)?, "echo must be off while prompting");
        drop(guard);
        assert!(echoing(&terminal)?, "echo must come back on drop");
        Ok(())
    }

    /// Something that is not a terminal cannot be guarded: an error, never a
    /// silently echoing prompt.
    #[test]
    fn the_echo_guard_refuses_a_file_that_is_not_a_terminal() -> R {
        let file = tempfile::tempfile()?;
        assert!(EchoGuard::new(&file).is_err());
        Ok(())
    }

    /// The prompt goes to the terminal, the answer comes from the reader
    /// without its newline, and the cursor moves to the next line.
    #[test]
    fn prompt_tty_writes_the_prompt_and_reads_one_line() -> R {
        let (mut controller, terminal) = pty()?;
        let mut input = std::io::Cursor::new(b"s3cret\nleftover".to_vec());
        let password = prompt_tty(
            &terminal,
            &mut input,
            &messages(),
            MessageId::new("cli-password-prompt"),
        )?;
        assert_eq!(password.as_str(), "s3cret");
        // Both writes already happened; read until the trailing newline.
        let mut shown = Vec::new();
        let mut chunk = [0_u8; 64];
        while !shown.ends_with(b"\n") {
            let read = controller.read(&mut chunk)?;
            shown.extend_from_slice(chunk.get(..read).unwrap_or_default());
        }
        let shown = String::from_utf8(shown)?;
        assert!(shown.starts_with("password:"), "{shown:?}");
        assert!(shown.ends_with('\n'), "{shown:?}");
        Ok(())
    }
}
