//! detent Phase 0 spike binary.
//!
//! Usage:
//!   xbuild probe            Link-and-run check: rustls TLS1.3 config, axum /healthz,
//!                           argon2id hash, Landlock ABI report (Linux).
//!   xbuild sandbox-probe    Linux sandbox checks: Landlock write restriction,
//!                           seccomp allow-list + ptrace denial, no_new_privs,
//!                           capability bounding-set drop.
//!   xbuild sigstore-probe   Links the sigstore verifier (feature `update-sigstore`).
//!
//! Switches: none beyond the subcommand.

use clap::{Parser, Subcommand};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Parser)]
#[command(name = "xbuild")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Probe,
    SandboxProbe,
    SeccompAllowlist,
    SigstoreProbe,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Ping {
    v: u16,
}

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Probe => probe(),
        Cmd::SandboxProbe => sandbox_probe(),
        Cmd::SeccompAllowlist => seccomp_allowlist(),
        Cmd::SigstoreProbe => sigstore_probe(),
    }
}

/// Build a rustls 1.3-only ServerConfig so the rustls/provider code is linked.
fn tls_config() -> Result<rustls::ServerConfig, Box<dyn std::error::Error>> {
    let provider = default_provider();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let chain = vec![rustls::pki_types::CertificateDer::from(cert.cert)];
    let cfg = rustls::ServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    Ok(cfg)
}

#[cfg(feature = "crypto-aws-lc")]
fn default_provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::aws_lc_rs::default_provider()
}

#[cfg(all(feature = "crypto-ring", not(feature = "crypto-aws-lc")))]
fn default_provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::ring::default_provider()
}

fn probe() {
    let cfg = tls_config().expect("rustls TLS1.3 config");
    println!("rustls: TLS1.3-only ServerConfig built; alpn slots={}", cfg.alpn_protocols.len());

    // Link instant-acme + hyper-rustls.
    let _acme_ty = instant_acme::ChallengeType::Dns01;
    println!("instant-acme: challenge type linked = {:?}", _acme_ty);

    // argon2id m=64MiB t=3 p=1
    let params = argon2::Params::new(65536, 3, 1, Some(32)).expect("argon2 params");
    let a2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = [0u8; 32];
    let t0 = std::time::Instant::now();
    a2.hash_password_into(b"correct horse battery staple", b"saltsaltsaltsalt", &mut out)
        .expect("argon2id hash");
    println!(
        "argon2id(m=64MiB,t=3,p=1): {} ms; first byte 0x{:02x}",
        t0.elapsed().as_millis(),
        out[0]
    );

    // postcard + serde
    let enc = postcard::to_allocvec(&Ping { v: 1 }).expect("postcard");
    println!("postcard: {} bytes; serde_json: {}", enc.len(), serde_json::to_string(&Ping { v: 1 }).expect("json"));

    // axum /healthz on 127.0.0.1:0
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("rt");
    rt.block_on(async {
        let app = axum::Router::new().route("/healthz", axum::routing::get(|| async { "ok" }));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = l.local_addr().expect("addr");
        let h = tokio::spawn(async move { let _ = axum::serve(l, app).await; });
        let mut s = tokio::net::TcpStream::connect(addr).await.expect("connect");
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        s.write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await.expect("write");
        let mut buf = Vec::new();
        let _ = s.read_to_end(&mut buf).await;
        println!("axum: {} -> {}", addr, String::from_utf8_lossy(&buf).lines().next().unwrap_or(""));
        h.abort();
    });

    landlock_report();
    println!("PROBE OK");
}

#[cfg(target_os = "linux")]
fn landlock_report() {
    use landlock::{ABI, Access, AccessFs, Compatible, RulesetAttr, RulesetStatus};
    let abis = [ABI::V1, ABI::V2, ABI::V3, ABI::V4, ABI::V5];
    let mut best = 0u8;
    for abi in abis {
        let r = landlock::Ruleset::default()
            .set_compatibility(landlock::CompatLevel::HardRequirement)
            .handle_access(AccessFs::from_all(abi))
            .and_then(|r| r.create());
        match r {
            Ok(created) => {
                // Do not enforce here; just probe support.
                let _ = created;
                best = abi as u8;
            }
            Err(_) => break,
        }
    }
    println!("landlock: highest supported ABI = {}", best);
    let _ = RulesetStatus::FullyEnforced;
}

#[cfg(not(target_os = "linux"))]
fn landlock_report() {
    println!("landlock: n/a (non-Linux target)");
}

#[cfg(target_os = "linux")]
fn sandbox_probe() {
    use std::io::Write;
    println!("uname: {}", std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default().trim());
    landlock_report();

    // 1. no_new_privs
    let nnp = unsafe_prctl_no_new_privs();
    println!("no_new_privs: {}", if nnp { "OK" } else { "FAIL" });

    // 2. Landlock: allow writes under /tmp/allowed only.
    std::fs::create_dir_all("/tmp/allowed").ok();
    std::fs::create_dir_all("/tmp/denied").ok();
    {
        use landlock::{ABI, Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus};
        let abi = ABI::V1;
        let res = (|| -> Result<RulesetStatus, Box<dyn std::error::Error>> {
            let st = Ruleset::default()
                .handle_access(AccessFs::from_all(abi))?
                .create()?
                .add_rule(PathBeneath::new(PathFd::new("/tmp/allowed")?, AccessFs::from_all(abi)))?
                .add_rule(PathBeneath::new(PathFd::new("/")?, AccessFs::from_read(abi)))?
                .restrict_self()?;
            Ok(st.ruleset)
        })();
        match res {
            Ok(status) => println!("landlock enforce: {:?}", status),
            Err(e) => println!("landlock enforce: FAILED: {e}"),
        }
    }
    match std::fs::File::create("/tmp/allowed/ok.txt").and_then(|mut f| f.write_all(b"x")) {
        Ok(()) => println!("write /tmp/allowed/ok.txt: OK (expected OK)"),
        Err(e) => println!("write /tmp/allowed/ok.txt: ERR {:?} (expected OK)", e.kind()),
    }
    match std::fs::File::create("/tmp/denied/no.txt") {
        Ok(_) => println!("write /tmp/denied/no.txt: OK (expected EACCES) -> LANDLOCK NOT ENFORCING"),
        Err(e) => println!("write /tmp/denied/no.txt: ERR {:?} raw={:?} (expected PermissionDenied)", e.kind(), e.raw_os_error()),
    }

    // 3. capability bounding set drop
    match caps::read(None, caps::CapSet::Bounding) {
        Ok(before) => {
            let n_before = before.len();
            let keep: std::collections::HashSet<caps::Capability> =
                [caps::Capability::CAP_DAC_OVERRIDE, caps::Capability::CAP_CHOWN, caps::Capability::CAP_FOWNER]
                    .into_iter().collect();
            let mut err = None;
            for c in before {
                if !keep.contains(&c) {
                    if let Err(e) = caps::drop(None, caps::CapSet::Bounding, c) { err = Some(format!("{c:?}: {e}")); break; }
                }
            }
            let after = caps::read(None, caps::CapSet::Bounding).map(|s| s.len()).unwrap_or(usize::MAX);
            match err {
                None => println!("caps bounding: {} -> {} OK", n_before, after),
                Some(e) => println!("caps bounding: {} -> {} FAILED at {}", n_before, after, e),
            }
        }
        Err(e) => println!("caps bounding: read failed: {e}"),
    }

    // 4. seccomp allow-list; ptrace must be denied.
    seccomp_probe();

    println!("ptrace after seccomp: {}", try_ptrace());
    println!("SANDBOX PROBE DONE");
}

#[cfg(target_os = "linux")]
fn seccomp_probe() {
    use seccompiler::{SeccompAction, SeccompFilter};
    use std::collections::BTreeMap;
    // Deny-list style: default allow, ptrace -> errno EPERM. Simplest reliable
    // demonstration that a seccompiler filter installs and takes effect.
    const NR_PTRACE_AARCH64: i64 = 117;
    const NR_PTRACE_X86_64: i64 = 101;
    let nr = if cfg!(target_arch = "aarch64") { NR_PTRACE_AARCH64 } else { NR_PTRACE_X86_64 };
    let mut rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();
    rules.insert(nr, vec![]);
    let arch = if cfg!(target_arch = "aarch64") { seccompiler::TargetArch::aarch64 } else { seccompiler::TargetArch::x86_64 };
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,                 // default for un-listed syscalls
        SeccompAction::Errno(1),              // matched (ptrace) -> EPERM
        arch,
    );
    let r = (|| -> Result<(), String> {
        let f = filter.map_err(|e| format!("{e}"))?;
        let p = seccompiler::BpfProgram::try_from(f).map_err(|e| format!("{e}"))?;
        seccompiler::apply_filter(&p).map_err(|e| format!("{e}"))
    })();
    match r {
        Ok(()) => println!("seccomp: filter installed OK (ptrace -> EPERM)"),
        Err(e) => println!("seccomp: FAILED: {e}"),
    }
}

#[cfg(target_os = "linux")]
fn try_ptrace() -> String {
    // PTRACE_TRACEME = 0 via raw syscall through libc-free path: use std::process
    // is not possible; call the syscall with the `syscall` shim from seccompiler's
    // dependency is not exposed, so shell out to a helper is overkill. Use libc
    // through the `caps` crate's transitive libc.
    let r = unsafe { libc_syscall_ptrace() };
    if r == 0 { "ALLOWED (returned 0) -> seccomp NOT effective".to_string() }
    else { format!("DENIED rc={} errno={}", r, std::io::Error::last_os_error()) }
}

#[cfg(target_os = "linux")]
unsafe fn libc_syscall_ptrace() -> i64 {
    unsafe extern "C" {
        fn syscall(num: std::ffi::c_long, ...) -> std::ffi::c_long;
    }
    const NR_PTRACE_AARCH64: std::ffi::c_long = 117;
    const NR_PTRACE_X86_64: std::ffi::c_long = 101;
    let nr = if cfg!(target_arch = "aarch64") { NR_PTRACE_AARCH64 } else { NR_PTRACE_X86_64 };
    unsafe { syscall(nr, 0i64, 0i64, 0i64, 0i64) as i64 }
}

#[cfg(target_os = "linux")]
fn unsafe_prctl_no_new_privs() -> bool {
    unsafe extern "C" {
        fn prctl(option: std::ffi::c_int, ...) -> std::ffi::c_int;
    }
    const PR_SET_NO_NEW_PRIVS: std::ffi::c_int = 38;
    unsafe { prctl(PR_SET_NO_NEW_PRIVS, 1i64, 0i64, 0i64, 0i64) == 0 }
}

/// Install a real allow-list seccomp filter (default action = Trap -> SIGSYS)
/// and then issue `ptrace`, which is not on the list. Expected: SIGSYS (rc 159).
#[cfg(target_os = "linux")]
fn seccomp_allowlist() {
    use seccompiler::{SeccompAction, SeccompFilter};
    use std::collections::BTreeMap;
    use std::io::Write;
    // aarch64 / asm-generic syscall numbers.
    const ALLOWED_AARCH64: &[i64] = &[
        63, 64, 66, 57, 93, 94, 139, 134, 135, 98, 214, 222, 215, 226, 233, 113, 278, 101, 73,
        132, 29, 80, 124, 178, 131, 172, 216, 99, 261, 96, 260, 167, 116, 78, 434, 435,
    ];
    const ALLOWED_X86_64: &[i64] = &[
        0, 1, 20, 3, 60, 231, 15, 13, 14, 202, 12, 9, 11, 10, 28, 228, 35, 271, 131, 16, 5, 24,
        186, 234, 39, 25, 273, 302, 318, 158, 39,
    ];
    let (list, arch) = if cfg!(target_arch = "aarch64") {
        (ALLOWED_AARCH64, seccompiler::TargetArch::aarch64)
    } else {
        (ALLOWED_X86_64, seccompiler::TargetArch::x86_64)
    };
    let mut rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();
    for nr in list {
        rules.insert(*nr, vec![]);
    }
    println!("seccomp-allowlist: installing ({} syscalls allowed, default=Trap)", list.len());
    std::io::stdout().flush().ok();
    let r = (|| -> Result<(), String> {
        let f = SeccompFilter::new(rules, SeccompAction::Trap, SeccompAction::Allow, arch)
            .map_err(|e| format!("{e}"))?;
        let p = seccompiler::BpfProgram::try_from(f).map_err(|e| format!("{e}"))?;
        seccompiler::apply_filter(&p).map_err(|e| format!("{e}"))
    })();
    match r {
        Ok(()) => {
            println!("seccomp-allowlist: installed; calling ptrace (expect SIGSYS)");
            std::io::stdout().flush().ok();
            let rc = unsafe { libc_syscall_ptrace() };
            println!("seccomp-allowlist: ptrace returned {rc} -- NOT trapped");
        }
        Err(e) => println!("seccomp-allowlist: install FAILED: {e}"),
    }
}

#[cfg(not(target_os = "linux"))]
fn seccomp_allowlist() {
    println!("seccomp-allowlist: Linux only");
}

#[cfg(not(target_os = "linux"))]
fn sandbox_probe() {
    println!("sandbox-probe: Linux only");
}

#[cfg(feature = "update-sigstore")]
fn sigstore_probe() {
    use sigstore::bundle::verify::{policy, Verifier, VerificationPolicy};
    let id = policy::Identity::new(
        "https://github.com/jauderho/detent/.github/workflows/release.yml@refs/tags/v0.0.1",
        "https://token.actions.githubusercontent.com",
    );
    // Force the policy trait object and the verifier type to be linked.
    let _p: &dyn VerificationPolicy = &id;
    let root = sigstore::trust::ManualTrustRoot::default();
    let v = sigstore::bundle::verify::blocking::Verifier::new(Default::default(), root);
    println!("sigstore: blocking verifier constructed = {}", v.is_ok());
    if let Ok(v) = v {
        // Link the full bundle verification path.
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let bundle: Result<sigstore::bundle::Bundle, _> = serde_json::from_str("{}");
            bundle.map(|b| v.verify(std::io::Cursor::new(b"x"), b, &id, true).is_ok())
        }));
        println!("sigstore: verify path linked; bundle-parse result = {:?}", r.is_ok());
    }
    println!("SIGSTORE PROBE OK");
}

#[cfg(not(feature = "update-sigstore"))]
fn sigstore_probe() {
    println!("sigstore: feature not enabled");
}
