//! Host profile detection (PLAN §2.3, §1.6: Linux + macOS only, BSD deferred).
//!
//! Populates [`detent_core::descriptor::HostProfile`] plus platform facts
//! ([`HostFacts`]) that modules use to pick a backend, size defaults, and
//! hide options newer than the installed service. All reads go through
//! [`HostFs`] and [`Prober`] so every detection branch is unit-testable
//! without touching the real system.

mod fakes;
mod io;
mod linux;
mod macos;
mod os_release;
mod prober;
mod version;

pub use io::{HostFs, RealFs};
pub use prober::{ProbeError, Prober, RealProber};

use std::collections::BTreeMap;

use detent_core::descriptor::{HostProfile, InitSystem, Os};

/// A parsed Linux distro identity from `/etc/os-release`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Distro {
    /// `ID=`, e.g. `"debian"`.
    pub id: String,
    /// `ID_LIKE=`, split on whitespace, e.g. `["debian"]` for Raspberry Pi OS.
    pub id_like: Vec<String>,
    /// `VERSION_ID=`, e.g. `"12"`.
    pub version_id: Option<String>,
}

/// Which service manages the host's network configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetworkBackend {
    /// `systemd-networkd`.
    SystemdNetworkd,
    /// `NetworkManager`.
    NetworkManager,
    /// Debian/`ifupdown`-style `/etc/network/interfaces`.
    Ifupdown,
    /// `netplan`, which itself renders to networkd or `NetworkManager`.
    Netplan,
    /// No known backend detected.
    #[default]
    Unknown,
}

/// Which service manages DNS resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResolverBackend {
    /// `systemd-resolved`.
    SystemdResolved,
    /// `NetworkManager`'s built-in resolver management.
    NetworkManager,
    /// A plain, unmanaged `/etc/resolv.conf`.
    Static,
    /// `unbound`, when it is the only resolver-managing service found.
    Unbound,
    /// No known backend detected.
    #[default]
    Unknown,
}

/// Platform facts that don't belong on [`HostProfile`] (which is shared
/// with non-platform crates and kept minimal — see `detent-core`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HostFacts {
    /// Linux distro identity, or `None` on non-Linux hosts or when
    /// `/etc/os-release` is unreadable.
    pub distro: Option<Distro>,
    /// The detected network backend.
    pub network_backend: NetworkBackend,
    /// The detected DNS resolver backend.
    pub resolver_backend: ResolverBackend,
    /// Human-readable caveats surfaced during detection, e.g. a
    /// resolver-backend runner-up that was not chosen.
    pub notes: Vec<String>,
}

/// The result of a host detection pass: the core [`HostProfile`] plus
/// [`HostFacts`] the platform layer additionally observed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Detected {
    /// The host profile consumed by `detent-core` modules.
    pub profile: HostProfile,
    /// Additional platform facts not part of the shared [`HostProfile`].
    pub facts: HostFacts,
}

/// `(service_versions key, candidate absolute paths, version-flag args)` for
/// each service version probe. The first existing path is used.
const SERVICE_PROBES: &[(&str, &[&str], &[&str])] = &[
    (
        "chrony",
        &["/usr/sbin/chronyd", "/usr/bin/chronyd"],
        &["--version"],
    ),
    ("samba", &["/usr/sbin/smbd", "/usr/bin/smbd"], &["-V"]),
    (
        "unbound",
        &["/usr/sbin/unbound", "/usr/bin/unbound"],
        &["-V"],
    ),
    (
        "dnsmasq",
        &["/usr/sbin/dnsmasq", "/usr/bin/dnsmasq"],
        &["--version"],
    ),
    (
        "kea",
        &["/usr/sbin/kea-dhcp4", "/usr/bin/kea-dhcp4"],
        &["-v"],
    ),
    (
        "systemd-resolved",
        &["/usr/bin/resolvectl", "/bin/resolvectl"],
        &["--version"],
    ),
];

/// Detect the host profile and facts using the given filesystem and prober.
///
/// Per-OS detection is dispatched once, into a single tuple, rather than
/// four separate `match`es: `Os::Other` (no supported host is ever this —
/// PLAN §1.6 scopes support to Linux and macOS) would otherwise need a
/// dead arm in each of the four, all equally unreachable on any real build.
#[must_use]
pub fn detect(fs: &dyn HostFs, prober: &dyn Prober) -> Detected {
    let os = compile_time_os();

    let (init, hostname, ram_mib, facts) = match os {
        Os::Linux => (
            linux::detect_init(fs),
            linux::detect_hostname(fs, prober),
            linux::detect_ram_mib(fs),
            linux::collect_facts(fs),
        ),
        Os::MacOs => (
            InitSystem::Launchd,
            macos::detect_hostname(prober),
            macos::detect_ram_mib(prober),
            HostFacts::default(),
        ),
        Os::Other => (InitSystem::None, String::new(), 0, HostFacts::default()),
    };
    let service_versions = detect_service_versions(fs, prober);

    Detected {
        profile: HostProfile {
            os,
            init,
            hostname,
            service_versions,
            ram_mib,
        },
        facts,
    }
}

/// Detect using the real filesystem and process spawner.
#[must_use]
pub fn detect_real() -> Detected {
    detect(&RealFs, &RealProber)
}

fn compile_time_os() -> Os {
    if cfg!(target_os = "linux") {
        Os::Linux
    } else if cfg!(target_os = "macos") {
        Os::MacOs
    } else {
        Os::Other
    }
}

/// Probe installed service versions: only binaries that exist (per `fs`)
/// at one of their known absolute paths are run.
fn detect_service_versions(fs: &dyn HostFs, prober: &dyn Prober) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (key, paths, args) in SERVICE_PROBES {
        let Some(path) = paths.iter().find(|p| fs.exists(p)) else {
            continue;
        };
        if let Ok(output) = prober.run(path, args)
            && let Some(v) = version::first_version_token(&output)
        {
            out.insert((*key).to_string(), v);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::fakes::{FakeFs, FakeProber};
    use crate::host::prober::ProbeError;

    #[test]
    fn detect_service_versions_only_probes_existing_binaries() {
        let fs = FakeFs::new().with_file("/usr/sbin/chronyd", "");
        let prober = FakeProber::new().with(
            "/usr/sbin/chronyd",
            &["--version"],
            Ok("chronyd (chrony) version 4.5 (+CMDMON +NTP)"),
        );
        let versions = detect_service_versions(&fs, &prober);
        assert_eq!(versions.get("chrony").map(String::as_str), Some("4.5"));
        assert_eq!(versions.len(), 1);
    }

    #[test]
    fn detect_service_versions_skips_missing_binaries() {
        let fs = FakeFs::new();
        let prober = FakeProber::new();
        assert!(detect_service_versions(&fs, &prober).is_empty());
    }

    #[test]
    fn detect_service_versions_skips_probe_errors_and_unparseable_output() {
        let fs = FakeFs::new()
            .with_file("/usr/sbin/chronyd", "")
            .with_file("/usr/sbin/smbd", "")
            .with_file("/usr/sbin/unbound", "");
        let prober = FakeProber::new()
            .with(
                "/usr/sbin/chronyd",
                &["--version"],
                Err(ProbeError::Spawn("boom".to_string())),
            )
            .with("/usr/sbin/smbd", &["-V"], Ok("no version here"))
            .with("/usr/sbin/unbound", &["-V"], Ok("unbound 1.19.3"));
        let versions = detect_service_versions(&fs, &prober);
        assert_eq!(versions.len(), 1);
        assert_eq!(versions.get("unbound").map(String::as_str), Some("1.19.3"));
    }

    #[test]
    fn detect_service_versions_prefers_first_existing_candidate_path() {
        let fs = FakeFs::new()
            .with_file("/usr/sbin/chronyd", "")
            .with_file("/usr/bin/chronyd", "");
        let prober = FakeProber::new().with("/usr/sbin/chronyd", &["--version"], Ok("4.6"));
        let versions = detect_service_versions(&fs, &prober);
        assert_eq!(versions.get("chrony").map(String::as_str), Some("4.6"));
    }

    #[test]
    fn detect_dispatches_by_compile_time_os() {
        let fs = FakeFs::new();
        let prober = FakeProber::new();
        let detected = detect(&fs, &prober);
        assert_eq!(detected.profile.os, compile_time_os());
        match compile_time_os() {
            Os::MacOs => assert_eq!(detected.profile.init, InitSystem::Launchd),
            Os::Linux | Os::Other => assert_eq!(detected.profile.init, InitSystem::None),
        }
    }

    #[test]
    fn detect_real_smoke_test() {
        let detected = detect_real();
        assert_eq!(detected.profile.os, compile_time_os());
        assert!(detected.profile.ram_mib > 0);
    }
}
