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

/// When an installed service counts as present. A network stack is
/// installed on many hosts that do not use it (Debian ships `networkctl`
/// with systemd, an image may carry `NetworkManager` stopped), so a module
/// that picks its backend from the probes needs the stack in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InUse {
    /// Installed is enough.
    Installed,
    /// The systemd unit is active (`systemctl is-active <unit>`). On a host
    /// without systemd the installed program is enough.
    Unit(&'static str),
    /// A file whose name ends in the suffix is in the directory.
    ConfigIn(&'static str, &'static str),
    /// netplan: a `*.yaml` in `/etc/netplan` that does not render only for
    /// `NetworkManager`. When it does, `NetworkManager` owns the network and
    /// detent edits its keyfile (owner decision 2026-10-21).
    Netplan,
}

/// One service version probe.
#[derive(Debug, Clone, Copy)]
struct ServiceProbe {
    /// The `service_versions` key.
    key: &'static str,
    /// Candidate absolute paths of the program; the first existing one runs.
    paths: &'static [&'static str],
    /// The version flag. `None`: the program prints no version (netplan),
    /// so an installed and used one is filed as [`UNKNOWN_VERSION`] and
    /// nothing runs.
    args: Option<&'static [&'static str]>,
    /// When the installed service counts.
    in_use: InUse,
}

/// The version filed for a service that is present but prints no version.
pub const UNKNOWN_VERSION: &str = "unknown";

/// Candidate paths of `systemctl`, for [`InUse::Unit`].
const SYSTEMCTL: &[&str] = &["/usr/bin/systemctl", "/bin/systemctl"];

/// Every service version probe. The first existing path is used.
const SERVICE_PROBES: &[ServiceProbe] = &[
    ServiceProbe {
        key: "chrony",
        paths: &["/usr/sbin/chronyd", "/usr/bin/chronyd"],
        args: Some(&["--version"]),
        in_use: InUse::Installed,
    },
    ServiceProbe {
        key: "samba",
        paths: &["/usr/sbin/smbd", "/usr/bin/smbd"],
        args: Some(&["-V"]),
        in_use: InUse::Installed,
    },
    ServiceProbe {
        key: "unbound",
        paths: &["/usr/sbin/unbound", "/usr/bin/unbound"],
        args: Some(&["-V"]),
        in_use: InUse::Installed,
    },
    ServiceProbe {
        key: "dnsmasq",
        paths: &["/usr/sbin/dnsmasq", "/usr/bin/dnsmasq"],
        args: Some(&["--version"]),
        in_use: InUse::Installed,
    },
    ServiceProbe {
        key: "kea",
        paths: &["/usr/sbin/kea-dhcp4", "/usr/bin/kea-dhcp4"],
        args: Some(&["-v"]),
        in_use: InUse::Installed,
    },
    ServiceProbe {
        key: "systemd-resolved",
        paths: &["/usr/bin/resolvectl", "/bin/resolvectl"],
        args: Some(&["--version"]),
        in_use: InUse::Installed,
    },
    // The network stacks (BUGFIX Track D 7): the `network` module picks its
    // file from these, with the precedence of `detect_network_backend`.
    ServiceProbe {
        key: "NetworkManager",
        paths: &["/usr/sbin/NetworkManager", "/usr/bin/NetworkManager"],
        args: Some(&["--version"]),
        in_use: InUse::Unit("NetworkManager.service"),
    },
    ServiceProbe {
        key: "systemd-networkd",
        paths: &["/usr/bin/networkctl", "/bin/networkctl"],
        args: Some(&["--version"]),
        in_use: InUse::Unit("systemd-networkd.service"),
    },
    ServiceProbe {
        key: "netplan",
        paths: &["/usr/sbin/netplan", "/usr/bin/netplan"],
        args: None,
        in_use: InUse::Netplan,
    },
    ServiceProbe {
        key: "ifupdown",
        paths: &["/usr/sbin/ifup", "/sbin/ifup"],
        args: Some(&["--version"]),
        in_use: InUse::Unit("networking.service"),
    },
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
    let service_versions = detect_service_versions(fs, prober, init);

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
/// at one of their known absolute paths, and that are in use ([`InUse`]),
/// are run.
fn detect_service_versions(
    fs: &dyn HostFs,
    prober: &dyn Prober,
    init: InitSystem,
) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for probe in SERVICE_PROBES {
        let Some(path) = probe.paths.iter().find(|p| fs.exists(p)) else {
            continue;
        };
        if !in_use(fs, prober, init, probe.in_use) {
            continue;
        }
        let version = match probe.args {
            Some(args) => prober
                .run(path, args)
                .ok()
                .and_then(|output| version::first_version_token(&output)),
            None => Some(UNKNOWN_VERSION.to_owned()),
        };
        if let Some(version) = version {
            out.insert(probe.key.to_string(), version);
        }
    }
    out
}

/// Whether an installed service is in use on this host.
fn in_use(fs: &dyn HostFs, prober: &dyn Prober, init: InitSystem, rule: InUse) -> bool {
    match rule {
        InUse::Installed => true,
        InUse::Unit(unit) => {
            if init != InitSystem::Systemd {
                return true;
            }
            SYSTEMCTL
                .iter()
                .find(|p| fs.exists(p))
                .is_some_and(|systemctl| prober.run(systemctl, &["is-active", unit]).is_ok())
        }
        InUse::ConfigIn(dir, suffix) => fs.list_dir(dir).iter().any(|name| name.ends_with(suffix)),
        InUse::Netplan => {
            in_use(fs, prober, init, InUse::ConfigIn("/etc/netplan", ".yaml"))
                && !linux::netplan_renders_only_for_network_manager(fs)
        }
    }
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
        let versions = detect_service_versions(&fs, &prober, InitSystem::Systemd);
        assert_eq!(versions.get("chrony").map(String::as_str), Some("4.5"));
        assert_eq!(versions.len(), 1);
    }

    #[test]
    fn detect_service_versions_skips_missing_binaries() {
        let fs = FakeFs::new();
        let prober = FakeProber::new();
        assert!(detect_service_versions(&fs, &prober, InitSystem::Systemd).is_empty());
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
        let versions = detect_service_versions(&fs, &prober, InitSystem::Systemd);
        assert_eq!(versions.len(), 1);
        assert_eq!(versions.get("unbound").map(String::as_str), Some("1.19.3"));
    }

    #[test]
    fn detect_service_versions_prefers_first_existing_candidate_path() {
        let fs = FakeFs::new()
            .with_file("/usr/sbin/chronyd", "")
            .with_file("/usr/bin/chronyd", "");
        let prober = FakeProber::new().with("/usr/sbin/chronyd", &["--version"], Ok("4.6"));
        let versions = detect_service_versions(&fs, &prober, InitSystem::Systemd);
        assert_eq!(versions.get("chrony").map(String::as_str), Some("4.6"));
    }

    /// The D3 Debian container: `NetworkManager`, ifupdown and `networkctl`
    /// all installed; which stacks count depends on their units.
    fn network_host() -> (FakeFs, FakeProber) {
        let fs = FakeFs::new()
            .with_file("/usr/bin/systemctl", "")
            .with_file("/usr/sbin/NetworkManager", "")
            .with_file("/usr/bin/networkctl", "")
            .with_file("/usr/sbin/ifup", "")
            .with_file("/usr/sbin/netplan", "");
        let prober = FakeProber::new()
            .with("/usr/sbin/NetworkManager", &["--version"], Ok("1.52.0\n"))
            .with(
                "/usr/bin/networkctl",
                &["--version"],
                Ok("systemd 257 (257.9-1)\n"),
            )
            .with(
                "/usr/sbin/ifup",
                &["--version"],
                Ok("ifup version 0.8.44\n"),
            );
        (fs, prober)
    }

    #[test]
    fn a_network_stack_counts_only_while_its_unit_is_active() {
        let (fs, prober) = network_host();
        // No unit is active: no stack, however much is installed.
        assert!(detect_service_versions(&fs, &prober, InitSystem::Systemd).is_empty());
        let prober = prober.with(
            "/usr/bin/systemctl",
            &["is-active", "networking.service"],
            Ok("active\n"),
        );
        let versions = detect_service_versions(&fs, &prober, InitSystem::Systemd);
        assert_eq!(
            versions.into_iter().collect::<Vec<_>>(),
            [("ifupdown".to_owned(), "0.8.44".to_owned())]
        );
        let prober = prober
            .with(
                "/usr/bin/systemctl",
                &["is-active", "NetworkManager.service"],
                Ok("active\n"),
            )
            .with(
                "/usr/bin/systemctl",
                &["is-active", "systemd-networkd.service"],
                Err(ProbeError::NonZero("exit status: 3".to_owned())),
            );
        let versions = detect_service_versions(&fs, &prober, InitSystem::Systemd);
        assert_eq!(
            versions.get("NetworkManager").map(String::as_str),
            Some("1.52.0")
        );
        assert_eq!(versions.get("ifupdown").map(String::as_str), Some("0.8.44"));
        assert!(!versions.contains_key("systemd-networkd"));
    }

    #[test]
    fn without_systemd_an_installed_stack_counts_and_without_systemctl_none_does() {
        let (fs, prober) = network_host();
        let versions = detect_service_versions(&fs, &prober, InitSystem::OpenRc);
        assert_eq!(
            versions.get("NetworkManager").map(String::as_str),
            Some("1.52.0")
        );
        assert_eq!(
            versions.get("systemd-networkd").map(String::as_str),
            Some("257.9")
        );
        assert_eq!(versions.get("ifupdown").map(String::as_str), Some("0.8.44"));
        // systemd without `systemctl`: a unit cannot be asked, so it is not active.
        let bare = FakeFs::new().with_file("/usr/sbin/ifup", "");
        assert!(detect_service_versions(&bare, &prober, InitSystem::Systemd).is_empty());
    }

    #[test]
    fn netplan_counts_with_a_yaml_file_and_has_no_version() {
        let (fs, prober) = network_host();
        assert!(
            !detect_service_versions(&fs, &prober, InitSystem::Systemd).contains_key("netplan")
        );
        let fs = fs
            .with_file("/etc/netplan/50-cloud-init.yaml", "network: {}\n")
            .with_file("/etc/netplan/README", "");
        let versions = detect_service_versions(&fs, &prober, InitSystem::Systemd);
        assert_eq!(
            versions.get("netplan").map(String::as_str),
            Some(UNKNOWN_VERSION)
        );
        let fs = FakeFs::new().with_file("/etc/netplan/01.yaml", "");
        assert!(detect_service_versions(&fs, &prober, InitSystem::Systemd).is_empty());
    }

    #[test]
    fn netplan_that_renders_only_for_network_manager_leaves_the_network_to_it() {
        // The stock Ubuntu desktop file, a per-interface renderer, quoted
        // and commented values: NetworkManager's keyfile is the file to edit.
        for (name, yaml) in [
            (
                "01-network-manager-all.yaml",
                "# Let NetworkManager manage all devices on this system\n\
                 network:\n  version: 2\n  renderer: NetworkManager\n",
            ),
            (
                "50-eth.yaml",
                "network:\n  ethernets:\n    eth0:\n      renderer: \"NetworkManager\" # nm\n",
            ),
        ] {
            let (fs, prober) = network_host();
            let fs = fs.with_file(&format!("/etc/netplan/{name}"), yaml);
            assert!(
                !detect_service_versions(&fs, &prober, InitSystem::Systemd).contains_key("netplan"),
                "{name}"
            );
        }
        // Mixed, networkd, or no renderer (netplan's default is networkd):
        // netplan stays the backend, as before.
        for files in [
            &[
                ("01.yaml", "network:\n  renderer: NetworkManager\n"),
                ("02.yaml", "network:\n  renderer: networkd\n"),
            ][..],
            &[("01.yaml", "network:\n  renderer: networkd\n")][..],
            &[("01.yaml", "network:\n  version: 2\n")][..],
        ] {
            let (mut fs, prober) = network_host();
            for (name, yaml) in files {
                fs = fs.with_file(&format!("/etc/netplan/{name}"), yaml);
            }
            assert_eq!(
                detect_service_versions(&fs, &prober, InitSystem::Systemd)
                    .get("netplan")
                    .map(String::as_str),
                Some(UNKNOWN_VERSION),
                "{files:?}"
            );
        }
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
