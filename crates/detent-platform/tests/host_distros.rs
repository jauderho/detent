//! Integration tests for `detent_platform::host`: full `detect()` passes
//! against distro-shaped scenarios, using on-disk `os-release` fixtures for
//! the distro identity and an in-memory `FakeFs`/`FakeProber` (defined
//! locally, since this crate's `#[cfg(test)]` fakes are private) for
//! everything else.
//!
//! The crate denies `clippy::unwrap_used`/`expect_used`/`panic` in every
//! target, tests included.
//!
//! `detect()` dispatches its Linux-specific facts collection on the
//! *compile-time* OS (`cfg!(target_os = "linux")`), not on what the fake
//! filesystem looks like, so these Linux-shaped scenarios only exercise
//! that code path when actually compiled for Linux. Run under
//! `docker run --rm -v "$PWD:/src" -w /src rust:1-bookworm cargo test -p
//! detent-platform host` (see the crate's host-detection task notes) to
//! execute this file; on macOS it is not compiled at all.
#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::path::Path;

use detent_core::descriptor::{InitSystem, Os};
use detent_platform::host::{
    Distro, HostFs, NetworkBackend, ProbeError, Prober, ResolverBackend, detect,
};

/// In-memory [`HostFs`]: files/symlinks as entries; directory listings are
/// derived from entry paths under a given directory.
#[derive(Default)]
struct FakeFs {
    files: HashMap<String, String>,
    links: HashMap<String, String>,
    dirs: std::collections::HashSet<String>,
}

impl FakeFs {
    fn new() -> Self {
        Self::default()
    }

    fn with_file(mut self, path: &str, contents: &str) -> Self {
        self.files.insert(path.to_string(), contents.to_string());
        self
    }

    fn with_link(mut self, path: &str, target: &str) -> Self {
        self.links.insert(path.to_string(), target.to_string());
        self
    }

    fn with_dir(mut self, path: &str) -> Self {
        self.dirs.insert(path.to_string());
        self
    }
}

impl HostFs for FakeFs {
    fn read_to_string(&self, path: &str) -> Option<String> {
        self.files.get(path).cloned()
    }

    fn exists(&self, path: &str) -> bool {
        self.files.contains_key(path) || self.links.contains_key(path) || self.dirs.contains(path)
    }

    fn read_link(&self, path: &str) -> Option<String> {
        self.links.get(path).cloned()
    }

    fn list_dir(&self, path: &str) -> Vec<String> {
        let prefix = format!("{}/", path.trim_end_matches('/'));
        self.files
            .keys()
            .chain(self.links.keys())
            .filter_map(|full| full.strip_prefix(&prefix))
            .filter(|rest| !rest.contains('/'))
            .map(str::to_string)
            .collect()
    }
}

/// In-memory [`Prober`]: no configured responses are needed for these
/// distro-identity/network/resolver scenarios (no service binaries "exist").
#[derive(Default)]
struct FakeProber;

impl Prober for FakeProber {
    fn run(&self, _program: &str, _args: &[&str]) -> Result<String, ProbeError> {
        Err(ProbeError::Spawn("no fake response configured".to_string()))
    }
}

/// Read a fixture `os-release` file for `distro` under `tests/fixtures/host/`.
fn os_release_fixture(distro: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/host")
        .join(distro)
        .join("os-release");
    std::fs::read_to_string(&path).unwrap_or_else(|_| String::new())
}

fn assert_distro(distro: Option<&Distro>, id: &str, id_like: &[&str], version_id: Option<&str>) {
    let Some(distro) = distro else {
        unreachable!("expected a distro to be detected")
    };
    assert_eq!(distro.id, id);
    assert_eq!(distro.id_like, id_like);
    assert_eq!(distro.version_id.as_deref(), version_id);
}

#[test]
fn debian12_network_manager_static_resolver() {
    let os_release = os_release_fixture("debian12");
    assert!(!os_release.is_empty(), "debian12 fixture must be readable");

    let fs = FakeFs::new()
        .with_file("/etc/os-release", &os_release)
        .with_dir("/run/systemd/system")
        .with_file("/etc/NetworkManager/NetworkManager.conf", "")
        .with_file("/etc/resolv.conf", "nameserver 192.0.2.53\n");
    let detected = detect(&fs, &FakeProber);

    assert_distro(detected.facts.distro.as_ref(), "debian", &[], Some("12"));
    assert_eq!(detected.profile.init, InitSystem::Systemd);
    assert_eq!(
        detected.facts.network_backend,
        NetworkBackend::NetworkManager
    );
    assert_eq!(detected.facts.resolver_backend, ResolverBackend::Static);
}

#[test]
fn raspberry_pi_os_network_manager_static_resolver() {
    let os_release = os_release_fixture("raspberrypios");
    assert!(
        !os_release.is_empty(),
        "raspberrypios fixture must be readable"
    );

    let fs = FakeFs::new()
        .with_file("/etc/os-release", &os_release)
        .with_dir("/run/systemd/system")
        .with_dir("/run/NetworkManager")
        .with_file("/etc/resolv.conf", "nameserver 192.0.2.53\n");
    let detected = detect(&fs, &FakeProber);

    assert_distro(
        detected.facts.distro.as_ref(),
        "raspbian",
        &["debian"],
        Some("12"),
    );
    assert_eq!(
        detected.facts.network_backend,
        NetworkBackend::NetworkManager
    );
    assert_eq!(detected.facts.resolver_backend, ResolverBackend::Static);
}

#[test]
fn ubuntu2404_netplan_resolved() {
    let os_release = os_release_fixture("ubuntu2404");
    assert!(
        !os_release.is_empty(),
        "ubuntu2404 fixture must be readable"
    );

    let fs = FakeFs::new()
        .with_file("/etc/os-release", &os_release)
        .with_dir("/run/systemd/system")
        .with_file("/etc/netplan/01-netcfg.yaml", "")
        .with_link("/etc/resolv.conf", "/run/systemd/resolve/stub-resolv.conf");
    let detected = detect(&fs, &FakeProber);

    assert_distro(
        detected.facts.distro.as_ref(),
        "ubuntu",
        &["debian"],
        Some("24.04"),
    );
    assert_eq!(detected.facts.network_backend, NetworkBackend::Netplan);
    assert_eq!(
        detected.facts.resolver_backend,
        ResolverBackend::SystemdResolved
    );
}

#[test]
fn fedora41_network_manager_resolved() {
    let os_release = os_release_fixture("fedora41");
    assert!(!os_release.is_empty(), "fedora41 fixture must be readable");

    let fs = FakeFs::new()
        .with_file("/etc/os-release", &os_release)
        .with_dir("/run/systemd/system")
        .with_file("/etc/NetworkManager/NetworkManager.conf", "")
        .with_link("/etc/resolv.conf", "/run/systemd/resolve/stub-resolv.conf");
    let detected = detect(&fs, &FakeProber);

    assert_distro(detected.facts.distro.as_ref(), "fedora", &[], Some("41"));
    assert_eq!(
        detected.facts.network_backend,
        NetworkBackend::NetworkManager
    );
    assert_eq!(
        detected.facts.resolver_backend,
        ResolverBackend::SystemdResolved
    );
}

#[test]
fn arch_networkd_resolved() {
    let os_release = os_release_fixture("arch");
    assert!(!os_release.is_empty(), "arch fixture must be readable");

    let fs = FakeFs::new()
        .with_file("/etc/os-release", &os_release)
        .with_dir("/run/systemd/system")
        .with_dir("/run/systemd/netif")
        .with_link("/etc/resolv.conf", "/run/systemd/resolve/stub-resolv.conf");
    let detected = detect(&fs, &FakeProber);

    assert_distro(detected.facts.distro.as_ref(), "arch", &[], None);
    assert_eq!(
        detected.facts.network_backend,
        NetworkBackend::SystemdNetworkd
    );
    assert_eq!(
        detected.facts.resolver_backend,
        ResolverBackend::SystemdResolved
    );
}

#[test]
fn alpine_openrc_ifupdown_static() {
    let os_release = os_release_fixture("alpine");
    assert!(!os_release.is_empty(), "alpine fixture must be readable");

    let fs = FakeFs::new()
        .with_file("/etc/os-release", &os_release)
        .with_dir("/run/openrc")
        .with_file(
            "/etc/network/interfaces",
            "auto lo\niface lo inet loopback\n",
        )
        .with_file("/etc/resolv.conf", "nameserver 192.0.2.1\n");
    let detected = detect(&fs, &FakeProber);

    assert_distro(
        detected.facts.distro.as_ref(),
        "alpine",
        &[],
        Some("3.20.3"),
    );
    assert_eq!(detected.profile.init, InitSystem::OpenRc);
    assert_eq!(detected.facts.network_backend, NetworkBackend::Ifupdown);
    assert_eq!(detected.facts.resolver_backend, ResolverBackend::Static);
}

#[test]
fn no_os_release_yields_no_distro() {
    let fs = FakeFs::new();
    let detected = detect(&fs, &FakeProber);
    assert_eq!(detected.facts.distro, None);
    assert_eq!(detected.profile.os, expected_compile_time_os());
}

fn expected_compile_time_os() -> Os {
    if cfg!(target_os = "linux") {
        Os::Linux
    } else if cfg!(target_os = "macos") {
        Os::MacOs
    } else {
        Os::Other
    }
}
