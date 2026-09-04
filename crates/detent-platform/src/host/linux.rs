//! Linux-specific host detection: distro identity, init system, network
//! and resolver backend, hostname, and RAM.

use detent_core::descriptor::InitSystem;

use super::io::HostFs;
use super::prober::Prober;
use super::{Distro, HostFacts, NetworkBackend, ResolverBackend, os_release};

/// `/etc/os-release`, falling back to `/usr/lib/os-release` per
/// `os-release(5)`.
const OS_RELEASE_PATHS: &[&str] = &["/etc/os-release", "/usr/lib/os-release"];

/// Parse distro identity from `/etc/os-release` (or its fallback).
pub(super) fn detect_distro(fs: &dyn HostFs) -> Option<Distro> {
    let contents = OS_RELEASE_PATHS
        .iter()
        .find_map(|path| fs.read_to_string(path))?;
    let map = os_release::parse(&contents);
    let id = map.get("ID")?.clone();
    let id_like = map
        .get("ID_LIKE")
        .map(|v| v.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default();
    let version_id = map.get("VERSION_ID").cloned();
    Some(Distro {
        id,
        id_like,
        version_id,
    })
}

/// Detect the init system: systemd, `OpenRC`, or none.
pub(super) fn detect_init(fs: &dyn HostFs) -> InitSystem {
    if fs.exists("/run/systemd/system") {
        InitSystem::Systemd
    } else if fs.exists("/run/openrc") || fs.exists("/sbin/openrc-run") {
        InitSystem::OpenRc
    } else {
        InitSystem::None
    }
}

/// Detect the hostname: `/etc/hostname`, then `/proc/sys/kernel/hostname`,
/// then the `hostname` binary.
pub(super) fn detect_hostname(fs: &dyn HostFs, prober: &dyn Prober) -> String {
    for path in ["/etc/hostname", "/proc/sys/kernel/hostname"] {
        if let Some(name) = fs.read_to_string(path) {
            let trimmed = name.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    for path in ["/usr/bin/hostname", "/bin/hostname"] {
        if fs.exists(path)
            && let Ok(out) = prober.run(path, &[])
        {
            let trimmed = out.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    String::new()
}

/// Detect physical RAM in MiB from `/proc/meminfo`'s `MemTotal` (kB).
pub(super) fn detect_ram_mib(fs: &dyn HostFs) -> u64 {
    let Some(contents) = fs.read_to_string("/proc/meminfo") else {
        return 0;
    };
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let kib: u64 = rest
                .split_whitespace()
                .next()
                .and_then(|n| n.parse().ok())
                .unwrap_or(0);
            return kib / 1024;
        }
    }
    0
}

/// Detect the network backend.
///
/// Precedence (most to least specific): netplan renders down to
/// networkd/`NetworkManager`, so its presence is authoritative regardless
/// of what it rendered; `NetworkManager` next because distros that ship it
/// (Fedora, desktop Ubuntu variants) treat it as the sole manager even when
/// systemd-networkd units are also present; networkd next since it's
/// systemd's own manager and takes over from ifupdown when enabled;
/// ifupdown last as the oldest, most conservative option.
pub(super) fn detect_network_backend(fs: &dyn HostFs) -> NetworkBackend {
    if has_glob_match(fs, "/etc/netplan", ".yaml") {
        return NetworkBackend::Netplan;
    }
    if fs.exists("/etc/NetworkManager/NetworkManager.conf") || fs.exists("/run/NetworkManager") {
        return NetworkBackend::NetworkManager;
    }
    if fs.exists("/run/systemd/netif") || has_glob_match(fs, "/etc/systemd/network", ".network") {
        return NetworkBackend::SystemdNetworkd;
    }
    if fs.exists("/etc/network/interfaces") {
        return NetworkBackend::Ifupdown;
    }
    NetworkBackend::Unknown
}

fn has_glob_match(fs: &dyn HostFs, dir: &str, suffix: &str) -> bool {
    fs.list_dir(dir).iter().any(|name| name.ends_with(suffix))
}

/// Detect the DNS resolver backend from `/etc/resolv.conf`'s symlink target
/// (or, if it's a plain file, its header comment). `/etc/unbound/unbound.conf`
/// is checked separately since it can coexist with a managing resolver
/// (e.g. `unbound` as a local forwarder behind `systemd-resolved`) — in
/// that case the managing backend wins and unbound is only noted.
pub(super) fn detect_resolver_backend(fs: &dyn HostFs, notes: &mut Vec<String>) -> ResolverBackend {
    let mut backend = ResolverBackend::Unknown;

    if let Some(target) = fs.read_link("/etc/resolv.conf") {
        if target.contains("/run/systemd/resolve/") {
            backend = ResolverBackend::SystemdResolved;
        } else if target.contains("NetworkManager") {
            backend = ResolverBackend::NetworkManager;
        }
    }

    if backend == ResolverBackend::Unknown
        && let Some(contents) = fs.read_to_string("/etc/resolv.conf")
    {
        let header: String = contents.lines().take(5).collect::<Vec<_>>().join("\n");
        if header.contains("systemd-resolved") {
            backend = ResolverBackend::SystemdResolved;
        } else if header.contains("NetworkManager") {
            backend = ResolverBackend::NetworkManager;
        } else if !contents.trim().is_empty() {
            backend = ResolverBackend::Static;
        }
    }

    if fs.exists("/etc/unbound/unbound.conf") {
        if backend == ResolverBackend::Unknown {
            backend = ResolverBackend::Unbound;
        } else {
            notes.push("unbound.conf present; managed resolver takes precedence".to_string());
        }
    }

    backend
}

/// Collect all Linux-only [`HostFacts`].
pub(super) fn collect_facts(fs: &dyn HostFs) -> HostFacts {
    let mut notes = Vec::new();
    let distro = detect_distro(fs);
    let network_backend = detect_network_backend(fs);
    let resolver_backend = detect_resolver_backend(fs, &mut notes);
    HostFacts {
        distro,
        network_backend,
        resolver_backend,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::fakes::{FakeFs, FakeProber};

    #[test]
    fn distro_parses_os_release() {
        let fs = FakeFs::new().with_file(
            "/etc/os-release",
            "ID=debian\nID_LIKE=\"\"\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12\"\n",
        );
        let distro = detect_distro(&fs).unwrap_or_default();
        assert_eq!(distro.id, "debian");
        assert_eq!(distro.version_id.as_deref(), Some("12"));
        assert!(distro.id_like.is_empty());
    }

    #[test]
    fn distro_falls_back_to_usr_lib_os_release() {
        let fs = FakeFs::new().with_file("/usr/lib/os-release", "ID=arch\n");
        let distro = detect_distro(&fs).unwrap_or_default();
        assert_eq!(distro.id, "arch");
    }

    #[test]
    fn distro_splits_id_like_on_whitespace() {
        let fs = FakeFs::new().with_file(
            "/etc/os-release",
            "ID=raspbian\nID_LIKE=\"debian\"\nVERSION_ID=\"12\"\n",
        );
        let distro = detect_distro(&fs).unwrap_or_default();
        assert_eq!(distro.id_like, vec!["debian".to_string()]);
    }

    #[test]
    fn distro_is_none_when_no_os_release_present() {
        let fs = FakeFs::new();
        assert_eq!(detect_distro(&fs), None);
    }

    #[test]
    fn distro_is_none_when_id_missing() {
        let fs = FakeFs::new().with_file("/etc/os-release", "NAME=\"No ID\"\n");
        assert_eq!(detect_distro(&fs), None);
    }

    #[test]
    fn init_detects_systemd() {
        let fs = FakeFs::new().with_dir("/run/systemd/system");
        assert_eq!(detect_init(&fs), InitSystem::Systemd);
    }

    #[test]
    fn init_detects_openrc_via_run_dir() {
        let fs = FakeFs::new().with_dir("/run/openrc");
        assert_eq!(detect_init(&fs), InitSystem::OpenRc);
    }

    #[test]
    fn init_detects_openrc_via_binary() {
        let fs = FakeFs::new().with_file("/sbin/openrc-run", "");
        assert_eq!(detect_init(&fs), InitSystem::OpenRc);
    }

    #[test]
    fn init_is_none_without_markers() {
        let fs = FakeFs::new();
        assert_eq!(detect_init(&fs), InitSystem::None);
    }

    #[test]
    fn hostname_prefers_etc_hostname() {
        let fs = FakeFs::new()
            .with_file("/etc/hostname", "box\n")
            .with_file("/proc/sys/kernel/hostname", "other\n");
        let prober = FakeProber::new();
        assert_eq!(detect_hostname(&fs, &prober), "box");
    }

    #[test]
    fn hostname_falls_back_to_proc_when_etc_hostname_empty() {
        let fs = FakeFs::new()
            .with_file("/etc/hostname", "\n")
            .with_file("/proc/sys/kernel/hostname", "box2\n");
        let prober = FakeProber::new();
        assert_eq!(detect_hostname(&fs, &prober), "box2");
    }

    #[test]
    fn hostname_falls_back_to_prober() {
        let fs = FakeFs::new().with_file("/usr/bin/hostname", "");
        let prober = FakeProber::new().with("/usr/bin/hostname", &[], Ok("probed-box\n"));
        assert_eq!(detect_hostname(&fs, &prober), "probed-box");
    }

    #[test]
    fn hostname_skips_blank_prober_output() {
        let fs = FakeFs::new().with_file("/usr/bin/hostname", "");
        let prober = FakeProber::new().with("/usr/bin/hostname", &[], Ok("   \n"));
        assert_eq!(detect_hostname(&fs, &prober), "");
    }

    #[test]
    fn hostname_is_empty_when_nothing_available() {
        let fs = FakeFs::new();
        let prober = FakeProber::new();
        assert_eq!(detect_hostname(&fs, &prober), "");
    }

    #[test]
    fn hostname_skips_prober_error_and_tries_next_path() {
        let fs = FakeFs::new()
            .with_file("/usr/bin/hostname", "")
            .with_file("/bin/hostname", "");
        let prober = FakeProber::new().with("/bin/hostname", &[], Ok("fallback\n"));
        assert_eq!(detect_hostname(&fs, &prober), "fallback");
    }

    #[test]
    fn ram_parses_mem_total_kib_to_mib() {
        let fs = FakeFs::new().with_file(
            "/proc/meminfo",
            "MemTotal:        8000000 kB\nMemFree:          100 kB\n",
        );
        assert_eq!(detect_ram_mib(&fs), 8_000_000 / 1024);
    }

    #[test]
    fn ram_is_zero_without_meminfo() {
        let fs = FakeFs::new();
        assert_eq!(detect_ram_mib(&fs), 0);
    }

    #[test]
    fn ram_is_zero_when_mem_total_missing_or_unparseable() {
        let fs = FakeFs::new().with_file("/proc/meminfo", "MemFree: 100 kB\n");
        assert_eq!(detect_ram_mib(&fs), 0);

        let fs2 = FakeFs::new().with_file("/proc/meminfo", "MemTotal: notanumber kB\n");
        assert_eq!(detect_ram_mib(&fs2), 0);
    }

    #[test]
    fn network_backend_precedence_netplan_first() {
        let fs = FakeFs::new()
            .with_file("/etc/netplan/01-config.yaml", "")
            .with_file("/etc/NetworkManager/NetworkManager.conf", "");
        assert_eq!(detect_network_backend(&fs), NetworkBackend::Netplan);
    }

    #[test]
    fn network_backend_network_manager_via_conf() {
        let fs = FakeFs::new().with_file("/etc/NetworkManager/NetworkManager.conf", "");
        assert_eq!(detect_network_backend(&fs), NetworkBackend::NetworkManager);
    }

    #[test]
    fn network_backend_network_manager_via_run_dir() {
        let fs = FakeFs::new().with_dir("/run/NetworkManager");
        assert_eq!(detect_network_backend(&fs), NetworkBackend::NetworkManager);
    }

    #[test]
    fn network_backend_networkd_via_run_netif() {
        let fs = FakeFs::new().with_dir("/run/systemd/netif");
        assert_eq!(detect_network_backend(&fs), NetworkBackend::SystemdNetworkd);
    }

    #[test]
    fn network_backend_networkd_via_network_files() {
        let fs = FakeFs::new().with_file("/etc/systemd/network/20-wired.network", "");
        assert_eq!(detect_network_backend(&fs), NetworkBackend::SystemdNetworkd);
    }

    #[test]
    fn network_backend_ifupdown() {
        let fs = FakeFs::new().with_file("/etc/network/interfaces", "");
        assert_eq!(detect_network_backend(&fs), NetworkBackend::Ifupdown);
    }

    #[test]
    fn network_backend_unknown_without_markers() {
        let fs = FakeFs::new();
        assert_eq!(detect_network_backend(&fs), NetworkBackend::Unknown);
    }

    #[test]
    fn resolver_backend_resolved_via_symlink() {
        let fs =
            FakeFs::new().with_link("/etc/resolv.conf", "/run/systemd/resolve/stub-resolv.conf");
        let mut notes = Vec::new();
        assert_eq!(
            detect_resolver_backend(&fs, &mut notes),
            ResolverBackend::SystemdResolved
        );
        assert!(notes.is_empty());
    }

    #[test]
    fn resolver_backend_network_manager_via_symlink() {
        let fs = FakeFs::new().with_link("/etc/resolv.conf", "../run/NetworkManager/resolv.conf");
        let mut notes = Vec::new();
        assert_eq!(
            detect_resolver_backend(&fs, &mut notes),
            ResolverBackend::NetworkManager
        );
    }

    #[test]
    fn resolver_backend_resolved_via_header_comment() {
        let fs = FakeFs::new().with_file(
            "/etc/resolv.conf",
            "# This file is managed by man:systemd-resolved(8).\nnameserver 127.0.0.53\n",
        );
        let mut notes = Vec::new();
        assert_eq!(
            detect_resolver_backend(&fs, &mut notes),
            ResolverBackend::SystemdResolved
        );
    }

    #[test]
    fn resolver_backend_network_manager_via_header_comment() {
        let fs = FakeFs::new().with_file(
            "/etc/resolv.conf",
            "# Generated by NetworkManager\nnameserver 192.0.2.1\n",
        );
        let mut notes = Vec::new();
        assert_eq!(
            detect_resolver_backend(&fs, &mut notes),
            ResolverBackend::NetworkManager
        );
    }

    #[test]
    fn resolver_backend_static_plain_file() {
        let fs = FakeFs::new().with_file("/etc/resolv.conf", "nameserver 192.0.2.1\n");
        let mut notes = Vec::new();
        assert_eq!(
            detect_resolver_backend(&fs, &mut notes),
            ResolverBackend::Static
        );
    }

    #[test]
    fn resolver_backend_unbound_when_alone() {
        let fs = FakeFs::new().with_file("/etc/unbound/unbound.conf", "");
        let mut notes = Vec::new();
        assert_eq!(
            detect_resolver_backend(&fs, &mut notes),
            ResolverBackend::Unbound
        );
    }

    #[test]
    fn resolver_backend_notes_unbound_when_another_backend_manages() {
        let fs = FakeFs::new()
            .with_link("/etc/resolv.conf", "/run/systemd/resolve/stub-resolv.conf")
            .with_file("/etc/unbound/unbound.conf", "");
        let mut notes = Vec::new();
        assert_eq!(
            detect_resolver_backend(&fs, &mut notes),
            ResolverBackend::SystemdResolved
        );
        assert_eq!(notes.len(), 1);
    }

    #[test]
    fn resolver_backend_unknown_when_nothing_present() {
        let fs = FakeFs::new();
        let mut notes = Vec::new();
        assert_eq!(
            detect_resolver_backend(&fs, &mut notes),
            ResolverBackend::Unknown
        );
    }

    #[test]
    fn resolver_backend_unknown_for_empty_resolv_conf() {
        let fs = FakeFs::new().with_file("/etc/resolv.conf", "   \n");
        let mut notes = Vec::new();
        assert_eq!(
            detect_resolver_backend(&fs, &mut notes),
            ResolverBackend::Unknown
        );
    }

    #[test]
    fn collect_facts_combines_all_linux_detection() {
        let fs = FakeFs::new()
            .with_file("/etc/os-release", "ID=ubuntu\nVERSION_ID=\"24.04\"\n")
            .with_file("/etc/netplan/01.yaml", "")
            .with_link("/etc/resolv.conf", "/run/systemd/resolve/stub-resolv.conf");
        let facts = collect_facts(&fs);
        assert_eq!(facts.distro.map(|d| d.id), Some("ubuntu".to_string()));
        assert_eq!(facts.network_backend, NetworkBackend::Netplan);
        assert_eq!(facts.resolver_backend, ResolverBackend::SystemdResolved);
    }
}
