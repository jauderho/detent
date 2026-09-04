//! macOS-specific host detection: hostname and RAM, via [`Prober`] only.
//! macOS has no `/proc` or `/etc/os-release` equivalent for these facts.

use super::prober::Prober;

/// Detect the hostname via `hostname -s`.
pub(super) fn detect_hostname(prober: &dyn Prober) -> String {
    prober
        .run("/bin/hostname", &["-s"])
        .ok()
        .map(|out| out.trim().to_string())
        .unwrap_or_default()
}

/// Detect physical RAM in MiB via `sysctl -n hw.memsize` (bytes).
pub(super) fn detect_ram_mib(prober: &dyn Prober) -> u64 {
    prober
        .run("/usr/sbin/sysctl", &["-n", "hw.memsize"])
        .ok()
        .and_then(|out| out.trim().parse::<u64>().ok())
        .map_or(0, |bytes| bytes / 1024 / 1024)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::fakes::FakeProber;
    use crate::host::prober::ProbeError;

    #[test]
    fn hostname_trims_prober_output() {
        let prober = FakeProber::new().with("/bin/hostname", &["-s"], Ok("mac-mini\n"));
        assert_eq!(detect_hostname(&prober), "mac-mini");
    }

    #[test]
    fn hostname_is_empty_on_probe_error() {
        let prober = FakeProber::new().with(
            "/bin/hostname",
            &["-s"],
            Err(ProbeError::Spawn("missing".to_string())),
        );
        assert_eq!(detect_hostname(&prober), "");
    }

    #[test]
    fn ram_converts_bytes_to_mib() {
        let prober = FakeProber::new().with(
            "/usr/sbin/sysctl",
            &["-n", "hw.memsize"],
            Ok("17179869184\n"),
        );
        assert_eq!(detect_ram_mib(&prober), 16384);
    }

    #[test]
    fn ram_is_zero_when_output_unparseable() {
        let prober = FakeProber::new().with(
            "/usr/sbin/sysctl",
            &["-n", "hw.memsize"],
            Ok("not-a-number\n"),
        );
        assert_eq!(detect_ram_mib(&prober), 0);
    }

    #[test]
    fn ram_is_zero_on_probe_error() {
        let prober = FakeProber::new();
        assert_eq!(detect_ram_mib(&prober), 0);
    }
}
