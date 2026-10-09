//! `[privilege] mode` (PLAN §2.4, Phase 12).
//!
//! The unit file decides who the process is: `detent.service` runs it as
//! root (`root-confined`), the `capability-user.conf` drop-in runs it as
//! `detent` with ambient capabilities (`capability-user`). The process
//! behaves by what it really is (its effective uid and capability sets), never
//! by the configuration. The configured mode is the operator's statement of
//! which unit they installed: [`check_mode`] compares it with the real
//! process, and `serve` refuses to start when the two disagree, so the
//! configuration and the unit cannot silently say different things.

use serde::{Deserialize, Serialize};

use crate::sandbox::{Capability, has_capability};

/// How the monitor holds its privilege.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrivilegeMode {
    /// The monitor keeps uid 0, confined (ADR-001 default).
    #[default]
    RootConfined,
    /// The monitor runs as `detent` with [`CAPABILITY_USER_CAPS`] as ambient
    /// capabilities; service control goes through polkit.
    CapabilityUser,
}

impl PrivilegeMode {
    /// The value as written in `detent.toml`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RootConfined => "root-confined",
            Self::CapabilityUser => "capability-user",
        }
    }
}

/// The capabilities the monitor needs in capability-user mode, the ones the
/// drop-in grants: `CAP_DAC_OVERRIDE` to open and replace root-owned targets
/// and backups, `CAP_CHOWN` to give a replaced target its old owner,
/// `CAP_FOWNER` to set the mode and extended attributes of a file it does not
/// own.
pub const CAPABILITY_USER_CAPS: [Capability; 3] = [
    Capability::DacOverride,
    Capability::Chown,
    Capability::Fowner,
];

/// What this process really is, read before any confinement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessPrivilege {
    /// The effective uid.
    pub euid: u32,
    /// Each of [`CAPABILITY_USER_CAPS`] that is not in the effective set.
    pub missing: Vec<Capability>,
    /// Whether the effective or permitted set holds any capability.
    pub holds_any: bool,
}

impl ProcessPrivilege {
    /// Read this process.
    #[must_use]
    pub fn current() -> Self {
        Self {
            euid: rustix::process::geteuid().as_raw(),
            missing: CAPABILITY_USER_CAPS
                .into_iter()
                .filter(|cap| !has_capability(*cap))
                .collect(),
            holds_any: crate::sandbox::holds_capabilities(),
        }
    }
}

/// The configured mode does not match the process the unit started.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ModeMismatch {
    /// `capability-user` configured, but the process is root.
    #[error(
        "privilege.mode is capability-user, but the service runs as root: install the capability-user drop-in (install.sh --mode capability-user) or set mode = \"root-confined\""
    )]
    RootInCapabilityUser,
    /// `capability-user` configured, but a needed capability is missing.
    #[error(
        "privilege.mode is capability-user, but uid {euid} does not hold {missing}: the unit must set AmbientCapabilities=CAP_DAC_OVERRIDE CAP_CHOWN CAP_FOWNER (install.sh --mode capability-user)"
    )]
    MissingCapabilities {
        /// The effective uid.
        euid: u32,
        /// The missing capabilities, space-separated.
        missing: String,
    },
    /// `root-confined` configured, but the process is not root and holds
    /// capabilities: the capability-user drop-in is installed.
    #[error(
        "the service runs as uid {euid} with capabilities, but privilege.mode is root-confined: set [privilege] mode = \"capability-user\" or remove the capability-user drop-in"
    )]
    CapabilitiesInRootConfined {
        /// The effective uid.
        euid: u32,
    },
}

/// Whether `mode` matches `process`.
///
/// `root-confined` accepts root, and also a process that is not root and
/// holds no capability: the unprivileged developer run `serve` has always
/// supported (it confines what it can and reports the rest).
///
/// # Errors
///
/// The [`ModeMismatch`] that names the disagreement.
pub fn check_mode(mode: PrivilegeMode, process: &ProcessPrivilege) -> Result<(), ModeMismatch> {
    let root = process.euid == 0;
    match mode {
        PrivilegeMode::RootConfined if !root && process.holds_any => {
            Err(ModeMismatch::CapabilitiesInRootConfined { euid: process.euid })
        }
        PrivilegeMode::CapabilityUser if root => Err(ModeMismatch::RootInCapabilityUser),
        PrivilegeMode::CapabilityUser if !process.missing.is_empty() => {
            let names: Vec<&str> = process.missing.iter().map(|cap| cap.name()).collect();
            Err(ModeMismatch::MissingCapabilities {
                euid: process.euid,
                missing: names.join(" "),
            })
        }
        PrivilegeMode::RootConfined | PrivilegeMode::CapabilityUser => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::{CAPABILITY_USER_CAPS, ModeMismatch, PrivilegeMode, ProcessPrivilege, check_mode};
    use crate::sandbox::Capability;

    fn process(euid: u32, missing: &[Capability], holds_any: bool) -> ProcessPrivilege {
        ProcessPrivilege {
            euid,
            missing: missing.to_vec(),
            holds_any,
        }
    }

    #[test]
    fn root_confined_is_the_default() {
        assert_eq!(PrivilegeMode::default(), PrivilegeMode::RootConfined);
        assert_eq!(PrivilegeMode::RootConfined.as_str(), "root-confined");
        assert_eq!(PrivilegeMode::CapabilityUser.as_str(), "capability-user");
    }

    #[test]
    fn root_confined_accepts_root_and_an_unprivileged_developer_run() {
        let root = process(0, &[], true);
        assert_eq!(check_mode(PrivilegeMode::RootConfined, &root), Ok(()));
        let developer = process(1000, &CAPABILITY_USER_CAPS, false);
        assert_eq!(check_mode(PrivilegeMode::RootConfined, &developer), Ok(()));
    }

    #[test]
    fn root_confined_refuses_a_non_root_process_with_capabilities() {
        let dropin = process(999, &[], true);
        assert_eq!(
            check_mode(PrivilegeMode::RootConfined, &dropin),
            Err(ModeMismatch::CapabilitiesInRootConfined { euid: 999 })
        );
    }

    #[test]
    fn capability_user_refuses_root() {
        let root = process(0, &[], true);
        let err = check_mode(PrivilegeMode::CapabilityUser, &root);
        assert_eq!(err, Err(ModeMismatch::RootInCapabilityUser));
        assert!(
            err.err()
                .is_some_and(|err| err.to_string().contains("--mode capability-user"))
        );
    }

    #[test]
    fn capability_user_names_each_missing_capability() {
        let partial = process(999, &[Capability::Chown, Capability::Fowner], true);
        let err = check_mode(PrivilegeMode::CapabilityUser, &partial);
        assert_eq!(
            err,
            Err(ModeMismatch::MissingCapabilities {
                euid: 999,
                missing: "CAP_CHOWN CAP_FOWNER".to_owned(),
            })
        );
        let none = process(999, &CAPABILITY_USER_CAPS, false);
        assert!(check_mode(PrivilegeMode::CapabilityUser, &none).is_err());
    }

    #[test]
    fn capability_user_accepts_a_non_root_process_with_every_capability() {
        let unit = process(999, &[], true);
        assert_eq!(check_mode(PrivilegeMode::CapabilityUser, &unit), Ok(()));
    }

    #[test]
    fn the_mode_reads_from_its_kebab_case_name() -> Result<(), serde_json::Error> {
        let mode: PrivilegeMode = serde_json::from_str("\"capability-user\"")?;
        assert_eq!(mode, PrivilegeMode::CapabilityUser);
        assert!(serde_json::from_str::<PrivilegeMode>("\"capability_user\"").is_err());
        assert!(serde_json::from_str::<PrivilegeMode>("\"root\"").is_err());
        Ok(())
    }

    #[test]
    fn the_current_process_reads_its_own_euid() {
        let current = ProcessPrivilege::current();
        assert_eq!(current.euid, rustix::process::geteuid().as_raw());
        if !current.holds_any {
            assert_eq!(current.missing, CAPABILITY_USER_CAPS.to_vec());
        }
    }
}
