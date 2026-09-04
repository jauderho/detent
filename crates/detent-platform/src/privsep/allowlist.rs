//! The tables that turn worker-supplied ids into privileged operations.
//!
//! This is the heart of ADR-001's "no path, unit name, or program name ever
//! crosses the socket". The monitor builds these tables **once, at startup**,
//! from the compiled-in
//! [`ModuleDescriptor`] set — which
//! is `&'static` data with `const` paths — and nothing the worker sends can
//! extend them. An id is an index; an index that is out of range is an error,
//! never a fallback.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use detent_core::descriptor::{ExternalCheck, ModuleDescriptor, ServiceBinding, Target};

use super::proto::{
    BindingId, BindingInfo, CheckId, CheckInfo, HelloAck, ModuleId, ModuleInfo, PROTO_VERSION,
    PathKind, ServiceAction, TargetId, TargetInfo,
};
use crate::fs::atomic::DEFAULT_KEEP_BACKUPS;

/// Default root of `detent`'s mutable state (PLAN §2.10).
pub const DEFAULT_STATE_ROOT: &str = "/var/lib/detent";

/// The subdirectory of the state root that holds rotated backups.
pub const BACKUPS_DIR: &str = "backups";

/// The subdirectory of the state root used for external-check candidate files.
pub const CHECK_TMP_DIR: &str = "tmp";

/// Everything the allow-list needs that does not come from a module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Root of `detent`'s mutable state. Overridable so tests never touch
    /// `/var`.
    pub state_root: PathBuf,
    /// How many backups to retain per target.
    pub keep_backups: usize,
    /// Which init system's unit names to advertise in [`HelloAck`].
    pub init: InitFlavor,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            state_root: PathBuf::from(DEFAULT_STATE_ROOT),
            keep_backups: DEFAULT_KEEP_BACKUPS,
            init: InitFlavor::Systemd,
        }
    }
}

impl Config {
    /// A configuration rooted at `state_root`, otherwise default.
    #[must_use]
    pub fn with_state_root(state_root: impl Into<PathBuf>) -> Self {
        Self {
            state_root: state_root.into(),
            ..Self::default()
        }
    }
}

/// Which of a [`ServiceBinding`]'s name lists applies to this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InitFlavor {
    /// systemd unit names.
    #[default]
    Systemd,
    /// `OpenRC` service names.
    OpenRc,
    /// BSD `rc.d` script names.
    BsdRc,
}

/// Building the tables failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AllowlistError {
    /// More entries than an id can address. `u16` ids cap each table at 65 536
    /// entries, which is orders of magnitude above any plausible module set;
    /// hitting this means something built the table in a loop.
    #[error("too many {kind} entries for a {width}-bit id")]
    TooManyEntries {
        /// Which table overflowed.
        kind: &'static str,
        /// Width of the id type.
        width: u32,
    },
    /// Two modules claim the same id.
    #[error("duplicate module id {0}")]
    DuplicateModule(String),
    /// A module declares a target whose path is not absolute. Paths are
    /// compile-time constants, so this is a module bug, caught at startup
    /// rather than at write time.
    #[error("module {module} declares a relative target path")]
    RelativeTargetPath {
        /// The offending module.
        module: String,
    },
}

/// One writable target, resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetEntry {
    /// Its id.
    pub id: TargetId,
    /// The module that owns it.
    pub module: ModuleId,
    /// Absolute path on disk.
    pub path: PathBuf,
    /// File, drop-in directory, or directory.
    pub kind: PathKind,
    /// Mode to apply when the file has to be created.
    pub create_mode: u32,
    /// Directory holding this target's rotated backups.
    pub backup_dir: PathBuf,
}

/// One external validator, resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckEntry {
    /// Its id.
    pub id: CheckId,
    /// The module that owns it.
    pub module: ModuleId,
    /// The static check declaration.
    pub check: &'static ExternalCheck,
}

/// One service binding, resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingEntry {
    /// Its id.
    pub id: BindingId,
    /// The module that owns it.
    pub module: ModuleId,
    /// The static binding declaration.
    pub binding: &'static ServiceBinding,
}

/// The monitor's complete view of what it is allowed to do.
#[derive(Debug, Clone)]
pub struct Allowlist {
    config: Config,
    modules: Vec<&'static ModuleDescriptor>,
    targets: Vec<TargetEntry>,
    checks: Vec<CheckEntry>,
    bindings: Vec<BindingEntry>,
    by_name: BTreeMap<&'static str, ModuleId>,
}

impl Allowlist {
    /// Build the tables from the enabled modules.
    ///
    /// Ids are assigned as indices in iteration order, so a given binary with a
    /// given feature set always produces the same ids.
    ///
    /// # Errors
    ///
    /// [`AllowlistError::DuplicateModule`] when two descriptors share an id,
    /// [`AllowlistError::RelativeTargetPath`] when a module declares a
    /// non-absolute target, and [`AllowlistError::TooManyEntries`] when a table
    /// would overflow its id type.
    pub fn from_modules(
        modules: &[&'static ModuleDescriptor],
        config: &Config,
    ) -> Result<Self, AllowlistError> {
        let mut by_name = BTreeMap::new();
        let mut targets = Vec::new();
        let mut checks = Vec::new();
        let mut bindings = Vec::new();

        for (index, descriptor) in modules.iter().enumerate() {
            let module = ModuleId(narrow_u16(index, "module")?);
            if by_name.insert(descriptor.id, module).is_some() {
                return Err(AllowlistError::DuplicateModule(descriptor.id.to_owned()));
            }
            let module_backups = backup_dir_for(&config.state_root, descriptor.id);

            for (ordinal, target) in descriptor.targets.iter().enumerate() {
                let entry = resolve_target(
                    TargetId(narrow_u16(targets.len(), "target")?),
                    module,
                    descriptor,
                    target,
                    &module_backups,
                    ordinal,
                )?;
                targets.push(entry);
            }
            for check in descriptor.checks {
                checks.push(CheckEntry {
                    id: CheckId(narrow_u16(checks.len(), "check")?),
                    module,
                    check,
                });
            }
            for binding in descriptor.services {
                bindings.push(BindingEntry {
                    id: BindingId(narrow_u16(bindings.len(), "binding")?),
                    module,
                    binding,
                });
            }
        }

        Ok(Self {
            config: config.clone(),
            modules: modules.to_vec(),
            targets,
            checks,
            bindings,
            by_name,
        })
    }

    /// The configuration these tables were built with.
    #[must_use]
    pub const fn config(&self) -> &Config {
        &self.config
    }

    /// Root of the state directory.
    #[must_use]
    pub fn state_root(&self) -> &Path {
        &self.config.state_root
    }

    /// How many backups are retained per target.
    #[must_use]
    pub const fn keep_backups(&self) -> usize {
        self.config.keep_backups
    }

    /// Directory holding candidate files for external checks.
    #[must_use]
    pub fn check_tmp_dir(&self) -> PathBuf {
        self.config.state_root.join(CHECK_TMP_DIR)
    }

    /// Directory holding every backup of `module`'s targets.
    #[must_use]
    pub fn backup_dir_for(&self, module: &str) -> PathBuf {
        backup_dir_for(&self.config.state_root, module)
    }

    /// The target with this id, or `None` when the id is outside the table.
    #[must_use]
    pub fn target(&self, id: TargetId) -> Option<&TargetEntry> {
        self.targets.get(usize::from(id.get()))
    }

    /// The check with this id, or `None` when the id is outside the table.
    #[must_use]
    pub fn check(&self, id: CheckId) -> Option<&CheckEntry> {
        self.checks.get(usize::from(id.get()))
    }

    /// The binding with this id, or `None` when the id is outside the table.
    #[must_use]
    pub fn binding(&self, id: BindingId) -> Option<&BindingEntry> {
        self.bindings.get(usize::from(id.get()))
    }

    /// The module with this id, or `None` when the id is outside the table.
    #[must_use]
    pub fn module(&self, id: ModuleId) -> Option<&'static ModuleDescriptor> {
        self.modules.get(usize::from(id.get())).copied()
    }

    /// The id of the module with this name.
    #[must_use]
    pub fn module_id(&self, name: &str) -> Option<ModuleId> {
        self.by_name.get(name).copied()
    }

    /// Every target belonging to `module`, in id order.
    pub fn targets_of(&self, module: ModuleId) -> impl Iterator<Item = &TargetEntry> {
        self.targets.iter().filter(move |t| t.module == module)
    }

    /// Number of targets in the table.
    #[must_use]
    pub fn target_count(&self) -> usize {
        self.targets.len()
    }

    /// Number of checks in the table.
    #[must_use]
    pub fn check_count(&self) -> usize {
        self.checks.len()
    }

    /// Number of service bindings in the table.
    #[must_use]
    pub fn binding_count(&self) -> usize {
        self.bindings.len()
    }

    /// The handshake reply describing these tables to the worker.
    #[must_use]
    pub fn hello_ack(&self) -> HelloAck {
        HelloAck {
            proto: PROTO_VERSION,
            modules: self
                .modules
                .iter()
                .enumerate()
                .map(|(index, descriptor)| ModuleInfo {
                    id: ModuleId(narrow_u16_saturating(index)),
                    name: descriptor.id.to_owned(),
                    commit_confirm: descriptor.commit_confirm,
                })
                .collect(),
            targets: self
                .targets
                .iter()
                .map(|entry| TargetInfo {
                    id: entry.id,
                    module: entry.module,
                    path: entry.path.to_string_lossy().into_owned(),
                    kind: entry.kind,
                })
                .collect(),
            checks: self
                .checks
                .iter()
                .map(|entry| CheckInfo {
                    id: entry.id,
                    module: entry.module,
                    program: entry.check.program.as_str().to_owned(),
                })
                .collect(),
            bindings: self
                .bindings
                .iter()
                .map(|entry| BindingInfo {
                    id: entry.id,
                    module: entry.module,
                    unit: preferred_unit(entry.binding, self.config.init).to_owned(),
                    actions: entry
                        .binding
                        .actions
                        .iter()
                        .copied()
                        .map(ServiceAction::from)
                        .collect(),
                })
                .collect(),
        }
    }
}

/// `<state_root>/backups/<module>/`
fn backup_dir_for(state_root: &Path, module: &str) -> PathBuf {
    state_root.join(BACKUPS_DIR).join(module)
}

fn resolve_target(
    id: TargetId,
    module: ModuleId,
    descriptor: &'static ModuleDescriptor,
    target: &'static Target,
    module_backups: &Path,
    ordinal: usize,
) -> Result<TargetEntry, AllowlistError> {
    let path = PathBuf::from(target.path.as_str());
    if !path.is_absolute() {
        return Err(AllowlistError::RelativeTargetPath {
            module: descriptor.id.to_owned(),
        });
    }
    Ok(TargetEntry {
        id,
        module,
        path,
        kind: target.kind.into(),
        create_mode: target.mode,
        // One directory per target under the module's directory: a module may
        // own several files, and `restore_backup` needs to know which file a
        // backup belongs to. The ordinal is the target's position within its
        // own module, so it is stable for a given binary.
        backup_dir: module_backups.join(ordinal.to_string()),
    })
}

/// The first unit name declared for `init`, or the module's first systemd name
/// as a last resort. Purely advisory: it is shown in the UI, never accepted
/// back from the worker.
fn preferred_unit(binding: &'static ServiceBinding, init: InitFlavor) -> &'static str {
    let list = match init {
        InitFlavor::Systemd => binding.units.systemd,
        InitFlavor::OpenRc => binding.units.openrc,
        InitFlavor::BsdRc => binding.units.bsdrc,
    };
    list.first()
        .or_else(|| binding.units.systemd.first())
        .copied()
        .unwrap_or("")
}

fn narrow_u16(index: usize, kind: &'static str) -> Result<u16, AllowlistError> {
    u16::try_from(index).map_err(|_| AllowlistError::TooManyEntries { kind, width: 16 })
}

/// Used only where `from_modules` already proved the index fits.
fn narrow_u16_saturating(index: usize) -> u16 {
    u16::try_from(index).unwrap_or(u16::MAX)
}

#[cfg(test)]
mod tests {
    use super::{
        Allowlist, AllowlistError, BACKUPS_DIR, CHECK_TMP_DIR, Config, DEFAULT_STATE_ROOT,
        InitFlavor, narrow_u16, narrow_u16_saturating, preferred_unit,
    };
    use crate::privsep::proto::{BindingId, CheckId, ModuleId, PathKind, ServiceAction, TargetId};
    use detent_core::descriptor::{
        ArgTemplate, CheckExpectation, ExternalCheck, HostProfile, ModuleDescriptor, Owner,
        PathSpec, ServiceAction as CoreServiceAction, ServiceBinding, Target, TargetKind,
        UnitNames, Upstream,
    };
    use detent_core::diag::MessageId;
    use std::path::{Path, PathBuf};

    const fn always(_: &HostProfile) -> bool {
        true
    }

    static UPSTREAM: Upstream = Upstream {
        project: "test",
        repo_url: "https://example.invalid/test",
        tracked_version: "1.0",
        release_feed: None,
        docs: &[],
    };

    static HOSTS_TARGETS: &[Target] = &[Target {
        path: PathSpec::new("/etc/hosts"),
        kind: TargetKind::File,
        mode: 0o644,
        owner: Owner::Root,
        backend_detect: always,
    }];

    static CHRONY_TARGETS: &[Target] = &[
        Target {
            path: PathSpec::new("/etc/chrony/chrony.conf"),
            kind: TargetKind::File,
            mode: 0o644,
            owner: Owner::Root,
            backend_detect: always,
        },
        Target {
            path: PathSpec::new("/etc/chrony/conf.d"),
            kind: TargetKind::DropInDir,
            mode: 0o755,
            owner: Owner::Named("chrony"),
            backend_detect: always,
        },
    ];

    static CHRONY_CHECKS: &[ExternalCheck] = &[ExternalCheck {
        program: PathSpec::new("/usr/sbin/chronyd"),
        args: &[ArgTemplate::Literal("-p"), ArgTemplate::TempFile],
        expects: CheckExpectation::ExitZero,
    }];

    static CHRONY_SERVICES: &[ServiceBinding] = &[ServiceBinding {
        units: UnitNames {
            systemd: &["chronyd.service", "chrony.service"],
            openrc: &["chronyd"],
            bsdrc: &[],
        },
        actions: &[CoreServiceAction::Restart, CoreServiceAction::Reload],
    }];

    static HOSTS: ModuleDescriptor = ModuleDescriptor {
        id: "hosts",
        display_name_id: MessageId::new("hosts-name"),
        targets: HOSTS_TARGETS,
        upstream: UPSTREAM,
        services: &[],
        checks: &[],
        commit_confirm: false,
        security_notes: &[],
    };

    static CHRONY: ModuleDescriptor = ModuleDescriptor {
        id: "chrony",
        display_name_id: MessageId::new("chrony-name"),
        targets: CHRONY_TARGETS,
        upstream: UPSTREAM,
        services: CHRONY_SERVICES,
        checks: CHRONY_CHECKS,
        commit_confirm: true,
        security_notes: &[],
    };

    static RELATIVE_TARGETS: &[Target] = &[Target {
        path: PathSpec::new("etc/hosts"),
        kind: TargetKind::File,
        mode: 0o644,
        owner: Owner::Root,
        backend_detect: always,
    }];

    static RELATIVE: ModuleDescriptor = ModuleDescriptor {
        id: "relative",
        display_name_id: MessageId::new("relative-name"),
        targets: RELATIVE_TARGETS,
        upstream: UPSTREAM,
        services: &[],
        checks: &[],
        commit_confirm: false,
        security_notes: &[],
    };

    static EMPTY_NAMES: ServiceBinding = ServiceBinding {
        units: UnitNames {
            systemd: &[],
            openrc: &[],
            bsdrc: &[],
        },
        actions: &[],
    };

    fn build(root: &Path) -> Result<Allowlist, AllowlistError> {
        Allowlist::from_modules(&[&HOSTS, &CHRONY], &Config::with_state_root(root))
    }

    #[test]
    fn ids_are_dense_indices_in_declaration_order() -> Result<(), Box<dyn std::error::Error>> {
        let list = build(Path::new("/tmp/detent-test"))?;
        assert_eq!(list.target_count(), 3);
        assert_eq!(list.check_count(), 1);
        assert_eq!(list.binding_count(), 1);
        assert_eq!(list.module_id("hosts"), Some(ModuleId(0)));
        assert_eq!(list.module_id("chrony"), Some(ModuleId(1)));
        assert_eq!(list.module_id("nope"), None);
        assert_eq!(
            list.target(TargetId(0)).map(|t| t.path.clone()),
            Some(PathBuf::from("/etc/hosts"))
        );
        assert_eq!(
            list.target(TargetId(0)).map(|t| t.kind),
            Some(PathKind::File)
        );
        assert_eq!(
            list.target(TargetId(2)).map(|t| t.kind),
            Some(PathKind::DropInDir)
        );
        assert_eq!(list.target(TargetId(2)).map(|t| t.create_mode), Some(0o755));
        assert_eq!(
            list.check(CheckId(0)).map(|c| c.check.program.as_str()),
            Some("/usr/sbin/chronyd")
        );
        assert_eq!(
            list.binding(BindingId(0)).map(|b| b.module),
            Some(ModuleId(1))
        );
        assert_eq!(list.module(ModuleId(1)).map(|m| m.id), Some("chrony"));
        Ok(())
    }

    #[test]
    fn ids_outside_the_tables_resolve_to_nothing() -> Result<(), Box<dyn std::error::Error>> {
        let list = build(Path::new("/tmp/detent-test"))?;
        // Every id one past the end, and a few wildly out of range values,
        // must resolve to `None` rather than to a neighbouring entry.
        for id in [3_u16, 4, 100, u16::MAX] {
            assert!(list.target(TargetId(id)).is_none(), "target {id}");
        }
        for id in [1_u16, 2, u16::MAX] {
            assert!(list.check(CheckId(id)).is_none(), "check {id}");
            assert!(list.binding(BindingId(id)).is_none(), "binding {id}");
        }
        for id in [2_u16, 3, u16::MAX] {
            assert!(list.module(ModuleId(id)).is_none(), "module {id}");
        }
        // And an empty allow-list resolves nothing at all.
        let empty = Allowlist::from_modules(&[], &Config::default())?;
        assert!(empty.target(TargetId(0)).is_none());
        assert!(empty.check(CheckId(0)).is_none());
        assert!(empty.binding(BindingId(0)).is_none());
        assert!(empty.module(ModuleId(0)).is_none());
        assert!(empty.hello_ack().targets.is_empty());
        Ok(())
    }

    #[test]
    fn backup_directories_are_per_target_under_the_module() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = Path::new("/tmp/detent-test");
        let list = build(root)?;
        assert_eq!(list.state_root(), root);
        assert_eq!(list.keep_backups(), 20);
        assert_eq!(list.check_tmp_dir(), root.join(CHECK_TMP_DIR));
        assert_eq!(
            list.backup_dir_for("chrony"),
            root.join(BACKUPS_DIR).join("chrony")
        );
        assert_eq!(
            list.target(TargetId(1)).map(|t| t.backup_dir.clone()),
            Some(root.join(BACKUPS_DIR).join("chrony").join("0"))
        );
        assert_eq!(
            list.target(TargetId(2)).map(|t| t.backup_dir.clone()),
            Some(root.join(BACKUPS_DIR).join("chrony").join("1"))
        );
        let chrony_targets: Vec<_> = list.targets_of(ModuleId(1)).map(|t| t.id).collect();
        assert_eq!(chrony_targets, vec![TargetId(1), TargetId(2)]);
        assert_eq!(list.targets_of(ModuleId(9)).count(), 0);
        Ok(())
    }

    #[test]
    fn the_handshake_describes_every_table() -> Result<(), Box<dyn std::error::Error>> {
        let list = build(Path::new("/tmp/detent-test"))?;
        let ack = list.hello_ack();
        assert_eq!(ack.proto, crate::privsep::proto::PROTO_VERSION);
        assert_eq!(ack.modules.len(), 2);
        assert_eq!(
            ack.modules.first().map(|m| m.name.clone()),
            Some("hosts".to_owned())
        );
        assert_eq!(ack.modules.get(1).map(|m| m.commit_confirm), Some(true));
        assert_eq!(ack.targets.len(), 3);
        assert_eq!(
            ack.targets.first().map(|t| t.path.clone()),
            Some("/etc/hosts".to_owned())
        );
        assert_eq!(
            ack.checks.first().map(|c| c.program.clone()),
            Some("/usr/sbin/chronyd".to_owned())
        );
        assert_eq!(
            ack.bindings.first().map(|b| b.unit.clone()),
            Some("chronyd.service".to_owned())
        );
        assert_eq!(
            ack.bindings.first().map(|b| b.actions.clone()),
            Some(vec![ServiceAction::Restart, ServiceAction::Reload])
        );
        Ok(())
    }

    #[test]
    fn the_advertised_unit_follows_the_init_flavor() -> Result<(), Box<dyn std::error::Error>> {
        let root = Path::new("/tmp/detent-test");
        for (init, expected) in [
            (InitFlavor::Systemd, "chronyd.service"),
            (InitFlavor::OpenRc, "chronyd"),
            // chrony declares no bsdrc names, so the systemd name is shown.
            (InitFlavor::BsdRc, "chronyd.service"),
        ] {
            let config = Config {
                init,
                ..Config::with_state_root(root)
            };
            let list = Allowlist::from_modules(&[&CHRONY], &config)?;
            assert_eq!(
                list.hello_ack().bindings.first().map(|b| b.unit.clone()),
                Some(expected.to_owned())
            );
            assert_eq!(list.config().init, init);
        }
        assert_eq!(InitFlavor::default(), InitFlavor::Systemd);
        assert_eq!(preferred_unit(&EMPTY_NAMES, InitFlavor::Systemd), "");
        Ok(())
    }

    #[test]
    fn malformed_module_sets_are_refused() {
        assert_eq!(
            Allowlist::from_modules(&[&HOSTS, &HOSTS], &Config::default()).err(),
            Some(AllowlistError::DuplicateModule("hosts".to_owned()))
        );
        assert_eq!(
            Allowlist::from_modules(&[&RELATIVE], &Config::default()).err(),
            Some(AllowlistError::RelativeTargetPath {
                module: "relative".to_owned()
            })
        );
        assert_eq!(
            narrow_u16(usize::from(u16::MAX) + 1, "target").err(),
            Some(AllowlistError::TooManyEntries {
                kind: "target",
                width: 16
            })
        );
        assert_eq!(narrow_u16(5, "target").ok(), Some(5));
        assert_eq!(narrow_u16_saturating(usize::MAX), u16::MAX);
        assert!(
            AllowlistError::TooManyEntries {
                kind: "target",
                width: 16
            }
            .to_string()
            .contains("target")
        );
    }

    #[test]
    fn the_default_config_points_at_the_documented_state_root() {
        let config = Config::default();
        assert_eq!(config.state_root, PathBuf::from(DEFAULT_STATE_ROOT));
        assert_eq!(config.keep_backups, 20);
        assert_eq!(config, Config::default());
        assert!(format!("{config:?}").contains("detent"));
    }

    /// `Target::backend_detect` is not called by anything in this module yet
    /// (host-specific target selection is later work); this exercises the
    /// fixtures' shared `always` function directly so its trivial body is not
    /// silently untested.
    #[test]
    fn the_test_fixtures_backend_detect_always_matches() {
        assert!(always(&HostProfile::default_for_tests()));
    }
}
