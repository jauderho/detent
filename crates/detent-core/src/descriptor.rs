//! Static module metadata and the `x-detent` JSON Schema UI hints.
//!
//! Everything a module declares about itself — which files it owns, which upstream
//! project it tracks, which service units it restarts, which external validator binary
//! confirms a candidate file — is `&'static` data. In particular **paths are static
//! templates and are never user-supplied**: a request can select a module, but it can
//! never name the file that module writes.

use crate::diag::MessageId;
use std::collections::BTreeMap;

/// A filesystem path owned by a module. Always a compile-time constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(transparent)]
pub struct PathSpec(&'static str);

impl PathSpec {
    /// Wraps a static absolute path.
    #[must_use]
    pub const fn new(path: &'static str) -> Self {
        Self(path)
    }

    /// The underlying path.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

/// What kind of filesystem object a [`Target`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    /// A single configuration file.
    File,
    /// A directory of drop-in fragments the module may add files to.
    DropInDir,
    /// A directory whose contents the module owns wholesale.
    Directory,
}

/// The account a [`Target`] must belong to after a write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Owner {
    /// `root`, the usual case for `/etc`.
    Root,
    /// A named service account, e.g. `unbound`.
    Named(&'static str),
}

/// One file or directory a module manages.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct Target {
    /// Where it lives.
    pub path: PathSpec,
    /// File, drop-in directory, or directory.
    pub kind: TargetKind,
    /// The mode the target must end up with, e.g. `0o644`.
    pub mode: u32,
    /// The owner the target must end up with.
    pub owner: Owner,
    /// Whether this target is the right backend for a given host. Not serialized:
    /// it is behaviour, not metadata.
    #[serde(skip)]
    pub backend_detect: fn(&HostProfile) -> bool,
}

/// The upstream project whose configuration format a module tracks.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct Upstream {
    /// Upstream project name, e.g. `chrony`.
    pub project: &'static str,
    /// Canonical source repository URL.
    pub repo_url: &'static str,
    /// The upstream release this module's option set was derived from.
    pub tracked_version: &'static str,
    /// A release feed URL the upstream-watch workflow polls, when one exists.
    pub release_feed: Option<&'static str>,
    /// Documentation URLs shown in the UI.
    pub docs: &'static [&'static str],
}

/// Per-init-system names for one service, most preferred first.
///
/// Distributions disagree (`chronyd.service` on Fedora, `chrony.service` on Debian),
/// so each backend gets a list of alternatives rather than a single name.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct UnitNames {
    /// systemd unit names.
    pub systemd: &'static [&'static str],
    /// `OpenRC` service names.
    pub openrc: &'static [&'static str],
    /// BSD `rc.d` script names. Kept for portability; BSD is a deferred tier.
    pub bsdrc: &'static [&'static str],
}

/// What may be done to a service after a config change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceAction {
    /// Full restart.
    Restart,
    /// Reload configuration in place.
    Reload,
    /// Start a stopped service.
    Start,
    /// Stop a running service.
    Stop,
}

/// A service a module's files configure.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct ServiceBinding {
    /// Names of the service per init system.
    pub units: UnitNames,
    /// Actions this module may request, most preferred first.
    pub actions: &'static [ServiceAction],
}

/// One argument of an [`ExternalCheck`] command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgTemplate {
    /// A fixed argument.
    Literal(&'static str),
    /// Replaced by the path of the temporary file holding the candidate config.
    TempFile,
}

/// How the result of an [`ExternalCheck`] is judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckExpectation {
    /// The program must exit 0.
    ExitZero,
    /// The program's output must match this regular expression. Compiled and applied
    /// by the platform layer; the core carries the pattern only.
    StdoutPattern(&'static str),
}

/// An upstream validator run against a candidate file before it is installed, e.g.
/// `chronyd -p -f <tmp>` or `testparm -s <tmp>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct ExternalCheck {
    /// Absolute path of the validator binary.
    pub program: PathSpec,
    /// Its argument list.
    pub args: &'static [ArgTemplate],
    /// The success condition.
    pub expects: CheckExpectation,
}

/// Everything a module declares about itself.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct ModuleDescriptor {
    /// Stable module id, e.g. `hosts`. Used in URLs, the CLI, the audit log and
    /// feature names.
    pub id: &'static str,
    /// Fluent id of the module's display name.
    pub display_name_id: MessageId,
    /// Files and directories this module owns.
    pub targets: &'static [Target],
    /// The upstream project tracked.
    pub upstream: Upstream,
    /// Services affected by a change.
    pub services: &'static [ServiceBinding],
    /// Upstream validators run before installing a candidate file.
    pub checks: &'static [ExternalCheck],
    /// Whether a change to this module needs commit-confirm (it can lock an admin
    /// out, e.g. network configuration).
    pub commit_confirm: bool,
    /// Fluent ids of security notes shown alongside this module.
    pub security_notes: &'static [MessageId],
}

/// The operating system family of the host being configured.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Os {
    /// Linux.
    Linux,
    /// macOS.
    MacOs,
    /// Anything else. Modules must degrade gracefully rather than assume.
    #[default]
    Other,
}

/// The init system of the host being configured.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum InitSystem {
    /// systemd.
    Systemd,
    /// `OpenRC`.
    OpenRc,
    /// launchd (macOS).
    Launchd,
    /// No supported init system: service actions are unavailable.
    #[default]
    None,
}

/// What is known about the host a module is producing configuration for.
///
/// Populated by `detent-platform`; the core only reads it. Modules use it to pick a
/// backend, to size defaults, and to hide options newer than the installed service.
#[derive(
    Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct HostProfile {
    /// Operating system family.
    pub os: Os,
    /// Init system.
    pub init: InitSystem,
    /// The host's own name, used by defaults such as the `/etc/hosts` entry for it.
    pub hostname: String,
    /// Installed version per service name, e.g. `{"chronyd": "4.5"}`.
    pub service_versions: BTreeMap<String, String>,
    /// Physical memory in MiB, used to size caches and worker counts.
    pub ram_mib: u64,
}

impl HostProfile {
    /// The installed version of `service`, if it was detected.
    #[must_use]
    pub fn service_version(&self, service: &str) -> Option<&str> {
        self.service_versions.get(service).map(String::as_str)
    }

    /// A representative host for module conformance tests: Linux/systemd, a
    /// stable hostname, and enough memory that low-memory validation
    /// recommendations do not fire. `Default::default()` stays the "nothing is
    /// known" profile; this is the one `module_conformance!` hands to
    /// `defaults` when checking that a module's own defaults apply cleanly.
    #[must_use]
    pub fn default_for_tests() -> Self {
        Self {
            os: Os::Linux,
            init: InitSystem::Systemd,
            hostname: "detent-test".to_owned(),
            service_versions: BTreeMap::new(),
            ram_mib: 1024,
        }
    }
}

/// Read-only context handed to `ConfigModule::validate`.
///
/// A struct rather than a bare `&HostProfile` so that later additions (locale,
/// sibling module state) do not change every module's signature.
#[derive(Debug, Clone, Copy)]
pub struct ValidationCtx<'a> {
    /// The host the model is being validated for.
    pub profile: &'a HostProfile,
}

impl<'a> ValidationCtx<'a> {
    /// Wraps a host profile.
    #[must_use]
    pub const fn new(profile: &'a HostProfile) -> Self {
        Self { profile }
    }
}

/// Which pane of the UI a field belongs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiGroup {
    /// Shown by default.
    Basic,
    /// Hidden behind "advanced".
    Advanced,
}

impl UiGroup {
    /// The value written into the schema.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Basic => "basic",
            Self::Advanced => "advanced",
        }
    }
}

/// How much getting a field wrong matters for security.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityImpact {
    /// No security consequence.
    None,
    /// Weakens hardening.
    Low,
    /// Can expose the service or the host.
    High,
}

impl SecurityImpact {
    /// The value written into the schema.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Low => "low",
            Self::High => "high",
        }
    }
}

/// UI hints for one model field, injected into the JSON Schema as `x-detent`.
///
/// Const-constructible so a module can declare its hints in a `static` table next to
/// the model definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldHints {
    /// Basic or advanced.
    pub group: UiGroup,
    /// Fluent id of the field's tooltip.
    pub tooltip: MessageId,
    /// Fluent id of a recommended value or practice, when there is one.
    pub recommendation: Option<MessageId>,
    /// Security weight of the field.
    pub security_impact: SecurityImpact,
    /// Upstream version that introduced the option, e.g. `"4.5"`.
    pub since: Option<&'static str>,
    /// Upstream version that deprecated the option.
    pub deprecated_in: Option<&'static str>,
    /// Whether changing the field requires a service restart.
    pub requires_restart: bool,
}

impl FieldHints {
    /// Renders the hints as the JSON object stored under `x-detent`.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        map.insert("group".to_owned(), self.group.as_str().into());
        map.insert("tooltip".to_owned(), self.tooltip.as_str().into());
        map.insert(
            "security_impact".to_owned(),
            self.security_impact.as_str().into(),
        );
        map.insert("requires_restart".to_owned(), self.requires_restart.into());
        if let Some(recommendation) = self.recommendation {
            map.insert("recommendation".to_owned(), recommendation.as_str().into());
        }
        if let Some(since) = self.since {
            map.insert("since".to_owned(), since.into());
        }
        if let Some(deprecated_in) = self.deprecated_in {
            map.insert("deprecated_in".to_owned(), deprecated_in.into());
        }
        serde_json::Value::Object(map)
    }
}

/// Adds an `x-detent` hint object to one node of a generated JSON Schema.
///
/// `pointer` is an RFC 6901 JSON Pointer into `schema`, e.g.
/// `"/properties/entries"` or `"/$defs/HostEntry/properties/ip"`. Returns `false`
/// when the pointer does not resolve or does not name an object, so a module's test
/// suite can catch a hint that silently applies to nothing.
#[must_use]
pub fn apply_hints(schema: &mut serde_json::Value, pointer: &str, hints: &FieldHints) -> bool {
    let Some(target) = schema.pointer_mut(pointer) else {
        return false;
    };
    let Some(object) = target.as_object_mut() else {
        return false;
    };
    object.insert("x-detent".to_owned(), hints.to_json());
    true
}

#[cfg(test)]
mod tests {
    use super::{
        ArgTemplate, CheckExpectation, ExternalCheck, FieldHints, HostProfile, InitSystem,
        ModuleDescriptor, Os, Owner, PathSpec, SecurityImpact, ServiceAction, ServiceBinding,
        Target, TargetKind, UiGroup, UnitNames, Upstream, ValidationCtx, apply_hints,
    };
    use crate::diag::MessageId;

    fn is_linux(profile: &HostProfile) -> bool {
        profile.os == Os::Linux
    }

    static TARGETS: &[Target] = &[
        Target {
            path: PathSpec::new("/etc/chrony/chrony.conf"),
            kind: TargetKind::File,
            mode: 0o644,
            owner: Owner::Root,
            backend_detect: is_linux,
        },
        Target {
            path: PathSpec::new("/etc/chrony/conf.d"),
            kind: TargetKind::DropInDir,
            mode: 0o755,
            owner: Owner::Named("chrony"),
            backend_detect: is_linux,
        },
        Target {
            path: PathSpec::new("/etc/chrony/sources.d"),
            kind: TargetKind::Directory,
            mode: 0o755,
            owner: Owner::Root,
            backend_detect: is_linux,
        },
    ];

    static CHECKS: &[ExternalCheck] = &[
        ExternalCheck {
            program: PathSpec::new("/usr/sbin/chronyd"),
            args: &[
                ArgTemplate::Literal("-p"),
                ArgTemplate::Literal("-f"),
                ArgTemplate::TempFile,
            ],
            expects: CheckExpectation::ExitZero,
        },
        ExternalCheck {
            program: PathSpec::new("/usr/bin/testparm"),
            args: &[ArgTemplate::Literal("-s")],
            expects: CheckExpectation::StdoutPattern("^Loaded services"),
        },
    ];

    static DESCRIPTOR: ModuleDescriptor = ModuleDescriptor {
        id: "chrony",
        display_name_id: MessageId::new("chrony-name"),
        targets: TARGETS,
        upstream: Upstream {
            project: "chrony",
            repo_url: "https://gitlab.com/chrony/chrony",
            tracked_version: "4.5",
            release_feed: Some("https://gitlab.com/chrony/chrony/-/tags?format=atom"),
            docs: &["https://chrony-project.org/documentation.html"],
        },
        services: &[ServiceBinding {
            units: UnitNames {
                systemd: &["chronyd.service", "chrony.service"],
                openrc: &["chronyd"],
                bsdrc: &["chronyd"],
            },
            actions: &[
                ServiceAction::Restart,
                ServiceAction::Reload,
                ServiceAction::Start,
                ServiceAction::Stop,
            ],
        }],
        checks: CHECKS,
        commit_confirm: false,
        security_notes: &[MessageId::new("chrony-note-nts")],
    };

    #[test]
    fn descriptor_serializes_without_the_detector() {
        let json = serde_json::to_value(DESCRIPTOR).unwrap_or_default();
        assert_eq!(json.pointer("/id").and_then(|v| v.as_str()), Some("chrony"));
        assert_eq!(
            json.pointer("/targets/0/path").and_then(|v| v.as_str()),
            Some("/etc/chrony/chrony.conf")
        );
        assert_eq!(
            json.pointer("/targets/0/kind").and_then(|v| v.as_str()),
            Some("file")
        );
        assert_eq!(
            json.pointer("/targets/1/kind").and_then(|v| v.as_str()),
            Some("drop_in_dir")
        );
        assert_eq!(
            json.pointer("/targets/2/kind").and_then(|v| v.as_str()),
            Some("directory")
        );
        assert_eq!(
            json.pointer("/targets/0/owner").and_then(|v| v.as_str()),
            Some("root")
        );
        assert_eq!(
            json.pointer("/targets/1/owner/named")
                .and_then(|v| v.as_str()),
            Some("chrony")
        );
        assert_eq!(
            json.pointer("/services/0/units/systemd/1")
                .and_then(|v| v.as_str()),
            Some("chrony.service")
        );
        assert_eq!(
            json.pointer("/services/0/actions/0")
                .and_then(|v| v.as_str()),
            Some("restart")
        );
        assert_eq!(
            json.pointer("/checks/0/args/2").and_then(|v| v.as_str()),
            Some("temp_file")
        );
        assert_eq!(
            json.pointer("/checks/0/expects").and_then(|v| v.as_str()),
            Some("exit_zero")
        );
        assert_eq!(
            json.pointer("/checks/1/expects/stdout_pattern")
                .and_then(|v| v.as_str()),
            Some("^Loaded services")
        );
        assert_eq!(
            json.pointer("/upstream/tracked_version")
                .and_then(|v| v.as_str()),
            Some("4.5")
        );
        assert_eq!(
            json.pointer("/commit_confirm")
                .and_then(serde_json::Value::as_bool),
            Some(false)
        );
        assert_eq!(
            json.pointer("/security_notes/0").and_then(|v| v.as_str()),
            Some("chrony-note-nts")
        );
        assert!(json.pointer("/targets/0/backend_detect").is_none());
        assert!(format!("{DESCRIPTOR:?}").contains("chrony"));
        assert_eq!(
            DESCRIPTOR.targets.first().map(|t| t.path.as_str()),
            Some("/etc/chrony/chrony.conf")
        );
        assert_eq!(
            DESCRIPTOR.targets.first().map(|t| t.path),
            Some(PathSpec::new("/etc/chrony/chrony.conf"))
        );
    }

    #[test]
    fn backend_detection_reads_the_profile() {
        let mut profile = HostProfile::default();
        assert_eq!(profile.os, Os::Other);
        assert_eq!(profile.init, InitSystem::None);
        assert_eq!(profile.ram_mib, 0);
        assert_eq!(profile.service_version("chronyd"), None);
        let detect = TARGETS.first().map(|t| t.backend_detect);
        assert_eq!(detect.map(|f| f(&profile)), Some(false));
        profile.os = Os::Linux;
        profile.init = InitSystem::Systemd;
        profile.hostname = "gps1".to_owned();
        profile.ram_mib = 512;
        profile
            .service_versions
            .insert("chronyd".to_owned(), "4.5".to_owned());
        assert_eq!(detect.map(|f| f(&profile)), Some(true));
        assert_eq!(profile.service_version("chronyd"), Some("4.5"));
        let ctx = ValidationCtx::new(&profile);
        assert_eq!(ctx.profile.hostname, "gps1");
        assert!(format!("{ctx:?}").contains("gps1"));
    }

    #[test]
    fn host_profile_round_trips_as_json_and_schema() {
        let mut profile = HostProfile {
            os: Os::MacOs,
            init: InitSystem::Launchd,
            ..HostProfile::default()
        };
        profile.ram_mib = 16_384;
        let json = serde_json::to_value(&profile).unwrap_or_default();
        assert_eq!(json.pointer("/os").and_then(|v| v.as_str()), Some("mac_os"));
        assert_eq!(
            json.pointer("/init").and_then(|v| v.as_str()),
            Some("launchd")
        );
        assert_eq!(
            serde_json::from_value::<HostProfile>(json).ok(),
            Some(profile)
        );
        for schema in [
            schemars::schema_for!(HostProfile),
            schemars::schema_for!(Os),
            schemars::schema_for!(InitSystem),
        ] {
            assert!(!schema.to_value().is_null());
        }
        assert_eq!(
            serde_json::from_str::<Os>("\"linux\"").ok(),
            Some(Os::Linux)
        );
        assert_eq!(
            serde_json::from_str::<InitSystem>("\"open_rc\"").ok(),
            Some(InitSystem::OpenRc)
        );
    }

    const FULL: FieldHints = FieldHints {
        group: UiGroup::Advanced,
        tooltip: MessageId::new("chrony-tip-nts"),
        recommendation: Some(MessageId::new("chrony-rec-nts")),
        security_impact: SecurityImpact::High,
        since: Some("4.0"),
        deprecated_in: Some("5.0"),
        requires_restart: true,
    };

    const MINIMAL: FieldHints = FieldHints {
        group: UiGroup::Basic,
        tooltip: MessageId::new("chrony-tip-pool"),
        recommendation: None,
        security_impact: SecurityImpact::None,
        since: None,
        deprecated_in: None,
        requires_restart: false,
    };

    #[test]
    fn hints_render_every_field() {
        let full = FULL.to_json();
        assert_eq!(
            full.pointer("/group").and_then(|v| v.as_str()),
            Some("advanced")
        );
        assert_eq!(
            full.pointer("/tooltip").and_then(|v| v.as_str()),
            Some("chrony-tip-nts")
        );
        assert_eq!(
            full.pointer("/recommendation").and_then(|v| v.as_str()),
            Some("chrony-rec-nts")
        );
        assert_eq!(
            full.pointer("/security_impact").and_then(|v| v.as_str()),
            Some("high")
        );
        assert_eq!(full.pointer("/since").and_then(|v| v.as_str()), Some("4.0"));
        assert_eq!(
            full.pointer("/deprecated_in").and_then(|v| v.as_str()),
            Some("5.0")
        );
        assert_eq!(
            full.pointer("/requires_restart")
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );

        let minimal = MINIMAL.to_json();
        assert_eq!(
            minimal.pointer("/group").and_then(|v| v.as_str()),
            Some("basic")
        );
        assert_eq!(
            minimal.pointer("/security_impact").and_then(|v| v.as_str()),
            Some("none")
        );
        assert!(minimal.pointer("/recommendation").is_none());
        assert!(minimal.pointer("/since").is_none());
        assert!(minimal.pointer("/deprecated_in").is_none());
        assert_eq!(SecurityImpact::Low.as_str(), "low");
        assert_eq!(FULL, FULL.clone());
        assert!(format!("{MINIMAL:?}").contains("Basic"));
    }

    #[test]
    fn apply_hints_targets_a_json_pointer() {
        let mut schema = serde_json::json!({
            "type": "object",
            "properties": { "pool": { "type": "string" }, "count": 3 }
        });
        assert!(apply_hints(&mut schema, "/properties/pool", &MINIMAL));
        assert_eq!(
            schema
                .pointer("/properties/pool/x-detent/group")
                .and_then(|v| v.as_str()),
            Some("basic")
        );
        assert!(!apply_hints(&mut schema, "/properties/missing", &MINIMAL));
        assert!(!apply_hints(&mut schema, "/properties/count", &MINIMAL));
    }
}
