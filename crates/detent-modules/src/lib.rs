//! Facade: registry of enabled modules (cfg(feature) per module).
//!
//! Module enablement is explicit code under `cfg(feature)` — no link-time
//! registration magic (`inventory`, `linkme`), so a build contains exactly the
//! modules its features name and nothing is registered by accident (PLAN §2.2,
//! ADR-004).
//!
//! Every module contributes one constructor returning `Vec<Box<dyn DynModule>>`,
//! in two `cfg`-gated halves: the adapter when its feature is on, empty when it is
//! not. [`modules`] flattens them. Adding a module means adding one constructor
//! pair and one array element.
//!
//! The halves return a `Vec` rather than an `Option` so that neither half trips a
//! lint in either configuration: `Option` makes the enabled half
//! `clippy::unnecessary_wraps`, and pushing under `#[cfg]` into a local makes the
//! binding `unused_mut` in a build with no modules at all.

use detent_core::module::DynModule;

/// The `hosts` module, because `module-hosts` is enabled.
#[cfg(feature = "module-hosts")]
fn hosts() -> Vec<Box<dyn DynModule>> {
    vec![Box::new(detent_core::module::Dyn::<
        detent_module_hosts::HostsModule,
    >::new())]
}

/// Nothing, because `module-hosts` is disabled.
#[cfg(not(feature = "module-hosts"))]
fn hosts() -> Vec<Box<dyn DynModule>> {
    Vec::new()
}

// `module-resolver`, `module-chrony`, `module-mounts`, `module-nfs`,
// `module-samba`, `module-dhcp` and `module-network` are all wired as far as
// the feature flag and the (currently empty) crate: see
// `crates/detent-modules/Cargo.toml`. None has a constructor pair here yet
// because none has a `ConfigModule` impl yet (PLAN §2.3 Appendix A) — add one
// alongside its module crate, following the `hosts()` shape above.

/// The modules this build was compiled with, in registry order.
#[must_use]
pub fn modules() -> Vec<Box<dyn DynModule>> {
    [hosts()].into_iter().flatten().collect()
}

#[cfg(test)]
mod tests {
    use super::modules;
    use std::collections::BTreeSet;

    #[test]
    fn ids_are_unique() {
        let registry = modules();
        let ids: BTreeSet<&str> = registry.iter().map(|m| m.id()).collect();
        assert_eq!(ids.len(), registry.len());
    }

    #[cfg(feature = "module-hosts")]
    #[test]
    fn hosts_is_registered_and_speaks_json() {
        let registry = modules();
        let found = registry.iter().find(|m| m.id() == "hosts");
        assert!(
            found.is_some(),
            "module-hosts is enabled but `hosts` is not in the registry"
        );
        let Some(module) = found else { return };
        assert_eq!(module.descriptor().id, "hosts");
        assert!(!module.schema_json().is_null());
        assert_eq!(
            module
                .parse_to_model_json("127.0.0.1\tlocalhost\n")
                .ok()
                .as_ref()
                .and_then(|v| v.pointer("/entries/0/hostnames/0"))
                .and_then(|v| v.as_str()),
            Some("localhost")
        );
    }

    #[cfg(not(feature = "module-hosts"))]
    #[test]
    fn the_registry_is_empty_without_any_module_feature() {
        assert!(modules().is_empty());
    }
}
