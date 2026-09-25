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

/// The `resolver` module, because `module-resolver` is enabled.
#[cfg(feature = "module-resolver")]
fn resolver() -> Vec<Box<dyn DynModule>> {
    vec![Box::new(detent_core::module::Dyn::<
        detent_module_resolver::ResolverModule,
    >::new())]
}

/// Nothing, because `module-resolver` is disabled.
#[cfg(not(feature = "module-resolver"))]
fn resolver() -> Vec<Box<dyn DynModule>> {
    Vec::new()
}

/// The `chrony` module, because `module-chrony` is enabled.
#[cfg(feature = "module-chrony")]
fn chrony() -> Vec<Box<dyn DynModule>> {
    vec![Box::new(detent_core::module::Dyn::<
        detent_module_chrony::ChronyModule,
    >::new())]
}

/// Nothing, because `module-chrony` is disabled.
#[cfg(not(feature = "module-chrony"))]
fn chrony() -> Vec<Box<dyn DynModule>> {
    Vec::new()
}

/// The `mounts` module, because `module-mounts` is enabled.
#[cfg(feature = "module-mounts")]
fn mounts() -> Vec<Box<dyn DynModule>> {
    vec![Box::new(detent_core::module::Dyn::<
        detent_module_mounts::MountsModule,
    >::new())]
}

/// Nothing, because `module-mounts` is disabled.
#[cfg(not(feature = "module-mounts"))]
fn mounts() -> Vec<Box<dyn DynModule>> {
    Vec::new()
}

/// The `nfs` module, because `module-nfs` is enabled.
#[cfg(feature = "module-nfs")]
fn nfs() -> Vec<Box<dyn DynModule>> {
    vec![Box::new(detent_core::module::Dyn::<
        detent_module_nfs::NfsModule,
    >::new())]
}

/// Nothing, because `module-nfs` is disabled.
#[cfg(not(feature = "module-nfs"))]
fn nfs() -> Vec<Box<dyn DynModule>> {
    Vec::new()
}

/// The `samba` module, because `module-samba` is enabled.
#[cfg(feature = "module-samba")]
fn samba() -> Vec<Box<dyn DynModule>> {
    vec![Box::new(detent_core::module::Dyn::<
        detent_module_samba::SambaModule,
    >::new())]
}

/// Nothing, because `module-samba` is disabled.
#[cfg(not(feature = "module-samba"))]
fn samba() -> Vec<Box<dyn DynModule>> {
    Vec::new()
}

/// The `dhcp` module, because `module-dhcp` is enabled.
#[cfg(feature = "module-dhcp")]
fn dhcp() -> Vec<Box<dyn DynModule>> {
    vec![Box::new(detent_core::module::Dyn::<
        detent_module_dhcp::DhcpModule,
    >::new())]
}

/// Nothing, because `module-dhcp` is disabled.
#[cfg(not(feature = "module-dhcp"))]
fn dhcp() -> Vec<Box<dyn DynModule>> {
    Vec::new()
}

/// The `network` module, because `module-network` is enabled.
#[cfg(feature = "module-network")]
fn network() -> Vec<Box<dyn DynModule>> {
    vec![Box::new(detent_core::module::Dyn::<
        detent_module_network::NetworkModule,
    >::new())]
}

/// Nothing, because `module-network` is disabled.
#[cfg(not(feature = "module-network"))]
fn network() -> Vec<Box<dyn DynModule>> {
    Vec::new()
}

/// The modules this build was compiled with, in registry order.
#[must_use]
pub fn modules() -> Vec<Box<dyn DynModule>> {
    [
        hosts(),
        resolver(),
        chrony(),
        mounts(),
        nfs(),
        samba(),
        dhcp(),
        network(),
    ]
    .into_iter()
    .flatten()
    .collect()
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

    #[cfg(feature = "module-resolver")]
    #[test]
    fn resolver_is_registered_and_speaks_json() {
        let registry = modules();
        let found = registry.iter().find(|m| m.id() == "resolver");
        assert!(
            found.is_some(),
            "module-resolver is enabled but `resolver` is not in the registry"
        );
        let Some(module) = found else { return };
        assert_eq!(module.descriptor().id, "resolver");
        assert!(!module.schema_json().is_null());
        assert_eq!(
            module
                .parse_to_model_json("nameserver 192.0.2.1\n")
                .ok()
                .as_ref()
                .and_then(|v| v.pointer("/resolv/0/nameserver/ip"))
                .and_then(|v| v.as_str()),
            Some("192.0.2.1")
        );
    }

    #[cfg(feature = "module-chrony")]
    #[test]
    fn chrony_is_registered_and_speaks_json() {
        let registry = modules();
        let found = registry.iter().find(|m| m.id() == "chrony");
        assert!(
            found.is_some(),
            "module-chrony is enabled but `chrony` is not in the registry"
        );
        let Some(module) = found else { return };
        assert_eq!(module.descriptor().id, "chrony");
        assert!(!module.schema_json().is_null());
        assert_eq!(
            module
                .parse_to_model_json("pool time.cloudflare.com iburst nts\n")
                .ok()
                .as_ref()
                .and_then(|v| v.pointer("/settings/0/key"))
                .and_then(|v| v.as_str()),
            Some("pool")
        );
    }

    #[cfg(feature = "module-mounts")]
    #[test]
    fn mounts_is_registered_and_speaks_json() {
        let registry = modules();
        let found = registry.iter().find(|m| m.id() == "mounts");
        assert!(
            found.is_some(),
            "module-mounts is enabled but `mounts` is not in the registry"
        );
        let Some(module) = found else { return };
        assert_eq!(module.descriptor().id, "mounts");
        assert!(!module.schema_json().is_null());
        assert_eq!(
            module
                .parse_to_model_json("UUID=x / ext4 defaults 0 1\n")
                .ok()
                .as_ref()
                .and_then(|v| v.pointer("/entries/0/fstype"))
                .and_then(|v| v.as_str()),
            Some("ext4")
        );
    }

    #[cfg(feature = "module-nfs")]
    #[test]
    fn nfs_is_registered_and_speaks_json() {
        let registry = modules();
        let found = registry.iter().find(|m| m.id() == "nfs");
        assert!(
            found.is_some(),
            "module-nfs is enabled but `nfs` is not in the registry"
        );
        let Some(module) = found else { return };
        assert_eq!(module.descriptor().id, "nfs");
        assert!(!module.schema_json().is_null());
        assert_eq!(
            module
                .parse_to_model_json("/srv/nfs4 192.168.1.0/24(rw,sync)\n")
                .ok()
                .as_ref()
                .and_then(|v| v.pointer("/entries/0/clients/0/host"))
                .and_then(|v| v.as_str()),
            Some("192.168.1.0/24")
        );
    }

    #[cfg(feature = "module-samba")]
    #[test]
    fn samba_is_registered_and_speaks_json() {
        let registry = modules();
        let found = registry.iter().find(|m| m.id() == "samba");
        assert!(
            found.is_some(),
            "module-samba is enabled but `samba` is not in the registry"
        );
        let Some(module) = found else { return };
        assert_eq!(module.descriptor().id, "samba");
        assert!(!module.schema_json().is_null());
        assert_eq!(
            module
                .parse_to_model_json("[global]\n   guest ok = yes\n")
                .ok()
                .as_ref()
                .and_then(|v| v.pointer("/entries/1/key"))
                .and_then(|v| v.as_str()),
            Some("guest ok")
        );
    }
    #[cfg(feature = "module-dhcp")]
    #[test]
    fn dhcp_is_registered_and_speaks_json() {
        let registry = modules();
        let found = registry.iter().find(|m| m.id() == "dhcp");
        assert!(
            found.is_some(),
            "module-dhcp is enabled but `dhcp` is not in the registry"
        );
        let Some(module) = found else { return };
        assert_eq!(module.descriptor().id, "dhcp");
        assert!(!module.schema_json().is_null());
        assert_eq!(
            module
                .parse_to_model_json("domain-needed\ninterface=eth0\n")
                .ok()
                .as_ref()
                .and_then(|v| v.pointer("/dnsmasq/0/key"))
                .and_then(|v| v.as_str()),
            Some("domain-needed")
        );
    }

    #[cfg(feature = "module-network")]
    #[allow(clippy::redundant_closure_for_method_calls)]
    #[test]
    fn network_is_registered_and_speaks_json() {
        let registry = modules();
        let found = registry.iter().find(|m| m.id() == "network");
        assert!(
            found.is_some(),
            "module-network is enabled but `network` is not in the registry"
        );
        let Some(module) = found else { return };
        assert_eq!(module.descriptor().id, "network");
        assert!(!module.schema_json().is_null());
        assert_eq!(
            module
                .parse_to_model_json("[Match]\nName=eth0\n\n[Network]\nDHCP=yes\n")
                .ok()
                .as_ref()
                .and_then(|v| v.pointer("/interfaces/0/dhcp_v4"))
                .and_then(|v| v.as_bool()),
            Some(true)
        );
    }

    #[cfg(not(any(
        feature = "module-hosts",
        feature = "module-resolver",
        feature = "module-chrony",
        feature = "module-mounts",
        feature = "module-nfs",
        feature = "module-samba",
        feature = "module-dhcp",
        feature = "module-network"
    )))]
    #[test]
    fn the_registry_is_empty_without_any_module_feature() {
        assert!(modules().is_empty());
    }
}
