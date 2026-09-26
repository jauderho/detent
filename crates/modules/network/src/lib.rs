// Copyright (c) 2026 The Detent Authors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! The `network` module: interface configuration across four backends.
//!
//! Four backends, one backend-neutral model (PLAN §7 network row, §2.3):
//!
//! * **systemd-networkd** — INI `.network`/`.netdev` plus drop-ins under
//!   `/etc/systemd/network`. Sections `[Match]`/`[Network]`/`[Address]`/
//!   `[Route]`/`[VLAN]` with `key=value` directives.
//! * **`NetworkManager`** — keyfiles `*.nmconnection` INI under
//!   `/etc/NetworkManager/system-connections` (`0600`), sections
//!   `[connection]`/`[ethernet]`/`[ipv4]`/`[ipv6]` with `key=value`.
//! * **ifupdown** — stanzas `auto <iface>` and `iface <name> inet <method>`
//!   with indented options, `source-directory interfaces.d`.
//! * **netplan** — YAML under `/etc/netplan` (`0600`). A lossless
//!   line-oriented CST with an indent stack mapping key-paths to line ranges.
//!
//! # What a line can be
//!
//! For every backend a line is `Blank` (empty/whitespace), `Comment` (`#` or
//! `;` after optional whitespace, and for ifupdown/netplan also YAML `#`),
//! `Directive` when any backend's parser accepts it, or `Unknown` otherwise.
//! `Directive` means exactly `parse_entry` succeeds (invariant 2).
//!
//! Anything outside the modeled subset — an unrecognized section, an unknown
//! key, an unmodeled YAML subtree, a continuation line, a malformed directive
//! — stays `Unknown` and is copied through an edit byte for byte. The `Doc`
//! owns that text, the `Model` never duplicates it (PLAN §7: "unsupported
//! constructs remain preserved-but-opaque").
//!
//! # Netplan YAML subset — line-oriented CST with indent-stack preservation
//!
//! The YAML handled here is the narrow subset netplan actually emits:
//!
//! * nested maps via `key:` lines with increasing indent (2 spaces per level
//!   in the canonical rendering, any indent accepted on input),
//! * inline flow lists `key: [a, b]`,
//! * block lists `- value` and `- key: value` at deeper indent,
//! * `#` comments and blank lines.
//!
//! Unknown subtrees — any map/list branch whose key-path is not in the
//! modeled set (`network.ethernets.<iface>.{dhcp4,dhcp6,addresses,gateway4,
//! gateway6,nameservers.addresses,routes}`, `network.vlans.<iface>.{id,link}`,
//! `network.bridges.<iface>.interfaces`) — are left `Unknown` by the
//! classifier and therefore preserved byte-identical. Anchors (`&`/`*`),
//! `!` tags and `|`/`>` literals are not parsed and are likewise `Unknown`.
//!
//! # Formatting policy
//!
//! A `Directive` line whose parsed entry already equals the model's entry is
//! left byte for byte alone, so hand alignment and odd spacing survive. Only
//! changed lines are re-rendered canonically:
//!
//! * networkd: `Key=Value` with no spaces,
//! * `NetworkManager`: `key=value`,
//! * ifupdown: `iface <name> inet <method>` and indented `<key> <value>`,
//! * netplan: `key: value` at the indent implied by its key-path, block lists
//!   as `- to: …`/`via: …` under `routes:`.
//!
//! # No I/O
//!
//! Like every module crate this one is pure: fixtures used by its tests are
//! `include_str!`ed, nothing is read from disk at run time. `detent-platform`
//! owns every file operation (PLAN §2.1).

use detent_core::align::{Step, align, replace_all};
use detent_core::descriptor::{
    ArgTemplate, CheckExpectation, ExternalCheck, FieldHints, HostProfile, ModuleDescriptor, Os,
    Owner, PathSpec, SecurityImpact, ServiceAction, ServiceBinding, Target, TargetKind, UiGroup,
    UnitNames, Upstream, ValidationCtx, apply_hints,
};
use detent_core::diag::{Diagnostic, Diagnostics, FieldPath, MessageId, Severity};
use detent_core::doc::{Document, EntryPlan, LineKind};
use detent_core::module::{ConfigModule, EditError, EditReport, ModelError, ParseError};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

// ------------------------------------------------------------------------- model

/// One static route.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(deny_unknown_fields)]
pub struct Route {
    /// Destination CIDR, e.g. `10.0.0.0/24` or `default`.
    pub to: String,
    /// Next-hop IP.
    pub via: String,
}

/// One VLAN interface.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(deny_unknown_fields)]
pub struct Vlan {
    /// Parent link name, e.g. `eth0`.
    pub link: String,
    /// VLAN id, 1–4094.
    pub id: u16,
}

/// One bridge interface.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(deny_unknown_fields)]
pub struct Bridge {
    /// Member interface names.
    pub members: Vec<String>,
}

/// One network interface.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(deny_unknown_fields)]
pub struct Interface {
    /// Interface name, e.g. `eth0`.
    pub name: String,
    /// Whether `DHCPv4` is enabled.
    pub dhcp_v4: bool,
    /// Whether `DHCPv6` is enabled.
    pub dhcp_v6: bool,
    /// Static addresses in CIDR notation.
    pub addresses: Vec<String>,
    /// Default gateway for `IPv4`, when statically addressed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_v4: Option<String>,
    /// Default gateway for `IPv6`, when statically addressed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_v6: Option<String>,
    /// DNS servers.
    pub dns: Vec<String>,
    /// Static routes.
    pub routes: Vec<Route>,
    /// VLAN settings, when this interface is a `VLAN`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vlan: Option<Vlan>,
    /// Bridge settings, when this interface is a bridge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge: Option<Bridge>,
}

/// The backend-neutral model: interfaces the UI edits.
#[derive(
    Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(deny_unknown_fields)]
pub struct Model {
    /// Interfaces, in file order.
    pub interfaces: Vec<Interface>,
}

// ------------------------------------------------------------ parsing / rendering

/// Whether `c` starts a comment line (tolerates `#` and `;` for INI/YAML).
fn is_comment_start(raw: &str) -> bool {
    let t = raw.trim_start();
    t.starts_with('#') || t.starts_with(';')
}

/// Parse a `Key=Value` INI line (networkd / `NetworkManager` style).
fn parse_kv_equals(raw: &str) -> Option<(String, String)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || is_comment_start(trimmed) || trimmed.starts_with('[') {
        return None;
    }
    let (k, v) = trimmed.split_once('=')?;
    let key = k.trim();
    let value = v.trim();
    if key.is_empty() || key.contains(char::is_whitespace) {
        return None;
    }
    Some((key.to_owned(), value.to_owned()))
}

/// Parse an INI section header `[Name]`.
fn parse_section(raw: &str) -> Option<String> {
    let t = raw.trim();
    let inner = t.strip_prefix('[').and_then(|s| s.strip_suffix(']'))?;
    let inner = inner.trim();
    if inner.is_empty() {
        return None;
    }
    Some(inner.to_owned())
}

/// Whether a key is a known networkd directive.
fn is_networkd_key(key: &str) -> bool {
    matches!(
        key,
        "Name"
            | "DHCP"
            | "Address"
            | "Gateway"
            | "DNS"
            | "Destination"
            | "Id"
            | "Kind"
            | "VLAN"
            | "Bridge"
    )
}

/// Whether a section is a known networkd section.
fn is_networkd_section(section: &str) -> bool {
    matches!(
        section,
        "Match" | "Network" | "Address" | "Route" | "VLAN" | "NetDev"
    )
}

/// Whether a key is a known `NetworkManager` key.
fn is_nm_key(key: &str) -> bool {
    matches!(
        key,
        "id" | "type"
            | "method"
            | "addresses"
            | "gateway"
            | "dns"
            | "interface-name"
            | "master"
            | "slave-type"
            | "parent"
    )
}

/// Whether a section is a known `NetworkManager` section.
fn is_nm_section(section: &str) -> bool {
    matches!(
        section,
        "connection" | "ethernet" | "ipv4" | "ipv6" | "bridge" | "vlan" | "wifi"
    )
}

/// Parse an ifupdown `auto <iface>` line.
fn parse_ifupdown_auto(raw: &str) -> Option<String> {
    let t = raw.trim();
    let rest = t.strip_prefix("auto")?;
    if rest.is_empty() || !rest.starts_with(char::is_whitespace) {
        return None;
    }
    let name = rest.trim();
    if name.is_empty() || name.contains(char::is_whitespace) {
        return None;
    }
    Some(name.to_owned())
}

/// Parse an ifupdown `iface <name> inet <method>` line.
fn parse_ifupdown_iface(raw: &str) -> Option<(String, String)> {
    let t = raw.trim();
    let rest = t.strip_prefix("iface")?;
    if rest.is_empty() || !rest.starts_with(char::is_whitespace) {
        return None;
    }
    let mut parts = rest.split_whitespace();
    let name = parts.next()?;
    let inet = parts.next()?;
    if inet != "inet" && inet != "inet6" {
        return None;
    }
    let method = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    Some((name.to_owned(), method.to_owned()))
}

/// Parse an ifupdown indented option line (must be indented).
fn parse_ifupdown_option(raw: &str) -> Option<(String, String)> {
    if raw.is_empty() || !raw.starts_with(char::is_whitespace) {
        return None;
    }
    let t = raw.trim();
    if t.is_empty() || is_comment_start(t) {
        return None;
    }
    if t.starts_with("auto") || t.starts_with("iface") || t.starts_with("source") {
        return None;
    }
    let mut parts = t.splitn(2, char::is_whitespace);
    let key = parts.next()?;
    let value = parts.next().unwrap_or("").trim();
    // Only known ifupdown option keys are Directives; unknown indented keys stay Unknown.
    if !matches!(
        key,
        "address"
            | "netmask"
            | "gateway"
            | "dns-nameservers"
            | "dns-nameserver"
            | "vlan-raw-device"
            | "vlan_id"
            | "bridge_ports"
            | "bridge-ports"
            | "up"
            | "mtu"
    ) {
        return None;
    }
    Some((key.to_owned(), value.to_owned()))
}

/// Whether a line is an ifupdown `source` / `source-directory` directive.
fn is_ifupdown_source(raw: &str) -> bool {
    let t = raw.trim();
    t.starts_with("source ") || t.starts_with("source-directory ")
}

/// Count leading spaces (tabs count as 2).
fn indent_of(raw: &str) -> usize {
    raw.chars()
        .take_while(|c| *c == ' ' || *c == '\t')
        .map(|c| if c == '\t' { 2 } else { 1 })
        .sum()
}

/// Parse a netplan YAML `key: value` line (with optional indent).
fn parse_netplan_kv(raw: &str) -> Option<(usize, String, String)> {
    let indent = indent_of(raw);
    let t = raw.trim();
    if t.is_empty() || is_comment_start(t) || t.starts_with('-') {
        return None;
    }
    // Flow-list values contain `:` inside brackets — but netplan's `addresses:`
    // inline form is `addresses: [10.0.0.1/24]`; we still split on first `:`.
    let colon = t.find(':')?;
    let key = t[..colon].trim();
    let value = t
        .get(colon.saturating_add(1)..)
        .unwrap_or("")
        .trim()
        .to_owned();
    let value = value.as_str();
    if key.is_empty() || key.contains(char::is_whitespace) || key.contains('/') {
        return None;
    }
    // Only known netplan keys at known paths are Directives; check via key name.
    // Top-level `network:` and second-level `ethernets:`/`vlans:`/`bridges:` and
    // per-iface leaves are the modeled subset; everything else stays Unknown.
    let known_leaves = [
        "network",
        "version",
        "ethernets",
        "vlans",
        "bridges",
        "dhcp4",
        "dhcp6",
        "addresses",
        "gateway4",
        "gateway6",
        "nameservers",
        "routes",
        "to",
        "via",
        "id",
        "link",
        "interfaces",
        "optional",
    ];
    if !known_leaves.contains(&key) && !value.is_empty() {
        // Unknown keys with a value stay opaque (Unknown) and are preserved byte-identical.
        // Map keys with empty value like 'eth0:' under ethernets/vlans/bridges are interface names.
        return None;
    }
    // Reject anchors/tags/literals that would be opaque subtrees.
    if value.starts_with('&') || value.starts_with('*') || value.starts_with('!') {
        return None;
    }
    Some((indent, key.to_owned(), value.to_owned()))
}

/// Parse a netplan block-list item `- ...` (with indent).
fn parse_netplan_list_item(raw: &str) -> Option<(usize, String)> {
    let indent = indent_of(raw);
    let t = raw.trim();
    if !t.starts_with("- ") && t != "-" {
        return None;
    }
    let value = t.strip_prefix("- ").unwrap_or("").trim().to_owned();
    // Reject opaque values.
    if value.starts_with('&') || value.starts_with('*') || value.starts_with('!') {
        return None;
    }
    // List items under unknown parents stay Unknown — but we classify them as
    // Directive only when they look like CIDR/IP/route fragments.
    // Keep the check loose: any non-empty value that is not a comment.
    if value.is_empty() {
        return Some((indent, String::new()));
    }
    Some((indent, value))
}

/// Unified classifier: `Directive` when any backend accepts the line.
fn classify(raw: &str) -> LineKind {
    if raw.trim().is_empty() {
        return LineKind::Blank;
    }
    if is_comment_start(raw) {
        return LineKind::Comment;
    }
    // INI section headers — only known sections are Directive, unknown stay Unknown.
    if let Some(section) = parse_section(raw) {
        if is_networkd_section(&section) || is_nm_section(&section) {
            return LineKind::Directive;
        }
        return LineKind::Unknown;
    }
    // INI key=value — only known keys are Directive.
    if let Some((k, _)) = parse_kv_equals(raw) {
        if is_networkd_key(&k) || is_nm_key(&k) {
            return LineKind::Directive;
        }
        return LineKind::Unknown;
    }
    // ifupdown stanzas
    if parse_ifupdown_auto(raw).is_some()
        || parse_ifupdown_iface(raw).is_some()
        || parse_ifupdown_option(raw).is_some()
        || is_ifupdown_source(raw)
    {
        return LineKind::Directive;
    }
    // netplan YAML
    if parse_netplan_kv(raw).is_some() || parse_netplan_list_item(raw).is_some() {
        return LineKind::Directive;
    }
    LineKind::Unknown
}

/// Whether a line is a parsable directive (for `to_model`/`apply`).
fn is_directive_like(raw: &str) -> bool {
    classify(raw) == LineKind::Directive
}

/// Strip inline `addresses: [a, b]` brackets into a vec.
#[allow(clippy::assigning_clones)]
fn parse_inline_list(value: &str) -> Option<Vec<String>> {
    let t = value.trim();
    if let Some(inner) = t.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        if inner.trim().is_empty() {
            return Some(Vec::new());
        }
        return Some(
            inner
                .split(',')
                .map(|s| s.trim().trim_matches('"').trim_matches('\'').to_owned())
                .filter(|s| !s.is_empty())
                .collect(),
        );
    }
    None
}

/// Build the model from a document by scanning directive lines and updating
/// interface builders in file order. Each backend's syntax contributes to the
/// same `BTreeMap<name, Interface>` so mixed-backend files merge.
#[allow(
    clippy::too_many_lines,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::assigning_clones
)]
fn build_model_from_lines(lines: &[String]) -> Model {
    let mut ifaces: BTreeMap<String, Interface> = BTreeMap::new();
    let mut current_iface: Option<String> = None;
    let mut current_section: String = String::new();
    let mut netplan_stack: Vec<(usize, String)> = Vec::new();
    let mut netplan_iface: Option<String> = None;
    let mut netplan_pending_route_to: Option<String> = None;
    let mut i = 0usize;
    while i < lines.len() {
        let raw = &lines[i];
        // Track netplan indent stack for key-path.
        if let Some((indent, key, value)) = parse_netplan_kv(raw) {
            while netplan_stack.last().is_some_and(|(d, _)| *d >= indent) {
                netplan_stack.pop();
            }
            netplan_stack.push((indent, key.clone()));
            let path: Vec<String> = netplan_stack.iter().map(|(_, k)| k.clone()).collect();
            // `network:` top
            if path == ["network"] {
                // nothing
            } else if path.len() >= 3 && path[0] == "network" {
                let collection = &path[1];
                if path.len() == 3
                    && (collection == "ethernets"
                        || collection == "vlans"
                        || collection == "bridges")
                {
                    // New interface under this collection
                    let iface = key.clone();
                    netplan_iface = Some(iface.clone());
                    ifaces.entry(iface.clone()).or_insert_with(|| Interface {
                        name: iface.clone(),
                        dhcp_v4: false,
                        dhcp_v6: false,
                        addresses: Vec::new(),
                        gateway_v4: None,
                        gateway_v6: None,
                        dns: Vec::new(),
                        routes: Vec::new(),
                        vlan: None,
                        bridge: None,
                    });
                } else if let Some(iface_name) = netplan_iface.clone()
                    && let Some(entry) = ifaces.get_mut(&iface_name)
                {
                    // Leaf under an interface; the interface was created above
                    // when `netplan_iface` was set, so the entry always exists.
                    let leaf = key.as_str();
                    match leaf {
                        "dhcp4" => {
                            entry.dhcp_v4 = value == "true" || value == "yes";
                        }
                        "dhcp6" => {
                            entry.dhcp_v6 = value == "true" || value == "yes";
                        }
                        "gateway4" if !value.is_empty() => {
                            entry.gateway_v4 = Some(value.clone());
                        }
                        "gateway6" if !value.is_empty() => {
                            entry.gateway_v6 = Some(value.clone());
                        }
                        "addresses" => {
                            if let Some(list) = parse_inline_list(&value) {
                                // `nameservers: {addresses: [...]}` is DNS, not
                                // interface addresses.
                                if path.len() >= 2 && path[path.len() - 2] == "nameservers" {
                                    entry.dns.extend(list);
                                } else {
                                    entry.addresses.extend(list);
                                }
                            } else if !value.is_empty() && !value.starts_with('[') {
                                entry.addresses.push(value.clone());
                            }
                        }
                        "id" => {
                            if let Ok(id) = value.parse::<u16>() {
                                let link = entry
                                    .vlan
                                    .as_ref()
                                    .map(|v| v.link.clone())
                                    .unwrap_or_default();
                                entry.vlan = Some(Vlan { link, id });
                            }
                        }
                        "link" if !value.is_empty() => {
                            let id = entry.vlan.as_ref().map_or(0, |v| v.id);
                            entry.vlan = Some(Vlan {
                                link: value.clone(),
                                id,
                            });
                        }
                        "interfaces" => {
                            if let Some(list) = parse_inline_list(&value) {
                                entry.bridge = Some(Bridge { members: list });
                            }
                        }
                        _ => {}
                    }
                }
            }
            // Handle netplan nameservers.addresses inline
            if path.last().is_some_and(|k| k == "nameservers")
                && !value.is_empty()
                && let Some(list) = parse_inline_list(&value)
                && let Some(iface_name) = netplan_iface.clone()
                && let Some(entry) = ifaces.get_mut(&iface_name)
            {
                entry.dns.extend(list);
            }
            i += 1;
            continue;
        }
        if let Some((indent, value)) = parse_netplan_list_item(raw) {
            // Determine parent key via stack top.
            let parent = netplan_stack.last().map_or("", |(_, k)| k.as_str());
            if parent == "addresses" {
                if let Some(iface_name) = netplan_iface.clone()
                    && let Some(entry) = ifaces.get_mut(&iface_name)
                    && !value.is_empty()
                {
                    if netplan_stack
                        .iter()
                        .rev()
                        .nth(1)
                        .is_some_and(|(_, key)| key == "nameservers")
                    {
                        entry.dns.push(value);
                    } else {
                        entry.addresses.push(value);
                    }
                }
            } else if parent == "routes" {
                // `- to: ...` or `- via: ...` or `- to: ... via: ...` simplified:
                // Look ahead: value may be `to: 10.0.0.0/24` etc.
                if value.starts_with("to:") {
                    let to = value.strip_prefix("to:").unwrap_or("").trim().to_owned();
                    // Next line may be `via: ...` at deeper indent.
                    if i + 1 < lines.len()
                        && let Some((next_indent, k, v)) = parse_netplan_kv(&lines[i + 1])
                        && k == "via"
                        && next_indent > indent
                    {
                        netplan_pending_route_to = Some(to.clone());
                        // Consume the via line
                        i += 1;
                        if let Some(iface_name) = netplan_iface.clone()
                            && let Some(entry) = ifaces.get_mut(&iface_name)
                        {
                            entry.routes.push(Route { to, via: v });
                        }
                        i += 1;
                        continue;
                    }
                    // Single-line route with only `to:`
                    netplan_pending_route_to = Some(to);
                } else if value.starts_with("via:")
                    && let Some(to) = netplan_pending_route_to.take()
                {
                    let via = value.strip_prefix("via:").unwrap_or("").trim().to_owned();
                    if let Some(iface_name) = netplan_iface.clone()
                        && let Some(entry) = ifaces.get_mut(&iface_name)
                    {
                        // Replace last route's via if it was pending
                        if let Some(last) = entry.routes.last_mut() {
                            if last.to == to && last.via.is_empty() {
                                last.via = via;
                            } else {
                                entry.routes.push(Route { to, via });
                            }
                        } else {
                            entry.routes.push(Route { to, via });
                        }
                    }
                }
            } else if parent == "nameservers" {
                // nameservers block list — not modeled separately, treat as dns
                if let Some(iface_name) = netplan_iface.clone()
                    && let Some(entry) = ifaces.get_mut(&iface_name)
                    && !value.is_empty()
                {
                    entry.dns.push(value.clone());
                }
            }
            // Also handle `  - addresses:` nested — ignore
            i += 1;
            continue;
        }

        // INI section header
        if let Some(section) = parse_section(raw) {
            current_section = section.clone();
            // Reset netplan stack when leaving YAML context? Keep separate.
            i += 1;
            continue;
        }
        // INI key=value
        if let Some((k, v)) = parse_kv_equals(raw) {
            // NetworkManager `id=` under `[connection]` introduces interface
            if current_section == "connection" && k == "id" && !v.is_empty() {
                current_iface = Some(v.clone());
                ifaces.entry(v.clone()).or_insert_with(|| Interface {
                    name: v.clone(),
                    dhcp_v4: false,
                    dhcp_v6: false,
                    addresses: Vec::new(),
                    gateway_v4: None,
                    gateway_v6: None,
                    dns: Vec::new(),
                    routes: Vec::new(),
                    vlan: None,
                    bridge: None,
                });
            } else if k == "Name" && current_section == "Match" && !v.is_empty() {
                current_iface = Some(v.clone());
                ifaces.entry(v.clone()).or_insert_with(|| Interface {
                    name: v.clone(),
                    dhcp_v4: false,
                    dhcp_v6: false,
                    addresses: Vec::new(),
                    gateway_v4: None,
                    gateway_v6: None,
                    dns: Vec::new(),
                    routes: Vec::new(),
                    vlan: None,
                    bridge: None,
                });
            } else if let Some(iface_name) = current_iface.clone()
                && let Some(entry) = ifaces.get_mut(&iface_name)
            {
                // The interface was created when `current_iface` was set, so
                // the entry always exists.
                match k.as_str() {
                    "DHCP" => {
                        let low = v.to_ascii_lowercase();
                        entry.dhcp_v4 = low == "yes" || low == "ipv4" || low == "true";
                        entry.dhcp_v6 = low == "yes" || low == "ipv6" || low == "true";
                        if low == "ipv4" {
                            entry.dhcp_v6 = false;
                        } else if low == "ipv6" {
                            entry.dhcp_v4 = false;
                        } else if low == "no" || low == "false" {
                            entry.dhcp_v4 = false;
                            entry.dhcp_v6 = false;
                        }
                    }
                    "Address" if !v.is_empty() => {
                        entry.addresses.push(v.clone());
                    }
                    "Gateway" if !v.is_empty() && current_section != "Route" => {
                        if v.contains(':') {
                            entry.gateway_v6 = Some(v.clone());
                        } else {
                            entry.gateway_v4 = Some(v.clone());
                        }
                    }
                    "DNS" if !v.is_empty() => {
                        for part in v.split([',', ' ']) {
                            let p = part.trim();
                            if !p.is_empty() {
                                entry.dns.push(p.to_owned());
                            }
                        }
                    }
                    "Destination" if current_section == "Route" && !v.is_empty() => {
                        // Start a new route; Gateway may follow
                        entry.routes.push(Route {
                            to: v.clone(),
                            via: String::new(),
                        });
                    }
                    "VLAN" if !v.is_empty() => {
                        if let Some((link, id)) = v.split_once(':')
                            && let Ok(id) = id.trim().parse::<u16>()
                        {
                            entry.vlan = Some(Vlan {
                                link: link.trim().to_owned(),
                                id,
                            });
                        }
                    }
                    "Id" if current_section == "VLAN" => {
                        if let Ok(id) = v.parse::<u16>() {
                            let link = entry
                                .vlan
                                .as_ref()
                                .map_or_else(|| iface_name.clone(), |x| x.link.clone());
                            entry.vlan = Some(Vlan { link, id });
                        }
                    }
                    // NetworkManager ipv4/ipv6
                    "method" if current_section == "ipv4" || current_section == "ipv6" => {
                        let is_v4 = current_section == "ipv4";
                        if v == "auto" {
                            if is_v4 {
                                entry.dhcp_v4 = true;
                            } else {
                                entry.dhcp_v6 = true;
                            }
                        } else if v == "manual" {
                            if is_v4 {
                                entry.dhcp_v4 = false;
                            } else {
                                entry.dhcp_v6 = false;
                            }
                        }
                    }
                    "addresses"
                        if (current_section == "ipv4" || current_section == "ipv6")
                            && !v.is_empty() =>
                    {
                        for part in v.split(';') {
                            let p = part.trim();
                            if p.is_empty() {
                                continue;
                            }
                            // NM stores `address/prefix,gateway`
                            let addr = p.split(',').next().unwrap_or("").trim();
                            if !addr.is_empty() {
                                entry.addresses.push(addr.to_owned());
                            }
                            if let Some(gw) = p.split(',').nth(1) {
                                let gw = gw.trim();
                                if !gw.is_empty() {
                                    if gw.contains(':') {
                                        entry.gateway_v6 = Some(gw.to_owned());
                                    } else {
                                        entry.gateway_v4 = Some(gw.to_owned());
                                    }
                                }
                            }
                        }
                    }
                    "gateway"
                        if (current_section == "ipv4" || current_section == "ipv6")
                            && !v.is_empty() =>
                    {
                        if v.contains(':') {
                            entry.gateway_v6 = Some(v.clone());
                        } else {
                            entry.gateway_v4 = Some(v.clone());
                        }
                    }
                    "dns"
                        if (current_section == "ipv4" || current_section == "ipv6")
                            && !v.is_empty() =>
                    {
                        for part in v.split(';') {
                            let p = part.trim();
                            if !p.is_empty() {
                                entry.dns.push(p.to_owned());
                            }
                        }
                    }
                    _ => {}
                }
                // For Route Gateway (networkd) — second key after Destination
                if k == "Gateway"
                    && current_section == "Route"
                    && let Some(last) = entry.routes.last_mut()
                    && last.via.is_empty()
                {
                    last.via = v.clone();
                }
            }
            i += 1;
            continue;
        }
        // ifupdown
        if let Some(name) = parse_ifupdown_auto(raw) {
            current_iface = Some(name.clone());
            ifaces.entry(name.clone()).or_insert_with(|| Interface {
                name: name.clone(),
                dhcp_v4: false,
                dhcp_v6: false,
                addresses: Vec::new(),
                gateway_v4: None,
                gateway_v6: None,
                dns: Vec::new(),
                routes: Vec::new(),
                vlan: None,
                bridge: None,
            });
            i += 1;
            continue;
        }
        if let Some((name, method)) = parse_ifupdown_iface(raw) {
            current_iface = Some(name.clone());
            let entry = ifaces.entry(name.clone()).or_insert_with(|| Interface {
                name: name.clone(),
                dhcp_v4: false,
                dhcp_v6: false,
                addresses: Vec::new(),
                gateway_v4: None,
                gateway_v6: None,
                dns: Vec::new(),
                routes: Vec::new(),
                vlan: None,
                bridge: None,
            });
            // `dhcp6`/`static`/`loopback` methods contribute nothing here.
            // `inet6 dhcp` enables IPv6 DHCP only; it does not clear an
            // earlier `inet dhcp` stanza for the same interface. The family
            // is the third word (the name may itself read `inet6`).
            if method == "dhcp" {
                if raw.split_whitespace().nth(2) == Some("inet6") {
                    entry.dhcp_v6 = true;
                } else {
                    entry.dhcp_v4 = true;
                }
            }
            i += 1;
            continue;
        }
        if let Some((k, v)) = parse_ifupdown_option(raw)
            && let Some(iface_name) = current_iface.clone()
            && let Some(entry) = ifaces.get_mut(&iface_name)
        {
            // The interface was created when `current_iface` was set, so the
            // entry always exists.
            match k.as_str() {
                "address" if !v.is_empty() => entry.addresses.push(v.clone()),
                "gateway" if !v.is_empty() => {
                    if v.contains(':') {
                        entry.gateway_v6 = Some(v.clone());
                    } else {
                        entry.gateway_v4 = Some(v.clone());
                    }
                }
                "dns-nameservers" | "dns-nameserver" if !v.is_empty() => {
                    for part in v.split_whitespace() {
                        entry.dns.push(part.to_owned());
                    }
                }
                "vlan-raw-device" if !v.is_empty() => {
                    let id = entry.vlan.as_ref().map_or(0, |x| x.id);
                    entry.vlan = Some(Vlan {
                        link: v.clone(),
                        id,
                    });
                }
                "vlan_id" => {
                    if let Ok(id) = v.parse::<u16>() {
                        let link = entry
                            .vlan
                            .as_ref()
                            .map_or_else(|| iface_name.clone(), |x| x.link.clone());
                        entry.vlan = Some(Vlan { link, id });
                    }
                }
                "bridge_ports" | "bridge-ports" if !v.is_empty() => {
                    let members = v.split_whitespace().map(str::to_owned).collect();
                    entry.bridge = Some(Bridge { members });
                }
                // Routes render as `up ip route add <to> via <via>`.
                "up" if !v.is_empty() => {
                    // Expected shape: `ip route add <to> via <via>`.
                    let words: Vec<&str> = v.split_whitespace().collect();
                    if words.len() >= 5
                        && words[0] == "ip"
                        && words[1] == "route"
                        && words[2] == "add"
                        && let Some(via_pos) = words.iter().position(|w| *w == "via")
                        && via_pos == words.len() - 2
                    {
                        let to = words[3..via_pos].join(" ");
                        let via = words[via_pos + 1].to_owned();
                        if !to.is_empty() && !via.is_empty() {
                            entry.routes.push(Route { to, via });
                        }
                    }
                }
                _ => {}
            }
            i += 1;
            continue;
        }
        if is_ifupdown_source(raw) {
            i += 1;
            continue;
        }
        i += 1;
    }
    let mut interfaces: Vec<Interface> = ifaces.into_values().collect();
    interfaces.sort_by(|a, b| a.name.cmp(&b.name));
    Model { interfaces }
}

/// Render the model losslessly per detected backend.
///
/// Detection: count directive flavors; majority wins, tie goes to networkd.
/// For an empty document or all-Unknown, render as networkd (the default).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackendFlavor {
    /// `systemd-networkd`.
    Networkd,
    /// `NetworkManager` keyfiles.
    NetworkManager,
    /// ifupdown.
    Ifupdown,
    /// netplan YAML.
    Netplan,
}

#[allow(clippy::arithmetic_side_effects)]
fn detect_flavor(doc: &Document) -> BackendFlavor {
    let mut networkd = 0usize;
    let mut nm = 0usize;
    let mut ifupdown = 0usize;
    let mut netplan = 0usize;
    for line in doc.lines() {
        if line.kind() != LineKind::Directive {
            continue;
        }
        let raw = line.raw();
        if let Some(s) = parse_section(raw) {
            if is_networkd_section(&s) {
                networkd += 1;
            } else if is_nm_section(&s) {
                nm += 1;
            }
        } else if let Some((k, _)) = parse_kv_equals(raw) {
            if is_networkd_key(&k) {
                networkd += 1;
            } else if is_nm_key(&k) {
                nm += 1;
            }
        } else if parse_ifupdown_auto(raw).is_some()
            || parse_ifupdown_iface(raw).is_some()
            || parse_ifupdown_option(raw).is_some()
            || is_ifupdown_source(raw)
        {
            ifupdown += 1;
        } else if parse_netplan_kv(raw).is_some() || parse_netplan_list_item(raw).is_some() {
            netplan += 1;
        }
    }
    let max = networkd.max(nm).max(ifupdown).max(netplan);
    if max == 0 {
        return BackendFlavor::Networkd;
    }
    if netplan == max {
        return BackendFlavor::Netplan;
    }
    if ifupdown == max {
        return BackendFlavor::Ifupdown;
    }
    if nm == max {
        return BackendFlavor::NetworkManager;
    }
    BackendFlavor::Networkd
}

/// Refuse a route that is not one destination and one next hop.
///
/// `to` must be `default`, a CIDR or an IP; `via` must be an IP, or empty
/// (a direct route) where `via_required` is false. Every renderer that writes a
/// route calls this first, so a value cannot carry backend syntax (`;`, `$()`,
/// `#`, whitespace, `"`, `[`, `=`) into the file even when the model was never
/// validated.
fn check_route(route: &Route, via_required: bool) -> Result<(), EditError> {
    let to_ok = route.to == "default" || is_valid_cidr(&route.to) || is_valid_ip(&route.to);
    let via_ok = is_valid_ip(&route.via) || (!via_required && route.via.is_empty());
    if to_ok && via_ok {
        return Ok(());
    }
    Err(EditError::Unsupported {
        message: format!(
            "route {:?} via {:?} is not a destination and a next-hop address",
            route.to, route.via
        ),
    })
}

/// Whether `s` is an interface name every backend reads back as one token:
/// ASCII letters, digits, `-`, `_` and `.` only.
fn is_valid_ifname(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// Refuse an interface value that is not its field's syntax, so no backend
/// file receives a name, address, gateway or DNS server carrying `#`, `;`,
/// `:`, whitespace, `"`, `[`, `]`, `=` or `,`.
fn check_interface(iface: &Interface) -> Result<(), EditError> {
    let bad = std::iter::once(&iface.name)
        .chain(iface.vlan.iter().map(|v| &v.link))
        .chain(iface.bridge.iter().flat_map(|b| b.members.iter()))
        .find(|name| !is_valid_ifname(name))
        .or_else(|| iface.addresses.iter().find(|a| !is_valid_cidr(a)))
        .or_else(|| {
            iface
                .gateway_v4
                .as_ref()
                .filter(|gw| gw.parse::<std::net::Ipv4Addr>().is_err())
        })
        .or_else(|| {
            iface
                .gateway_v6
                .as_ref()
                .filter(|gw| gw.parse::<std::net::Ipv6Addr>().is_err())
        })
        .or_else(|| iface.dns.iter().find(|d| !is_valid_ip(d)));
    match bad {
        None => Ok(()),
        Some(value) => Err(EditError::Unsupported {
            message: format!(
                "{value:?} is not valid for its field of interface {:?}",
                iface.name
            ),
        }),
    }
}

/// Render one interface as networkd INI lines.
#[allow(clippy::assigning_clones)]
fn render_networkd(iface: &Interface) -> Result<Vec<String>, EditError> {
    // A `.network` file has no bridge-member primitive (`Bridge=` lives on
    // the member and names one bridge); refuse the bridge instead of
    // dropping it from the file.
    if iface.bridge.is_some() {
        return Err(EditError::Unsupported {
            message: format!(
                "systemd-networkd cannot hold the bridge of {:?}",
                iface.name
            ),
        });
    }
    let mut out = Vec::new();
    out.push("[Match]".to_owned());
    out.push(format!("Name={}", iface.name));
    out.push(String::new());
    out.push("[Network]".to_owned());
    let dhcp = match (iface.dhcp_v4, iface.dhcp_v6) {
        (true, true) => "yes",
        (true, false) => "ipv4",
        (false, true) => "ipv6",
        (false, false) => "no",
    };
    out.push(format!("DHCP={dhcp}"));
    for addr in &iface.addresses {
        out.push(format!("Address={addr}"));
    }
    if let Some(gw) = iface.gateway_v4.as_deref() {
        out.push(format!("Gateway={gw}"));
    }
    if let Some(gw) = iface.gateway_v6.as_deref() {
        out.push(format!("Gateway={gw}"));
    }
    if !iface.dns.is_empty() {
        out.push(format!("DNS={}", iface.dns.join(" ")));
    }
    if let Some(vlan) = iface.vlan.as_ref() {
        out.push(format!("VLAN={}:{}", vlan.link, vlan.id));
    }
    for route in &iface.routes {
        check_route(route, false)?;
        out.push(String::new());
        out.push("[Route]".to_owned());
        out.push(format!("Destination={}", route.to));
        out.push(format!("Gateway={}", route.via));
    }
    if let Some(vlan) = iface.vlan.as_ref()
        && vlan.id != 0
    {
        out.push(String::new());
        out.push("[VLAN]".to_owned());
        out.push(format!("Id={}", vlan.id));
    }
    Ok(out)
}

/// Render one interface as `NetworkManager` keyfile lines.
#[allow(clippy::assigning_clones)]
fn render_nm(iface: &Interface) -> Result<Vec<String>, EditError> {
    // Routes have no keyfile representation in the modeled subset (NM stores
    // them as `ipv4.routes` with a different syntax); refuse them instead of
    // dropping them from the file.
    if !iface.routes.is_empty() || iface.bridge.is_some() {
        return Err(EditError::Unsupported {
            message: format!(
                "NetworkManager keyfiles cannot hold the routes or bridge of {:?}",
                iface.name
            ),
        });
    }
    let mut out = Vec::new();
    out.push("[connection]".to_owned());
    out.push(format!("id={}", iface.name));
    out.push("type=ethernet".to_owned());
    out.push(format!("interface-name={}", iface.name));
    out.push(String::new());
    out.push("[ethernet]".to_owned());
    out.push(String::new());
    // ipv4
    out.push("[ipv4]".to_owned());
    if iface.addresses.is_empty() {
        out.push("method=auto".to_owned());
    } else {
        out.push("method=manual".to_owned());
        let mut addrs: Vec<String> = Vec::new();
        for addr in &iface.addresses {
            if addr.contains(':') {
                continue;
            }
            if let Some(gw) = iface.gateway_v4.as_deref() {
                addrs.push(format!("{addr},{gw}"));
            } else {
                addrs.push(addr.clone());
            }
        }
        if !addrs.is_empty() {
            out.push(format!("addresses={}", addrs.join(";")));
        }
    }
    if !iface.dns.is_empty() {
        let v4dns: Vec<&String> = iface.dns.iter().filter(|d| !d.contains(':')).collect();
        if !v4dns.is_empty() {
            out.push(format!(
                "dns={}",
                v4dns
                    .into_iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join(";")
            ));
        }
    }
    out.push(String::new());
    out.push("[ipv6]".to_owned());
    if iface.dhcp_v6 {
        out.push("method=auto".to_owned());
    } else {
        out.push("method=disabled".to_owned());
        if let Some(gw) = iface.gateway_v6.as_deref() {
            out.push(format!("gateway={gw}"));
        }
    }
    let v6addrs: Vec<&String> = iface.addresses.iter().filter(|a| a.contains(':')).collect();
    if !v6addrs.is_empty() {
        out.push(format!(
            "addresses={}",
            v6addrs
                .into_iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(";")
        ));
    }
    let v6dns: Vec<&String> = iface.dns.iter().filter(|d| d.contains(':')).collect();
    if !v6dns.is_empty() {
        out.push(format!(
            "dns={}",
            v6dns
                .into_iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(";")
        ));
    }
    if let Some(vlan) = iface.vlan.as_ref() {
        out.push(String::new());
        out.push("[vlan]".to_owned());
        out.push(format!("id={}", vlan.id));
        out.push(format!("parent={}", vlan.link));
    }
    Ok(out)
}

/// Render one interface as ifupdown stanza lines.
///
/// A route becomes a shell command (`up ip route add <to> via <via>`), so its
/// fields are checked here, not left to validation.
fn render_ifupdown(iface: &Interface) -> Result<Vec<String>, EditError> {
    let mut out = Vec::new();
    out.push(format!("auto {}", iface.name));
    let method = if iface.dhcp_v4 && iface.addresses.is_empty() {
        "dhcp"
    } else {
        "static"
    };
    out.push(format!("iface {} inet {}", iface.name, method));
    for addr in &iface.addresses {
        if !addr.contains(':') {
            out.push(format!("\taddress {addr}"));
        }
    }
    let v6addrs: Vec<&String> = iface.addresses.iter().filter(|a| a.contains(':')).collect();
    if !v6addrs.is_empty() {
        out.push(format!("iface {} inet6 static", iface.name));
        for addr in v6addrs {
            out.push(format!("\taddress {addr}"));
        }
        if let Some(gw) = iface.gateway_v6.as_deref() {
            out.push(format!("\tgateway {gw}"));
        }
    } else if iface.dhcp_v6 {
        out.push(format!("iface {} inet6 dhcp", iface.name));
    }
    if let Some(gw) = iface.gateway_v4.as_deref() {
        out.push(format!("\tgateway {gw}"));
    }
    if !iface.dns.is_empty() {
        out.push(format!("\tdns-nameservers {}", iface.dns.join(" ")));
    }
    if let Some(vlan) = iface.vlan.as_ref() {
        out.push(format!("\tvlan-raw-device {}", vlan.link));
        out.push(format!("\tvlan_id {}", vlan.id));
    }
    if let Some(bridge) = iface.bridge.as_ref() {
        // `bridge_ports` with no value reads back as no bridge.
        if bridge.members.is_empty() {
            return Err(EditError::Unsupported {
                message: format!(
                    "ifupdown cannot hold the memberless bridge {:?}",
                    iface.name
                ),
            });
        }
        out.push(format!("\tbridge_ports {}", bridge.members.join(" ")));
    }
    for route in &iface.routes {
        check_route(route, true)?;
        out.push(format!("\tup ip route add {} via {}", route.to, route.via));
    }
    Ok(out)
}

/// Render the whole model as netplan YAML lines.
fn render_netplan(model: &Model) -> Result<Vec<String>, EditError> {
    let mut out = Vec::new();
    out.push("network:".to_owned());
    out.push("  version: 2".to_owned());
    if model.interfaces.is_empty() {
        return Ok(out);
    }
    let has_ethernets = model
        .interfaces
        .iter()
        .any(|i| i.vlan.is_none() && i.bridge.is_none());
    let has_vlans = model.interfaces.iter().any(|i| i.vlan.is_some());
    let has_bridges = model.interfaces.iter().any(|i| i.bridge.is_some());
    if has_ethernets {
        out.push("  ethernets:".to_owned());
        for iface in &model.interfaces {
            if iface.vlan.is_some() || iface.bridge.is_some() {
                continue;
            }
            out.push(format!("    {}:", iface.name));
            render_netplan_iface(&mut out, iface)?;
        }
    }
    if has_vlans {
        out.push("  vlans:".to_owned());
        for iface in &model.interfaces {
            if let Some(vlan) = iface.vlan.as_ref() {
                out.push(format!("    {}:", iface.name));
                out.push(format!("      id: {}", vlan.id));
                out.push(format!("      link: {}", vlan.link));
                render_netplan_iface(&mut out, iface)?;
            }
        }
    }
    if has_bridges {
        out.push("  bridges:".to_owned());
        for iface in &model.interfaces {
            if let Some(bridge) = iface.bridge.as_ref() {
                out.push(format!("    {}:", iface.name));
                out.push(format!("      interfaces: [{}]", bridge.members.join(", ")));
                render_netplan_iface(&mut out, iface)?;
            }
        }
    }
    Ok(out)
}

/// Render the keys every netplan interface kind shares: DHCP, addresses,
/// gateways, name servers and routes.
fn render_netplan_iface(out: &mut Vec<String>, iface: &Interface) -> Result<(), EditError> {
    out.push(format!(
        "      dhcp4: {}",
        if iface.dhcp_v4 { "true" } else { "false" }
    ));
    out.push(format!(
        "      dhcp6: {}",
        if iface.dhcp_v6 { "true" } else { "false" }
    ));
    if !iface.addresses.is_empty() {
        out.push("      addresses:".to_owned());
        for addr in &iface.addresses {
            out.push(format!("        - {addr}"));
        }
    }
    if let Some(gw) = iface.gateway_v4.as_deref() {
        out.push(format!("      gateway4: {gw}"));
    }
    if let Some(gw) = iface.gateway_v6.as_deref() {
        out.push(format!("      gateway6: {gw}"));
    }
    if !iface.dns.is_empty() {
        out.push("      nameservers:".to_owned());
        out.push(format!("        addresses: [{}]", iface.dns.join(", ")));
    }
    if !iface.routes.is_empty() {
        out.push("      routes:".to_owned());
        for route in &iface.routes {
            check_route(route, false)?;
            out.push(format!("        - to: {}", route.to));
            out.push(format!("          via: {}", route.via));
        }
    }
    Ok(())
}

/// Render the model in the flavor's syntax, returning lines.
#[allow(clippy::too_many_lines)]
fn render_model_lines(flavor: BackendFlavor, model: &Model) -> Result<Vec<String>, EditError> {
    for iface in &model.interfaces {
        check_interface(iface)?;
    }
    let mut lines: Vec<String> = Vec::new();
    match flavor {
        BackendFlavor::Networkd => {
            for (idx, iface) in model.interfaces.iter().enumerate() {
                if idx > 0 {
                    lines.push(String::new());
                }
                lines.extend(render_networkd(iface)?);
            }
        }
        BackendFlavor::NetworkManager => {
            for (idx, iface) in model.interfaces.iter().enumerate() {
                if idx > 0 {
                    lines.push(String::new());
                }
                lines.extend(render_nm(iface)?);
            }
        }
        BackendFlavor::Ifupdown => {
            for iface in &model.interfaces {
                lines.extend(render_ifupdown(iface)?);
                lines.push(String::new());
            }
            // Drop trailing blank
            if lines.last().is_some_and(std::string::String::is_empty) {
                lines.pop();
            }
        }
        BackendFlavor::Netplan => {
            lines.extend(render_netplan(model)?);
        }
    }
    Ok(lines)
}

// -------------------------------------------------------------------- descriptor

/// systemd-networkd is the right backend when a `.network` directory or
/// `netif` state exists. Mirrors `detent-platform`'s
/// `detect_network_backend` precedence for the networkd tier.
fn networkd_backend_detect(profile: &HostProfile) -> bool {
    // Match the resolver pattern: check `HostProfile` service versions or OS.
    // `systemd-networkd` is probed via `networkctl` version; fall back to Linux.
    profile.os == Os::Linux
        && (profile.service_version("systemd-networkd").is_some()
            || profile.service_version("networkd").is_some()
            || profile.service_version("systemd").is_some()
            || profile.service_versions.is_empty())
}

/// `NetworkManager` keyfiles are the right backend when `NetworkManager`
/// is detected.
fn nm_backend_detect(profile: &HostProfile) -> bool {
    profile.service_version("NetworkManager").is_some()
        || profile.service_version("network-manager").is_some()
}

/// ifupdown is the right backend for the classic `/etc/network/interfaces`.
fn ifupdown_backend_detect(profile: &HostProfile) -> bool {
    profile.os == Os::Linux && profile.service_version("ifupdown").is_some()
        || (profile.os == Os::Linux
            && profile.service_version("NetworkManager").is_none()
            && profile.service_version("systemd-networkd").is_none())
}

/// netplan is the right backend when netplan YAML is present (authoritative
/// over networkd/`NetworkManager` per `detent-platform` precedence).
fn netplan_backend_detect(profile: &HostProfile) -> bool {
    profile.service_version("netplan").is_some() || profile.service_version("netplan.io").is_some()
}

static TARGETS: &[Target] = &[
    Target {
        path: PathSpec::new("/etc/systemd/network"),
        kind: TargetKind::DropInDir,
        mode: 0o755,
        owner: Owner::Root,
        backend_detect: networkd_backend_detect,
    },
    Target {
        path: PathSpec::new("/etc/NetworkManager/system-connections"),
        kind: TargetKind::Directory,
        mode: 0o700,
        owner: Owner::Root,
        backend_detect: nm_backend_detect,
    },
    Target {
        path: PathSpec::new("/etc/network/interfaces"),
        kind: TargetKind::File,
        mode: 0o644,
        owner: Owner::Root,
        backend_detect: ifupdown_backend_detect,
    },
    Target {
        path: PathSpec::new("/etc/network/interfaces.d"),
        kind: TargetKind::DropInDir,
        mode: 0o755,
        owner: Owner::Root,
        backend_detect: ifupdown_backend_detect,
    },
    Target {
        path: PathSpec::new("/etc/netplan"),
        kind: TargetKind::DropInDir,
        mode: 0o600,
        owner: Owner::Root,
        backend_detect: netplan_backend_detect,
    },
];

static CHECKS: &[ExternalCheck] = &[
    ExternalCheck {
        program: PathSpec::new("/usr/sbin/netplan"),
        args: &[
            ArgTemplate::Literal("generate"),
            ArgTemplate::Literal("--root-dir"),
            ArgTemplate::TempFile,
        ],
        expects: CheckExpectation::ExitZero,
    },
    ExternalCheck {
        program: PathSpec::new("/usr/bin/networkctl"),
        args: &[ArgTemplate::Literal("status")],
        expects: CheckExpectation::ExitZero,
    },
    ExternalCheck {
        program: PathSpec::new("/usr/bin/nmcli"),
        args: &[ArgTemplate::Literal("general")],
        expects: CheckExpectation::ExitZero,
    },
    ExternalCheck {
        program: PathSpec::new("/sbin/ifup"),
        args: &[ArgTemplate::Literal("-n"), ArgTemplate::Literal("-a")],
        expects: CheckExpectation::ExitZero,
    },
];

static SERVICES: &[ServiceBinding] = &[
    ServiceBinding {
        units: UnitNames {
            systemd: &["systemd-networkd.service"],
            openrc: &["networking", "network"],
            bsdrc: &[],
        },
        actions: &[ServiceAction::Restart, ServiceAction::Reload],
    },
    ServiceBinding {
        units: UnitNames {
            systemd: &["NetworkManager.service"],
            openrc: &["NetworkManager", "networkmanager"],
            bsdrc: &[],
        },
        actions: &[ServiceAction::Reload, ServiceAction::Restart],
    },
    ServiceBinding {
        units: UnitNames {
            systemd: &["networking.service"],
            openrc: &["networking", "network"],
            bsdrc: &[],
        },
        actions: &[ServiceAction::Restart, ServiceAction::Reload],
    },
];

static DESCRIPTOR: ModuleDescriptor = ModuleDescriptor {
    id: "network",
    display_name_id: MessageId::new("network-name"),
    targets: TARGETS,
    upstream: Upstream {
        project: "systemd",
        repo_url: "https://github.com/systemd/systemd.git",
        tracked_version: "261.3",
        release_feed: Some("https://github.com/systemd/systemd/releases.atom"),
        docs: &[
            "https://www.freedesktop.org/software/systemd/man/latest/systemd.network.html",
            "https://networkmanager.dev/docs/api/latest/nm-settings-keyfile.html",
            "https://manpages.debian.org/bookworm/ifupdown/interfaces.5.en.html",
            "https://netplan.readthedocs.io/en/stable/netplan-yaml/",
        ],
    },
    services: SERVICES,
    checks: CHECKS,
    commit_confirm: true,
    security_notes: &[MessageId::new("network-note-precedence")],
};

// ------------------------------------------------------------------ schema hints

static INTERFACES_HINTS: FieldHints = FieldHints {
    group: UiGroup::Basic,
    tooltip: MessageId::new("network-tip-interfaces"),
    recommendation: None,
    security_impact: SecurityImpact::Low,
    since: None,
    deprecated_in: None,
    requires_restart: false,
};

static IFACE_NAME_HINTS: FieldHints = FieldHints {
    group: UiGroup::Basic,
    tooltip: MessageId::new("network-tip-iface-name"),
    recommendation: None,
    security_impact: SecurityImpact::None,
    since: None,
    deprecated_in: None,
    requires_restart: false,
};

static IFACE_DHCP_V4_HINTS: FieldHints = FieldHints {
    group: UiGroup::Basic,
    tooltip: MessageId::new("network-tip-iface-dhcp-v4"),
    recommendation: None,
    security_impact: SecurityImpact::Low,
    since: None,
    deprecated_in: None,
    requires_restart: true,
};

static IFACE_DHCP_V6_HINTS: FieldHints = FieldHints {
    group: UiGroup::Basic,
    tooltip: MessageId::new("network-tip-iface-dhcp-v6"),
    recommendation: Some(MessageId::new("network-rec-ipv6-privacy")),
    security_impact: SecurityImpact::Low,
    since: None,
    deprecated_in: None,
    requires_restart: true,
};

static IFACE_ADDRESSES_HINTS: FieldHints = FieldHints {
    group: UiGroup::Basic,
    tooltip: MessageId::new("network-tip-iface-addresses"),
    recommendation: None,
    security_impact: SecurityImpact::Low,
    since: None,
    deprecated_in: None,
    requires_restart: true,
};

static IFACE_GW_V4_HINTS: FieldHints = FieldHints {
    group: UiGroup::Basic,
    tooltip: MessageId::new("network-tip-iface-gateway-v4"),
    recommendation: None,
    security_impact: SecurityImpact::Low,
    since: None,
    deprecated_in: None,
    requires_restart: true,
};

static IFACE_GW_V6_HINTS: FieldHints = FieldHints {
    group: UiGroup::Basic,
    tooltip: MessageId::new("network-tip-iface-gateway-v6"),
    recommendation: None,
    security_impact: SecurityImpact::Low,
    since: None,
    deprecated_in: None,
    requires_restart: true,
};

static IFACE_DNS_HINTS: FieldHints = FieldHints {
    group: UiGroup::Basic,
    tooltip: MessageId::new("network-tip-iface-dns"),
    recommendation: None,
    security_impact: SecurityImpact::Low,
    since: None,
    deprecated_in: None,
    requires_restart: false,
};

static IFACE_ROUTES_HINTS: FieldHints = FieldHints {
    group: UiGroup::Advanced,
    tooltip: MessageId::new("network-tip-iface-routes"),
    recommendation: None,
    security_impact: SecurityImpact::Low,
    since: None,
    deprecated_in: None,
    requires_restart: true,
};

static IFACE_VLAN_HINTS: FieldHints = FieldHints {
    group: UiGroup::Advanced,
    tooltip: MessageId::new("network-tip-iface-vlan"),
    recommendation: None,
    security_impact: SecurityImpact::None,
    since: None,
    deprecated_in: None,
    requires_restart: true,
};

static IFACE_BRIDGE_HINTS: FieldHints = FieldHints {
    group: UiGroup::Advanced,
    tooltip: MessageId::new("network-tip-iface-bridge"),
    recommendation: None,
    security_impact: SecurityImpact::None,
    since: None,
    deprecated_in: None,
    requires_restart: true,
};

static ROUTE_TO_HINTS: FieldHints = FieldHints {
    group: UiGroup::Advanced,
    tooltip: MessageId::new("network-tip-route-to"),
    recommendation: None,
    security_impact: SecurityImpact::None,
    since: None,
    deprecated_in: None,
    requires_restart: true,
};

static ROUTE_VIA_HINTS: FieldHints = FieldHints {
    group: UiGroup::Advanced,
    tooltip: MessageId::new("network-tip-route-via"),
    recommendation: None,
    security_impact: SecurityImpact::None,
    since: None,
    deprecated_in: None,
    requires_restart: true,
};

static VLAN_LINK_HINTS: FieldHints = FieldHints {
    group: UiGroup::Advanced,
    tooltip: MessageId::new("network-tip-vlan-link"),
    recommendation: None,
    security_impact: SecurityImpact::None,
    since: None,
    deprecated_in: None,
    requires_restart: true,
};

static VLAN_ID_HINTS: FieldHints = FieldHints {
    group: UiGroup::Advanced,
    tooltip: MessageId::new("network-tip-vlan-id"),
    recommendation: None,
    security_impact: SecurityImpact::Low,
    since: None,
    deprecated_in: None,
    requires_restart: true,
};

static BRIDGE_MEMBERS_HINTS: FieldHints = FieldHints {
    group: UiGroup::Advanced,
    tooltip: MessageId::new("network-tip-bridge-members"),
    recommendation: None,
    security_impact: SecurityImpact::None,
    since: None,
    deprecated_in: None,
    requires_restart: true,
};

fn schema_with_hints() -> serde_json::Value {
    let mut schema = schemars::schema_for!(Model).to_value();
    for (pointer, hints) in [
        ("/properties/interfaces", &INTERFACES_HINTS),
        ("/$defs/Interface/properties/name", &IFACE_NAME_HINTS),
        ("/$defs/Interface/properties/dhcp_v4", &IFACE_DHCP_V4_HINTS),
        ("/$defs/Interface/properties/dhcp_v6", &IFACE_DHCP_V6_HINTS),
        (
            "/$defs/Interface/properties/addresses",
            &IFACE_ADDRESSES_HINTS,
        ),
        ("/$defs/Interface/properties/gateway_v4", &IFACE_GW_V4_HINTS),
        ("/$defs/Interface/properties/gateway_v6", &IFACE_GW_V6_HINTS),
        ("/$defs/Interface/properties/dns", &IFACE_DNS_HINTS),
        ("/$defs/Interface/properties/routes", &IFACE_ROUTES_HINTS),
        ("/$defs/Interface/properties/vlan", &IFACE_VLAN_HINTS),
        ("/$defs/Interface/properties/bridge", &IFACE_BRIDGE_HINTS),
        ("/$defs/Route/properties/to", &ROUTE_TO_HINTS),
        ("/$defs/Route/properties/via", &ROUTE_VIA_HINTS),
        ("/$defs/Vlan/properties/link", &VLAN_LINK_HINTS),
        ("/$defs/Vlan/properties/id", &VLAN_ID_HINTS),
        ("/$defs/Bridge/properties/members", &BRIDGE_MEMBERS_HINTS),
    ] {
        let _applied: bool = apply_hints(&mut schema, pointer, hints);
    }
    schema
}

// ------------------------------------------------------------------- validation

/// Fluent id: malformed CIDR or IP.
const INVALID_CIDR: MessageId = MessageId::new("network-invalid-cidr");
/// Fluent id: malformed IP.
const INVALID_IP: MessageId = MessageId::new("network-invalid-ip");
/// Fluent id: gateway outside interface subnets.
const GATEWAY_OUTSIDE_SUBNET: MessageId = MessageId::new("network-gateway-outside-subnet");
/// Fluent id: VLAN id outside 1–4094.
const VLAN_RANGE: MessageId = MessageId::new("network-vlan-range");
/// Fluent id: duplicate interface names.
const DUPLICATE_INTERFACE: MessageId = MessageId::new("network-duplicate-interface");
const INTERFACE_ORDER: MessageId = MessageId::new("network-interface-order");
/// Fluent id: NUL or newline injection (also enforced at render time).
const INJECTION: MessageId = MessageId::new("network-injection");
/// Fluent id: static addresses with no gateway/DNS.
const STATIC_NO_GATEWAY: MessageId = MessageId::new("network-static-no-gateway");
/// Fluent id: static addresses with no DNS.
const STATIC_NO_DNS: MessageId = MessageId::new("network-static-no-dns");
/// Fluent id: dhcp+static mixed on one interface.
const DHCP_STATIC_MIXED: MessageId = MessageId::new("network-dhcp-static-mixed");
/// Fluent id: recommendation for IPv6 privacy extensions when `DHCPv6` is on.
const REC_IPV6_PRIVACY: MessageId = MessageId::new("network-rec-ipv6-privacy");
/// Fluent id: recommendation for sane RA acceptance.
const REC_RA_ACCEPT: MessageId = MessageId::new("network-rec-ra-accept");
/// Fluent id: recommendation against promiscuous mode.
const REC_NO_PROMISC: MessageId = MessageId::new("network-rec-no-promisc");

/// Whether `s` contains NUL, newline or carriage return.
fn has_injection(s: &str) -> bool {
    s.contains(['\n', '\r', '\0'])
}

/// Whether `s` is a valid `IPv4` or `IPv6` address.
fn is_valid_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

/// Validate a CIDR string `addr/prefix` (prefix required).
fn is_valid_cidr(s: &str) -> bool {
    let Some((ip_part, prefix_part)) = s.split_once('/') else {
        return false;
    };
    if ip_part.is_empty() || !prefix_part.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    if !is_valid_ip(ip_part) {
        return false;
    }
    let Ok(prefix) = prefix_part.parse::<u8>() else {
        return false;
    };
    if ip_part.contains(':') {
        prefix <= 128
    } else {
        prefix <= 32
    }
}

/// Whether an IP string is `IPv6`.
fn is_ipv6_str(s: &str) -> bool {
    s.contains(':')
}

/// Extract the network prefix length from a CIDR, or `None`.
fn cidr_prefix(s: &str) -> Option<u8> {
    s.split_once('/').and_then(|(_, p)| p.parse().ok())
}

/// Whether `gateway` lies within any of `cidrs` (when statically addressed).
/// Uses prefix-length containment: gateway's IP must share the CIDR's
/// network prefix with the address's IP.
#[allow(clippy::too_many_lines)]
fn gateway_in_subnets(gateway: &str, cidrs: &[String]) -> bool {
    let Ok(gw_ip) = gateway.parse::<std::net::IpAddr>() else {
        return false;
    };
    for cidr in cidrs {
        let Some((ip_part, _)) = cidr.split_once('/') else {
            continue;
        };
        let Ok(cidr_ip) = ip_part.parse::<std::net::IpAddr>() else {
            continue;
        };
        let prefix = cidr_prefix(cidr).unwrap_or(0);
        if ips_in_same_subnet(cidr_ip, gw_ip, prefix) {
            return true;
        }
    }
    false
}

#[allow(clippy::arithmetic_side_effects)]
fn ips_in_same_subnet(a: std::net::IpAddr, b: std::net::IpAddr, prefix: u8) -> bool {
    match (a, b) {
        (std::net::IpAddr::V4(a4), std::net::IpAddr::V4(b4)) => {
            if prefix > 32 {
                return false;
            }
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(a4) & mask) == (u32::from(b4) & mask)
        }
        (std::net::IpAddr::V6(a6), std::net::IpAddr::V6(b6)) => {
            if prefix > 128 {
                return false;
            }
            let a_bits = u128::from(a6);
            let b_bits = u128::from(b6);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (a_bits & mask) == (b_bits & mask)
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------- defaults

/// Scope key of one networkd directive line: `(section, key)`. Headers use an
/// empty key. Lines outside known sections return `None` and stay verbatim.
fn networkd_scope(raw: &str, current: &str) -> Option<(String, String)> {
    if let Some(section) = parse_section(raw) {
        if is_networkd_section(&section) {
            return Some((section, String::new()));
        }
        return None;
    }
    if let Some((k, _)) = parse_kv_equals(raw) {
        if is_networkd_key(&k) && !current.is_empty() {
            return Some((current.to_owned(), k));
        }
        return None;
    }
    None
}

/// Section-aware minimal edit for networkd documents. Aligns planned
/// directives with existing ones and pairs the changed ones inside the same
/// `(section, key)` group; surplus planned lines insert after their planned
/// predecessor; unpaired existing directives are removed. Unknown lines stay
/// verbatim. Refuses when the result would parse back to a different model.
/// Returns `None` when the document has no networkd sections so the caller
/// uses the flat edit.
fn apply_networkd_sections(
    doc: &mut Document,
    new_lines: &[String],
    model: &Model,
) -> Option<Result<EditReport, EditError>> {
    if !doc
        .lines()
        .iter()
        .any(|l| parse_section(l.raw()).is_some_and(|s| is_networkd_section(&s)))
    {
        return None;
    }
    Some(edit_networkd_sections(doc, new_lines, model))
}

/// The edit of [`apply_networkd_sections`] for a document that has networkd
/// sections. One pass over the file ([`Document::apply_plan`]).
fn edit_networkd_sections(
    doc: &mut Document,
    new_lines: &[String],
    model: &Model,
) -> Result<EditReport, EditError> {
    let planned: Vec<&String> = new_lines.iter().filter(|l| is_directive_like(l)).collect();
    let (planned_raw, planned_scopes): (Vec<&String>, Vec<(String, String)>) = planned
        .iter()
        .zip(networkd_scopes(planned.iter().copied()))
        .filter_map(|(raw, scope)| Some((*raw, scope?)))
        .unzip();
    let managed = managed_lines(doc);
    let partner = pair_aligned(&managed, &planned_raw, &planned_scopes);

    let mut plan = EntryPlan::default();
    // Where a line that follows each placed planned line is inserted.
    let mut placed: BTreeMap<usize, usize> = BTreeMap::new();
    for ((row, raw, _), paired) in managed.iter().zip(&partner) {
        match paired.and_then(|pi| Some((pi, *planned_raw.get(pi)?))) {
            None => plan.remove(*row),
            Some((pi, want)) => {
                if *raw != want.as_str() {
                    plan.replace(*row, want.clone())?;
                }
                placed.insert(pi, row.saturating_add(1));
            }
        }
    }
    // Surplus planned lines, in render order, each after its planned
    // predecessor. Lines with no placed predecessor (brand-new sections) go
    // to the end, in planned order.
    let mut at_end = Vec::new();
    for (pi, raw) in planned_raw.iter().enumerate() {
        if placed.contains_key(&pi) {
            continue;
        }
        if let Some((_, &at)) = placed.range(..pi).next_back() {
            plan.insert(at, (*raw).clone())?;
            placed.insert(pi, at);
        } else {
            at_end.push((*raw).clone());
        }
    }
    for raw in at_end {
        plan.insert(doc.len(), raw)?;
    }
    let before = doc.clone();
    let report = doc.apply_plan(plan);
    // Refuse an edit that parses back to a different model instead of
    // silently dropping modeled state, leaving the document as it was.
    if !round_trips(doc, model) {
        *doc = before;
        return Err(EditError::Unsupported {
            message: "edit would not round-trip; refusing".to_owned(),
        });
    }
    Ok(report)
}

/// The directive lines of `doc` inside a known networkd section, as `(row,
/// raw, scope)`. A section is in force from its header until the next header;
/// an unknown header ends it.
fn managed_lines(doc: &Document) -> Vec<(usize, &str, (String, String))> {
    let mut current = String::new();
    let mut managed = Vec::new();
    for (row, line) in doc.lines().iter().enumerate() {
        let raw = line.raw();
        if line.kind() == LineKind::Directive
            && let Some(scope) = networkd_scope(raw, &current)
        {
            managed.push((row, raw, scope));
        }
        if let Some(section) = parse_section(raw) {
            current = if is_networkd_section(&section) {
                section
            } else {
                String::new()
            };
        }
    }
    managed
}

/// The `(section, key)` scope of each line, tracking the section headers
/// among `lines` as they pass.
fn networkd_scopes<'a>(lines: impl Iterator<Item = &'a String>) -> Vec<Option<(String, String)>> {
    let mut current = String::new();
    lines
        .map(|raw| {
            let scope = networkd_scope(raw, &current);
            if let Some((section, key)) = &scope
                && key.is_empty()
            {
                current.clone_from(section);
            }
            scope
        })
        .collect()
}

/// The planned partner of each managed line. Unchanged lines are aligned
/// with [`align`], so dropping or adding a line never rewrites another.
/// Between two unchanged lines, a removed line and an added line of the same
/// `(section, key)` group are paired in order, so a changed value is
/// rewritten in place.
fn pair_aligned(
    managed: &[(usize, &str, (String, String))],
    planned_raw: &[&String],
    planned_scopes: &[(String, String)],
) -> Vec<Option<usize>> {
    let have: Vec<&str> = managed.iter().map(|(_, raw, _)| *raw).collect();
    let want: Vec<&str> = planned_raw.iter().map(|raw| raw.as_str()).collect();
    let steps = align(&have, &want).unwrap_or_else(|| replace_all(have.len(), want.len()));
    let mut partner = vec![None; managed.len()];
    let mut deleted: BTreeMap<&(String, String), VecDeque<usize>> = BTreeMap::new();
    let mut inserted: Vec<usize> = Vec::new();
    for step in steps {
        match step {
            Step::Delete(old) => {
                if let Some((_, _, scope)) = managed.get(old) {
                    deleted.entry(scope).or_default().push_back(old);
                }
            }
            Step::Insert(new) => inserted.push(new),
            Step::Equal(old, new) => {
                settle_run(&mut deleted, &mut inserted, planned_scopes, &mut partner);
                if let Some(slot) = partner.get_mut(old) {
                    *slot = Some(new);
                }
            }
        }
    }
    settle_run(&mut deleted, &mut inserted, planned_scopes, &mut partner);
    partner
}

/// Pairs the removed and added lines of one run of changes by `(section,
/// key)` group, in order, and empties the run.
fn settle_run(
    deleted: &mut BTreeMap<&(String, String), VecDeque<usize>>,
    inserted: &mut Vec<usize>,
    planned_scopes: &[(String, String)],
    partner: &mut [Option<usize>],
) {
    for new in inserted.drain(..) {
        if let Some(slot) = planned_scopes
            .get(new)
            .and_then(|scope| deleted.get_mut(scope)?.pop_front())
            .and_then(|old| partner.get_mut(old))
        {
            *slot = Some(new);
        }
    }
    deleted.clear();
}

/// Whether `doc` parses back to `model`, ignoring interface order.
fn round_trips(doc: &Document, model: &Model) -> bool {
    let reparsed = Document::parse(&doc.render(), classify);
    let mut back = build_model_from_lines(
        &reparsed
            .lines()
            .iter()
            .map(|l| l.raw().to_owned())
            .collect::<Vec<_>>(),
    );
    let mut want = model.clone();
    want.interfaces.sort_by(|a, b| a.name.cmp(&b.name));
    back.interfaces.sort_by(|a, b| a.name.cmp(&b.name));
    back == want
}

// ----------------------------------------------------------------------- module

/// The network config module.
pub struct NetworkModule;

impl ConfigModule for NetworkModule {
    const ID: &'static str = "network";
    type Doc = Document;
    type Model = Model;

    fn descriptor() -> &'static ModuleDescriptor {
        &DESCRIPTOR
    }

    fn parse(src: &str) -> Result<Self::Doc, ParseError> {
        Ok(Document::parse(src, classify))
    }

    fn render(doc: &Self::Doc) -> String {
        doc.render()
    }

    fn to_model(doc: &Self::Doc) -> Result<Self::Model, ModelError> {
        let raws: Vec<String> = doc.lines().iter().map(|l| l.raw().to_owned()).collect();
        Ok(build_model_from_lines(&raws))
    }

    fn apply(doc: &mut Self::Doc, model: &Self::Model) -> Result<EditReport, EditError> {
        // Pass 1: validate the model and every rendered line before touching
        // the document. A line break or NUL in any field is directive
        // injection.
        for iface in &model.interfaces {
            for s in std::iter::once(&iface.name)
                .chain(iface.addresses.iter())
                .chain(iface.gateway_v4.iter())
                .chain(iface.gateway_v6.iter())
                .chain(iface.dns.iter())
                .chain(
                    iface
                        .routes
                        .iter()
                        .flat_map(|r| [&r.to, &r.via].into_iter()),
                )
                .chain(iface.vlan.iter().flat_map(|v| [&v.link].into_iter()))
                .chain(iface.bridge.iter().flat_map(|b| b.members.iter()))
            {
                if has_injection(s) {
                    return Err(EditError::LineBreakInValue { value: s.clone() });
                }
            }
            if let Some(vlan) = iface.vlan.as_ref()
                && (vlan.id == 0 || vlan.id > 4094)
            {
                return Err(EditError::Unsupported {
                    message: format!("VLAN id {} out of range", vlan.id),
                });
            }
            if iface.name.is_empty() || iface.name.contains(char::is_whitespace) {
                return Err(EditError::Unsupported {
                    message: "interface name cannot round-trip".to_owned(),
                });
            }
        }
        // The document already holds this model, so nothing is written
        // (invariant 2) even when it holds a value the renderer refuses.
        // Compare against every line: unknown lines (an unknown section
        // header, say) change what the directives around them mean.
        if Self::to_model(doc).is_ok_and(|current| &current == model) {
            return Ok(EditReport::default());
        }
        let flavor = detect_flavor(doc);
        let new_lines = render_model_lines(flavor, model)?;
        for line in &new_lines {
            if !line.is_empty() && !is_directive_like(line) && !line.trim().is_empty() {
                // Rendered a directive that the classifier would mark Unknown — refuse.
                return Err(EditError::Unsupported {
                    message: format!("rendered line does not round-trip: {line:?}"),
                });
            }
        }

        // Pass 2: two-pass minimal edit, section-aware for networkd.
        if flavor == BackendFlavor::Networkd
            && let Some(result) = apply_networkd_sections(doc, &new_lines, model)
        {
            return result;
        }
        // Other flavors: directives are aligned with the rendering
        // ([`Document::edit_entries`]); a new INI section header goes at the
        // end of the section before it.
        let before = doc.clone();
        let planned: Vec<String> = new_lines
            .into_iter()
            .filter(|l| is_directive_like(l))
            .collect();
        let edited = doc.edit_entries(
            &planned,
            |raw| Some(raw.to_owned()),
            |raw| Ok(raw.clone()),
            |raw| parse_section(raw).is_some(),
        );
        // An unknown line between rewritten directives (an unknown section
        // header, say) can change what they mean; refuse, leaving the
        // document as it was, instead of silently dropping modeled state.
        match edited {
            Ok(report) if round_trips(doc, model) => Ok(report),
            refused => {
                *doc = before;
                refused.and(Err(EditError::Unsupported {
                    message: "edit would not round-trip; refusing".to_owned(),
                }))
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn validate(model: &Self::Model, _ctx: &ValidationCtx<'_>) -> Diagnostics {
        let mut diagnostics = Diagnostics::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut previous: Option<&str> = None;
        for (idx, iface) in model.interfaces.iter().enumerate() {
            let base = format!("interfaces/{idx}");
            // `to_model` reads interfaces back in name order, so only a
            // model in that order survives apply unchanged.
            if previous.is_some_and(|name| name > iface.name.as_str()) {
                diagnostics.push(
                    Diagnostic::new(Severity::Error, INTERFACE_ORDER)
                        .with_field(FieldPath::new(format!("{base}/name")))
                        .with_arg("name", iface.name.clone()),
                );
            }
            previous = Some(iface.name.as_str());
            // The names every renderer writes: the charset of
            // `check_interface`, and no leading `-`, which ifup, ip and
            // networkctl read as an option.
            let names = std::iter::once(("name".to_owned(), &iface.name))
                .chain(iface.vlan.iter().map(|v| ("vlan/link".to_owned(), &v.link)))
                .chain(iface.bridge.iter().flat_map(|b| {
                    b.members
                        .iter()
                        .enumerate()
                        .map(|(pos, member)| (format!("bridge/members/{pos}"), member))
                }));
            for (field, name) in names {
                if !is_valid_ifname(name) || name.starts_with('-') {
                    diagnostics.push(
                        Diagnostic::new(Severity::Error, INVALID_CIDR)
                            .with_field(FieldPath::new(format!("{base}/{field}")))
                            .with_arg("value", name.clone()),
                    );
                }
            }
            // Injection
            for (field, value) in [
                ("name", iface.name.as_str()),
                ("gateway_v4", iface.gateway_v4.as_deref().unwrap_or("")),
                ("gateway_v6", iface.gateway_v6.as_deref().unwrap_or("")),
            ] {
                if has_injection(value) && !value.is_empty() {
                    diagnostics.push(
                        Diagnostic::new(Severity::Error, INJECTION)
                            .with_field(FieldPath::new(format!("{base}/{field}")))
                            .with_arg("value", value.to_owned()),
                    );
                }
            }
            for (pos, addr) in iface.addresses.iter().enumerate() {
                if has_injection(addr) {
                    diagnostics.push(
                        Diagnostic::new(Severity::Error, INJECTION)
                            .with_field(FieldPath::new(format!("{base}/addresses/{pos}")))
                            .with_arg("value", addr.clone()),
                    );
                } else if !is_valid_cidr(addr) {
                    diagnostics.push(
                        Diagnostic::new(Severity::Error, INVALID_CIDR)
                            .with_field(FieldPath::new(format!("{base}/addresses/{pos}")))
                            .with_arg("value", addr.clone()),
                    );
                }
            }
            for (pos, dns) in iface.dns.iter().enumerate() {
                if has_injection(dns) {
                    diagnostics.push(
                        Diagnostic::new(Severity::Error, INJECTION)
                            .with_field(FieldPath::new(format!("{base}/dns/{pos}")))
                            .with_arg("value", dns.clone()),
                    );
                } else if !is_valid_ip(dns) {
                    diagnostics.push(
                        Diagnostic::new(Severity::Error, INVALID_IP)
                            .with_field(FieldPath::new(format!("{base}/dns/{pos}")))
                            .with_arg("value", dns.clone()),
                    );
                }
            }
            for (pos, route) in iface.routes.iter().enumerate() {
                if has_injection(&route.to) || has_injection(&route.via) {
                    diagnostics.push(
                        Diagnostic::new(Severity::Error, INJECTION)
                            .with_field(FieldPath::new(format!("{base}/routes/{pos}/to")))
                            .with_arg("value", route.to.clone()),
                    );
                } else {
                    // `to` may be CIDR or "default"
                    if route.to != "default" && !is_valid_cidr(&route.to) && !is_valid_ip(&route.to)
                    {
                        diagnostics.push(
                            Diagnostic::new(Severity::Error, INVALID_CIDR)
                                .with_field(FieldPath::new(format!("{base}/routes/{pos}/to")))
                                .with_arg("value", route.to.clone()),
                        );
                    }
                    if !route.via.is_empty() && !is_valid_ip(&route.via) {
                        diagnostics.push(
                            Diagnostic::new(Severity::Error, INVALID_IP)
                                .with_field(FieldPath::new(format!("{base}/routes/{pos}/via")))
                                .with_arg("value", route.via.clone()),
                        );
                    }
                }
            }
            if let Some(gw) = iface.gateway_v4.as_deref() {
                if has_injection(gw) {
                    diagnostics.push(
                        Diagnostic::new(Severity::Error, INJECTION)
                            .with_field(FieldPath::new(format!("{base}/gateway_v4")))
                            .with_arg("value", gw.to_owned()),
                    );
                } else if !is_valid_ip(gw) || is_ipv6_str(gw) {
                    diagnostics.push(
                        Diagnostic::new(Severity::Error, INVALID_IP)
                            .with_field(FieldPath::new(format!("{base}/gateway_v4")))
                            .with_arg("value", gw.to_owned()),
                    );
                } else if !iface.addresses.is_empty() {
                    let v4_addrs: Vec<String> = iface
                        .addresses
                        .iter()
                        .filter(|a| !is_ipv6_str(a))
                        .cloned()
                        .collect();
                    if !v4_addrs.is_empty() && !gateway_in_subnets(gw, &v4_addrs) {
                        diagnostics.push(
                            Diagnostic::new(Severity::Error, GATEWAY_OUTSIDE_SUBNET)
                                .with_field(FieldPath::new(format!("{base}/gateway_v4")))
                                .with_arg("gateway", gw.to_owned()),
                        );
                    }
                }
            }
            if let Some(gw) = iface.gateway_v6.as_deref() {
                if has_injection(gw) {
                    diagnostics.push(
                        Diagnostic::new(Severity::Error, INJECTION)
                            .with_field(FieldPath::new(format!("{base}/gateway_v6")))
                            .with_arg("value", gw.to_owned()),
                    );
                } else if !is_valid_ip(gw) || !is_ipv6_str(gw) {
                    diagnostics.push(
                        Diagnostic::new(Severity::Error, INVALID_IP)
                            .with_field(FieldPath::new(format!("{base}/gateway_v6")))
                            .with_arg("value", gw.to_owned()),
                    );
                } else if !iface.addresses.is_empty() {
                    let v6_addrs: Vec<String> = iface
                        .addresses
                        .iter()
                        .filter(|a| is_ipv6_str(a))
                        .cloned()
                        .collect();
                    if !v6_addrs.is_empty() && !gateway_in_subnets(gw, &v6_addrs) {
                        diagnostics.push(
                            Diagnostic::new(Severity::Error, GATEWAY_OUTSIDE_SUBNET)
                                .with_field(FieldPath::new(format!("{base}/gateway_v6")))
                                .with_arg("gateway", gw.to_owned()),
                        );
                    }
                }
            }
            // Duplicate interface names
            if !seen.insert(iface.name.clone()) {
                diagnostics.push(
                    Diagnostic::new(Severity::Error, DUPLICATE_INTERFACE)
                        .with_field(FieldPath::new(format!("{base}/name")))
                        .with_arg("name", iface.name.clone()),
                );
            }
            // VLAN id range
            if let Some(vlan) = iface.vlan.as_ref() {
                if vlan.id == 0 || vlan.id > 4094 {
                    diagnostics.push(
                        Diagnostic::new(Severity::Error, VLAN_RANGE)
                            .with_field(FieldPath::new(format!("{base}/vlan/id")))
                            .with_arg("id", vlan.id.to_string()),
                    );
                }
                if has_injection(&vlan.link) {
                    diagnostics.push(
                        Diagnostic::new(Severity::Error, INJECTION)
                            .with_field(FieldPath::new(format!("{base}/vlan/link")))
                            .with_arg("value", vlan.link.clone()),
                    );
                }
            }
            // Static without gateway/DNS warnings
            let has_static = !iface.addresses.is_empty();
            if has_static {
                let has_gw = iface.gateway_v4.is_some() || iface.gateway_v6.is_some();
                if !has_gw {
                    diagnostics.push(
                        Diagnostic::new(Severity::Warning, STATIC_NO_GATEWAY)
                            .with_field(FieldPath::new(format!("{base}/gateway_v4"))),
                    );
                }
                if iface.dns.is_empty() {
                    diagnostics.push(
                        Diagnostic::new(Severity::Warning, STATIC_NO_DNS)
                            .with_field(FieldPath::new(format!("{base}/dns"))),
                    );
                }
            }
            // dhcp+static mixed
            if (iface.dhcp_v4 || iface.dhcp_v6) && has_static {
                diagnostics.push(
                    Diagnostic::new(Severity::Warning, DHCP_STATIC_MIXED)
                        .with_field(FieldPath::new(format!("{base}/addresses"))),
                );
            }
            // Recommendations
            if iface.dhcp_v6 {
                diagnostics.push(
                    Diagnostic::new(Severity::Recommendation, REC_IPV6_PRIVACY)
                        .with_field(FieldPath::new(format!("{base}/dhcp_v6"))),
                );
                diagnostics.push(
                    Diagnostic::new(Severity::Recommendation, REC_RA_ACCEPT)
                        .with_field(FieldPath::new(format!("{base}/dhcp_v6"))),
                );
            }
            if iface.dhcp_v4 || iface.dhcp_v6 {
                diagnostics.push(
                    Diagnostic::new(Severity::Recommendation, REC_NO_PROMISC)
                        .with_field(FieldPath::new(format!("{base}/name"))),
                );
            }
        }
        diagnostics
    }

    fn defaults(profile: &HostProfile) -> Self::Model {
        let _ = profile;
        match profile.os {
            Os::Linux | Os::MacOs | Os::Other => Model {
                interfaces: vec![Interface {
                    name: "eth0".to_owned(),
                    dhcp_v4: true,
                    dhcp_v6: true,
                    addresses: Vec::new(),
                    gateway_v4: None,
                    gateway_v6: None,
                    dns: Vec::new(),
                    routes: Vec::new(),
                    vlan: None,
                    bridge: None,
                }],
            },
        }
    }

    fn schema() -> serde_json::Value {
        schema_with_hints()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic
)]
mod tests {
    use super::{
        DESCRIPTOR, DHCP_STATIC_MIXED, DUPLICATE_INTERFACE, GATEWAY_OUTSIDE_SUBNET, INJECTION,
        INVALID_CIDR, INVALID_IP, NetworkModule, REC_IPV6_PRIVACY, REC_NO_PROMISC, REC_RA_ACCEPT,
        STATIC_NO_DNS, STATIC_NO_GATEWAY, VLAN_RANGE, classify, detect_flavor, is_valid_cidr,
        is_valid_ip, parse_ifupdown_auto, parse_ifupdown_iface, parse_inline_list, parse_kv_equals,
        parse_netplan_kv, parse_section, schema_with_hints,
    };
    use detent_core::descriptor::{HostProfile, InitSystem, Os, ValidationCtx};
    use detent_core::diag::{MessageId, Severity};
    use detent_core::doc::LineKind;
    use detent_core::module::{ConfigModule, EditReport};

    const CORE_FTL: &str = include_str!("../../../../locales/en-US/core.ftl");
    const UPSTREAM_TOML: &str = include_str!("../upstream.toml");

    #[test]
    fn every_message_id_has_a_locale_entry() {
        for id in [
            "network-name",
            "network-note-precedence",
            "network-tip-interfaces",
            "network-tip-iface-name",
            "network-tip-iface-dhcp-v4",
            "network-tip-iface-dhcp-v6",
            "network-tip-iface-addresses",
            "network-tip-iface-gateway-v4",
            "network-tip-iface-gateway-v6",
            "network-tip-iface-dns",
            "network-tip-iface-routes",
            "network-tip-iface-vlan",
            "network-tip-iface-bridge",
            "network-tip-route-to",
            "network-tip-route-via",
            "network-tip-vlan-link",
            "network-tip-vlan-id",
            "network-tip-bridge-members",
            "network-invalid-cidr",
            "network-invalid-ip",
            "network-gateway-outside-subnet",
            "network-vlan-range",
            "network-duplicate-interface",
            "network-injection",
            "network-static-no-gateway",
            "network-static-no-dns",
            "network-dhcp-static-mixed",
            "network-rec-ipv6-privacy",
            "network-rec-ra-accept",
            "network-rec-no-promisc",
        ] {
            assert!(
                CORE_FTL.contains(&format!("{id} =")),
                "locales/en-US/core.ftl is missing `{id} =`"
            );
        }
    }

    #[test]
    fn upstream_toml_matches_the_descriptor() {
        let upstream = DESCRIPTOR.upstream;
        for value in [
            upstream.project,
            upstream.repo_url,
            upstream.tracked_version,
        ] {
            assert!(
                UPSTREAM_TOML.contains(value),
                "upstream.toml does not mention `{value}`"
            );
        }
        for doc in upstream.docs {
            assert!(
                UPSTREAM_TOML.contains(doc),
                "upstream.toml is missing {doc}"
            );
        }
        assert!(
            upstream
                .release_feed
                .is_some_and(|feed| UPSTREAM_TOML.contains(feed))
        );
    }

    fn profile(os: Os) -> HostProfile {
        HostProfile {
            os,
            init: InitSystem::None,
            hostname: "test".to_owned(),
            service_versions: std::collections::BTreeMap::new(),
            ram_mib: 1024,
        }
    }

    fn has(model: &super::Model, id: MessageId, severity: Severity) -> bool {
        let host = profile(Os::Linux);
        let ctx = ValidationCtx::new(&host);
        NetworkModule::validate(model, &ctx)
            .iter()
            .any(|d| d.id.as_str() == id.as_str() && d.severity == severity)
    }

    #[test]
    fn descriptor_declares_commit_confirm_and_targets() {
        let descriptor = NetworkModule::descriptor();
        assert_eq!(descriptor.id, "network");
        assert!(
            descriptor.commit_confirm,
            "network is commit_confirm per ADR-012"
        );
        assert_eq!(descriptor.targets.len(), 5);
        let paths: Vec<&str> = descriptor.targets.iter().map(|t| t.path.as_str()).collect();
        assert!(paths.contains(&"/etc/systemd/network"));
        assert!(paths.contains(&"/etc/NetworkManager/system-connections"));
        assert!(paths.contains(&"/etc/network/interfaces"));
        assert!(paths.contains(&"/etc/network/interfaces.d"));
        assert!(paths.contains(&"/etc/netplan"));
        // Check kinds/modes
        let netplan = descriptor
            .targets
            .iter()
            .find(|t| t.path.as_str() == "/etc/netplan")
            .unwrap_or_else(|| panic!("/etc/netplan target missing"));
        assert_eq!(netplan.mode, 0o600);
        let nm = descriptor
            .targets
            .iter()
            .find(|t| t.path.as_str() == "/etc/NetworkManager/system-connections")
            .unwrap_or_else(|| panic!("nm target missing"));
        assert_eq!(nm.mode, 0o700);
        assert_eq!(descriptor.checks.len(), 4);
        assert_eq!(descriptor.services.len(), 3);
        for svc in descriptor.services {
            assert!(svc.units.bsdrc.is_empty());
        }
    }

    #[test]
    fn schema_with_hints_attaches_every_hint() {
        let schema = schema_with_hints();
        assert_eq!(schema, NetworkModule::schema());
        for pointer in [
            "/properties/interfaces",
            "/$defs/Interface/properties/name",
            "/$defs/Interface/properties/dhcp_v4",
            "/$defs/Interface/properties/dhcp_v6",
            "/$defs/Interface/properties/addresses",
            "/$defs/Interface/properties/gateway_v4",
            "/$defs/Interface/properties/gateway_v6",
            "/$defs/Interface/properties/dns",
            "/$defs/Interface/properties/routes",
            "/$defs/Interface/properties/vlan",
            "/$defs/Interface/properties/bridge",
            "/$defs/Route/properties/to",
            "/$defs/Route/properties/via",
            "/$defs/Vlan/properties/link",
            "/$defs/Vlan/properties/id",
            "/$defs/Bridge/properties/members",
        ] {
            assert!(
                schema
                    .pointer(pointer)
                    .and_then(|v| v.get("x-detent"))
                    .is_some(),
                "missing x-detent hint at {pointer}"
            );
        }
    }

    #[test]
    fn defaults_are_valid_and_exhaustive_os_match() {
        for os in [Os::Linux, Os::MacOs, Os::Other] {
            let host = profile(os);
            let model = NetworkModule::defaults(&host);
            assert_eq!(model.interfaces.len(), 1);
            let first = model
                .interfaces
                .first()
                .unwrap_or_else(|| panic!("defaults empty"));
            assert_eq!(first.name, "eth0");
            assert!(first.dhcp_v4);
            assert!(first.dhcp_v6);
            assert!(first.addresses.is_empty());
            let ctx = ValidationCtx::new(&host);
            let diags = NetworkModule::validate(&model, &ctx);
            assert!(
                !diags.has_errors(),
                "defaults must have no errors for {os:?}: {diags:?}"
            );
        }
    }

    #[test]
    fn defaults_apply_to_empty_file() -> Result<(), String> {
        let host = profile(Os::Linux);
        let model = NetworkModule::defaults(&host);
        let mut doc = NetworkModule::parse("").map_err(|e| e.to_string())?;
        let report = NetworkModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert!(report.added > 0);
        let back = NetworkModule::to_model(&doc).map_err(|e| e.to_string())?;
        assert_eq!(back, model);
        Ok(())
    }

    #[test]
    fn classify_assigns_four_buckets() {
        assert_eq!(classify(""), LineKind::Blank);
        assert_eq!(classify("   \t "), LineKind::Blank);
        assert_eq!(classify("# comment"), LineKind::Comment);
        assert_eq!(classify("; ini comment"), LineKind::Comment);
        assert_eq!(classify("[Match]"), LineKind::Directive);
        assert_eq!(classify("Name=eth0"), LineKind::Directive);
        assert_eq!(classify("auto eth0"), LineKind::Directive);
        assert_eq!(classify("iface eth0 inet dhcp"), LineKind::Directive);
        assert_eq!(classify("\taddress 192.168.1.10/24"), LineKind::Directive);
        assert_eq!(classify("network:"), LineKind::Directive);
        assert_eq!(classify("  dhcp4: true"), LineKind::Directive);
        assert_eq!(classify("    - 192.168.1.10/24"), LineKind::Directive);
        assert_eq!(classify("UnknownKey=foo"), LineKind::Unknown);
        assert_eq!(classify("[UnknownSection]"), LineKind::Unknown);
        assert_eq!(classify("garbage line no directive"), LineKind::Unknown);
    }

    #[test]
    fn parse_helpers_cover_known_shapes() {
        assert_eq!(parse_section("[Match]"), Some("Match".to_owned()));
        assert_eq!(parse_section("[]"), None);
        assert_eq!(parse_section("[bad"), None);
        assert_eq!(
            parse_kv_equals("Name=eth0"),
            Some(("Name".to_owned(), "eth0".to_owned()))
        );
        assert_eq!(parse_kv_equals("=value"), None);
        assert_eq!(parse_kv_equals("no-equals"), None);
        assert_eq!(parse_ifupdown_auto("auto eth0"), Some("eth0".to_owned()));
        assert_eq!(parse_ifupdown_auto("auto"), None);
        assert_eq!(
            parse_ifupdown_iface("iface eth0 inet dhcp"),
            Some(("eth0".to_owned(), "dhcp".to_owned()))
        );
        assert_eq!(parse_ifupdown_iface("iface eth0"), None);
        assert_eq!(
            parse_netplan_kv("  dhcp4: true"),
            Some((2, "dhcp4".to_owned(), "true".to_owned()))
        );
        assert_eq!(parse_netplan_kv("  unknown-key: foo"), None);
        assert_eq!(
            parse_inline_list("[a, b]"),
            Some(vec!["a".to_owned(), "b".to_owned()])
        );
        assert_eq!(parse_inline_list("[]"), Some(Vec::new()));
        assert_eq!(parse_inline_list("not a list"), None);
    }

    #[test]
    fn is_valid_cidr_and_ip() {
        assert!(is_valid_cidr("192.168.1.10/24"));
        assert!(is_valid_cidr("2001:db8::1/64"));
        assert!(!is_valid_cidr("192.168.1.10"));
        assert!(!is_valid_cidr("999.0.0.1/24"));
        assert!(!is_valid_cidr("192.168.1.10/33"));
        assert!(is_valid_ip("192.168.1.1"));
        assert!(is_valid_ip("2001:db8::1"));
        assert!(!is_valid_ip("not-an-ip"));
    }

    #[test]
    fn is_valid_cidr_refuses_a_signed_prefix() {
        // `u8::from_str` takes a leading `+`; no backend does.
        assert!(!is_valid_cidr("10.0.0.1/+24"));
        assert!(!is_valid_cidr("2001:db8::1/+64"));
        assert!(!is_valid_cidr("10.0.0.1/-1"));
        assert!(is_valid_cidr("10.0.0.1/0"));
    }

    #[test]
    fn validate_flags_malformed_cidr_and_ip() {
        let mut model = NetworkModule::defaults(&profile(Os::Linux));
        model.interfaces[0].addresses = vec!["not-a-cidr".to_owned()];
        assert!(has(&model, INVALID_CIDR, Severity::Error));
        model.interfaces[0].addresses = vec!["192.168.1.10/24".to_owned()];
        model.interfaces[0].dns = vec!["not-an-ip".to_owned()];
        assert!(has(&model, INVALID_IP, Severity::Error));
    }

    /// The model fields that `validate` flags as an invalid name (Error).
    fn name_errors(model: &super::Model) -> Vec<String> {
        let host = profile(Os::Linux);
        let ctx = ValidationCtx::new(&host);
        NetworkModule::validate(model, &ctx)
            .iter()
            .filter(|d| d.severity == Severity::Error && d.id.as_str() == INVALID_CIDR.as_str())
            .filter_map(|d| d.field.as_ref().map(|f| f.as_str().to_owned()))
            .collect()
    }

    #[test]
    fn validate_flags_interface_names_the_renderer_refuses() {
        let mut model = NetworkModule::defaults(&profile(Os::Linux));
        assert!(name_errors(&model).is_empty());
        // Every renderer accepts ASCII alphanumerics and `-_.` only, and a
        // leading `-` reads as an option to ifup, ip and networkctl.
        for bad in ["eth/0", "eth0:1", "ethé", "-eth0", "eth\"0", "-"] {
            model.interfaces[0].name = bad.to_owned();
            assert_eq!(
                name_errors(&model),
                vec!["interfaces/0/name".to_owned()],
                "{bad:?}"
            );
        }
        for good in ["eth0", "br-lan", "eth0.10", "wlan_1", "e-"] {
            model.interfaces[0].name = good.to_owned();
            assert!(name_errors(&model).is_empty(), "{good:?}");
        }
        model.interfaces[0].name = "eth0".to_owned();
        model.interfaces[0].vlan = Some(super::Vlan {
            link: "-eth1".to_owned(),
            id: 10,
        });
        model.interfaces[0].bridge = Some(super::Bridge {
            members: vec!["eth2".to_owned(), "eth:3".to_owned()],
        });
        assert_eq!(
            name_errors(&model),
            vec![
                "interfaces/0/vlan/link".to_owned(),
                "interfaces/0/bridge/members/1".to_owned()
            ]
        );
    }

    #[test]
    fn validate_flags_gateway_outside_subnet() {
        let mut model = NetworkModule::defaults(&profile(Os::Linux));
        model.interfaces[0].dhcp_v4 = false;
        model.interfaces[0].addresses = vec!["192.168.1.10/24".to_owned()];
        model.interfaces[0].gateway_v4 = Some("10.0.0.1".to_owned());
        assert!(has(&model, GATEWAY_OUTSIDE_SUBNET, Severity::Error));
        // Inside subnet is fine
        model.interfaces[0].gateway_v4 = Some("192.168.1.1".to_owned());
        assert!(!has(&model, GATEWAY_OUTSIDE_SUBNET, Severity::Error));
    }

    #[test]
    fn validate_flags_vlan_range_and_duplicate() {
        let mut model = NetworkModule::defaults(&profile(Os::Linux));
        model.interfaces[0].vlan = Some(super::Vlan {
            link: "eth0".to_owned(),
            id: 0,
        });
        assert!(has(&model, VLAN_RANGE, Severity::Error));
        model.interfaces[0].vlan = Some(super::Vlan {
            link: "eth0".to_owned(),
            id: 4095,
        });
        assert!(has(&model, VLAN_RANGE, Severity::Error));
        model.interfaces[0].vlan = Some(super::Vlan {
            link: "eth0".to_owned(),
            id: 100,
        });
        assert!(!has(&model, VLAN_RANGE, Severity::Error));
        // Duplicate names
        let mut dup = model.clone();
        dup.interfaces.push(dup.interfaces[0].clone());
        assert!(has(&dup, DUPLICATE_INTERFACE, Severity::Error));
    }

    /// `to_model` reads interfaces back in name order, so a model in any
    /// other order cannot survive apply unchanged (invariant 3): validation
    /// refuses it, and a sorted model passes.
    #[test]
    fn interfaces_out_of_name_order_are_an_error() {
        let iface = |name: &str| super::Interface {
            name: name.to_owned(),
            dhcp_v4: true,
            dhcp_v6: false,
            addresses: Vec::new(),
            gateway_v4: None,
            gateway_v6: None,
            dns: Vec::new(),
            routes: Vec::new(),
            vlan: None,
            bridge: None,
        };
        let unsorted = super::Model {
            interfaces: vec![iface("XXXXXXXXX"), iface("Pl")],
        };
        assert!(has(&unsorted, super::INTERFACE_ORDER, Severity::Error));
        let sorted = super::Model {
            interfaces: vec![iface("Pl"), iface("XXXXXXXXX")],
        };
        assert!(!has(&sorted, super::INTERFACE_ORDER, Severity::Error));
    }

    #[test]
    fn validate_warns_static_no_gateway_dns_and_mixed() {
        let mut model = NetworkModule::defaults(&profile(Os::Linux));
        model.interfaces[0].dhcp_v4 = false;
        model.interfaces[0].dhcp_v6 = false;
        model.interfaces[0].addresses = vec!["192.168.1.10/24".to_owned()];
        // No gateway, no dns
        assert!(has(&model, STATIC_NO_GATEWAY, Severity::Warning));
        assert!(has(&model, STATIC_NO_DNS, Severity::Warning));
        model.interfaces[0].gateway_v4 = Some("192.168.1.1".to_owned());
        model.interfaces[0].dns = vec!["8.8.8.8".to_owned()];
        assert!(!has(&model, STATIC_NO_GATEWAY, Severity::Warning));
        assert!(!has(&model, STATIC_NO_DNS, Severity::Warning));
        // dhcp+static mixed
        model.interfaces[0].dhcp_v4 = true;
        assert!(has(&model, DHCP_STATIC_MIXED, Severity::Warning));
    }

    #[test]
    fn validate_recommends_ipv6_privacy_and_no_promisc() {
        let model = NetworkModule::defaults(&profile(Os::Linux));
        assert!(has(&model, REC_IPV6_PRIVACY, Severity::Recommendation));
        assert!(has(&model, REC_RA_ACCEPT, Severity::Recommendation));
        assert!(has(&model, REC_NO_PROMISC, Severity::Recommendation));
    }

    #[test]
    fn validate_flags_injection() {
        let mut model = NetworkModule::defaults(&profile(Os::Linux));
        model.interfaces[0].name = "a\nb".to_owned();
        assert!(has(&model, INJECTION, Severity::Error));
        model.interfaces[0].name = "eth0".to_owned();
        model.interfaces[0].addresses = vec!["192.168.1.10/24\0".to_owned()];
        assert!(has(&model, INJECTION, Severity::Error));
    }

    #[test]
    fn apply_rejects_injection_leaving_doc_untouched() -> Result<(), String> {
        let src = "[Match]\nName=eth0\n";
        let mut doc = NetworkModule::parse(src).map_err(|e| e.to_string())?;
        let mut model = NetworkModule::defaults(&profile(Os::Linux));
        model.interfaces[0].name = "a\nb".to_owned();
        assert!(NetworkModule::apply(&mut doc, &model).is_err());
        assert_eq!(NetworkModule::render(&doc), src);
        Ok(())
    }

    #[test]
    fn apply_rejects_vlan_out_of_range() -> Result<(), String> {
        let mut doc = NetworkModule::parse("").map_err(|e| e.to_string())?;
        let mut model = NetworkModule::defaults(&profile(Os::Linux));
        model.interfaces[0].vlan = Some(super::Vlan {
            link: "eth0".to_owned(),
            id: 5000,
        });
        assert!(NetworkModule::apply(&mut doc, &model).is_err());
        Ok(())
    }

    #[test]
    fn to_model_reads_networkd_and_ifupdown_and_netplan() -> Result<(), String> {
        // networkd
        let src = "[Match]\nName=eth0\n\n[Network]\nDHCP=no\nAddress=192.168.1.10/24\nGateway=192.168.1.1\nDNS=8.8.8.8\n";
        let doc = NetworkModule::parse(src).map_err(|e| e.to_string())?;
        let model = NetworkModule::to_model(&doc).map_err(|e| e.to_string())?;
        assert_eq!(model.interfaces.len(), 1);
        assert_eq!(model.interfaces[0].addresses, vec!["192.168.1.10/24"]);
        // ifupdown
        let src2 =
            "auto eth0\niface eth0 inet static\n\taddress 192.168.1.10/24\n\tgateway 192.168.1.1\n";
        let doc2 = NetworkModule::parse(src2).map_err(|e| e.to_string())?;
        let model2 = NetworkModule::to_model(&doc2).map_err(|e| e.to_string())?;
        assert_eq!(model2.interfaces[0].addresses, vec!["192.168.1.10/24"]);
        // netplan
        let src3 = "network:\n  version: 2\n  ethernets:\n    eth0:\n      dhcp4: false\n      addresses:\n        - 192.168.1.10/24\n      gateway4: 192.168.1.1\n";
        let doc3 = NetworkModule::parse(src3).map_err(|e| e.to_string())?;
        let model3 = NetworkModule::to_model(&doc3).map_err(|e| e.to_string())?;
        assert_eq!(model3.interfaces[0].addresses, vec!["192.168.1.10/24"]);
        Ok(())
    }

    #[test]
    fn apply_is_noop_on_fresh_copy() -> Result<(), String> {
        let src = "[Match]\nName=eth0\n\n[Network]\nDHCP=yes\n";
        let mut doc = NetworkModule::parse(src).map_err(|e| e.to_string())?;
        let model = NetworkModule::to_model(&doc).map_err(|e| e.to_string())?;
        let report = NetworkModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report, EditReport::default());
        assert_eq!(NetworkModule::render(&doc), src);
        Ok(())
    }

    #[test]
    fn deleting_the_first_entry_rewrites_no_other_line() -> Result<(), String> {
        // networkd (sections) and ifupdown (no sections) take different paths.
        for (src, want) in [
            (
                "[Match]\nName=eth0\n\n[Network]\nDHCP=no\nAddress=10.0.0.1/24\nAddress=10.0.0.2/24\nDNS=1.1.1.1\n",
                "[Match]\nName=eth0\n\n[Network]\nDHCP=no\nAddress=10.0.0.2/24\nDNS=1.1.1.1\n",
            ),
            (
                "auto eth0\niface eth0 inet static\n\taddress 10.0.0.1/24\n\taddress 10.0.0.2/24\n\tgateway 10.0.0.9\n",
                "auto eth0\niface eth0 inet static\n\taddress 10.0.0.2/24\n\tgateway 10.0.0.9\n",
            ),
        ] {
            let mut doc = NetworkModule::parse(src).map_err(|e| e.to_string())?;
            let mut model = NetworkModule::to_model(&doc).map_err(|e| e.to_string())?;
            model.interfaces[0].addresses.remove(0);
            let report = NetworkModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
            assert_eq!(
                report,
                EditReport {
                    changed_lines: 0,
                    added: 0,
                    removed: 1,
                },
                "{src:?}"
            );
            assert_eq!(NetworkModule::render(&doc), want);
        }
        Ok(())
    }

    /// The fastest of three runs of `apply` with an empty model on `unit`
    /// repeated `times` times. Checks that every line goes.
    fn time_empty_apply(unit: &str, times: usize) -> Result<std::time::Duration, String> {
        let src = unit.repeat(times);
        let mut fastest = std::time::Duration::MAX;
        for _ in 0..3 {
            let mut doc = NetworkModule::parse(&src).map_err(|e| e.to_string())?;
            let lines = doc.len();
            let started = std::time::Instant::now();
            let report = NetworkModule::apply(&mut doc, &super::Model::default())
                .map_err(|e| e.to_string())?;
            fastest = fastest.min(started.elapsed());
            assert_eq!(report.removed, lines, "{unit:?}");
            assert_eq!(NetworkModule::render(&doc), "");
        }
        Ok(fastest)
    }

    #[test]
    fn apply_is_linear_in_file_size() -> Result<(), String> {
        // M21: ten times the lines must cost far less than a hundred times the
        // time. Linear work gives a ratio near 10, quadratic work near 100. A
        // ratio, not an absolute bound, so a slow or loaded runner still passes.
        // networkd takes the section-aware path, ifupdown the other one.
        for unit in [
            "[Match]\nName=eth0\n[Network]\nDHCP=yes\n",
            "auto eth0\niface eth0 inet dhcp\n",
        ] {
            let per_unit = unit.lines().count();
            let small = time_empty_apply(unit, 5_000 / per_unit)?;
            let large = time_empty_apply(unit, 50_000 / per_unit)?;
            assert!(
                large < small.saturating_mul(30),
                "{unit:?}: 5k lines took {small:?}, 50k lines took {large:?}"
            );
        }
        Ok(())
    }

    /// The flat edit (used for every flavor except sectioned networkd)
    /// must: skip a non-directive line without touching it, remove a surplus
    /// existing directive that has no planned counterpart, replace a
    /// directive whose text changed, and leave an unchanged one alone — all
    /// in one pass.
    #[test]
    fn positional_apply_skips_removes_and_replaces() -> Result<(), String> {
        let mut doc = NetworkModule::parse(
            "auto eth0\niface eth0 inet static\n\taddress 10.0.0.5/24\n\taddress 10.0.0.6/24\n# keep me\n\tgateway 10.0.0.9\n",
        )
        .map_err(|e| e.to_string())?;
        assert_eq!(detect_flavor(&doc), super::BackendFlavor::Ifupdown);
        let model = super::Model {
            interfaces: vec![super::Interface {
                name: "eth0".to_owned(),
                dhcp_v4: false,
                dhcp_v6: false,
                addresses: vec!["10.0.0.7/24".to_owned()],
                gateway_v4: Some("10.0.0.9".to_owned()),
                gateway_v6: None,
                dns: Vec::new(),
                routes: Vec::new(),
                vlan: None,
                bridge: None,
            }],
        };
        let report = NetworkModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report.removed, 1, "the surplus address line is removed");
        assert_eq!(
            report.changed_lines, 1,
            "only the changed address line is rewritten, not the gateway"
        );
        assert_eq!(report.added, 0);
        let rendered = NetworkModule::render(&doc);
        assert!(
            rendered.contains("# keep me"),
            "the comment line is not a directive and must survive verbatim: {rendered:?}"
        );
        assert_eq!(
            rendered,
            "auto eth0\niface eth0 inet static\n\taddress 10.0.0.7/24\n# keep me\n\tgateway 10.0.0.9\n"
        );
        Ok(())
    }

    /// A directive-shaped line that appears before any recognised networkd
    /// section header is not "in" any section, so the section-aware editor
    /// must leave it exactly as it found it instead of pairing or removing
    /// it.
    #[test]
    fn networkd_sections_leave_a_headerless_directive_verbatim() -> Result<(), String> {
        let mut doc = NetworkModule::parse("DHCP=yes\n[Match]\nName=eth0\n\n[Network]\nDHCP=yes\n")
            .map_err(|e| e.to_string())?;
        let mut model = NetworkModule::to_model(&doc).map_err(|e| e.to_string())?;
        model.interfaces[0].dhcp_v4 = false;
        model.interfaces[0].dhcp_v6 = false;
        NetworkModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        let rendered = NetworkModule::render(&doc);
        assert!(
            rendered.starts_with("DHCP=yes\n"),
            "the headerless line must survive untouched: {rendered:?}"
        );
        assert!(rendered.contains("DHCP=no"));
        Ok(())
    }

    /// A directive of another backend inside a networkd file (a
    /// `NetworkManager` section header, an ifupdown line) is not managed by
    /// the section-aware editor: it stays where it is, byte for byte.
    #[test]
    fn networkd_sections_leave_foreign_directives_verbatim() -> Result<(), String> {
        let src = "[Match]\nName=eth0\n\n[Network]\nDHCP=yes\nauto eth0\n[ipv4]\n";
        let mut doc = NetworkModule::parse(src).map_err(|e| e.to_string())?;
        assert_eq!(detect_flavor(&doc), super::BackendFlavor::Networkd);
        let mut model = NetworkModule::to_model(&doc).map_err(|e| e.to_string())?;
        model.interfaces[0].dhcp_v4 = false;
        model.interfaces[0].dhcp_v6 = false;
        let report = NetworkModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(
            report,
            EditReport {
                changed_lines: 1,
                added: 0,
                removed: 0,
            }
        );
        assert_eq!(
            NetworkModule::render(&doc),
            "[Match]\nName=eth0\n\n[Network]\nDHCP=no\nauto eth0\n[ipv4]\n"
        );
        Ok(())
    }

    /// An existing directive inside a managed section that the new model no
    /// longer wants (no planned counterpart in its scope group) is removed,
    /// not left behind or overwritten.
    #[test]
    fn networkd_sections_remove_an_existing_directive_with_no_planned_partner() -> Result<(), String>
    {
        let mut doc =
            NetworkModule::parse("[Match]\nName=eth0\n\n[Network]\nDHCP=yes\nAddress=1.2.3.4/24\n")
                .map_err(|e| e.to_string())?;
        let mut model = NetworkModule::to_model(&doc).map_err(|e| e.to_string())?;
        assert_eq!(model.interfaces[0].addresses, vec!["1.2.3.4/24".to_owned()]);
        model.interfaces[0].addresses.clear();
        let report = NetworkModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert!(report.removed > 0);
        let rendered = NetworkModule::render(&doc);
        assert!(!rendered.contains("1.2.3.4/24"));
        let back = NetworkModule::to_model(&doc).map_err(|e| e.to_string())?;
        assert!(back.interfaces[0].addresses.is_empty());
        Ok(())
    }

    /// A surplus planned directive whose group has no existing line at all
    /// (so its search for a placed predecessor exhausts every earlier
    /// planned index without a match) goes to the end-of-file buffer; one
    /// whose search finds an already-placed predecessor is spliced in right
    /// after it, shifting every later placement along. Both paths run in the
    /// same edit here, and the resulting reorder does not read back to the
    /// same model, which the section-aware editor must refuse rather than
    /// silently accept.
    #[test]
    fn networkd_sections_surplus_without_a_predecessor_refuses_a_lossy_reorder()
    -> Result<(), String> {
        let mut doc =
            NetworkModule::parse("[Network]\nDHCP=no\nDNS=1.1.1.1\n").map_err(|e| e.to_string())?;
        let model = super::Model {
            interfaces: vec![super::Interface {
                name: "eth0".to_owned(),
                dhcp_v4: false,
                dhcp_v6: false,
                addresses: vec!["10.0.0.9/24".to_owned()],
                gateway_v4: None,
                gateway_v6: None,
                dns: vec!["1.1.1.1".to_owned()],
                routes: Vec::new(),
                vlan: None,
                bridge: None,
            }],
        };
        assert_eq!(detect_flavor(&doc), super::BackendFlavor::Networkd);
        let err = NetworkModule::apply(&mut doc, &model);
        assert!(
            matches!(&err, Err(super::EditError::Unsupported { message }) if message.contains("round-trip")),
            "expected a round-trip refusal, got {err:?}"
        );
        Ok(())
    }

    /// A refused section-aware edit leaves the document as it was, as the
    /// flat edit does: the caller must not see a half-edited file.
    #[test]
    fn networkd_sections_refusal_leaves_the_document_untouched() -> Result<(), String> {
        let src = "[Network]\nDHCP=no\nDNS=1.1.1.1\n";
        let mut doc = NetworkModule::parse(src).map_err(|e| e.to_string())?;
        // `[Match]` is new and has no predecessor, so it lands at the end,
        // after the `[Network]` it should precede: the round-trip check
        // refuses.
        let model = super::Model {
            interfaces: vec![super::Interface {
                name: "eth0".to_owned(),
                dhcp_v4: false,
                dhcp_v6: false,
                addresses: vec!["10.0.0.9/24".to_owned()],
                gateway_v4: None,
                gateway_v6: None,
                dns: vec!["1.1.1.1".to_owned()],
                routes: Vec::new(),
                vlan: None,
                bridge: None,
            }],
        };
        assert!(matches!(
            NetworkModule::apply(&mut doc, &model),
            Err(super::EditError::Unsupported { message }) if message.contains("round-trip")
        ));
        assert_eq!(NetworkModule::render(&doc), src);
        Ok(())
    }

    #[test]
    fn apply_edits_all_four_flavors() -> Result<(), String> {
        // networkd edit
        let mut doc = NetworkModule::parse("[Match]\nName=eth0\n\n[Network]\nDHCP=yes\n")
            .map_err(|e| e.to_string())?;
        let mut model = NetworkModule::to_model(&doc).map_err(|e| e.to_string())?;
        model.interfaces[0].dhcp_v4 = false;
        model.interfaces[0].addresses = vec!["192.168.1.10/24".to_owned()];
        model.interfaces[0].gateway_v4 = Some("192.168.1.1".to_owned());
        let report = NetworkModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert!(report.added > 0 || report.removed > 0);
        let back = NetworkModule::to_model(&doc).map_err(|e| e.to_string())?;
        assert_eq!(back, model);
        Ok(())
    }

    #[test]
    fn at_least_one_edit_reaches_the_file() -> Result<(), String> {
        let mut doc = NetworkModule::parse("").map_err(|e| e.to_string())?;
        let model = NetworkModule::defaults(&profile(Os::Linux));
        let report = NetworkModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert!(report.added > 0, "defaults must add lines to an empty file");
        let rendered = NetworkModule::render(&doc);
        assert!(rendered.contains("eth0"));
        Ok(())
    }

    #[test]
    fn detect_flavor_works() -> Result<(), String> {
        let doc = NetworkModule::parse("[Match]\nName=eth0\n").map_err(|e| e.to_string())?;
        assert_eq!(detect_flavor(&doc), super::BackendFlavor::Networkd);
        let doc2 =
            NetworkModule::parse("auto eth0\niface eth0 inet dhcp\n").map_err(|e| e.to_string())?;
        assert_eq!(detect_flavor(&doc2), super::BackendFlavor::Ifupdown);
        let doc3 = NetworkModule::parse(
            "network:\n  version: 2\n  ethernets:\n    eth0:\n      dhcp4: true\n",
        )
        .map_err(|e| e.to_string())?;
        assert_eq!(detect_flavor(&doc3), super::BackendFlavor::Netplan);
        Ok(())
    }

    #[test]
    fn adversarial_inputs_round_trip() -> Result<(), String> {
        use std::fmt::Write as _;
        let long_line = format!("{}\n", "x".repeat(1024 * 1024));
        let mut many = String::new();
        for i in 0..5_000u32 {
            let _ = writeln!(many, "[Match]\nName=eth{i}\n");
        }
        for src in [
            "network:\n  version: 2\n",
            "auto eth0\niface eth0 inet dhcp\r\n",
            "\0\n",
            "\r\n",
            long_line.as_str(),
            many.as_str(),
            "\u{feff}network:\n  ethernets:\n    café:\n      dhcp4: true\n",
            "[Match]\rName=eth0\n[Network]\nDHCP=yes",
            "network:\n  ethernets:\n    eth0:\n      nameservers:\n        addresses:\n          - 8.8.8.8\n",
        ] {
            let mut doc = NetworkModule::parse(src).map_err(|e| e.to_string())?;
            assert_eq!(NetworkModule::render(&doc), src);
            let model = NetworkModule::to_model(&doc).map_err(|e| e.to_string())?;
            let report = NetworkModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
            assert_eq!(report, EditReport::default());
            assert_eq!(NetworkModule::render(&doc), src);
        }
        Ok(())
    }

    #[test]
    fn model_supports_debug_clone_default_and_serde() {
        let model = NetworkModule::defaults(&profile(Os::Linux));
        assert_eq!(model.clone(), model);
        assert!(format!("{model:?}").contains("eth0"));
        assert_eq!(
            super::Model::default(),
            super::Model {
                interfaces: Vec::new()
            }
        );
        let json = serde_json::to_value(&model).unwrap_or_default();
        assert_eq!(
            serde_json::from_value::<super::Model>(json).ok(),
            Some(model)
        );
        assert!(serde_json::from_str::<super::Interface>(r#"{"name":"eth0","dhcp_v4":true,"dhcp_v6":true,"addresses":[],"dns":[],"routes":[],"x":1}"#).is_err());
    }

    #[cfg(feature = "fuzzing")]
    #[test]
    fn arbitrary_builds_a_model() {
        use arbitrary::{Arbitrary, Unstructured};
        let data: Vec<u8> = (0u8..64).collect();
        let mut u = Unstructured::new(&data);
        assert!(super::Model::arbitrary(&mut u).is_ok());
        assert!(super::Interface::arbitrary(&mut u).is_ok());
        assert!(super::Route::arbitrary(&mut u).is_ok());
        assert!(super::Vlan::arbitrary(&mut u).is_ok());
        assert!(super::Bridge::arbitrary(&mut u).is_ok());
        assert!(<super::Model as Arbitrary>::size_hint(0).1.is_none());
    }
    #[test]
    fn ifupdown_guards_reject_malformed_stanzas() {
        // parse_ifupdown_auto: bare "auto", glued name, multiword name.
        assert_eq!(parse_ifupdown_auto("auto"), None);
        assert_eq!(parse_ifupdown_auto("autoeth0"), None);
        assert_eq!(parse_ifupdown_auto("auto a b"), None);
        assert_eq!(parse_ifupdown_auto("auto eth0"), Some("eth0".to_owned()));
        // parse_ifupdown_iface: bare, glued, wrong family, trailing junk.
        assert_eq!(parse_ifupdown_iface("iface"), None);
        assert_eq!(parse_ifupdown_iface("ifaceeth0"), None);
        assert_eq!(parse_ifupdown_iface("iface eth0 foo dhcp"), None);
        assert_eq!(parse_ifupdown_iface("iface eth0 inet dhcp extra"), None);
        assert_eq!(
            parse_ifupdown_iface("iface eth0 inet dhcp"),
            Some(("eth0".to_owned(), "dhcp".to_owned()))
        );
        // parse_ifupdown_option: indented stanza keywords are not options.
        assert_eq!(super::parse_ifupdown_option("  auto eth0"), None);
        assert_eq!(super::parse_ifupdown_option("  iface x"), None);
        assert_eq!(super::parse_ifupdown_option("  source foo"), None);
        assert_eq!(
            super::parse_ifupdown_option("\taddress 192.168.1.10"),
            Some(("address".to_owned(), "192.168.1.10".to_owned()))
        );
    }

    #[test]
    fn netplan_list_item_rejects_opaque_and_accepts_bare_dash() {
        assert_eq!(super::parse_netplan_list_item("  - &anchor"), None);
        assert_eq!(super::parse_netplan_list_item("  - *alias"), None);
        assert_eq!(super::parse_netplan_list_item("  - !tag"), None);
        let (indent, value) = super::parse_netplan_list_item("    -")
            .unwrap_or_else(|| panic!("bare dash must parse"));
        assert_eq!(indent, 4);
        assert!(value.is_empty());
        assert_eq!(super::parse_netplan_list_item("  not-a-list"), None);
    }

    #[test]
    fn cidr_and_ip_helpers_cover_families_and_prefix_bounds() {
        use super::{cidr_prefix, gateway_in_subnets, is_ipv6_str};
        assert!(is_valid_cidr("192.168.1.10/24"));
        assert!(is_valid_cidr("2001:db8::1/64"));
        assert!(!is_valid_cidr("no-slash"));
        assert!(!is_valid_cidr("/24"));
        assert!(!is_valid_cidr("192.168.1.10/"));
        assert!(!is_valid_cidr("999.1.1.1/24"));
        assert!(!is_valid_cidr("192.168.1.10/xx"));
        assert!(!is_valid_cidr("192.168.1.10/33"));
        assert!(!is_valid_cidr("2001:db8::1/129"));
        assert!(is_ipv6_str("2001:db8::1"));
        assert!(!is_ipv6_str("192.168.1.1"));
        assert_eq!(cidr_prefix("192.168.1.10/24"), Some(24));
        assert_eq!(cidr_prefix("no-slash"), None);
        // gateway containment: bad gateway, bad cidr entry, v6 pair, mismatch.
        assert!(!gateway_in_subnets(
            "not-an-ip",
            &["192.168.1.10/24".to_owned()]
        ));
        assert!(!gateway_in_subnets(
            "192.168.1.1",
            &["not-a-cidr".to_owned(), "999.1.1.1/24".to_owned()]
        ));
        assert!(gateway_in_subnets(
            "2001:db8::1",
            &["2001:db8::10/64".to_owned()]
        ));
        assert!(!gateway_in_subnets(
            "10.9.9.1",
            &["192.168.1.10/24".to_owned()]
        ));
        assert!(!gateway_in_subnets("::1", &["192.168.1.10/24".to_owned()]));
        // Prefix edge: 0 matches all, >32 v4 refuses, >128 v6 refuses.
        assert!(super::ips_in_same_subnet(
            "10.0.0.1".parse().unwrap_or_else(|_| panic!("ip")),
            "192.168.0.1".parse().unwrap_or_else(|_| panic!("ip")),
            0
        ));
        assert!(!super::ips_in_same_subnet(
            "10.0.0.1".parse().unwrap_or_else(|_| panic!("ip")),
            "10.0.0.2".parse().unwrap_or_else(|_| panic!("ip")),
            33
        ));
        assert!(!super::ips_in_same_subnet(
            "2001:db8::1".parse().unwrap_or_else(|_| panic!("ip")),
            "2001:db8::2".parse().unwrap_or_else(|_| panic!("ip")),
            129
        ));
        assert!(super::ips_in_same_subnet(
            "2001:db8::1".parse().unwrap_or_else(|_| panic!("ip")),
            "2001:db9::1".parse().unwrap_or_else(|_| panic!("ip")),
            0
        ));
    }
    #[test]
    fn netplan_full_doc_parses_gateways_dns_vlan_bridge_routes() -> Result<(), String> {
        let src = "network:\n  version: 2\n  ethernets:\n    eth0:\n      dhcp4: true\n      dhcp6: true\n      addresses:\n        - 192.168.1.10/24\n      gateway4: 192.168.1.1\n      gateway6: 2001:db8::1\n      nameservers:\n        addresses: [8.8.8.8, 2001:4860:4860::8888]\n      routes:\n        - to: 10.0.0.0/24\n          via: 192.168.1.254\n  vlans:\n    vlan10:\n      id: 10\n      link: eth0\n      addresses:\n        - 10.10.10.2/24\n  bridges:\n    br0:\n      interfaces: [eth0]\n      dhcp4: false\n      dhcp6: false\n      addresses:\n        - 192.168.2.10/24\n";
        let doc = NetworkModule::parse(src).map_err(|e| e.to_string())?;
        let model = NetworkModule::to_model(&doc).map_err(|e| e.to_string())?;
        assert_eq!(model.interfaces.len(), 3);
        let eth0 = model
            .interfaces
            .iter()
            .find(|i| i.name == "eth0")
            .unwrap_or_else(|| panic!("eth0 missing"));
        assert!(eth0.dhcp_v4 && eth0.dhcp_v6);
        assert_eq!(eth0.addresses, vec!["192.168.1.10/24"]);
        assert_eq!(eth0.gateway_v4.as_deref(), Some("192.168.1.1"));
        assert_eq!(eth0.gateway_v6.as_deref(), Some("2001:db8::1"));
        assert!(eth0.dns.contains(&"8.8.8.8".to_owned()));
        assert_eq!(eth0.routes.len(), 1);
        assert_eq!(eth0.routes[0].to, "10.0.0.0/24");
        assert_eq!(eth0.routes[0].via, "192.168.1.254");
        let vlan = model
            .interfaces
            .iter()
            .find(|i| i.name == "vlan10")
            .unwrap_or_else(|| panic!("vlan10 missing"));
        assert_eq!(
            vlan.vlan,
            Some(super::Vlan {
                link: "eth0".to_owned(),
                id: 10
            })
        );
        let br = model
            .interfaces
            .iter()
            .find(|i| i.name == "br0")
            .unwrap_or_else(|| panic!("br0 missing"));
        assert_eq!(
            br.bridge,
            Some(super::Bridge {
                members: vec!["eth0".to_owned()]
            })
        );
        // Round-trip: apply of own model is a noop.
        let mut doc2 = NetworkModule::parse(src).map_err(|e| e.to_string())?;
        let report = NetworkModule::apply(&mut doc2, &model).map_err(|e| e.to_string())?;
        assert_eq!(report, EditReport::default());
        Ok(())
    }

    #[test]
    fn netplan_block_nameservers_are_dns_not_interface_addresses() -> Result<(), String> {
        let src = "network:\n  ethernets:\n    eth0:\n      addresses:\n        - 192.0.2.10/24\n      nameservers:\n        addresses:\n          - 8.8.8.8\n          - 2001:4860:4860::8888\n";
        let doc = NetworkModule::parse(src).map_err(|e| e.to_string())?;
        let model = NetworkModule::to_model(&doc).map_err(|e| e.to_string())?;
        let eth0 = model
            .interfaces
            .iter()
            .find(|iface| iface.name == "eth0")
            .unwrap_or_else(|| panic!("eth0 missing"));
        assert_eq!(eth0.addresses, vec!["192.0.2.10/24"]);
        assert_eq!(eth0.dns, vec!["8.8.8.8", "2001:4860:4860::8888"]);
        Ok(())
    }

    #[test]
    fn netplan_inline_and_scalar_addresses_and_unknown_subtree() -> Result<(), String> {
        // Inline addresses list plus scalar address line.
        let src = "network:\n  version: 2\n  ethernets:\n    eth0:\n      addresses: [192.168.1.10/24]\n      gateway4: 192.168.1.1\n      routes:\n        - to: default\n";
        let doc = NetworkModule::parse(src).map_err(|e| e.to_string())?;
        let model = NetworkModule::to_model(&doc).map_err(|e| e.to_string())?;
        let eth0 = &model.interfaces[0];
        assert!(eth0.addresses.contains(&"192.168.1.10/24".to_owned()));
        assert_eq!(eth0.gateway_v4.as_deref(), Some("192.168.1.1"));
        let src2 =
            "network:\n  version: 2\n  ethernets:\n    eth0:\n      addresses: 192.168.5.5/24\n";
        let doc2 = NetworkModule::parse(src2).map_err(|e| e.to_string())?;
        let model2 = NetworkModule::to_model(&doc2).map_err(|e| e.to_string())?;
        assert!(
            model2.interfaces[0]
                .addresses
                .contains(&"192.168.5.5/24".to_owned())
        );
        // Unknown subtree (e.g. wifis) preserved byte-identical through apply.
        let src3 = "network:\n  version: 2\n  wifis:\n    wlan0:\n      access-points:\n        myssid:\n          password: secret\n  ethernets:\n    eth0:\n      dhcp4: true\n";
        let mut doc3 = NetworkModule::parse(src3).map_err(|e| e.to_string())?;
        let model3 = NetworkModule::to_model(&doc3).map_err(|e| e.to_string())?;
        let report3 = NetworkModule::apply(&mut doc3, &model3).map_err(|e| e.to_string())?;
        assert_eq!(report3, EditReport::default());
        assert!(NetworkModule::render(&doc3).contains("myssid"));
        // Inline `nameservers: [...]` maps straight to DNS; a block list under
        // `nameservers` does too (with bare dashes skipped); a bad `id` leaves
        // the VLAN unset but keeps the link.
        let src4 = "network:\n  version: 2\n  ethernets:\n    eth1:\n      nameservers: [8.8.8.8, 1.1.1.1]\n  vlans:\n    vlan9:\n      id: abc\n      link: eth1\n      nameservers:\n        -\n        - 9.9.9.9\n";
        let doc4 = NetworkModule::parse(src4).map_err(|e| e.to_string())?;
        let model4 = NetworkModule::to_model(&doc4).map_err(|e| e.to_string())?;
        let eth1 = model4
            .interfaces
            .iter()
            .find(|i| i.name == "eth1")
            .unwrap_or_else(|| panic!("eth1 missing"));
        assert_eq!(eth1.dns, vec!["8.8.8.8".to_owned(), "1.1.1.1".to_owned()]);
        let vlan9 = model4
            .interfaces
            .iter()
            .find(|i| i.name == "vlan9")
            .unwrap_or_else(|| panic!("vlan9 missing"));
        assert_eq!(
            vlan9.vlan,
            Some(super::Vlan {
                link: "eth1".to_owned(),
                id: 0
            })
        );
        assert_eq!(vlan9.dns, vec!["9.9.9.9".to_owned()]);

        // A bare `-` list item under a block `addresses:` is blank and must
        // be skipped, not pushed as an empty address.
        let src5 = "network:\n  version: 2\n  ethernets:\n    eth2:\n      addresses:\n        -\n        - 10.0.0.5/24\n";
        let doc5 = NetworkModule::parse(src5).map_err(|e| e.to_string())?;
        let model5 = NetworkModule::to_model(&doc5).map_err(|e| e.to_string())?;
        assert_eq!(
            model5.interfaces[0].addresses,
            vec!["10.0.0.5/24".to_owned()]
        );
        Ok(())
    }

    #[test]
    fn nm_and_ifupdown_docs_parse_all_leaves() -> Result<(), String> {
        // NetworkManager: v4 manual + v6 auto + dns; gateway rides the
        // `addresses` comma form (there is no `route1=` key in the subset).
        // Empty `;` parts and empty `,` gateways are skipped.
        let nm = "[connection]\nid=eth0\ntype=ethernet\n\n[ipv4]\nmethod=manual\naddresses=192.168.1.10/24,192.168.1.1;192.168.9.9/24,;\ngateway=192.168.1.1\ndns=8.8.8.8;1.1.1.1;\n\n[ipv6]\nmethod=auto\naddresses=2001:db8::10/64,fe80::1\ngateway=2001:db8::1\ndns=2001:4860:4860::8888;\n";
        let doc = NetworkModule::parse(nm).map_err(|e| e.to_string())?;
        let model = NetworkModule::to_model(&doc).map_err(|e| e.to_string())?;
        let eth0 = &model.interfaces[0];
        assert!(!eth0.dhcp_v4);
        assert!(eth0.dhcp_v6);
        assert!(eth0.addresses.contains(&"192.168.1.10/24".to_owned()));
        assert_eq!(eth0.gateway_v4.as_deref(), Some("192.168.1.1"));
        assert_eq!(eth0.gateway_v6.as_deref(), Some("2001:db8::1"));
        assert!(eth0.dns.contains(&"8.8.8.8".to_owned()));
        assert!(eth0.dns.contains(&"2001:4860:4860::8888".to_owned()));
        // `method=auto` on ipv4 and `method=manual` on ipv6.
        let nm2 = "[connection]\nid=eth1\n\n[ipv4]\nmethod=auto\n\n[ipv6]\nmethod=manual\n";
        let doc_m = NetworkModule::parse(nm2).map_err(|e| e.to_string())?;
        let model_m = NetworkModule::to_model(&doc_m).map_err(|e| e.to_string())?;
        assert!(model_m.interfaces[0].dhcp_v4);
        assert!(!model_m.interfaces[0].dhcp_v6);
        // ifupdown: v6 stanza, vlan, bridge, dns, inet6 dhcp, v6 gateway,
        // unknown-but-known-key options, bad vlan_id, and a stanza without `auto`.
        let ifup = "auto eth0\niface eth0 inet dhcp\niface eth0 inet6 dhcp\n\nauto vlan10\niface vlan10 inet static\n\taddress 10.0.0.2/24\n\tgateway 10.0.0.1\n\tvlan-raw-device eth0\n\tvlan_id 10\n\tvlan_id abc\n\nauto br0\niface br0 inet static\n\taddress 192.168.2.1/24\n\tgateway fe80::1\n\tbridge_ports eth0 eth1\n\tdns-nameservers 8.8.8.8\n\tmtu 1500\n\tup echo ignoring this\n\tup ip route add via 192.168.2.254\n\niface eth9 inet static\n\taddress 10.5.5.5/24\n";
        let doc2 = NetworkModule::parse(ifup).map_err(|e| e.to_string())?;
        let model2 = NetworkModule::to_model(&doc2).map_err(|e| e.to_string())?;
        let e0 = model2
            .interfaces
            .iter()
            .find(|i| i.name == "eth0")
            .unwrap_or_else(|| panic!("eth0 missing"));
        assert!(e0.dhcp_v6);
        assert!(e0.dhcp_v4);
        let v10 = model2
            .interfaces
            .iter()
            .find(|i| i.name == "vlan10")
            .unwrap_or_else(|| panic!("vlan10 missing"));
        assert_eq!(v10.vlan.as_ref().map(|v| v.id), Some(10));
        assert_eq!(v10.vlan.as_ref().map(|v| v.link.as_str()), Some("eth0"));
        let br = model2
            .interfaces
            .iter()
            .find(|i| i.name == "br0")
            .unwrap_or_else(|| panic!("br0 missing"));
        assert_eq!(br.bridge.as_ref().map(|b| b.members.len()), Some(2));
        assert!(br.dns.contains(&"8.8.8.8".to_owned()));
        assert_eq!(br.gateway_v6.as_deref(), Some("fe80::1"));
        // `iface` stanza without a preceding `auto` still creates the interface.
        let eth9 = model2
            .interfaces
            .iter()
            .find(|i| i.name == "eth9")
            .unwrap_or_else(|| panic!("eth9 missing"));
        assert_eq!(eth9.addresses, vec!["10.5.5.5/24".to_owned()]);
        Ok(())
    }

    #[test]
    fn networkd_dhcp_variants_and_gateway_split() -> Result<(), String> {
        for (dhcp, v4, v6) in [
            ("ipv4", true, false),
            ("ipv6", false, true),
            ("no", false, false),
            ("false", false, false),
            ("true", true, true),
        ] {
            let src = format!("[Match]\nName=eth0\n\n[Network]\nDHCP={dhcp}\n");
            let doc = NetworkModule::parse(&src).map_err(|e| e.to_string())?;
            let model = NetworkModule::to_model(&doc).map_err(|e| e.to_string())?;
            assert_eq!(model.interfaces[0].dhcp_v4, v4, "{dhcp}");
            assert_eq!(model.interfaces[0].dhcp_v6, v6, "{dhcp}");
        }
        // A [Route] Gateway fills only the route's via; the interface
        // gateway stays None (the Gateway arm skips the Route section).
        let src = "[Match]\nName=eth0\n\n[Network]\nDHCP=no\nAddress=192.168.1.10/24\nDNS=8.8.8.8, 1.1.1.1\n\n[Route]\nDestination=10.0.0.0/24\nGateway=192.168.1.254\n";
        let doc = NetworkModule::parse(src).map_err(|e| e.to_string())?;
        let model = NetworkModule::to_model(&doc).map_err(|e| e.to_string())?;
        assert_eq!(model.interfaces[0].gateway_v4, None);
        assert_eq!(model.interfaces[0].dns.len(), 2);
        assert_eq!(model.interfaces[0].routes.len(), 1);
        assert_eq!(model.interfaces[0].routes[0].via, "192.168.1.254");
        // A bad `[VLAN] Id=` leaves the VLAN unset.
        let src_v = "[Match]\nName=eth0\n\n[VLAN]\nId=abc\n";
        let doc_v = NetworkModule::parse(src_v).map_err(|e| e.to_string())?;
        let model_v = NetworkModule::to_model(&doc_v).map_err(|e| e.to_string())?;
        assert_eq!(model_v.interfaces[0].vlan, None);
        // A [Network] Gateway alone fills the interface gateway.
        let src_gw = "[Match]\nName=eth0\n\n[Network]\nDHCP=no\nGateway=192.168.1.1\n";
        let doc_gw = NetworkModule::parse(src_gw).map_err(|e| e.to_string())?;
        let model_gw = NetworkModule::to_model(&doc_gw).map_err(|e| e.to_string())?;
        assert_eq!(
            model_gw.interfaces[0].gateway_v4.as_deref(),
            Some("192.168.1.1")
        );
        let src6 = "[Match]\nName=eth0\n\n[Network]\nDHCP=no\nGateway=2001:db8::1\n";
        let doc6 = NetworkModule::parse(src6).map_err(|e| e.to_string())?;
        let model6 = NetworkModule::to_model(&doc6).map_err(|e| e.to_string())?;
        assert_eq!(
            model6.interfaces[0].gateway_v6.as_deref(),
            Some("2001:db8::1")
        );
        Ok(())
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn renderers_round_trip_vlan_bridge_routes_per_backend() -> Result<(), String> {
        // A model exercising vlan + bridge + routes through every backend.
        let model = super::Model {
            interfaces: vec![
                super::Interface {
                    name: "eth0".to_owned(),
                    dhcp_v4: false,
                    dhcp_v6: false,
                    addresses: vec!["192.168.1.10/24".to_owned(), "2001:db8::10/64".to_owned()],
                    gateway_v4: Some("192.168.1.1".to_owned()),
                    gateway_v6: Some("2001:db8::1".to_owned()),
                    dns: vec!["8.8.8.8".to_owned(), "2001:4860:4860::8888".to_owned()],
                    routes: vec![super::Route {
                        to: "10.0.0.0/24".to_owned(),
                        via: "192.168.1.254".to_owned(),
                    }],
                    vlan: None,
                    bridge: None,
                },
                super::Interface {
                    name: "vlan10".to_owned(),
                    dhcp_v4: false,
                    dhcp_v6: false,
                    addresses: vec!["10.10.10.2/24".to_owned()],
                    gateway_v4: Some("10.10.10.1".to_owned()),
                    gateway_v6: Some("2001:db8:10::1".to_owned()),
                    dns: vec!["10.10.10.53".to_owned()],
                    routes: Vec::new(),
                    vlan: Some(super::Vlan {
                        link: "eth0".to_owned(),
                        id: 10,
                    }),
                    bridge: None,
                },
                super::Interface {
                    name: "br0".to_owned(),
                    dhcp_v4: false,
                    dhcp_v6: false,
                    addresses: vec!["192.168.2.10/24".to_owned()],
                    gateway_v4: None,
                    gateway_v6: None,
                    dns: vec!["192.168.2.53".to_owned()],
                    routes: Vec::new(),
                    vlan: None,
                    bridge: Some(super::Bridge {
                        members: vec!["eth0".to_owned()],
                    }),
                },
                // A bridge with no addresses exercises the empty-addresses
                // render path.
                super::Interface {
                    name: "br1".to_owned(),
                    dhcp_v4: false,
                    dhcp_v6: false,
                    addresses: Vec::new(),
                    gateway_v4: None,
                    gateway_v6: None,
                    dns: Vec::new(),
                    routes: Vec::new(),
                    vlan: None,
                    bridge: Some(super::Bridge {
                        members: vec!["eth0".to_owned()],
                    }),
                },
            ],
        };
        // networkd seed: a `.network` file cannot hold a bridge, so the
        // model is refused and the file is left as it was.
        let seed = "[Match]\nName=eth0\n\n[Network]\nDHCP=no\n";
        let mut doc = NetworkModule::parse(seed).map_err(|e| e.to_string())?;
        assert!(matches!(
            NetworkModule::apply(&mut doc, &model),
            Err(super::EditError::Unsupported { .. })
        ));
        assert_eq!(NetworkModule::render(&doc), seed);
        let mut bridgeless = model.clone();
        for iface in &mut bridgeless.interfaces {
            iface.bridge = None;
        }
        let report = NetworkModule::apply(&mut doc, &bridgeless).map_err(|e| e.to_string())?;
        assert!(report.added > 0);
        let rendered = NetworkModule::render(&doc);
        assert!(rendered.contains("[VLAN]"));
        assert!(rendered.contains("[Route]"));
        let back = NetworkModule::to_model(&doc).map_err(|e| e.to_string())?;
        assert_eq!(back.interfaces.len(), 4);
        // Routes and bridges have no keyfile form, so NM refuses them rather
        // than drop them. Addresses and interface shape survive the NM round
        // trip.
        let mut nm = NetworkModule::parse("[connection]\nid=eth0\n").map_err(|e| e.to_string())?;
        assert!(matches!(
            NetworkModule::apply(&mut nm, &model),
            Err(super::EditError::Unsupported { .. })
        ));
        assert_eq!(NetworkModule::render(&nm), "[connection]\nid=eth0\n");
        let mut routeless = bridgeless.clone();
        for iface in &mut routeless.interfaces {
            iface.routes.clear();
        }
        // A keyfile does not read back `[vlan]`, and `method=auto` on an
        // address-less interface reads back as DHCP: refused, file untouched.
        assert!(matches!(
            NetworkModule::apply(&mut nm, &routeless),
            Err(super::EditError::Unsupported { .. })
        ));
        assert_eq!(NetworkModule::render(&nm), "[connection]\nid=eth0\n");
        routeless.interfaces.truncate(1);
        NetworkModule::apply(&mut nm, &routeless).map_err(|e| e.to_string())?;
        let nm_rendered = NetworkModule::render(&nm);
        assert!(!nm_rendered.contains("[bridge]"));
        assert!(nm_rendered.contains("method=manual"));
        let nm_back = NetworkModule::to_model(&nm).map_err(|e| e.to_string())?;
        assert_eq!(nm_back, routeless);
        // ifupdown seed: vlan/bridge stanzas + v6 block + route up-lines.
        // An IPv6 gateway with no IPv6 address has no stanza to live in, so
        // vlan10's is refused; without it the model applies.
        let mut ifup = NetworkModule::parse("auto eth0\n").map_err(|e| e.to_string())?;
        assert!(matches!(
            NetworkModule::apply(&mut ifup, &model),
            Err(super::EditError::Unsupported { .. })
        ));
        assert_eq!(NetworkModule::render(&ifup), "auto eth0\n");
        let mut ifup_model = model.clone();
        ifup_model.interfaces[1].gateway_v6 = None;
        NetworkModule::apply(&mut ifup, &ifup_model).map_err(|e| e.to_string())?;
        let ifup_rendered = NetworkModule::render(&ifup);
        assert!(ifup_rendered.contains("vlan-raw-device eth0"));
        assert!(ifup_rendered.contains("bridge_ports eth0"));
        assert!(ifup_rendered.contains("inet6 static"));
        assert!(ifup_rendered.contains("up ip route add"));
        // netplan seed: empty doc renders networkd, so parse netplan first.
        let mut netplan_doc =
            NetworkModule::parse("network:\n  version: 2\n").map_err(|e| e.to_string())?;
        NetworkModule::apply(&mut netplan_doc, &model).map_err(|e| e.to_string())?;
        let netplan_text = NetworkModule::render(&netplan_doc);
        assert!(netplan_text.contains("vlans:"));
        assert!(netplan_text.contains("bridges:"));
        assert!(netplan_text.contains("gateway6:"));
        let netplan_model = NetworkModule::to_model(&netplan_doc).map_err(|e| e.to_string())?;
        assert_eq!(netplan_model.interfaces.len(), 4);
        Ok(())
    }

    #[test]
    fn netplan_writes_routes_and_gateways_for_bridges_and_vlans() -> Result<(), String> {
        let route = |to: &str, via: &str| super::Route {
            to: to.to_owned(),
            via: via.to_owned(),
        };
        let model = super::Model {
            interfaces: vec![
                super::Interface {
                    name: "br0".to_owned(),
                    dhcp_v4: false,
                    dhcp_v6: false,
                    addresses: vec!["192.168.2.10/24".to_owned(), "2001:db8:2::10/64".to_owned()],
                    gateway_v4: Some("192.168.2.1".to_owned()),
                    gateway_v6: Some("2001:db8:2::1".to_owned()),
                    dns: vec!["192.168.2.53".to_owned()],
                    routes: vec![route("10.2.0.0/16", "192.168.2.254")],
                    vlan: None,
                    bridge: Some(super::Bridge {
                        members: vec!["eth0".to_owned()],
                    }),
                },
                super::Interface {
                    name: "eth0".to_owned(),
                    dhcp_v4: true,
                    dhcp_v6: false,
                    addresses: Vec::new(),
                    gateway_v4: None,
                    gateway_v6: None,
                    dns: Vec::new(),
                    routes: Vec::new(),
                    vlan: None,
                    bridge: None,
                },
                super::Interface {
                    name: "vlan10".to_owned(),
                    dhcp_v4: false,
                    dhcp_v6: false,
                    addresses: vec!["10.10.10.2/24".to_owned()],
                    gateway_v4: Some("10.10.10.1".to_owned()),
                    gateway_v6: None,
                    dns: Vec::new(),
                    routes: vec![route("10.20.0.0/16", "10.10.10.254")],
                    vlan: Some(super::Vlan {
                        link: "eth0".to_owned(),
                        id: 10,
                    }),
                    bridge: None,
                },
            ],
        };
        let mut doc =
            NetworkModule::parse("network:\n  version: 2\n").map_err(|e| e.to_string())?;
        NetworkModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        let back = NetworkModule::to_model(&doc).map_err(|e| e.to_string())?;
        assert_eq!(back, model, "{}", NetworkModule::render(&doc));
        Ok(())
    }

    #[test]
    fn flavor_detection_and_empty_model_render() -> Result<(), String> {
        use super::BackendFlavor;
        // Majority wins; tie goes networkd; empty/all-unknown defaults networkd.
        let nm_heavy = NetworkModule::parse(
            "[connection]\nid=a\n[ipv4]\nmethod=auto\n[ipv6]\nmethod=auto\n[Match]\nName=x\n",
        )
        .map_err(|e| e.to_string())?;
        assert_eq!(detect_flavor(&nm_heavy), BackendFlavor::NetworkManager);
        let empty = NetworkModule::parse("").map_err(|e| e.to_string())?;
        assert_eq!(detect_flavor(&empty), BackendFlavor::Networkd);
        let unknown = NetworkModule::parse("garbage line\n").map_err(|e| e.to_string())?;
        assert_eq!(detect_flavor(&unknown), BackendFlavor::Networkd);
        // Empty model renders the netplan header only.
        let lines = super::render_netplan(&super::Model::default()).map_err(|e| e.to_string())?;
        assert_eq!(
            lines,
            vec!["network:".to_owned(), "  version: 2".to_owned()]
        );
        // `DHCP=ipv4` arm: v4-only DHCP renders distinctly.
        let mut v4only = NetworkModule::defaults(&profile(Os::Linux));
        v4only.interfaces[0].dhcp_v6 = false;
        let lines = super::render_model_lines(super::BackendFlavor::Networkd, &v4only)
            .map_err(|e| e.to_string())?;
        assert!(lines.iter().any(|l| l == "DHCP=ipv4"));
        v4only.interfaces[0].dhcp_v6 = true;
        // ifupdown needs a separate inet6 stanza for DHCPv6.
        let lines = super::render_ifupdown(&v4only.interfaces[0]).map_err(|e| e.to_string())?;
        assert!(lines.iter().any(|l| l == "iface eth0 inet dhcp"));
        assert!(lines.iter().any(|l| l == "iface eth0 inet6 dhcp"));
        // NetworkManager writes DHCPv6 as `[ipv6]` `method=auto`.
        let nm = "[connection]\nid=eth0\n";
        assert!(assert_apply_keeps_model(nm, &v4only)?);
        Ok(())
    }

    /// `render_netplan` iterates every ethernet and every VLAN interface in
    /// turn; each one independently decides whether it has routes/addresses
    /// to render. A model mixing an interface that has them with one that
    /// does not, in both sections, exercises the "nothing to render for this
    /// one" fall-through for the second interface in each loop.
    #[test]
    fn render_netplan_without_a_plain_ethernet_writes_no_ethernets_key() -> Result<(), String> {
        let model = super::Model {
            interfaces: vec![super::Interface {
                name: "vlan10".to_owned(),
                dhcp_v4: true,
                dhcp_v6: false,
                addresses: Vec::new(),
                gateway_v4: None,
                gateway_v6: None,
                dns: Vec::new(),
                routes: Vec::new(),
                vlan: Some(super::Vlan {
                    link: "eth0".to_owned(),
                    id: 10,
                }),
                bridge: None,
            }],
        };
        let lines = super::render_netplan(&model).map_err(|e| e.to_string())?;
        assert!(!lines.iter().any(|l| l == "  ethernets:"), "{lines:?}");
        assert!(lines.iter().any(|l| l == "  vlans:"), "{lines:?}");
        Ok(())
    }

    #[test]
    fn render_netplan_handles_interfaces_with_and_without_extras() -> Result<(), String> {
        let model = super::Model {
            interfaces: vec![
                super::Interface {
                    name: "eth0".to_owned(),
                    dhcp_v4: false,
                    dhcp_v6: false,
                    addresses: vec!["10.0.0.2/24".to_owned()],
                    gateway_v4: None,
                    gateway_v6: None,
                    dns: Vec::new(),
                    routes: vec![super::Route {
                        to: "10.0.0.0/24".to_owned(),
                        via: "10.0.0.1".to_owned(),
                    }],
                    vlan: None,
                    bridge: None,
                },
                super::Interface {
                    name: "eth1".to_owned(),
                    dhcp_v4: true,
                    dhcp_v6: false,
                    addresses: Vec::new(),
                    gateway_v4: None,
                    gateway_v6: None,
                    dns: Vec::new(),
                    routes: Vec::new(),
                    vlan: None,
                    bridge: None,
                },
                super::Interface {
                    name: "vlan10".to_owned(),
                    dhcp_v4: false,
                    dhcp_v6: false,
                    addresses: vec!["10.10.10.2/24".to_owned()],
                    gateway_v4: None,
                    gateway_v6: None,
                    dns: Vec::new(),
                    routes: Vec::new(),
                    vlan: Some(super::Vlan {
                        link: "eth0".to_owned(),
                        id: 10,
                    }),
                    bridge: None,
                },
                super::Interface {
                    name: "vlan20".to_owned(),
                    dhcp_v4: true,
                    dhcp_v6: false,
                    addresses: Vec::new(),
                    gateway_v4: None,
                    gateway_v6: None,
                    dns: Vec::new(),
                    routes: Vec::new(),
                    vlan: Some(super::Vlan {
                        link: "eth0".to_owned(),
                        id: 20,
                    }),
                    bridge: None,
                },
            ],
        };
        let lines = super::render_netplan(&model).map_err(|e| e.to_string())?;
        // eth0 (has routes) and vlan10 (has addresses) still render them.
        assert!(lines.iter().any(|l| l == "      routes:"));
        assert!(lines.iter().any(|l| l == "        - 10.10.10.2/24"));
        // eth1 has no routes and vlan20 has no addresses: each interface's
        // stanza ends right at the next interface's, with nothing in between.
        let eth1_pos = lines
            .iter()
            .position(|l| l == "    eth1:")
            .ok_or("eth1 missing")?;
        let vlan10_pos = lines
            .iter()
            .position(|l| l == "    vlan10:")
            .ok_or("vlan10 missing")?;
        assert_eq!(
            &lines[eth1_pos..vlan10_pos],
            &[
                "    eth1:".to_owned(),
                "      dhcp4: true".to_owned(),
                "      dhcp6: false".to_owned(),
                "  vlans:".to_owned(),
            ]
        );
        let vlan20_pos = lines
            .iter()
            .position(|l| l == "    vlan20:")
            .ok_or("vlan20 missing")?;
        assert_eq!(
            &lines[vlan20_pos..],
            &[
                "    vlan20:".to_owned(),
                "      id: 20".to_owned(),
                "      link: eth0".to_owned(),
                "      dhcp4: true".to_owned(),
                "      dhcp6: false".to_owned(),
            ]
        );
        Ok(())
    }

    #[test]
    fn netplan_via_list_items_and_pending_routes() -> Result<(), String> {
        // `- via:` list items complete a pending `- to:`; when no route exists
        // yet a new one is pushed, and one after a completed route adds another.
        let src = "network:\n  version: 2\n  ethernets:\n    eth0:\n      routes:\n        - to: 10.0.0.0/24\n        - via: 192.168.1.254\n    eth1:\n      routes:\n        - to: 10.0.1.0/24\n          via: 192.168.1.1\n        - via: 192.168.1.9\n";
        let doc = NetworkModule::parse(src).map_err(|e| e.to_string())?;
        let model = NetworkModule::to_model(&doc).map_err(|e| e.to_string())?;
        let eth0 = model
            .interfaces
            .iter()
            .find(|i| i.name == "eth0")
            .unwrap_or_else(|| panic!("eth0 missing"));
        assert_eq!(
            eth0.routes,
            vec![super::Route {
                to: "10.0.0.0/24".to_owned(),
                via: "192.168.1.254".to_owned()
            }]
        );
        let eth1 = model
            .interfaces
            .iter()
            .find(|i| i.name == "eth1")
            .unwrap_or_else(|| panic!("eth1 missing"));
        assert_eq!(
            eth1.routes,
            vec![
                super::Route {
                    to: "10.0.1.0/24".to_owned(),
                    via: "192.168.1.1".to_owned()
                },
                super::Route {
                    to: "10.0.1.0/24".to_owned(),
                    via: "192.168.1.9".to_owned()
                }
            ]
        );
        // A networkd `[Route] Destination=` route (empty via) is completed in
        // place by a netplan `- via:` item when both flavors share one file.
        let src_m = "[Match]\nName=eth0\n\n[Route]\nDestination=10.0.0.0/24\n\nnetwork:\n  version: 2\n  ethernets:\n    eth0:\n      routes:\n        - to: 10.0.0.0/24\n        - via: 192.168.1.254\n";
        let doc_m = NetworkModule::parse(src_m).map_err(|e| e.to_string())?;
        let model_m = NetworkModule::to_model(&doc_m).map_err(|e| e.to_string())?;
        assert_eq!(
            model_m.interfaces[0].routes,
            vec![super::Route {
                to: "10.0.0.0/24".to_owned(),
                via: "192.168.1.254".to_owned()
            }]
        );
        // `- via:` with nothing pending and no interface pushes nothing; a
        // bare item under `routes:` is ignored; list items under unmodeled
        // parents (`interfaces:`) are ignored.
        let src2 = "network:\n  version: 2\n  routes:\n    - to: 10.0.0.0/24\n    - via: 192.168.1.254\n  ethernets:\n    eth2:\n      routes:\n        - via: 192.168.1.9\n        - 10.0.0.0/24\n      interfaces:\n        - eth0\n";
        let doc2 = NetworkModule::parse(src2).map_err(|e| e.to_string())?;
        let model2 = NetworkModule::to_model(&doc2).map_err(|e| e.to_string())?;
        let eth2 = model2
            .interfaces
            .iter()
            .find(|i| i.name == "eth2")
            .unwrap_or_else(|| panic!("eth2 missing"));
        assert!(eth2.routes.is_empty());
        assert!(eth2.bridge.is_none());
        Ok(())
    }

    #[test]
    fn backend_detect_matches_service_presence() {
        use super::{
            ifupdown_backend_detect, netplan_backend_detect, networkd_backend_detect,
            nm_backend_detect,
        };
        // No services at all: networkd is the fallback on Linux.
        assert!(networkd_backend_detect(&profile(Os::Linux)));
        let mut systemd = profile(Os::Linux);
        systemd
            .service_versions
            .insert("systemd-networkd".into(), "255".into());
        assert!(networkd_backend_detect(&systemd));
        let mut nm = profile(Os::Linux);
        nm.service_versions
            .insert("NetworkManager".into(), "1.0".into());
        assert!(nm_backend_detect(&nm));
        assert!(!nm_backend_detect(&profile(Os::Linux)));
        let mut ifup = profile(Os::Linux);
        ifup.service_versions
            .insert("ifupdown".into(), "1.0".into());
        assert!(ifupdown_backend_detect(&ifup));
        assert!(!ifupdown_backend_detect(&nm));
        assert!(ifupdown_backend_detect(&profile(Os::Linux)));
        let mut netplan = profile(Os::Linux);
        netplan
            .service_versions
            .insert("netplan.io".into(), "1.0".into());
        assert!(netplan_backend_detect(&netplan));
        assert!(!netplan_backend_detect(&profile(Os::Linux)));
        // Non-Linux hosts get nothing but netplan (service presence only).
        assert!(!networkd_backend_detect(&profile(Os::MacOs)));
        assert!(!ifupdown_backend_detect(&profile(Os::MacOs)));
    }

    #[test]
    fn route_renderers_refuse_what_is_not_a_destination_and_next_hop() -> Result<(), String> {
        let mut iface = NetworkModule::defaults(&profile(Os::Linux)).interfaces[0].clone();
        let route = |to: &str, via: &str| super::Route {
            to: to.to_owned(),
            via: via.to_owned(),
        };
        // ifupdown writes a shell command, so the renderer itself refuses a
        // `to` that is not a CIDR/IP/`default` and a `via` that is not an IP.
        for bad in [
            route("0.0.0.0/0; reboot", "192.168.1.1"),
            route("10.0.0.0/24", "192.168.1.1 dev eth1"),
            route("10.0.0.0/24", ""),
        ] {
            iface.routes = vec![bad];
            assert!(matches!(
                super::render_ifupdown(&iface),
                Err(super::EditError::Unsupported { .. })
            ));
        }
        iface.routes = vec![
            route("default", "192.168.1.1"),
            route("10.0.0.1", "10.0.0.2"),
        ];
        let lines = super::render_ifupdown(&iface).map_err(|e| e.to_string())?;
        assert!(lines.contains(&"\tup ip route add default via 192.168.1.1".to_owned()));
        // networkd and netplan write a direct route (empty `via`) but refuse
        // a malformed one; NM has no route form at all.
        iface.routes = vec![route("10.0.0.0/24", "")];
        assert!(super::render_networkd(&iface).is_ok());
        let direct = super::Model {
            interfaces: vec![iface.clone()],
        };
        assert!(super::render_netplan(&direct).is_ok());
        assert!(super::render_nm(&iface).is_err());
        iface.routes = vec![route("10.0.0.0/24#x", "")];
        assert!(super::render_networkd(&iface).is_err());
        let bad = super::Model {
            interfaces: vec![iface],
        };
        assert!(super::render_netplan(&bad).is_err());
        Ok(())
    }

    #[test]
    fn check_interface_refuses_each_malformed_field() {
        let good = NetworkModule::defaults(&profile(Os::Linux)).interfaces[0].clone();
        assert!(super::check_interface(&good).is_ok());
        let mut cases: Vec<super::Interface> = Vec::new();
        let mut iface = good.clone();
        iface.name = "eth0:1".to_owned();
        cases.push(iface);
        let mut iface = good.clone();
        iface.vlan = Some(super::Vlan {
            link: "#eth0".to_owned(),
            id: 10,
        });
        cases.push(iface);
        let mut iface = good.clone();
        iface.bridge = Some(super::Bridge {
            members: vec!["eth0".to_owned(), "eth1,eth2".to_owned()],
        });
        cases.push(iface);
        let mut iface = good.clone();
        iface.addresses = vec!["[192.168.1.10/24]".to_owned()];
        cases.push(iface);
        let mut iface = good.clone();
        iface.gateway_v4 = Some("2001:db8::1".to_owned());
        cases.push(iface);
        let mut iface = good.clone();
        iface.gateway_v6 = Some("192.168.1.1".to_owned());
        cases.push(iface);
        let mut iface = good;
        iface.dns = vec!["8.8.8.8 1.1.1.1".to_owned()];
        cases.push(iface);
        for iface in cases {
            let result = super::check_interface(&iface);
            assert!(
                matches!(result, Err(super::EditError::Unsupported { .. })),
                "{iface:?}"
            );
        }
    }

    #[test]
    fn a_document_with_a_refused_route_applies_only_its_own_model() -> Result<(), String> {
        // The file already holds a route the renderer would refuse: applying
        // its own model writes nothing (invariant 2), any other edit is
        // refused and leaves the text alone.
        let src = "auto eth0\niface eth0 inet static\n\tup ip route add 0.0.0.0/0; reboot via 192.168.1.1\n";
        let mut doc = NetworkModule::parse(src).map_err(|e| e.to_string())?;
        let mut model = NetworkModule::to_model(&doc).map_err(|e| e.to_string())?;
        assert_eq!(model.interfaces[0].routes[0].to, "0.0.0.0/0; reboot");
        let report = NetworkModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report, super::EditReport::default());
        model.interfaces[0].dhcp_v6 = true;
        assert!(NetworkModule::apply(&mut doc, &model).is_err());
        assert_eq!(NetworkModule::render(&doc), src);
        Ok(())
    }

    #[test]
    fn apply_rejects_a_valid_name_that_renders_an_unknown_line() -> Result<(), String> {
        // `-eth0` passes the name checks but renders `    -eth0:`, which
        // netplan's classifier leaves Unknown; the rendered-line check refuses it.
        let src = "network:\n  version: 2\n";
        let mut doc = NetworkModule::parse(src).map_err(|e| e.to_string())?;
        let mut model = NetworkModule::defaults(&profile(Os::Linux));
        model.interfaces[0].name = "-eth0".to_owned();
        assert!(matches!(
            NetworkModule::apply(&mut doc, &model),
            Err(super::EditError::Unsupported { message }) if message.starts_with("rendered line")
        ));
        assert_eq!(NetworkModule::render(&doc), src);
        Ok(())
    }

    #[test]
    fn apply_rejects_rendered_unknown_line() -> Result<(), String> {
        // A name with a space renders an unparseable ifupdown stanza.
        let mut doc = NetworkModule::parse("auto eth0\n").map_err(|e| e.to_string())?;
        let mut model = NetworkModule::defaults(&profile(Os::Linux));
        model.interfaces[0].name = "a b".to_owned();
        assert!(NetworkModule::apply(&mut doc, &model).is_err());
        assert_eq!(NetworkModule::render(&doc), "auto eth0\n");
        Ok(())
    }

    #[test]
    fn validate_flags_route_gateway_and_vlan_link_problems() {
        let mut model = NetworkModule::defaults(&profile(Os::Linux));
        // DNS injection
        model.interfaces[0].dns = vec!["8.8.8.8\n".to_owned()];
        assert!(has(&model, INJECTION, Severity::Error));
        model.interfaces[0].dns = vec!["8.8.8.8".to_owned()];
        // Route injection, invalid destination, invalid via
        model.interfaces[0].routes = vec![super::Route {
            to: "10.0.0.0/24\n".to_owned(),
            via: String::new(),
        }];
        assert!(has(&model, INJECTION, Severity::Error));
        model.interfaces[0].routes = vec![super::Route {
            to: "not-a-route".to_owned(),
            via: "not-an-ip".to_owned(),
        }];
        assert!(has(&model, INVALID_CIDR, Severity::Error));
        assert!(has(&model, INVALID_IP, Severity::Error));
        model.interfaces[0].routes = Vec::new();
        // Gateway v4 injection and invalid IP
        model.interfaces[0].gateway_v4 = Some("192.168.1.1\n".to_owned());
        assert!(has(&model, INJECTION, Severity::Error));
        model.interfaces[0].gateway_v4 = Some("not-an-ip".to_owned());
        assert!(has(&model, INVALID_IP, Severity::Error));
        // Gateway without addresses: no subnet complaint
        model.interfaces[0].addresses = Vec::new();
        model.interfaces[0].gateway_v4 = Some("192.168.1.1".to_owned());
        assert!(!has(&model, GATEWAY_OUTSIDE_SUBNET, Severity::Error));
        assert!(!has(&model, INVALID_IP, Severity::Error));
        // Gateway v6 with no addresses is likewise just skipped.
        model.interfaces[0].gateway_v6 = Some("2001:db8::1".to_owned());
        assert!(!has(&model, GATEWAY_OUTSIDE_SUBNET, Severity::Error));
        assert!(!has(&model, INVALID_IP, Severity::Error));
        // Gateway v6: injection, invalid, outside subnet
        model.interfaces[0].gateway_v6 = Some("fe80::1\n".to_owned());
        assert!(has(&model, INJECTION, Severity::Error));
        model.interfaces[0].gateway_v6 = Some("not-an-ip".to_owned());
        assert!(has(&model, INVALID_IP, Severity::Error));
        model.interfaces[0].addresses = vec!["2001:db8::10/64".to_owned()];
        model.interfaces[0].gateway_v6 = Some("fe80::1".to_owned());
        assert!(has(&model, GATEWAY_OUTSIDE_SUBNET, Severity::Error));
        model.interfaces[0].gateway_v6 = None;
        // VLAN link injection
        model.interfaces[0].vlan = Some(super::Vlan {
            link: "eth0\n".to_owned(),
            id: 10,
        });
        assert!(has(&model, INJECTION, Severity::Error));
    }

    /// Applies `model` to `src`; when the edit succeeds, the written text
    /// must read back as exactly `model` (invariant 3).
    fn assert_apply_keeps_model(src: &str, model: &super::Model) -> Result<bool, String> {
        let mut doc = NetworkModule::parse(src).map_err(|e| e.to_string())?;
        if NetworkModule::apply(&mut doc, model).is_err() {
            return Ok(false);
        }
        let rendered = NetworkModule::render(&doc);
        let reparsed = NetworkModule::parse(&rendered).map_err(|e| e.to_string())?;
        let back = NetworkModule::to_model(&reparsed).map_err(|e| e.to_string())?;
        assert_eq!(
            &back, model,
            "apply succeeded but lost state in {rendered:?}"
        );
        Ok(true)
    }

    /// Fuzz regression (`fuzz_network_edit`): a bridge applied to a document
    /// with no directives (networkd by default) was dropped by the renderer
    /// and the edit still succeeded. A backend that cannot hold a bridge must
    /// refuse it; netplan holds even an empty one.
    #[test]
    fn a_bridge_is_refused_where_the_backend_cannot_hold_it() -> Result<(), String> {
        let bridge = |members: &[&str]| super::Model {
            interfaces: vec![super::Interface {
                name: "br0".to_owned(),
                dhcp_v4: true,
                dhcp_v6: false,
                addresses: Vec::new(),
                gateway_v4: None,
                gateway_v6: None,
                dns: Vec::new(),
                routes: Vec::new(),
                vlan: None,
                bridge: Some(super::Bridge {
                    members: members.iter().map(|m| (*m).to_owned()).collect(),
                }),
            }],
        };
        let empty = bridge(&[]);
        let one = bridge(&["eth0"]);
        // networkd (the default for a document with no directives, and a
        // sectioned one), NetworkManager and ifupdown-without-members refuse.
        for (src, model) in [
            ("# /etc\n", &empty),
            ("# /etc\n", &one),
            ("[Match]\nName=eth0\n", &one),
            ("[connection]\nid=eth0\n", &one),
            ("auto eth0\n", &empty),
        ] {
            assert!(!assert_apply_keeps_model(src, model)?, "{src:?} accepted");
        }
        // ifupdown with members and netplan (even empty) hold the bridge.
        assert!(assert_apply_keeps_model("auto eth0\n", &one)?);
        let netplan = "network:\n  version: 2\n";
        assert!(assert_apply_keeps_model(netplan, &empty)?);
        Ok(())
    }

    /// Fuzz regression (`fuzz_network_roundtrip`): the no-op check read only
    /// the directive lines, so an unknown section header dropped out and
    /// `Name=eth5` under it counted as an interface. The check missed, the
    /// positional edit moved `Foo=bar:` into the YAML block, and the result
    /// read back with no interfaces. A document's own model is a no-op.
    #[test]
    fn a_mixed_document_applies_its_own_model_as_a_noop() -> Result<(), String> {
        let src = "[Match]\nName=eth1\n[Unknown]\nName=eth5\nFoo=bar:\nnetwork:\n  ethernets:\n    eth0:\n      dhcp4: true\n";
        let mut doc = NetworkModule::parse(src).map_err(|e| e.to_string())?;
        let model = NetworkModule::to_model(&doc).map_err(|e| e.to_string())?;
        assert_eq!(model.interfaces.len(), 2);
        let report = NetworkModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report, EditReport::default());
        assert_eq!(NetworkModule::render(&doc), src);
        assert!(assert_apply_keeps_model(src, &model)?);
        Ok(())
    }

    /// Fuzz regression (`fuzz_network_edit`): `iface <name> inet6 dhcp` also
    /// set IPv4 DHCP, so a DHCPv6-only interface applied to an ifupdown file
    /// read back with IPv4 DHCP on. The address family decides which flag a
    /// `dhcp` stanza sets, even for an interface named `inet6`.
    #[test]
    fn an_inet6_dhcp_stanza_enables_only_dhcpv6() -> Result<(), String> {
        let model = super::Model {
            interfaces: vec![super::Interface {
                name: "eth0".to_owned(),
                dhcp_v4: false,
                dhcp_v6: true,
                addresses: Vec::new(),
                gateway_v4: None,
                gateway_v6: None,
                dns: Vec::new(),
                routes: Vec::new(),
                vlan: None,
                bridge: None,
            }],
        };
        assert!(assert_apply_keeps_model("auto eth0\n", &model)?);
        let doc = NetworkModule::parse("iface inet6 inet dhcp\n").map_err(|e| e.to_string())?;
        let back = NetworkModule::to_model(&doc).map_err(|e| e.to_string())?;
        assert!(back.interfaces[0].dhcp_v4);
        assert!(!back.interfaces[0].dhcp_v6);
        Ok(())
    }

    /// Fuzz regression (`fuzz_network_edit`): the positional edit rewrote
    /// directives in place, so `Name=` landed under the unknown `[MatCP]`
    /// header and the interface read back as gone while the edit succeeded.
    /// An edit that does not read back as the model is refused.
    #[test]
    fn a_positional_edit_that_would_not_round_trip_is_refused() -> Result<(), String> {
        let model = super::Model {
            interfaces: vec![super::Interface {
                name: "eth1".to_owned(),
                dhcp_v4: false,
                dhcp_v6: false,
                addresses: Vec::new(),
                gateway_v4: None,
                gateway_v6: None,
                dns: Vec::new(),
                routes: Vec::new(),
                vlan: None,
                bridge: None,
            }],
        };
        let src = "[Detwork]\nDHCP=yes\n[MatCP]\nName=eth0\n";
        assert!(!assert_apply_keeps_model(src, &model)?);
        Ok(())
    }
}
