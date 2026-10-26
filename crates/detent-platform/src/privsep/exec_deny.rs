//! Directives that make a privileged daemon run or load code (STAGE3 H23).
//!
//! The monitor writes worker-supplied bytes to allow-listed files as root, and
//! content there can still execute as root: an smb.conf `root preexec`, a
//! dnsmasq `dhcp-script`, a Kea hook library, an ifupdown `up` line.
//! [`adds_exec_directive`] refuses a candidate that adds such a directive or
//! changes the value of one; directives already present may stay unchanged.
//!
//! Each file is read the way its daemon reads it (name normalisation, line
//! joins, comment rules), and every choice errs toward refusal: a false
//! positive costs the operator a hand edit, a false negative is root.

/// Whether `candidate` holds an execution directive, name and value, that
/// `previous` does not hold as many times.
#[must_use]
pub fn adds_exec_directive(module: &str, previous: &[u8], candidate: &[u8]) -> bool {
    let mut before = exec_directives(module, &String::from_utf8_lossy(previous));
    exec_directives(module, &String::from_utf8_lossy(candidate))
        .into_iter()
        .any(|found| {
            before
                .iter()
                .position(|seen| *seen == found)
                .is_none_or(|at| {
                    before.swap_remove(at);
                    false
                })
        })
}

/// Every execution directive in `text`, normalised for comparison.
fn exec_directives(module: &str, text: &str) -> Vec<String> {
    match module {
        "samba" => samba(text),
        "dhcp" => {
            let mut found = dnsmasq(text);
            found.extend(kea(text));
            found
        }
        "chrony" => chrony(text),
        "resolver" => unbound(text),
        "network" => ifupdown(text),
        "mounts" => fstab(text),
        "nfs" => exports(text),
        _ => Vec::new(),
    }
}

/// Runs of whitespace collapsed to one space, ends trimmed.
fn squash(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A line ending in `\` continues on the next one (smb.conf, exports).
fn join_continuations(text: &str) -> String {
    text.replace("\\\r\n", " ").replace("\\\n", " ")
}

/// smb.conf. Samba ignores case, whitespace and (conservatively here)
/// underscores in parameter names, so `rootpreexec`, `root  preexec` and
/// `Root_PreExec` are one name. Any parameter that runs a program or loads
/// code or configuration counts.
fn samba(text: &str) -> Vec<String> {
    join_continuations(text)
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with(['#', ';', '[']) {
                return None;
            }
            let (key, value) = line.split_once('=').unwrap_or((line, ""));
            let key: String = key
                .chars()
                .filter(|c| !c.is_whitespace() && *c != '_')
                .collect::<String>()
                .to_ascii_lowercase();
            let exec = key.contains("exec")
                || key.ends_with("script")
                || key.ends_with("command")
                || key.ends_with("backend")
                || matches!(
                    key.as_str(),
                    "include" | "configfile" | "panicaction" | "vfsobjects" | "preloadmodules"
                );
            exec.then(|| format!("{key}={}", squash(value)))
        })
        .collect()
}

/// dnsmasq `key=value` lines.
fn dnsmasq(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with('#') {
                return None;
            }
            let (key, value) = line.split_once('=').unwrap_or((line, ""));
            let key = key.trim().trim_start_matches('-').to_ascii_lowercase();
            matches!(
                key.as_str(),
                "dhcp-script"
                    | "dhcp-luascript"
                    | "dhcp-scriptuser"
                    | "conf-file"
                    | "conf-dir"
                    | "conf-script"
            )
            .then(|| format!("{key}={}", squash(value)))
        })
        .collect()
}

/// Kea JSON: every `hooks-libraries` value, whole, and every `<?include?>`.
/// Escapes are decoded first, so `hooks-libraries` is the same key.
fn kea(text: &str) -> Vec<String> {
    let doc = squash(&decode_json_escapes(text)).to_ascii_lowercase();
    let mut found: Vec<String> = doc
        .match_indices("\"hooks-libraries\"")
        .filter_map(|(at, _)| doc.get(at..).map(bracketed))
        .collect();
    found.extend(doc.match_indices("<?include").filter_map(|(at, _)| {
        let rest = doc.get(at..)?;
        let end = rest
            .find("?>")
            .map_or(rest.len(), |end| end.saturating_add(2));
        rest.get(..end).map(str::to_owned)
    }));
    found
}

/// `text` from its start through the first balanced `[...]`/`{...}` group,
/// skipping string contents; all of `text` when the group never closes.
fn bracketed(text: &str) -> String {
    let mut depth = 0_usize;
    let mut in_string = false;
    let mut escaped = false;
    for (at, c) in text.char_indices() {
        if in_string {
            match (escaped, c) {
                (true, _) => escaped = false,
                (false, '\\') => escaped = true,
                (false, '"') => in_string = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => in_string = true,
            '[' | '{' => depth = depth.saturating_add(1),
            ']' | '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return text
                        .get(..at.saturating_add(c.len_utf8()))
                        .unwrap_or(text)
                        .to_owned();
                }
            }
            _ => {}
        }
    }
    text.to_owned()
}

/// `\uXXXX` escapes replaced by their character; everything else kept.
fn decode_json_escapes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("\\u") {
        out.push_str(rest.get(..at).unwrap_or_default());
        let after = rest.get(at.saturating_add(2)..).unwrap_or_default();
        let decoded = after
            .get(..4)
            .and_then(|hex| u32::from_str_radix(hex, 16).ok())
            .and_then(char::from_u32);
        if let Some(c) = decoded {
            out.push(c);
            rest = after.get(4..).unwrap_or_default();
        } else {
            out.push_str("\\u");
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// chrony `directive args` lines; chrony ignores case in directive names.
fn chrony(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with(['#', '!', ';', '%']) {
                return None;
            }
            let (key, value) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
            let key = key.to_ascii_lowercase();
            matches!(
                key.as_str(),
                "include" | "confdir" | "sourcedir" | "pidfile" | "user"
            )
            .then(|| format!("{key} {}", squash(value)))
        })
        .collect()
}

/// unbound. Its lexer is token based, so `server: include: x` on one line
/// and `include:/x` with no space are both directives.
fn unbound(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or_default();
        let mut tokens = line.split_whitespace();
        while let Some(token) = tokens.next() {
            let Some((key, value)) = token.split_once(':') else {
                continue;
            };
            let key = key.to_ascii_lowercase();
            let exec = matches!(
                key.as_str(),
                "include" | "include-toplevel" | "python-script" | "dynlib-file"
            );
            let module_config = key == "module-config";
            if !exec && !module_config {
                continue;
            }
            let value = if value.is_empty() {
                tokens.next().unwrap_or_default().to_owned()
            } else {
                value.to_owned()
            };
            // `module-config` counts only when it loads the python or
            // dynlib module; its quoted list can span several tokens.
            if module_config {
                let rest = line.to_ascii_lowercase();
                if !(rest.contains("python") || rest.contains("dynlib")) {
                    continue;
                }
                found.push(format!("{key}: {}", squash(&rest)));
                continue;
            }
            found.push(format!("{key}: {value}"));
        }
    }
    found
}

/// ifupdown hooks run through `/bin/sh`. Only the module's own route form,
/// `up ip route add <to> via <via>` with plain address words, is allowed.
fn ifupdown(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with('#') {
                return None;
            }
            let first = line.split_whitespace().next()?;
            let key = first
                .split_once('=')
                .map_or(first, |(key, _)| key)
                .to_ascii_lowercase();
            let hook = matches!(
                key.as_str(),
                "up" | "down"
                    | "pre-up"
                    | "post-up"
                    | "pre-down"
                    | "post-down"
                    | "source"
                    | "source-directory"
            );
            (hook && !(key == "up" && is_route_form(line))).then(|| squash(line))
        })
        .collect()
}

/// `up ip route add <to> via <via>`, where `<to>` and `<via>` hold only
/// address characters, so the shell sees no expansion or separator.
fn is_route_form(line: &str) -> bool {
    let plain = |word: &str| {
        !word.is_empty()
            && word
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '/'))
    };
    let words: Vec<&str> = line.split_whitespace().collect();
    matches!(
        words.as_slice(),
        ["up", "ip", "route", "add", to, "via", via] if plain(to) && plain(via)
    )
}

/// `x-systemd.` options that name no program and pull in no unit
/// (systemd.mount(5)). Every other `x-systemd.` option is refused: `makefs`
/// and `growfs` run a program on the device, and `requires=`, `wanted-by=`,
/// `before=` and the like start or order arbitrary units.
const SAFE_SYSTEMD_OPTIONS: &[&str] = &[
    "automount",
    "idle-timeout",
    "mount-timeout",
    "device-timeout",
    "rw-only",
];

/// Trees a new fstab mount point may not be in, equal or under (owner
/// decision 2026-10-26). A mount there replaces files that root reads or
/// runs: configuration and units (`/etc`, `/run` and its links `/var/run`
/// and `/var/lock`), programs and libraries (`/usr`, `/bin`, `/sbin` and
/// the `/lib*` trees, also where they are not links to `/usr`), the kernel
/// and boot loader (`/boot`), root's home (`/root`: `.ssh`, shell start
/// files) and detent's own state (`/var/lib/detent`, the packaged state
/// root). An ancestor of one (`/`, `/var`, `/var/lib`) is refused too.
const PROTECTED_TREES: &[&str] = &[
    "/bin",
    "/boot",
    "/etc",
    "/lib",
    "/lib32",
    "/lib64",
    "/libx32",
    "/root",
    "/run",
    "/sbin",
    "/usr",
    "/var/lib/detent",
    "/var/lock",
    "/var/run",
];

/// World-writable directories: the detent user can put a link below one,
/// and mount follows it, so a mount point under one is refused. The
/// directory itself is root's (a `tmpfs` on `/tmp` stays allowed).
const WRITABLE_DIRS: &[&str] = &["/tmp", "/var/tmp", "/dev/shm"];

/// fstab: systemd mount options outside [`SAFE_SYSTEMD_OPTIONS`], mount
/// helpers and FUSE types, which name the program to run, and mounts that
/// replace system files ([`replaces_system_files`]). Compared without case.
fn fstab(text: &str) -> Vec<String> {
    text.lines()
        .filter(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let fuse = fields
                .get(2)
                .is_some_and(|kind| kind.to_ascii_lowercase().contains("fuse"));
            fuse || replaces_system_files(&fields)
                || line
                    .split(|c: char| c == ',' || c.is_whitespace())
                    .map(str::to_ascii_lowercase)
                    .any(|word| {
                        let systemd = word.strip_prefix("x-systemd.").is_some_and(|option| {
                            let name = option.split_once('=').map_or(option, |(name, _)| name);
                            !SAFE_SYSTEMD_OPTIONS.contains(&name)
                        });
                        systemd || word.starts_with("helper=") || word.starts_with("uhelper=")
                    })
        })
        .map(squash)
        .collect()
}

/// An fstab entry (its whitespace-separated `fields`) that binds, rbinds or
/// overlays other files onto its mount point, or whose mount point is in
/// or over a protected tree ([`protected_mountpoint`]). A comment is none.
fn replaces_system_files(fields: &[&str]) -> bool {
    let Some(mountpoint) = fields.get(1) else {
        return false;
    };
    if fields.first().is_some_and(|spec| spec.starts_with('#')) {
        return false;
    }
    let lower = |at: usize| fields.get(at).map(|field| field.to_ascii_lowercase());
    let overlay = lower(2).is_some_and(|kind| kind.contains("overlay"));
    let binds = lower(3).is_some_and(|options| {
        options.split(',').any(|option| {
            matches!(option, "bind" | "rbind")
                || ["lowerdir=", "upperdir=", "workdir="]
                    .iter()
                    .any(|key| option.starts_with(key))
        })
    });
    overlay || binds || protected_mountpoint(mountpoint)
}

/// Whether a mount on the fstab field `raw` could replace system files: its
/// decoded path is in or over a [`PROTECTED_TREES`] entry (so also `/`), or
/// under a [`WRITABLE_DIRS`] entry. A path that is not absolute, has a `..`
/// component or does not decode to UTF-8 counts too. `none` and `swap`
/// (swap entries) do not.
fn protected_mountpoint(raw: &str) -> bool {
    use std::path::{Component, Path};
    if matches!(raw, "none" | "swap") {
        return false;
    }
    let Ok(decoded) = String::from_utf8(unmangle(raw.as_bytes())) else {
        return true;
    };
    let path = Path::new(&decoded);
    if !path.is_absolute() || path.components().any(|part| part == Component::ParentDir) {
        return true;
    }
    PROTECTED_TREES
        .iter()
        .any(|tree| path.starts_with(tree) || Path::new(tree).starts_with(path))
        || WRITABLE_DIRS
            .iter()
            .any(|dir| path.starts_with(dir) && path != Path::new(dir))
}

/// The `\ooo` octal escapes of an fstab field decoded, as libmount reads
/// them (`\040` is a space); any other backslash is kept. The mounts
/// module's rule, which this crate cannot reach (no dependency on it).
fn unmangle(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut rest = raw;
    while let Some((&byte, tail)) = rest.split_first() {
        let decoded = tail
            .get(..3)
            .filter(|digits| digits.iter().all(|digit| (b'0'..=b'7').contains(digit)))
            .and_then(|digits| std::str::from_utf8(digits).ok())
            .and_then(|digits| u8::from_str_radix(digits, 8).ok());
        match decoded {
            Some(decoded) if byte == b'\\' => {
                out.push(decoded);
                rest = tail.get(3..).unwrap_or_default();
            }
            _ => {
                out.push(byte);
                rest = tail;
            }
        }
    }
    out
}

/// exports: options that map a client to root.
fn exports(text: &str) -> Vec<String> {
    join_continuations(text)
        .lines()
        .filter(|line| {
            line.split(|c: char| matches!(c, ',' | '(' | ')') || c.is_whitespace())
                .any(|word| matches!(word, "no_root_squash" | "anonuid=0" | "anongid=0"))
        })
        .map(squash)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::adds_exec_directive;

    fn adds(module: &str, previous: &str, candidate: &str) -> bool {
        adds_exec_directive(module, previous.as_bytes(), candidate.as_bytes())
    }

    /// One case per bypass the H23 verification probe found, plus the ones
    /// the daemons' own parsers imply. Each must be refused.
    #[test]
    fn every_known_bypass_is_refused() {
        let cases: &[(&str, &str, &str)] = &[
            // samba: names without spaces, doubled spaces, underscores.
            ("samba", "[global]\n", "[global]\nrootpreexec = /bin/sh\n"),
            ("samba", "[global]\n", "[global]\nroot  preexec = /bin/sh\n"),
            ("samba", "[global]\n", "[global]\nroot_preexec = /bin/sh\n"),
            ("samba", "[global]\n", "[global]\nRoot PreExec = /bin/sh\n"),
            // samba: a changed value of an existing directive.
            (
                "samba",
                "[s]\nroot preexec = /bin/true\n",
                "[s]\nroot preexec = /bin/sh\n",
            ),
            // samba: a name split over a continuation line, and synonyms.
            ("samba", "[s]\n", "[s]\nroot pre\\\nexec = /bin/sh\n"),
            ("samba", "[s]\n", "[s]\nexec = /bin/sh\n"),
            ("samba", "[s]\n", "[s]\nmagic script = run.sh\n"),
            ("samba", "[s]\n", "[s]\nprint command = /bin/sh\n"),
            ("samba", "[s]\n", "[s]\nvfs objects = /tmp/x.so\n"),
            // ifupdown: indented hooks, `=` in the command, every hook name.
            ("network", "", "iface eth0 inet dhcp\n    up /bin/sh\n"),
            ("network", "", "\tup /bin/sh -c x=1\n"),
            ("network", "", "\tpost-up /bin/sh\n"),
            ("network", "", "\tpre-down /bin/sh\n"),
            ("network", "", "source /tmp/hooks\n"),
            // ifupdown: shell expansion inside the allowed route form.
            ("network", "", "\tup ip route add $(id) via 192.0.2.1\n"),
            (
                "network",
                "",
                "\tup ip route add 10.0.0.0/8 via 192.0.2.1;id\n",
            ),
            (
                "network",
                "",
                "\tup ip route add 10.0.0.0/8 via 192.0.2.1 x\n",
            ),
            // ifupdown: a changed hook value.
            ("network", "\tdown /bin/true\n", "\tdown /bin/sh\n"),
            // unbound: no space after the colon, one-line clauses, loaders.
            ("resolver", "server:\n", "server:\ninclude:/x\n"),
            ("resolver", "", "server: include: /x\n"),
            ("resolver", "server:\n", "server:\n\tdynlib-file: /x.so\n"),
            ("resolver", "server:\n", "server:\n\tpython-script: /x.py\n"),
            (
                "resolver",
                "server:\n",
                "server:\n\tmodule-config: \"python iterator\"\n",
            ),
            // dnsmasq: every script and include option, spaced or not.
            ("dhcp", "", "conf-script=/bin/sh\n"),
            ("dhcp", "", "dhcp-script = /bin/sh\n"),
            ("dhcp", "dhcp-script=/bin/true\n", "dhcp-script=/bin/sh\n"),
            // Kea: hook libraries, escaped keys, changed paths, includes.
            (
                "dhcp",
                "{\"Dhcp4\": {}}\n",
                "{\"Dhcp4\": {\"hooks-libraries\": [{\"library\": \"/x.so\"}]}}\n",
            ),
            (
                "dhcp",
                "{\"Dhcp4\": {}}\n",
                "{\"Dhcp4\": {\"hooks\\u002dlibraries\": [{\"library\": \"/x.so\"}]}}\n",
            ),
            (
                "dhcp",
                "{\"Dhcp4\": {\"hooks-libraries\": [{\"library\":\n \"/a.so\"}]}}\n",
                "{\"Dhcp4\": {\"hooks-libraries\": [{\"library\":\n \"/b.so\"}]}}\n",
            ),
            ("dhcp", "{}\n", "<?include \"/tmp/x.json\"?>\n{}\n"),
            // chrony: case, and the privilege directives.
            ("chrony", "", "Include /tmp/x.conf\n"),
            ("chrony", "", "user root\n"),
            // fstab: helpers and FUSE programs.
            ("mounts", "", "/dev/sda1 /mnt ext4 helper=/bin/sh 0 0\n"),
            ("mounts", "", "x#/bin/sh /mnt fuse.sshfs defaults 0 0\n"),
            // fstab: x-systemd options that run a program or pull in units.
            ("mounts", "", "/dev/sdb1 /mnt ext4 x-systemd.makefs 0 0\n"),
            ("mounts", "", "/dev/sdb1 /mnt ext4 x-systemd.growfs 0 0\n"),
            (
                "mounts",
                "",
                "/dev/sdb1 /mnt ext4 x-systemd.requires=evil.service 0 0\n",
            ),
            (
                "mounts",
                "",
                "/dev/sdb1 /mnt ext4 x-systemd.wanted-by=evil.target 0 0\n",
            ),
            ("mounts", "", "/dev/sdb1 /mnt ext4 X-SYSTEMD.MAKEFS 0 0\n"),
            (
                "mounts",
                "",
                "/dev/sdb1 /mnt ext4 x-systemd.automount,x-systemd.makefs 0 0\n",
            ),
            // exports: the root-mapping option first in the list, anonuid=0.
            ("nfs", "", "/srv 192.0.2.0/24(no_root_squash,rw)\n"),
            ("nfs", "", "/srv 192.0.2.0/24(rw,anonuid=0)\n"),
        ];
        for (module, previous, candidate) in cases {
            assert!(
                adds(module, previous, candidate),
                "{module}: {candidate:?} was not refused"
            );
        }
    }

    /// What must keep working: existing directives left alone or reordered,
    /// the module's own route form, and ordinary edits beside a hook.
    #[test]
    fn ordinary_edits_are_allowed() {
        let cases: &[(&str, &str, &str)] = &[
            (
                "samba",
                "[s]\nroot preexec = /bin/true\npath = /a\n",
                "[s]\npath = /b\nroot preexec = /bin/true\n",
            ),
            (
                "samba",
                "",
                "[s]\n; preexec = /x\n# include = /y\nread only = no\n",
            ),
            (
                "network",
                "",
                "iface eth0 inet static\n\tup ip route add 10.0.0.0/8 via 192.0.2.1\n",
            ),
            ("network", "", "\tup ip route add default via fe80::1\n"),
            (
                "network",
                "\tup /bin/true\n",
                "\tup /bin/true\n\taddress 192.0.2.2\n",
            ),
            ("resolver", "", "server:\n\tinterface: 127.0.0.1\n"),
            (
                "resolver",
                "",
                "server:\n\tmodule-config: \"validator iterator\"\n",
            ),
            ("resolver", "", "nameserver ::1\n"),
            (
                "dhcp",
                "{\"Dhcp4\": {\"hooks-libraries\": [{\"library\": \"/a.so\"}], \"valid-lifetime\": 1}}\n",
                "{\"Dhcp4\": {\"hooks-libraries\": [{\"library\": \"/a.so\"}], \"valid-lifetime\": 2}}\n",
            ),
            ("dhcp", "", "# dhcp-script=/bin/sh\ndomain-needed\n"),
            ("chrony", "", "server 192.0.2.1 iburst\n"),
            ("mounts", "", "/dev/sda1 /mnt ext4 defaults 0 0\n"),
            // fstab: x-systemd options that name no program and no unit.
            (
                "mounts",
                "",
                "nas:/export /mnt/nas nfs4 x-systemd.automount,x-systemd.idle-timeout=1min,x-systemd.mount-timeout=30,x-systemd.device-timeout=10s,x-systemd.rw-only,_netdev,nofail 0 0\n",
            ),
            ("nfs", "", "/srv 192.0.2.0/24(rw,root_squash)\n"),
            ("unknown", "", "preexec = /bin/true\n"),
        ];
        for (module, previous, candidate) in cases {
            assert!(
                !adds(module, previous, candidate),
                "{module}: {candidate:?} was refused"
            );
        }
    }

    #[test]
    fn duplicates_count() {
        assert!(adds(
            "dhcp",
            "dhcp-script=/bin/true\n",
            "dhcp-script=/bin/true\ndhcp-script=/bin/true\n"
        ));
    }

    #[test]
    fn an_unterminated_hooks_value_or_include_is_still_caught() {
        assert!(adds("dhcp", "", "{\"hooks-libraries\": [ \"/x.so\"\n"));
        assert!(adds("dhcp", "", "<?include \"/x\"\n"));
        assert!(adds(
            "dhcp",
            "",
            "{\"hooks\\u00zzlibraries\": 1, \"hooks-libraries\": []}"
        ));
        assert!(adds(
            "dhcp",
            "",
            "{\"x\": \"a\\\"b\", \"hooks-libraries\": [\"q]\"]}"
        ));
    }

    /// fstab lines that mount over a system tree or bind, rbind or overlay
    /// other files onto a mount point (owner decision 2026-10-26). Each must
    /// be refused when new.
    #[test]
    fn fstab_mounts_over_system_trees_and_binds_are_refused() {
        let cases: &[&str] = &[
            "/var/lib/detent/f /etc/ld.so.preload none bind 0 0\n",
            "/var/lib/detent/u /etc/systemd/system none bind 0 0\n",
            "/srv/a /srv/b none rbind 0 0\n",
            "/srv/a /srv/b none defaults,BIND 0 0\n",
            "overlay /srv/o overlay lowerdir=/a,upperdir=/b,workdir=/c 0 0\n",
            "x /srv/o ext4 lowerdir=/a 0 0\n",
            "x /srv/o ext4 upperdir=/b 0 0\n",
            "/dev/sdb1 /usr/local/bin ext4 defaults 0 2\n",
            "/dev/sdb1 /etc/foo ext4 defaults 0 2\n",
            "/dev/sdb1 /etc ext4 defaults 0 2\n",
            "/dev/sdb1 / ext4 defaults 0 1\n",
            "/dev/sdb1 /var ext4 defaults 0 2\n",
            "/dev/sdb1 /var/lib/detent ext4 defaults 0 2\n",
            "/dev/sdb1 /etc/my\\040dir ext4 defaults 0 2\n",
            "/dev/sdb1 /\\145tc/x ext4 defaults 0 2\n",
            "/dev/sdb1 /etc/../etc/x ext4 defaults 0 2\n",
            "/dev/sdb1 /srv/../etc ext4 defaults 0 2\n",
            "/dev/sdb1 //etc//x/ ext4 defaults 0 2\n",
            "/dev/sdb1 /./etc/./x ext4 defaults 0 2\n",
            "/dev/sdb1 /boot/efi vfat defaults 0 2\n",
            "/dev/sdb1 /bin/x ext4 defaults 0 2\n",
            "/dev/sdb1 /sbin/x ext4 defaults 0 2\n",
            "/dev/sdb1 /lib/x ext4 defaults 0 2\n",
            "/dev/sdb1 /lib64/x ext4 defaults 0 2\n",
            "/dev/sdb1 /root/.ssh ext4 defaults 0 2\n",
            "tmpfs /run/systemd/system tmpfs mode=0777 0 0\n",
            "tmpfs /var/run/systemd/system tmpfs mode=0777 0 0\n",
            "/dev/sdb1 /tmp/link ext4 defaults 0 2\n",
            "/dev/sdb1 /var/tmp/link ext4 defaults 0 2\n",
            "/dev/sdb1 /dev/shm/link ext4 defaults 0 2\n",
            "/dev/sdb1 srv/rel ext4 defaults 0 2\n",
            "/dev/sdb1 /etc/\\377 ext4 defaults 0 2\n",
            "  /dev/sdb1   /etc/foo   ext4 defaults 0 2\n",
        ];
        for candidate in cases {
            assert!(
                adds("mounts", "", candidate),
                "{candidate:?} was not refused"
            );
        }
        // A changed line over a protected tree counts as new.
        assert!(adds(
            "mounts",
            "/dev/sdb1 /etc/foo ext4 defaults 0 2\n",
            "/dev/sdc1 /etc/foo ext4 defaults 0 2\n",
        ));
    }

    /// What must keep working in fstab: an unchanged bind line, ordinary
    /// data and network mounts, swap, comments, and a tmpfs on `/tmp`.
    #[test]
    fn fstab_ordinary_mounts_and_unchanged_binds_are_allowed() {
        let bind = "/srv/a /etc/foo none bind 0 0\n";
        let cases: &[(&str, &str)] = &[
            (bind, bind),
            (
                bind,
                "/srv/a   /etc/foo  none  bind  0  0\n/dev/sdb1 /srv/data ext4 defaults 0 2\n",
            ),
            ("", "/dev/sdb1 /srv/data ext4 defaults 0 2\n"),
            ("", "nas:/export /mnt/nas nfs defaults,_netdev,nofail 0 0\n"),
            ("", "UUID=1234 none swap sw 0 0\n"),
            ("", "/swapfile swap swap defaults 0 0\n"),
            ("", "# /boot/efi was on /dev/sda1 during installation\n"),
            ("", "  # /dev/sdb1 /etc/x none bind 0 0\n"),
            ("", "tmpfs /tmp tmpfs defaults,nosuid,nodev 0 0\n"),
            ("", "/dev/sdb1 /srv/etc ext4 defaults 0 2\n"),
            ("", "/dev/sdb1 /etcetera ext4 defaults 0 2\n"),
            ("", "/dev/sdb1 /var/log ext4 defaults 0 2\n"),
            ("", "/dev/sdb1 /srv/my\\040data ext4 defaults 0 2\n"),
            ("", "/dev/sdb1 /mnt/binder ext4 defaults 0 2\n"),
            ("", "\n"),
        ];
        for (previous, candidate) in cases {
            assert!(
                !adds("mounts", previous, candidate),
                "{candidate:?} was refused"
            );
        }
    }
}
