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

/// fstab: systemd mount hooks, mount helpers and FUSE types, which name the
/// program to run.
fn fstab(text: &str) -> Vec<String> {
    text.lines()
        .filter(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let fuse = fields
                .get(2)
                .is_some_and(|kind| kind.to_ascii_lowercase().contains("fuse"));
            fuse || line
                .split(|c: char| c == ',' || c.is_whitespace())
                .any(|word| {
                    word.starts_with("x-systemd.")
                        || word.starts_with("helper=")
                        || word.starts_with("uhelper=")
                })
        })
        .map(squash)
        .collect()
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
}
