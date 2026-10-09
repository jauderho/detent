# needs-review: machine-drafted German translation; not yet checked by a native speaker.
## detent-core — de
## Source: locales/en-US/core.ftl. Same ids, same placeables. Code-like tokens
## (directive names, paths, flags, option values) stay untranslated.

## chrony module — display name, security notes, schema tooltips
chrony-name = chrony
chrony-note-precedence = diese Datei überschreibt die einkompilierten Vorgaben; ein falscher Wert ändert stillschweigend, wie der Host die Uhrzeit hält.
chrony-tip-settings = die chrony.conf-Direktiven, die dieses Modul abbildet, in Dateireihenfolge; alles andere in der Datei bleibt unangetastet erhalten.
chrony-tip-key = der Name der Direktive, ein Wort, ohne Beachtung der Groß-/Kleinschreibung.
chrony-tip-value = der Wert dieser Direktive bis zum Zeilenende; leer bei Direktiven ohne Wert wie `rtcsync`.
chrony-rec-value = gib lieber einen expliziten Wert an, statt dich auf die einkompilierte Vorgabe zu verlassen.

## chrony module — validation diagnostics
chrony-privileged-directive = `{$key}` setzt eine Datei, die chronyd als root schreibt, oder den Benutzer, unter dem er läuft. Prüfe den Wert, bevor du ihn anwendest.
chrony-invalid-key = `{$key}` ist kein gültiger chrony-Direktivenname.
chrony-duplicate-key = `{$key}` ist mehrfach gesetzt; der letzte Wert gilt.
chrony-too-many-settings = diese Datei hat {$count} Einstellungen; teile sie auf Drop-in-Dateien unter /etc/chrony/conf.d auf.
chrony-allow-open = `allow {$value}` liefert die Uhrzeit an das gesamte Internet; erlaube nur die Netze, die sie brauchen.
chrony-missing-makestep = makestep ist nicht gesetzt; beim Start kann die Uhr unbegrenzt abweichen, statt in den Bereich gesetzt zu werden.
chrony-missing-rtcsync = rtcsync ist nicht gesetzt; die Hardware-Uhr driftet gegenüber der Systemuhr.
chrony-rec-nts = der Pool {$pool} wird ohne die Option nts verwendet; bevorzuge nts-fähige Quellen, damit die Zeit nicht gefälscht werden kann.
chrony-cmdport-open = cmdport ist {$port}; setze cmdport 0, außer chronyc muss diesen Host über das Netzwerk erreichen.
chrony-external-directive = `{$key}` lädt externe Dateien oder führt ein externes Programm aus; dieses Modul lehnt Direktiven ab, die seine konfigurierte Dateigrenze überschreiten.

## dhcp module — display name, security notes, schema tooltips
dhcp-name = dhcp
dhcp-note-commit-confirm = eine fehlerhafte DHCP-Änderung trennt alle Clients und dich vom Netzwerk; prüfe das Diff sorgfältig, bevor du bestätigst.
dhcp-tip-dnsmasq = die `key=value`-Einstellungen von /etc/dnsmasq.conf in Dateireihenfolge; Kommentare und unbekannte Zeilen bleiben unangetastet erhalten.
dhcp-tip-kea-v4 = die verwaltete Teilmenge des Kea-DHCPv4-Servers (`Dhcp4`); unbekannte Kea-Optionen bleiben unangetastet erhalten.
dhcp-tip-kea-v6 = die verwaltete Teilmenge des Kea-DHCPv6-Servers (`Dhcp6`); unbekannte Kea-Optionen bleiben unangetastet erhalten.
dhcp-tip-key = der Name der dnsmasq-Option, ein Wort, ohne Leerraum.
dhcp-tip-value = der Wert nach `=`; ein reines Flag wie `domain-needed` hat keinen Wert.
dhcp-tip-interfaces = die Schnittstellen, auf denen der Kea-Server lauscht; eine leere Liste bedeutet, dass der Server auf allen Schnittstellen antwortet.
dhcp-tip-valid-lifetime = die Standard-Lease-Dauer in Sekunden; 3600 ist für die meisten Netze ein vernünftiger Wert.
dhcp-tip-subnets = die Subnetze, aus denen der Server Adressen vergibt.
dhcp-tip-id = Keas stabile Subnetz-Kennung; halte sie über Änderungen hinweg stabil, denn Leases sind nach ihr geschlüsselt.
dhcp-tip-subnet = das Subnetzpräfix in CIDR-Form, z. B. `192.168.1.0/24`.
dhcp-tip-pools = die dynamischen Adresspools des Subnetzes.
dhcp-tip-routers = die Router-Option (Standard-Gateway), die an Clients gegeben wird.
dhcp-tip-domain-servers = die DNS-Server (`domain-name-servers`), die an Clients gegeben werden.
dhcp-tip-pool = ein Pool als Bereich `192.168.1.100 - 192.168.1.200` oder als Präfix `192.168.1.0/24`.

## dhcp module — validation diagnostics
dhcp-empty-key = eine dnsmasq-Einstellung hat einen leeren Optionsnamen.
dhcp-invalid-key = `{$key}` ist kein gültiger dnsmasq-Optionsname; er muss ein Wort ohne Leerraum, `=` oder `#` sein.
dhcp-malformed-cidr = `{$value}` ist kein gültiges CIDR-Präfix, z. B. `192.168.1.0/24`.
dhcp-malformed-pool = `{$value}` ist kein gültiger Pool; nutze einen Bereich wie `192.168.1.100 - 192.168.1.200` oder ein CIDR-Präfix.
dhcp-external-directive = `{$key}` lädt externe Dateien oder führt Befehle aus; dieses Modul erzeugt oder ändert keine Direktiven, die seine konfigurierte Dateigrenze überschreiten.
dhcp-authoritative-set = `dhcp-authoritative` macht dnsmasq zum alleinigen DHCP-Server im Segment; setze es nur, wenn kein anderer DHCP-Server existiert.
dhcp-kea-interfaces-empty = {$server} hat keine Schnittstellen konfiguriert und lauscht auf allen Schnittstellen; nenne die Schnittstellen ausdrücklich.
dhcp-rec-rebind = domain-needed und bogus-priv sind nicht beide gesetzt; sie filtern Rebind-Angriffe und vorgelagerte A-Anfragen für private Adressen.
dhcp-rec-lifetime = {$server} hat valid-lifetime {$lifetime}; halte sie zwischen 300 und 86400 Sekunden, damit Leases vorhersehbar erneuert werden.

## hosts module — display name, security notes, schema tooltips
hosts-name = hosts
hosts-note-spoofing = Einträge hier überschreiben DNS; ein falscher oder bösartiger Eintrag leitet Abfragen stillschweigend um.
hosts-tip-entries = die Zuordnungen von Adresse zu Name in /etc/hosts, in Dateireihenfolge.
hosts-tip-ip = die Adresse, auf die die folgenden Namen aufgelöst werden.
hosts-tip-hostnames = die Namen, die auf diese Adresse aufgelöst werden, der kanonische Name zuerst.
hosts-tip-comment = der Inline-Kommentar zu diesem Eintrag, falls vorhanden.

## hosts module — validation diagnostics
hosts-invalid-hostname = `{$name}` ist kein gültiger Hostname.
hosts-duplicate-canonical = `{$name}` ist der kanonische Name von mehr als einem Eintrag.
hosts-no-hostnames = dieser Eintrag hat keine Hostnamen.
hosts-hostname-is-ip = `{$name}` ist ein Adressliteral, kein Hostname.
hosts-ipv6-zone-unsupported = `{$name}` enthält eine IPv6-Zonen-ID, die /etc/hosts nicht unterstützt.
hosts-hostname-multiple-ips = `{$name}` wird auf mehr als eine Adresse derselben Familie aufgelöst.
hosts-localhost-not-loopback = `localhost` zeigt auf `{$ip}`, was keine Loopback-Adresse ist.
hosts-missing-localhost = es gibt keinen `localhost`-Eintrag.
hosts-missing-ipv6-localhost = es gibt keinen IPv6-`localhost`-Eintrag.
hosts-too-many-entries = diese Datei hat {$count} Einträge; erwäge stattdessen DNS.

## mounts module — display name, security notes, schema tooltips
mounts-name = mounts
mounts-note-boot = eine fehlerhafte /etc/fstab kann den Host beim nächsten Neustart unbootbar machen; jede Änderung braucht eine zweite Bestätigung. Die Bestätigung kann einen fehlerhaften Eintrag nicht erkennen, weil bis zum nächsten Boot nichts die Datei liest.
mounts-tip-entries = die Mount-Einträge in /etc/fstab, in Dateireihenfolge.
mounts-tip-spec = was eingehängt wird: ein Gerät, `UUID=...`/`LABEL=...`, ein NFS-Export oder `none` für Swap.
mounts-tip-mountpoint = wo das Dateisystem eingehängt wird, oder `none`/`swap` für Swap.
mounts-tip-fstype = der Dateisystemtyp, z. B. ext4, oder `swap`.
mounts-tip-options = die kommagetrennten Mount-Optionen, z. B. defaults,nosuid.
mounts-tip-dump = die Sicherungshäufigkeit von dump(8); fast immer 0.
mounts-tip-pass = die fsck-Durchlaufnummer: 1 für Root, 2 für andere geprüfte Dateisysteme, 0 zum Überspringen.
mounts-rec-options = schütze benutzerbeschreibbare Daten mit nosuid, nodev und noexec; bevorzuge x-systemd.automount bei Netzwerkdateisystemen.

## mounts module — validation diagnostics
mounts-empty-spec = Eintrag {$index} hat eine leere Spec (erste Spalte).
mounts-empty-mountpoint = Eintrag {$index} hat einen leeren Einhängepunkt (zweite Spalte).
mounts-invalid-fstype = `{$fstype}` ist kein gültiger Dateisystemtyp.
mounts-pass-too-high = Eintrag {$index} hat pass `{$pass}`; fsck führt höchstens 2 Durchläufe aus.
mounts-root-pass = das Root-Dateisystem sollte pass 1 haben, nicht `{$pass}`.
mounts-missing-nofail = `{$mountpoint}` ist ein Wechselmedium ohne `nofail`; der Boot hängt, wenn es abgezogen wird.
mounts-missing-boot-escape = `{$mountpoint}` hat weder nofail noch noauto; ein fehlgeschlagener Mount kann den Boot aufhalten.
mounts-critical-noauto = `{$mountpoint}` wird zum Booten gebraucht, hat aber noauto, sodass das System ohne es weiterlaufen kann.
mounts-missing-guards = `{$mountpoint}` hängt benutzerbeschreibbare Daten ohne `{$missing}` ein; füge sie hinzu.
mounts-network-automount = `{$mountpoint}` ist ein Netzwerkdateisystem ohne `x-systemd.automount`; der Boot wartet auf das Netzwerk.
mounts-noauto-without-user = `noauto` ohne `user`: nur root kann es einhängen, was den Zweck verfehlt.
mounts-relative-mountpoint = Eintrag {$index} hängt auf `{$mountpoint}` ein, was kein absoluter Pfad ist.
mounts-no-root-entry = kein Eintrag hängt `/` ein; prüfe, ob das Root-Dateisystem auf andere Weise eingehängt wird.

## network module — display name, security notes, schema tooltips
network-name = network
network-note-precedence = eine fehlerhafte Netzwerkkonfiguration kann den Administrator von diesem Host trennen; jede Änderung braucht eine zweite Bestätigung.
network-tip-interfaces = die Schnittstellen, die dieser Host konfiguriert, in Dateireihenfolge.
network-tip-iface-name = der Schnittstellenname, z. B. eth0.
network-tip-iface-dhcp-v4 = ob diese Schnittstelle ihre IPv4-Adresse per DHCP bekommt.
network-tip-iface-dhcp-v6 = ob diese Schnittstelle ihre IPv6-Adresse per DHCP bekommt.
network-tip-iface-addresses = statische Adressen in CIDR-Notation, z. B. 192.168.1.10/24.
network-tip-iface-gateway-v4 = das Standard-Gateway für IPv4, bei statischer Adressierung.
network-tip-iface-gateway-v6 = das Standard-Gateway für IPv6, bei statischer Adressierung.
network-tip-iface-dns = DNS-Server für diese Schnittstelle.
network-tip-iface-routes = statische Routen für diese Schnittstelle.
network-tip-iface-vlan = VLAN-Einstellungen für diese Schnittstelle, wenn sie ein VLAN ist.
network-tip-iface-bridge = Bridge-Einstellungen für diese Schnittstelle, wenn sie eine Bridge ist.
network-tip-route-to = das Ziel-CIDR oder default.
network-tip-route-via = die IP des nächsten Hops.
network-tip-vlan-link = der übergeordnete Link dieses VLANs, z. B. eth0.
network-tip-vlan-id = die VLAN-ID, 1–4094.
network-tip-bridge-members = Namen der Mitgliedsschnittstellen dieser Bridge.

## network module — validation diagnostics
network-invalid-cidr = `{$value}` ist keine gültige CIDR-Adresse.
network-invalid-ip = `{$value}` ist keine gültige IP-Adresse.
network-gateway-outside-subnet = das Gateway `{$gateway}` liegt außerhalb der Subnetze dieser Schnittstelle.
network-vlan-range = die VLAN-ID `{$id}` liegt außerhalb von 1–4094.
network-duplicate-interface = die Schnittstelle `{$name}` kommt mehrfach vor.
network-interface-order = die Schnittstelle `{$name}` muss vor den darüberstehenden Schnittstellen stehen: liste Schnittstellen in Namensreihenfolge auf.
network-injection = `{$value}` enthält einen Zeilenumbruch oder ein Nullbyte.
network-static-no-gateway = diese statisch adressierte Schnittstelle hat kein Gateway.
network-static-no-dns = diese statisch adressierte Schnittstelle hat keine DNS-Server.
network-dhcp-static-mixed = diese Schnittstelle hat sowohl DHCP- als auch statische Adressen.
network-rec-ipv6-privacy = aktiviere die IPv6-Datenschutzerweiterungen, wenn DHCPv6 an ist.
network-rec-ra-accept = akzeptiere Router Advertisements nur, wenn DHCPv6 ausdrücklich verwaltet wird.
network-rec-no-promisc = diese Schnittstelle sollte nicht im Promiscuous-Modus laufen.

## nfs module — display name, security notes, schema tooltips
nfs-name = nfs
nfs-note-live-state = Exporte werden bei jedem Mount vom Kernel durchgesetzt; eine falsche Zeile ändert stillschweigend, welche Hosts welche Dateisysteme lesen dürfen.
nfs-tip-entries = die Exporte in /etc/exports, in Dateireihenfolge.
nfs-tip-path = der Exportpunkt: ein absoluter Verzeichnispfad auf diesem Host.
nfs-tip-clients = die Hosts, die diesen Export einhängen dürfen, in Abgleichsreihenfolge; die erste passende Angabe gewinnt.
nfs-tip-host = die Client-Angabe: ein Name, eine Adresse, Adresse/Netzmaske, ein Platzhalter, `*` (jeder Client) oder @netgroup.
nfs-tip-options = die Exportoptionen dieses Clients, kommagetrennt; eine leere Liste übernimmt die Vorgaben der Datei.
nfs-rec-options = nenne rw/ro, sync/async, root_squash und die Subtree-Behandlung ausdrücklich; Vorgaben ändern sich zwischen nfs-utils-Versionen.

## nfs module — validation diagnostics
nfs-empty-path = ein Exportpunkt ist leer.
nfs-relative-path = `{$path}` ist nicht absolut; ein Exportpunkt muss mit `/` beginnen.
nfs-empty-host = ein Client von `{$path}` hat keine Host-Angabe.
nfs-bad-host = `{$host}` ist keine gültige Client-Angabe; sie beginnt mit `-` oder enthält Syntax, die die Zeile abschneiden würde.
nfs-bad-path = `{$path}` enthält Syntax, die die Exportzeile abschneiden würde.
nfs-bad-continuation = `{$path}` würde mit einem Fortsetzungs-Backslash enden und die nächste Zeile anhängen.
nfs-invalid-option = `{$option}` ist keine gültige Exportoption; Optionen sind einfache Token ohne Leerraum oder Klammern.
nfs-no-root-squash = `{$host}` hängt mit no_root_squash ein und behält Root-Rechte auf dem Export.
nfs-sec-sys-only = `{$host}` nutzt den Standard sec=sys oder handelt nur sec=sys aus; füge krb5p für kryptografischen Schutz hinzu.
nfs-world-export = `{$host}` ist für jeden Client mit Lese- und Schreibzugriff erreichbar.
nfs-subtree-undecided = `{$host}` nennt weder subtree_check noch no_subtree_check; Upstream hat die Vorgabe geändert, also lege fest, welche du willst.
nfs-root-squash-undecided = `{$host}` nennt weder root_squash noch no_root_squash; lege fest, welche du willst.
nfs-sync-undecided = `{$host}` nennt weder sync noch async; bevorzuge sync, das Schreibvorgänge dauerhaft sichert.

## resolver module — display name, security notes, schema tooltips
resolver-name = resolver
resolver-note-managed-symlink = auf diesem Host wird /etc/resolv.conf von einem Resolver-Backend verwaltet; detent weigert sich, das Ziel eines verwalteten Symlinks zu bearbeiten, und konfiguriert stattdessen das Backend.
resolver-tip-resolv = die /etc/resolv.conf-Direktiven, die dieses Modul abbildet; alles andere in der Datei bleibt unangetastet erhalten.
resolver-tip-resolved = die systemd-resolved-Einstellungen in Dateireihenfolge. Ihre Änderung startet systemd-resolved neu.
resolver-tip-unbound = die unbound.conf-Einträge, die dieses Modul abbildet, in Dateireihenfolge. Ihre Änderung startet unbound neu.

## resolver module — validation diagnostics
resolver-no-nameserver = es ist kein Nameserver konfiguriert.
resolver-duplicate-nameserver = `{$ip}` kommt als mehr als ein Nameserver vor.
resolver-too-many-nameservers = diese Datei listet {$count} Nameserver; glibc liest höchstens {$max}.
resolver-invalid-domain = `{$domain}` ist kein gültiger Domainname.
resolver-unknown-option = `{$option}` ist keine Option, die der resolv.conf-Parser von glibc akzeptiert.
resolver-search-and-domain = sowohl `search` als auch `domain` sind vorhanden; glibc ignoriert `domain`, wenn `search` gesetzt ist.
resolver-no-config = dieses Modell konfiguriert überhaupt kein Resolver-Backend.
resolver-backend-missing = diese Einstellungen konfigurieren {$service}, das auf diesem Host nicht erkannt wurde.
resolver-rec-dnssec = DNSSEC steht auf allow-downgrade; `DNSSEC=yes` validiert strikt und wird empfohlen, wo die Upstream-Daten es zulassen.
resolver-rec-dot = DNSOverTLS ist opportunistisch, was auf Klartext herabstuft; `DNSOverTLS=yes` erzwingt stattdessen TLS.
resolver-unknown-hardening = `{$key}` ist keine Direktive, die dieses Modul für unbound abbildet.
resolver-unbound-misplaced = `{$key}` gehört in den Abschnitt {$section} von unbound.conf, nicht hierher.
resolver-invalid-forward-addr = `{$addr}` ist keine gültige forward-addr der Form ip[@port][#auth-name].
resolver-invalid-forward-name = `{$name}` ist kein gültiger forward-zone-Name.
resolver-forward-tls-no-auth = diese Zone leitet über TLS weiter, ohne `#auth-name` an der forward-addr, daher ist die TLS-Verbindung nicht authentifiziert.
resolver-rec-hardening = `{$key}` ist deaktiviert; es zu aktivieren härtet unbound gegen Upstream-Fälschung und Delegierungsmissbrauch.
resolver-forward-zone-unnamed = eine forward-zone: ohne Namen leitet nichts weiter und schwächt die Konfiguration; gib jeder Zone einen Namen.

## samba module — display name, security notes, schema tooltips
samba-name = samba
samba-note-guest-access = Gastzugriff wird pro Freigabe beim Verbindungsaufbau gewährt; ein falscher Wert legt Dateien ohne Passwort offen.
samba-tip-entries = die smb.conf-Einträge, die dieses Modul abbildet, in Dateireihenfolge: `[section]`-Köpfe und Direktiven gleichermaßen.
samba-tip-section = der Abschnittsname für einen `[section]`-Kopf; leer bei einer einfachen Direktivenzeile.
samba-tip-key = der Parametername, ohne Beachtung der Groß-/Kleinschreibung und möglicherweise mehrwortig (`guest ok`).
samba-tip-value = der Wert des Parameters bis zum Zeilenende; `%`-Makros bleiben unverändert erhalten.
samba-rec-value = gib lieber einen expliziten gehärteten Wert an, statt dich auf die einkompilierte Vorgabe von Upstream zu verlassen.

## samba module — validation diagnostics
samba-empty-key = eine Direktive hat keinen Parameternamen.
samba-empty-section = ein Abschnittskopf ist leer.
samba-bad-key = `{$key}` würde als Abschnitt oder Kommentar geparst, nicht als Direktivenschlüssel.
samba-bad-value = `{$value}` endet mit `\` und würde die nächste Zeile verschlucken.
samba-bad-section = `{$section}` enthält `[` oder `]` oder endet mit `\` und würde nicht verlustfrei umgesetzt.
samba-guest-ok = `guest ok` ist auf {$value} gesetzt; nicht authentifizierte Clients können sich mit jeder Freigabe verbinden, die es erbt.
samba-map-to-guest = `map to guest` ist {$value}; alles außer Never macht aus fehlgeschlagenen Anmeldungen Gastsitzungen.
samba-min-protocol = `server min protocol` ist {$value}; setze mindestens SMB3_00 und lasse die Protokollstufen aus der SMB1-Zeit weg.
samba-smb-encrypt = `smb encrypt` ist {$value}; setze required, damit SMB-Verkehr nicht unverschlüsselt laufen kann.
samba-restrict-anonymous = `restrict anonymous` ist {$value}; 2 verbirgt die Freigabeliste vor anonymen Benutzern.
samba-rec-server-signing = `server signing` ist {$value}; setze mandatory, damit SMB-Verkehr kryptografisch signiert wird.
samba-rec-load-printers = `load printers` ist {$value}; setze no, es sei denn, dieser Host gibt tatsächlich Drucker frei.
samba-rec-interfaces = es ist keine `interfaces`-Direktive gesetzt; binde samba an ausdrückliche Adressen, statt auf allen Schnittstellen zu lauschen.
samba-writable-exposure = diese Freigabe erlaubt Schreibzugriff über writeable, read only oder write list; bestätige, dass jeder Client Schreibzugriff haben soll.
samba-root-command = `{$key}` führt bei jeder passenden Verbindung einen Befehl mit Root-Rechten aus.
samba-client-command = `{$key}` lässt einen Client samba einen Befehl ausführen lassen; der Client bestimmt, was der Befehl bekommt.
samba-usershare-guests = `usershare allow guests` ist {$value}; Benutzer können Freigaben veröffentlichen, die jeder ohne Passwort öffnet.
samba-wide-links = `wide links` ist {$value}; symbolische Links können Clients aus der Freigabe hinausführen.

## module template — copy-me example
TEMPLATE-name = Modulvorlage
TEMPLATE-note-precedence = dieses fiktive Modul ist ein vom Compiler geprüftes Beispiel für neue Konfigurationsmodule.
TEMPLATE-tip-settings = die Einstellungen, die dieses fiktive Modul abbildet, in Dateireihenfolge.
TEMPLATE-tip-key = der Name der Direktive, ein Wort, ohne Leerraum.
TEMPLATE-tip-value = der Wert der Direktive bis zum Zeilenende.
TEMPLATE-rec-value = gib lieber einen expliziten Wert an, statt dich auf eine Upstream-Vorgabe zu verlassen.
TEMPLATE-invalid-key = `{$key}` ist kein gültiger Direktivenname.
TEMPLATE-duplicate-key = `{$key}` ist mehrfach gesetzt; der letzte Wert gilt.
TEMPLATE-too-many-settings = diese Datei hat {$count} Einstellungen; teile große Konfigurationen in kleinere Dateien auf.

## detent-core — parse, model, and edit errors
## These are the failures a module's own document model can raise, so they are
## prefixed `core-` rather than with a module id.
core-parse-malformed = diese Datei entspricht nicht dem Format, das `{$module}` erwartet: {$reason}
core-model-shape = die übergebene Konfiguration hat nicht die erwartete Form: {$reason}
core-model-unrepresentable = diese Datei enthält etwas, das der Editor nicht darstellen kann: {$reason}
core-edit-line-break = ein Wert darf keinen Zeilenumbruch und kein Nullbyte enthalten; `{$value}` tut es.
core-edit-index-out-of-range = interner Fehler: Zeile {$index} liegt außerhalb einer Datei mit {$len} Zeilen.
core-edit-unsupported = diese Änderung lässt sich im Format der Datei nicht ausdrücken: {$reason}

## detent-core — version-gated options
core-version-too-old = `{$option}` braucht {$service} {$since} oder neuer; dieser Host hat {$installed}.
core-version-unknown = die installierte Version von {$service} ist unbekannt, daher funktioniert `{$option}` (braucht {$service} {$since} oder neuer) möglicherweise nicht.

## operations layer — errors surfaced by detent-ops
ops-unknown-module = in diesem Build gibt es kein Modul namens `{$module}`.
ops-invalid-model = die Konfiguration für `{$module}` ist ungültig: {$reason}
ops-check-failed = der externe Validator `{$program}` hat den Kandidaten abgelehnt: {$reason}
ops-hash-conflict = `{$path}` hat sich seit dem Lesen auf dem Datenträger geändert; lies sie neu ein und versuche es erneut.
ops-privsep-failed = der privilegierte Helfer hat die Anfrage abgelehnt oder konnte sie nicht abschließen: {$reason}
ops-service-failed = die Dienstaktion wurde nicht abgeschlossen: {$reason}
ops-no-target = `{$module}` verwaltet auf diesem Host keine Datei.
ops-no-service = `{$module}` steuert auf diesem Host keinen Dienst, daher kann er nicht neu gestartet werden.
ops-audit-failed = das Audit-Protokoll konnte nicht gelesen werden: {$reason}
ops-audit-unavailable = das Audit-Protokoll konnte nicht geschrieben werden, daher wurde der Vorgang abgelehnt: {$reason}
ops-unsupported = {$what} wird in diesem Build nicht unterstützt.
ops-commit-pending = ein anderes commit-confirm-Fenster ist bereits offen.
ops-update-running = ein Update läuft bereits; warte, bis es fertig ist, und prüfe dann die laufende Version.
ops-update-tag-invalid = das ist keine Release-Version; sie muss wie v1.2.3 aussehen.
ops-update-not-newer = dieses Release ist nicht neuer als die laufende Version; es wurde nichts gestartet.
ops-no-backup = commit-confirm erfordert eine aufbewahrte Sicherung; es wurde nichts geändert.
ops-arm-failed-restored = commit-confirm konnte nicht scharfgestellt werden, daher wurde die Änderung rückgängig gemacht; der vorherige Inhalt ist zurück.
ops-arm-failed-unrestored = commit-confirm konnte nicht scharfgestellt werden und die Änderung konnte NICHT rückgängig gemacht werden; der neue Inhalt liegt weiterhin auf dem Datenträger. Stelle jetzt die vorherige Sicherung wieder her.
ops-target-missing = die verwaltete Datei existiert nicht; lege sie an (installiere ihr Paket oder erstelle sie von Hand) und versuche es dann erneut.
ops-denied = dazu fehlt dir die Berechtigung.

## detent-web — configuration, TLS, the operations bridge, and the listener
web-config-unreadable = `{$path}` konnte nicht gelesen werden: {$reason}
web-config-malformed = `{$path}` ist keine gültige detent-Konfiguration: {$reason}
web-config-zero-value = `{$field}` muss größer als null sein.
web-config-weak-argon2 = `auth.argon2.m_kib` ist {$m}, unter dem Minimum von {$min} kib.
web-tls-generate-failed = das Bootstrap-Zertifikat konnte nicht erzeugt werden: {$reason}
web-tls-key-rejected = das Zertifikat und sein privater Schlüssel wurden abgelehnt: {$reason}
web-tls-store-unreadable = `{$path}` konnte nicht gelesen werden: {$reason}
web-tls-store-unwritable = `{$path}` konnte nicht zum Schreiben vorbereitet werden: {$reason}
web-tls-store-write-failed = `{$path}` konnte nicht geschrieben werden: {$reason}
web-tls-acme-pem-rejected = das ausgestellte Zertifikat oder der Schlüssel war kein brauchbares PEM.
web-engine-stopped = die Operations-Engine läuft nicht mehr; versuche es erneut, sobald der Dienst wieder da ist.
web-cert-renew-not-acme = die Erneuerung braucht `tls.bootstrap = "acme"` in detent.toml.
web-cert-renew-unavailable = der ACME-Client hat die Erneuerungsanfrage nicht erhalten; versuche es später erneut.
web-update-not-checked = auf diesem Host wurde noch keine Update-Prüfung ausgeführt; führe `detent update --check` als root aus.
web-server-bind-failed = auf `{$addr}` konnte nicht gelauscht werden: {$reason}
web-server-address-unknown = die Lauschadresse konnte nicht zurückgelesen werden: {$reason}

## detent-web — auth: passwords, sessions, api tokens, totp, csrf
web-auth-entropy-unavailable = der Zufallszahlengenerator des Systems ist ausgefallen, daher konnten keine Zugangsdaten ausgestellt werden.
web-auth-argon2-params = die konfigurierten argon2-Parameter sind nicht verwendbar: {$reason}
web-auth-hash-failed = das Passwort konnte nicht gehasht werden.
web-auth-user-name-invalid = `{$name}` ist kein verwendbarer Benutzername; nutze 1 bis 32 Zeichen aus `a-z`, `0-9`, `.`, `_` oder `-`, beginnend mit einem Buchstaben oder einer Ziffer.
web-auth-user-exists = ein Benutzer namens `{$name}` existiert bereits.
web-auth-user-unknown = es gibt keinen Benutzer namens `{$name}`.
web-auth-invalid-credentials = der Benutzername, das Passwort oder der Code war nicht korrekt.
web-auth-rate-limited = zu viele Versuche; warte {$seconds} Sekunden und versuche es erneut.
web-auth-session-limit = zu viele Sitzungen sind offen; warte, bis eine abläuft, und melde dich erneut an.
web-auth-busy = zu viele Anmeldungen laufen gerade; warte einen Moment und versuche es erneut.
web-auth-unauthenticated = melde dich an, um das zu tun.
web-auth-ambiguous-credentials = sende entweder ein Sitzungs-Cookie oder ein Bearer-Token, nicht beides.
web-auth-csrf-rejected = diese Anfrage hat die Cross-Site-Prüfungen nicht bestanden.
web-auth-token-unknown = dieses API-Token existiert nicht, wurde widerrufen oder ist abgelaufen.
web-auth-token-limit = dieser Host hält bereits die maximale Anzahl an API-Token.
web-auth-totp-secret-invalid = dieses Authenticator-Geheimnis ist kein gültiges Base32.
web-auth-store-unreadable = `{$path}` konnte nicht gelesen werden: {$reason}
web-auth-store-unwritable = `{$path}` konnte nicht zum Schreiben vorbereitet werden: {$reason}
web-auth-store-write-failed = `{$path}` konnte nicht geschrieben werden: {$reason}
web-auth-store-malformed = `{$path}` ist keine gültige detent-Zugangsdatendatei: {$reason}
web-denied-scope = diese Zugangsdaten tragen nicht den Geltungsbereich `{$scope}`.

## detent-web — the api surface
web-request-malformed = der Anfragetext hat nicht die Form, die dieser Endpunkt erwartet.
web-request-too-deep = der Anfragetext ist zu tief verschachtelt.
web-api-unexpected-outcome = der Vorgang wurde abgeschlossen, aber sein Ergebnis konnte nicht dargestellt werden.
