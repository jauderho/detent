# needs-review: machine-drafted German translation; not yet checked by a native speaker.
## detent CLI — de
## Source: locales/en-US/cli.ftl. Same ids, same placeables. Identifiers — module ids,
## paths, unit names, digests, enum wire names such as `restart` or `active` — are
## interpolated verbatim and must not be translated.

## severity words, prefixed to every rendered diagnostic
cli-severity-error = Fehler
cli-severity-warning = Warnung
cli-severity-recommendation = Hinweis

## yes/no, used wherever a flag is rendered
cli-yes = ja
cli-no = nein

## progress notes, printed on stderr under --verbose
cli-note-settings = Sprache {$locale}, Zustandsverzeichnis {$state}, Konfiguration {$config}
cli-note-operation = {$operation} wird für {$module} ausgeführt

## failures that stop a command before the operations layer sees it
cli-bad-stdin = das Modell konnte nicht von stdin gelesen werden: {$reason}
cli-bad-json = das Modell auf stdin ist kein gültiges JSON: {$reason}
cli-bad-hash = `{$value}` ist kein SHA-256-Digest aus 64 Hexadezimalzeichen.
cli-start-failed = der privilegierte Helfer konnte nicht gestartet werden: {$reason}
cli-monitor-stop = der privilegierte Helfer wurde nicht sauber beendet: {$reason}
cli-monitor-busy = ein anderer detent-Monitor besitzt dieses Zustandsverzeichnis bereits; versuche es über die Web-Oberfläche erneut oder führe `detent serve` aus.
cli-monitor-lock-unavailable = die Zustandssperre in {$path} kann nicht gesetzt werden, daher kann dieser Befehl nichts ändern; führe ihn als Benutzer aus, der dieses Verzeichnis beschreiben darf, oder übergib --state-root.
cli-commit-recovered = unbestätigter Commit {$commit} wiederhergestellt; {$restored} Ziele zurückgesetzt, {$failures} Fehler.
cli-commit-confirm-needs-serve = dieses Modul erfordert commit-confirm; nutze die Web-Oberfläche oder `detent serve`, damit das Bestätigungsfenster durchgesetzt bleibt.
cli-config-load-failed = die Konfiguration in {$path} konnte nicht geladen werden: {$reason}
cli-no-command = es wurde kein Befehl angegeben.

## self-test probe and self-update (PLAN §2.9)
cli-self-test = Version {$version}, Funktionen {$features}
cli-update-available = Update verfügbar: {$tag}, veröffentlicht {$published}
cli-update-security-available = Sicherheitsupdate verfügbar: {$tag}, veröffentlicht {$published}
cli-update-none = kein Update verfügbar (aktuell {$current})
cli-update-held-young = {$tag} ist neuer als {$current}, aber jünger als {$days} Tag(e); die Altersschranke hält es zurück
cli-update-held-rejected = {$tag} ist neuer als {$current}, wurde auf diesem Host aber zurückgerollt; es wird übersprungen
cli-verify-bundle-ok = {$file} ist für {$tag} beglaubigt
cli-update-failed = Update fehlgeschlagen: {$reason}
cli-update-installed = {$tag} installiert; die ersetzte Binärdatei liegt weiter unter {$previous}
cli-update-not-restarted = der Dienst wurde nicht neu gestartet, daher läuft die neue Binärdatei noch nicht: {$reason}
cli-update-rolled-back = zurückgerollt: {$reason}
cli-update-rollback-failed = das Update ist fehlgeschlagen ({$reason}) und das Zurückrollen ebenfalls ({$error}); dieser Host braucht Aufmerksamkeit

## config
cli-module-line = {$id}  {$name}
cli-no-model = dieses Modul verwaltet auf diesem Host noch keine Datei, daher gibt es kein Modell zum Anzeigen.
cli-valid = diese Konfiguration ist gültig.
cli-plan-no-change = {$module} entspricht bereits dem Inhalt von {$path}; es würde sich nichts ändern.
cli-plan-service = das Anwenden würde {$unit} betreffen.
cli-plan-hash = die Datei hat jetzt den Hash {$hash}; übergib ihn als --expect-hash, um eine konkurrierende Änderung abzulehnen.
cli-check-ran = der vorgelagerte Validator {$program} wurde ausgeführt; bestanden: {$passed}. {$detail}
cli-check-skipped = der vorgelagerte Validator {$program} wurde nicht ausgeführt. {$detail}
cli-applied = {$module} wurde nach {$path} geschrieben.
cli-applied-hash = der Hash war {$prev} und ist jetzt {$new}; Sicherung behalten: {$backup}
cli-mounts-off = mounts: Aktivierung ist aus ([mounts] activate_new_entries); neue fstab-Einträge wirken beim nächsten Neustart oder Mount.
cli-mounts-error = mounts: es wurde keine Mount-Unit gestartet: {$reason}
cli-mounts-none = mounts: kein neuer fstab-Eintrag zum Einhängen.
cli-mounts-unit = mount {$mountpoint} ({$unit}): {$state}
cli-mounts-unit-detail = mount {$mountpoint} ({$unit}): {$state}: {$detail}
cli-commit-armed = Commit {$id} muss innerhalb von {$seconds} Sekunden bestätigt werden, bis {$deadline}, sonst wird er zurückgerollt.
cli-commit-confirmed = Commit {$id} ist bestätigt und wird nicht zurückgerollt.
cli-commit-rolled-back = Commit {$id} wurde zurückgerollt; {$targets} Ziele wurden zurückgesetzt.

## backups
cli-no-backups = für dieses Modul wurden noch keine Sicherungen aufbewahrt.
cli-backup-line = {$id}  {$name}  {$bytes} Bytes  {$digest}
cli-restored = Ziel {$target} wurde zurückgesetzt und hat jetzt den Hash {$hash}.

## services
cli-service-status = {$unit} ist {$state}; startet beim Booten: {$enabled}
cli-serviced = {$unit} wurde aufgefordert: {$action}; läuft jetzt: {$active}

## host
cli-host-profile = {$hostname}: {$os}, init {$init}, {$ram} MiB RAM
cli-host-service-version = installiertes {$service} hat Version {$version}
cli-host-backends = Netzwerk-Backend {$network}, Resolver-Backend {$resolver}, Distribution {$distro} {$version}
cli-host-note = Hinweis zur Erkennung: {$note}

## audit
cli-no-audit = das Audit-Protokoll hat keine passenden Einträge.
cli-audit-line = {$ts}  {$who}  {$op}  {$module}  {$result}  {$error}

## --dryrun
cli-dryrun-apply = Probelauf: das würde für {$module} nach {$path} geschrieben.
cli-dryrun-operation = Probelauf: {$operation} würde für {$module} ausgeführt.
cli-dryrun-nothing = Probelauf: es wurde nichts geändert.
cli-dryrun-serve = Probelauf: Monitor und Worker würden mit {$modules} Modulen und {$targets} Zielen starten, verwurzelt in {$state}.
cli-dryrun-serve-mounts = Probelauf: nach einem mounts-Apply würde der Runner die Mount-Units neuer fstab-Einträge starten (mounts.activate_new_entries = true).
cli-dryrun-cert-renew = Probelauf: würde den Server unter {$address} (als {$name}) bitten, sein Zertifikat jetzt zu erneuern; es wurde nichts gesendet.

## serve
cli-serve-monitor = der Worker wurde als pid {$pid} gestartet; Privilegien abgegeben: {$dropped}
cli-serve-worker = der Worker läuft; sein HTTP-Server folgt in Phase 4. Handshake: {$greeted}
cli-serve-failed = Monitor und Worker konnten nicht gestartet werden: {$reason}
cli-serve-stopped = das Paar wurde unerwartet beendet: {$reason} {$status}
cli-serve-privileged-port = Port {$port} braucht cap_net_bind_service oder einen vom Monitor übergebenen Socket, was dieser Build beides nicht unterstützt; nutze einen Port ab 1024 oder setze einen Reverse-Proxy davor.
cli-serve-privilege-mode = der eingestellte Privilegienmodus passt nicht zu diesem Prozess, daher wurde der Dienst nicht gestartet: {$reason}
cli-serve-acme-unsupported = dieser Build hat keine dns-01-Anbieter (Feature acme-dns-providers) und kann daher keine ACME-Zertifikate beziehen; setze tls.bootstrap in {$path} auf "self-signed".
cli-serve-acme-setting-missing = tls.bootstrap ist "acme", aber {$setting} ist in {$path} nicht gesetzt.
cli-serve-acme-path-outside = {$setting} ({$value}) liegt nicht unter dem Zustandsverzeichnis {$root}: die eingesperrten Prozesse schreiben nur dort.
cli-serve-acme-credentials-dir = das ACME-Zugangsdatenverzeichnis {$path} konnte nicht vorbereitet werden: {$reason}
cli-serve-secrets-failed = die Geheimnisdatei {$path} wurde abgelehnt: {$reason}
cli-serve-acme-secret-missing = acme.provider ist gesetzt, aber {$path} hat kein dns_provider-Geheimnis in der Tabelle [acme].
cli-serve-acme-provider-invalid = der dns-01-Anbieter in acme.provider kann nicht verwendet werden: {$reason}
cli-serve-acme-providers-not-built = dieser Build hat keine dns-01-Anbieter (Feature acme-dns-providers); entferne [acme.provider] aus {$path}.
cli-serve-handshake-failed = der Worker konnte den Handshake mit dem Monitor nicht abschließen.
cli-serve-auth-failed = der Speicher für Konten, Token und Sitzungen konnte nicht geöffnet werden: {$reason}
cli-serve-tls-failed = das TLS-Zertifikat konnte nicht vorbereitet werden: {$reason}
cli-serve-cert-fingerprint = Fingerabdruck des TLS-Bootstrap-Zertifikats (sha-256): {$fingerprint}
cli-serve-web-failed = der Webserver konnte nicht gestartet werden: {$reason}
cli-serve-web-stopped = der Webserver wurde nicht sauber beendet: {$reason}
cli-serve-listening = lauscht auf {$addr}
cli-serve-confinement-degraded = Einsperrung eingeschränkt: {$detail}
cli-mcp-missing-token = {$var} ist nicht gesetzt; erzeuge eines mit `detent token create` und exportiere es, bevor du den MCP-Server startest.
cli-mcp-serve-failed = der MCP-Server konnte nicht gestartet werden: {$reason}
cli-mcp-listening = mcp bedient {$transport}
cli-mcp-http-needs-privsep = der MCP-HTTP-Transport kann nicht als root oder mit Capabilities laufen: der Netzwerk-Parser würde mit root-ähnlichen Rechten laufen; starte ihn als Nicht-root-Benutzer ohne Capabilities oder nutze den stdio-Transport.
cli-mcp-bind-not-loopback = die MCP-HTTP-Bindung muss Loopback sein (127.0.0.1 oder ::1); das Bearer-Token läuft im Klartext über die Leitung.
cli-dryrun-mcp = Probelauf: mcp würde {$transport} auf {$addr} mit dem Geltungsbereich {$scope} bedienen.

## setup, user, token
cli-setup-exists = auf diesem Host existiert bereits ein Benutzer namens `{$name}`; übergib --force, um ihn zu überschreiben.
cli-setup-created = das Administratorkonto `{$name}` wurde angelegt.
cli-user-created = das Konto `{$name}` wurde angelegt.
cli-user-passwd = das Passwort für `{$name}` wurde geändert.
cli-user-removed = das Konto `{$name}` wurde entfernt.
cli-totp-uri = füge dies deiner Authenticator-App hinzu: {$uri}
cli-totp-secret = oder gib diesen Schlüssel dort ein: {$secret}
cli-totp-code-prompt = Code aus deiner Authenticator-App:
cli-totp-code-empty = ein Code darf nicht leer sein.
cli-totp-code-wrong = dieser Code ist ungültig, daher wurde der zweite Faktor nicht eingeschaltet.
cli-user-totp-enabled = der zweite Faktor für `{$name}` wurde eingeschaltet.
cli-totp-disable-prompt = den zweiten Faktor für `{$name}` ausschalten? [y/N]
cli-totp-disable-cancelled = der zweite Faktor für `{$name}` bleibt eingeschaltet.
cli-user-totp-disabled = der zweite Faktor für `{$name}` wurde ausgeschaltet.
cli-token-created = Token {$id} ({$label}) wurde erstellt; es wird nicht noch einmal angezeigt: {$token}
cli-token-revoked = Token {$id} wurde widerrufen.
cli-token-no-tokens = es wurden keine Token ausgestellt.
cli-token-line = {$id}  {$label}  {$scopes}  {$created}  {$expires}
cli-credential-failed = die Anfrage konnte nicht abgeschlossen werden: {$reason}
cli-state-command-as-root = detent {$command} darf nicht als root laufen: die geschriebenen Dateien gehörten root, und der Dienst könnte sie nicht lesen. Führe es stattdessen als Dienstkonto aus: sudo -u {$account} detent {$command}

## cert status
cli-cert-source = Quelle: {$source}
cli-cert-fingerprint = Fingerabdruck (sha-256): {$fingerprint}
cli-cert-not-after = läuft ab: {$not_after}
cli-cert-not-after-unknown = Ablauf: unbekannt (das Zertifikat ließ sich nicht parsen).
cli-cert-lifetime = Lebensdauer verbraucht: {$percent} (Warnung: {$warning}).
cli-cert-lifetime-no-warning = Lebensdauer verbraucht: {$percent} (keine Warnung).
cli-cert-lifetime-unknown = Lebensdauer verbraucht: unbekannt (das Zertifikat ließ sich nicht parsen).
cli-cert-missing = in {$path} ist kein Zertifikat gespeichert; starte den Server einmal, damit er eines schreibt.
cli-cert-unreadable = das Zertifikat in {$path} konnte nicht gelesen werden: {$reason}

## cert renew
cli-cert-renew-requested = Erneuerung angefordert: der Server hat seinen ACME-Client gebeten, jetzt zu erneuern. Prüfe das Ergebnis mit `detent cert status`.
cli-cert-renew-token-refused = das Token wurde abgelehnt (HTTP {$status}); es braucht Schreibrechte: `detent token create <name> --write`.
cli-cert-renew-not-acme = der Server führt keinen ACME-Prozess aus (`tls.bootstrap` ist nicht `acme`), daher gibt es nichts zu erneuern.
cli-cert-renew-server-error = der Server antwortete mit HTTP {$status}: {$message_id}
cli-cert-renew-server-error-bare = der Server antwortete mit HTTP {$status}.
cli-cert-renew-unreachable = keine Verbindung zum Server unter {$address} möglich: {$reason}
cli-cert-renew-no-token = kein API-Token: übergib --token-file <path> oder setze {$var}. Erzeuge ein Schreib-Token mit `detent token create <name> --write`.
cli-cert-renew-bad-token = das Token aus {$source} wurde abgelehnt: {$reason}
cli-cert-renew-ca-unreadable = die CA-Datei {$path} konnte nicht gelesen werden: {$reason}

## password entry (setup, user add, user passwd)
cli-password-prompt = Passwort:
cli-password-confirm = Passwort bestätigen:
cli-password-mismatch = die Passwörter stimmten nicht überein.
cli-password-empty = ein Passwort darf nicht leer sein.

## doctor
cli-status-ok = ok
cli-status-warn = Warnung
cli-status-fail = Fehler
cli-doctor-modules = in diesen Build einkompilierte Module: {$detail}
cli-doctor-state-root = Zustandsverzeichnis {$detail}
cli-doctor-config = Konfigurationsdatei {$detail}
cli-doctor-privsep = die Rechtetrennung kann ein funktionierendes Paar forken: {$detail}
cli-doctor-landlock = landlock: {$detail}
cli-doctor-seccomp = seccomp: {$detail}
cli-doctor-confinement = Sandbox-Einsperrung: {$detail}
cli-doctor-serve-confinement = Einsperrung beim letzten serve-Start: {$detail}
cli-doctor-mounts = Mount-Aktivierung nach einem fstab-Apply: {$detail}
cli-doctor-privilege-mode = Privilegienmodus: {$detail}
cli-doctor-service-account = Dienstkonto: {$detail}
cli-doctor-state-owner = Eigentümer des Zustandsverzeichnisses: {$detail}
cli-doctor-backups-dir = Backup-Verzeichnis: {$detail}
cli-doctor-polkit-rule = polkit-Regel: {$detail}
cli-doctor-polkit-daemon = polkit-Daemon: {$detail}
cli-doctor-unit-capabilities = Identität und Capabilities der Dienst-Unit: {$detail}
