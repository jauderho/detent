# needs-review: machine-drafted German translation; not yet checked by a native speaker.
## detent web admin UI — de
## Source: locales/en-US/web.ftl. Same ids, same placeables.

## Status bar
status-brand = detent
status-online = System online
status-clock-label = utc
status-mode-label = Modus
theme-toggle-aria = zwischen hellem und dunklem Modus wechseln
theme-toggle-title = hell / dunkel umschalten

## catfu component layer
## Chrome the shared components render themselves. Content strings (field
## captions, table headers, banner copy) are supplied by the calling page.
component-countdown-remaining = verbleibende Zeit
component-field-info = weitere Informationen
component-modal-close = schließen
component-switch-off = aus
component-switch-on = an
component-table-empty = keine Einträge

## API failures
## docs/API.md: every failure is `{ code, message_id }`, and `message_id` is a
## Fluent id. src/api/messages.ts resolves it here; an id this build does not
## know falls back to `api-error-unknown`, so an id is never rendered raw.
##
## The first three are the console's own — a failure that never reached a
## server has no `message_id` to resolve. The rest mirror the ids the server
## sends, argument-free: locales/en-US/core.ftl interpolates `{$path}`,
## `{$reason}` and friends, and the API deliberately sends none of them.
api-error-network = die Konsole konnte diesen Host nicht erreichen.
api-error-malformed = dieser Host hat eine Antwort gesendet, die die Konsole nicht lesen konnte.
api-error-unknown = dieser Host hat einen Fehler gemeldet, für den die Konsole keine Beschreibung hat.
core-edit-index-out-of-range = interner Fehler: eine Änderung betraf eine Zeile außerhalb der Datei.
core-edit-line-break = ein Wert darf keinen Zeilenumbruch und kein Nullbyte enthalten.
core-edit-unsupported = diese Änderung lässt sich im Format der Datei nicht ausdrücken.
core-model-shape = die übergebene Konfiguration hat nicht die erwartete Form.
core-model-unrepresentable = diese Datei enthält etwas, das der Editor nicht darstellen kann.
core-parse-malformed = diese Datei entspricht nicht dem Format, das ihr Modul erwartet.
ops-audit-failed = das Audit-Protokoll konnte nicht gelesen werden.
ops-audit-unavailable = das Audit-Protokoll konnte nicht geschrieben werden, daher wurde der Vorgang abgelehnt.
ops-denied = dazu fehlt dir die Berechtigung.
ops-hash-conflict = die Datei hat sich seit dem Lesen auf dem Datenträger geändert; lies sie neu ein und versuche es erneut.
ops-check-failed = der externe Validator hat den Kandidaten abgelehnt.
ops-invalid-model = diese Konfiguration ist ungültig.
ops-no-service = dieses Modul steuert auf diesem Host keinen Dienst, daher kann er nicht neu gestartet werden.
ops-no-target = dieses Modul verwaltet auf diesem Host keine Datei.
ops-privsep-failed = der privilegierte Helfer hat die Anfrage abgelehnt oder konnte sie nicht abschließen.
ops-service-failed = die Dienstaktion wurde nicht abgeschlossen.
ops-unknown-module = in diesem Build gibt es kein Modul dieses Namens.
ops-unsupported = das wird in diesem Build nicht unterstützt.
ops-commit-pending = ein anderes commit-confirm-Fenster ist bereits offen.
ops-update-running = ein Update läuft bereits; warte, bis es fertig ist, und prüfe dann die laufende Version.
ops-update-tag-invalid = das ist keine Release-Version; sie muss wie v1.2.3 aussehen.
ops-update-not-newer = dieses Release ist nicht neuer als die laufende Version; es wurde nichts gestartet.
ops-no-backup = commit-confirm erfordert eine aufbewahrte Sicherung; es wurde nichts geändert.
ops-arm-failed-restored = commit-confirm konnte nicht scharfgestellt werden, daher wurde die Änderung rückgängig gemacht; der vorherige Inhalt ist zurück.
ops-arm-failed-unrestored = commit-confirm konnte nicht scharfgestellt werden und die Änderung konnte NICHT rückgängig gemacht werden; der neue Inhalt liegt weiterhin auf dem Datenträger. Stelle jetzt die vorherige Sicherung wieder her.
ops-target-missing = die verwaltete Datei existiert nicht; lege sie an (installiere ihr Paket oder erstelle sie von Hand) und versuche es dann erneut.
web-api-unexpected-outcome = der Vorgang wurde abgeschlossen, aber sein Ergebnis konnte nicht dargestellt werden.
web-auth-ambiguous-credentials = sende entweder ein Sitzungs-Cookie oder ein Bearer-Token, nicht beides.
web-auth-argon2-params = die konfigurierten argon2-Parameter sind nicht verwendbar.
web-auth-busy = zu viele Anmeldungen laufen gerade; warte einen Moment und versuche es erneut.
web-auth-csrf-rejected = diese Anfrage hat die Cross-Site-Prüfungen nicht bestanden; lade die Seite neu und versuche es erneut.
web-auth-entropy-unavailable = der Zufallszahlengenerator des Systems ist ausgefallen, daher konnten keine Zugangsdaten ausgestellt werden.
web-auth-hash-failed = das Passwort konnte nicht gehasht werden.
web-auth-invalid-credentials = der Benutzername, das Passwort oder der Code war nicht korrekt.
web-auth-rate-limited = zu viele Versuche; warte einen Moment und versuche es erneut.
web-auth-session-limit = zu viele Sitzungen sind offen; warte, bis eine abläuft, und melde dich erneut an.
web-auth-store-malformed = eine Zugangsdatendatei auf diesem Host ist ungültig.
web-auth-store-unreadable = eine Zugangsdatendatei auf diesem Host konnte nicht gelesen werden.
web-auth-store-unwritable = eine Zugangsdatendatei auf diesem Host konnte nicht zum Schreiben vorbereitet werden.
web-auth-store-write-failed = eine Zugangsdatendatei auf diesem Host konnte nicht geschrieben werden.
web-auth-token-limit = dieser Host hält bereits die maximale Anzahl an API-Token.
web-auth-token-unknown = dieses API-Token existiert nicht, wurde widerrufen oder ist abgelaufen.
web-auth-totp-secret-invalid = dieses Authenticator-Geheimnis ist kein gültiges Base32.
web-auth-unauthenticated = melde dich an, um das zu tun.
web-auth-user-exists = ein Benutzer mit diesem Namen existiert bereits.
web-auth-user-name-invalid = dieser Benutzername ist nicht verwendbar; nutze 1 bis 32 Zeichen aus `a-z`, `0-9`, `.`, `_` oder `-`, beginnend mit einem Buchstaben oder einer Ziffer.
web-auth-user-unknown = es gibt keinen Benutzer mit diesem Namen.
web-cert-renew-not-acme = die Erneuerung braucht `tls.bootstrap = "acme"` in detent.toml.
web-cert-renew-unavailable = der ACME-Client hat die Erneuerungsanfrage nicht erhalten; versuche es später erneut.
web-denied-scope = diese Zugangsdaten tragen nicht den Geltungsbereich, den diese Aktion braucht.
web-engine-stopped = die Operations-Engine läuft nicht mehr; versuche es erneut, sobald der Dienst wieder da ist.
web-update-not-checked = auf diesem Host wurde noch keine Update-Prüfung ausgeführt; führe `detent update --check` als root aus.
web-request-malformed = der Anfragetext hat nicht die Form, die dieser Endpunkt erwartet.
web-request-too-deep = der Anfragetext ist zu tief verschachtelt.

## Sign in
login-title = Anmelden
login-panel-label = Sitzung
login-username-label = Benutzername
login-password-label = Passwort
login-totp-label = Authenticator-Code
login-totp-description = sechs Ziffern aus dem Authenticator, der für dieses Konto eingerichtet ist.
login-totp-reveal = Authenticator-Code verwenden
login-submit = Anmelden
login-submitting = Anmeldung läuft
login-retry-after = zu viele Versuche; warte {$seconds} Sekunden und versuche es erneut.

## Session and scope
auth-checking = Sitzung wird geprüft
auth-sign-out = Abmelden
scope-gate-read-only = diese Sitzung hat nur Lesezugriff; sie kann auf diesem Host nichts ändern.
scope-gate-signed-out = melde dich an, um etwas auf diesem Host zu ändern.

## Navigation
nav-label = Bereiche
nav-dashboard = Dashboard
nav-modules = Module
nav-services = Dienste
nav-backups = Sicherungen
nav-audit = Audit
nav-certificates = Zertifikate
nav-settings = Einstellungen

## Routed pages
## Certificates and settings are still named placeholders: neither has an API
## to drive. Certificates waits on Phase 6 (ACME); settings waits on the user
## and token endpoints.
page-placeholder-body = dieser Bereich ist noch nicht gebaut.
page-dashboard-title = Dashboard
page-modules-title = Module
page-module-detail-title = Modul {$module}
page-services-title = Dienste
page-backups-title = Sicherungen
page-audit-title = Audit-Protokoll
page-certificates-title = Zertifikate
page-settings-title = Einstellungen
page-not-found-title = Seite nicht gefunden
page-not-found-body = diese Adresse bezeichnet nichts in dieser Konsole.
page-not-found-home = zum Dashboard

## Pending commit
pending-commit-message = eine Konfigurationsänderung wartet auf Bestätigung; sie wird von selbst zurückgerollt, wenn dieses Fenster abläuft.
pending-commit-countdown-label = verbleibende Zeit zum Bestätigen
pending-commit-confirm = Änderung bestätigen
pending-commit-confirming = wird bestätigt…

## Shared page states
## Every section is a query away from its data, so loading, failure and "this
## host has none of these" are shared rather than re-worded per page.
state-loading = lädt
state-unknown = unbekannt
value-no = nein
value-yes = ja

## Dashboard
dashboard-host-panel = Host
dashboard-host-hostname = Hostname
dashboard-host-os = Betriebssystem
dashboard-host-init = Init-System
dashboard-host-distro = Distribution
dashboard-host-ram = Arbeitsspeicher
dashboard-host-network-backend = Netzwerk-Backend
dashboard-host-resolver-backend = Resolver-Backend
dashboard-host-notes = Hinweise zur Erkennung
dashboard-cert-panel = Zertifikat
dashboard-cert-fingerprint = Fingerabdruck
dashboard-cert-expires = läuft ab
dashboard-cert-lifetime-used = Lebensdauer verbraucht
dashboard-cert-expired = abgelaufen; ersetze dieses Zertifikat.
dashboard-cert-expiring-soon = läuft innerhalb von 30 Tagen ab; plane die Erneuerung.
dashboard-cert-half = die Hälfte der Zertifikatslebensdauer ist verbraucht; die Erneuerung ist geplant.
dashboard-cert-quarter = drei Viertel der Zertifikatslebensdauer sind verbraucht; erneuere bald.
cert-renew-panel = Erneuerung
cert-renew-now = jetzt erneuern
cert-renew-requested = Erneuerung angefordert. Das neue Zertifikat wird installiert, sobald die CA es ausstellt.
dashboard-modules-panel = Module
dashboard-modules-count = {$count ->
    [one] ein Modul ist in diesen Build einkompiliert.
   *[other] {$count} Module sind in diesen Build einkompiliert.
}
dashboard-audit-panel = letzte Aktivität
dashboard-view-all = alle anzeigen
dashboard-update-panel = Update
dashboard-update-current = laufende Version
dashboard-update-published = veröffentlicht
dashboard-update-up-to-date = für diesen Build wird kein neueres Release angeboten.
dashboard-update-available = das Release {$tag} ist für diesen Build verfügbar.
dashboard-update-security = dieses Release ist als Sicherheitsupdate gekennzeichnet; es umgeht die Altersschranke.
dashboard-update-install = {$tag} installieren
dashboard-update-confirm-title = dieses Update installieren?
dashboard-update-confirm-body = damit beginnt die Installation von {$tag} im Hintergrund. Wird es installiert, startet der detent-Dienst neu und die Seite trennt und verbindet sich möglicherweise neu; ist der neu gestartete Dienst nicht gesund, wird das Update zurückgerollt.
dashboard-update-confirm-action = installieren
dashboard-update-confirm-cancel = abbrechen
dashboard-update-started = das Update auf {$version} wurde im Hintergrund gestartet. Der Dienst startet neu, wenn es installiert wird, und wird zurückgerollt, wenn er nicht gesund ist; die laufende Version zeigt das Ergebnis.

## Modules
modules-panel-label = installierte Module
modules-col-module = Modul
modules-col-targets = Dateien
modules-col-services = Dienste
modules-col-commit-confirm = commit-confirm
modules-commit-confirm-required = erforderlich
modules-commit-confirm-not-required = nicht erforderlich
modules-empty = in diesen Build sind keine Module einkompiliert.
modules-none = keine

## One module
module-about-panel = Modul
module-configuration-panel = Konfiguration
module-upstream-label = folgt Upstream
module-targets-label = Dateien
module-services-label = Dienste
module-current-hash-label = Digest auf dem Datenträger
module-security-notes-label = Sicherheitshinweise
module-model-missing = die Datei dieses Moduls existiert auf diesem Host noch nicht. Das Formular unten beginnt mit den eigenen Vorgaben des Moduls, und das Anwenden legt die Datei an.
module-action-validate = prüfen
module-action-plan = planen
module-action-apply = anwenden
module-action-discard = Änderungen verwerfen
module-busy = in Arbeit
module-validate-clean = diese Konfiguration hat jede Prüfung bestanden, die dieser Host ausführt.
module-plan-title = geplante Änderung
module-plan-no-change = diese Konfiguration entspricht dem, was bereits auf dem Datenträger liegt; es gibt nichts anzuwenden.
module-plan-diff-label = Diff
module-plan-checks-label = Upstream-Prüfungen
module-plan-check-passed = bestanden
module-plan-check-failed = fehlgeschlagen
module-plan-check-exit = Exit {$code}
module-plan-services-label = Dienste, die davon betroffen wären
module-plan-apply = diese Änderung anwenden
module-apply-title = diese Änderung anwenden?
module-apply-body = damit wird {$path} auf diesem Host geschrieben. Der aktuelle Inhalt wird zuvor gesichert.
module-apply-commit-confirm = dieses Modul kann einen Administrator aussperren, daher stellt die Änderung ein commit-confirm-Fenster scharf: sie wird von selbst zurückgerollt, außer du bestätigst sie vor Fristablauf.
module-apply-service-label = danach
module-apply-service-none = den Dienst in Ruhe lassen
module-apply-cancel = abbrechen
module-applied = die Änderung wurde nach {$path} geschrieben.
module-applied-created = {$path} existierte nicht und wurde angelegt.
module-mounts-off = neue fstab-Einträge wurden nicht eingehängt ([mounts] activate_new_entries ist aus); sie wirken beim nächsten Boot oder Mount.
module-mounts-error = es wurde keine Mount-Unit gestartet: {$reason}
module-mounts-none = es gibt keinen neuen fstab-Eintrag zum Einhängen.
module-mounts-units = Mount-Units der neuen fstab-Einträge:
module-mount-state-mounted = eingehängt
module-mount-state-already-mounted = bereits eingehängt
module-mount-state-pending = wird noch eingehängt
module-mount-state-failed = fehlgeschlagen
module-mount-state-protected = abgelehnt: geschützter Pfad
module-mount-state-stopped = ausgehängt
module-cancel = abbrechen

## Services
services-panel-label = Dienste
services-col-module = Modul
services-col-unit = Unit
services-col-state = Zustand
services-col-enabled = beim Boot
services-col-since = seit
services-col-actions = Aktionen
services-state-active = aktiv
services-state-inactive = inaktiv
services-state-failed = fehlgeschlagen
services-state-activating = startet
services-state-deactivating = stoppt
services-state-unknown = unbekannt
services-action-restart = neu starten
services-action-reload = neu laden
services-action-start = starten
services-action-stop = stoppen
services-acted = {$unit}: {$detail}
services-empty = kein Modul in diesem Build steuert auf diesem Host einen Dienst.
services-confirm-title = {$action} {$unit}?
services-confirm-body = das wirkt sofort auf den laufenden Dienst.
services-confirm-cancel = abbrechen

## Backups
backups-col-name = Sicherung
backups-col-created = erstellt
backups-col-size = Größe
backups-col-digest = Digest
backups-col-actions = Aktionen
backups-action-restore = wiederherstellen
backups-confirm-title = diese Sicherung wiederherstellen?
backups-confirm-body = damit wird {$target} durch die aufbewahrte Kopie ersetzt. Der aktuelle Inhalt wird zuvor gesichert.
backups-confirm-cancel = abbrechen
backups-restored = die Sicherung wurde wiederhergestellt.
backups-empty = für dieses Modul wurde noch nichts gesichert.
backups-module-panel = Sicherungen von {$module}

## Audit log
audit-panel-label = Audit-Protokoll
audit-col-when = wann
audit-col-who = Aufrufer
audit-col-how = Zugangsdaten
audit-col-op = Vorgang
audit-col-module = Modul
audit-col-result = Ergebnis
audit-filter-module-label = Modul
audit-filter-who-label = Aufrufer
audit-filter-limit-label = Zeilen
audit-filter-apply = filtern
audit-filter-clear = zurücksetzen
audit-empty = auf diesem Host wurde noch nichts aufgezeichnet.
audit-result-ok = ok
audit-result-denied = abgelehnt
audit-result-error = fehlgeschlagen
audit-identity-local-user = lokaler Benutzer
audit-identity-session = Sitzung
audit-identity-token = API-Token
audit-op-list-modules = Module auflisten
audit-op-get-module = Modul lesen
audit-op-validate = prüfen
audit-op-plan = planen
audit-op-apply = anwenden
audit-op-confirm-commit = Commit bestätigen
audit-op-rollback-commit = Commit zurückrollen
audit-op-list-backups = Sicherungen auflisten
audit-op-restore = Sicherung wiederherstellen
audit-op-service-status = Dienstzustand lesen
audit-op-service-action = auf Dienst einwirken
audit-op-host-profile = Hostprofil lesen
audit-op-audit-query = Audit-Protokoll lesen
audit-op-cert-status = Zertifikatsstatus lesen
audit-op-update-status = Updatestatus lesen
audit-op-cert-renew = Zertifikat erneuern
audit-op-update-apply = Update installieren
## Schema-driven module forms
## Chrome the form engine (web/src/forms) renders around a module's schema.
## Field captions come from the schema's own property names, and a field's
## tooltip and recommendation are Fluent ids in the *module's* locale file, not
## here — a missing one degrades to no tooltip and is never rendered raw.
forms-advanced-toggle = erweitert
forms-badge-security-high = hohe Sicherheitsauswirkung
forms-badge-deprecated = veraltet seit {$version}
forms-diagnostic-at-field = {$field}: {$message}
forms-diagnostic-unknown = dieser Host hat ein Prüfergebnis gemeldet, für das dieser Build keine Beschreibung hat ({$id}).
forms-item-add-caption = neu
forms-item-move-down-caption = ab
forms-item-move-up-caption = auf
forms-item-remove-caption = weg
forms-list-empty = noch nichts vorhanden.
forms-option-none = keine
forms-row-add = Zeile zu {$field} hinzufügen
forms-row-label = Zeile {$index}
forms-row-move-down = Zeile {$index} von {$field} nach unten verschieben
forms-row-move-up = Zeile {$index} von {$field} nach oben verschieben
forms-row-remove = Zeile {$index} von {$field} entfernen
forms-tag-add = Element zu {$field} hinzufügen
forms-tag-item = Element {$index} von {$field}
forms-tag-move-down = Element {$index} von {$field} nach unten verschieben
forms-tag-move-up = Element {$index} von {$field} nach oben verschieben
forms-tag-remove = Element {$index} von {$field} entfernen
forms-unsupported-note = dieser Build kann diesen Wert nicht bearbeiten. Er wird wie gespeichert angezeigt und bleibt unverändert.
forms-version-unsupported = braucht {$service} {$since}, installiert ist {$installed}

## Form validation
## Mirrors the schema constraints for immediate feedback. The server is the
## authority: a clean pass here is not a promise that apply will succeed.
forms-error-enum = wähle einen der aufgeführten Werte.
forms-error-format-ip = das ist keine gültige IP-Adresse.
forms-error-integer = nutze eine ganze Zahl.
forms-error-max-length = nutze höchstens {$max} Zeichen.
forms-error-maximum = nutze {$max} oder weniger.
forms-error-min-length = nutze mindestens {$min} Zeichen.
forms-error-minimum = nutze {$min} oder mehr.
forms-error-pattern = dieser Wert entspricht nicht der Form, die dieses Feld akzeptiert.
forms-error-required = dieses Feld ist erforderlich.
forms-error-type = dieser Wert ist nicht die Art von Wert, die dieses Feld enthält.
