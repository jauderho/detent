# needs-review: machine-drafted French translation; not yet checked by a native speaker.
## detent web admin UI — fr
## Source: locales/en-US/web.ftl. Same ids, same placeables.

## Status bar
status-brand = detent
status-online = système en ligne
status-clock-label = utc
status-mode-label = mode
theme-toggle-aria = basculer entre le mode clair et le mode sombre
theme-toggle-title = basculer clair / sombre

## catfu component layer
## Chrome the shared components render themselves. Content strings (field
## captions, table headers, banner copy) are supplied by the calling page.
component-countdown-remaining = temps restant
component-field-info = plus d'informations
component-modal-close = fermer
component-switch-off = désactivé
component-switch-on = activé
component-table-empty = aucun enregistrement

## API failures
## docs/API.md: every failure is `{ code, message_id }`, and `message_id` is a
## Fluent id. src/api/messages.ts resolves it here; an id this build does not
## know falls back to `api-error-unknown`, so an id is never rendered raw.
##
## The first three are the console's own — a failure that never reached a
## server has no `message_id` to resolve. The rest mirror the ids the server
## sends, argument-free: locales/en-US/core.ftl interpolates `{$path}`,
## `{$reason}` and friends, and the API deliberately sends none of them.
api-error-network = la console n'a pas pu joindre cet hôte.
api-error-malformed = cet hôte a envoyé une réponse que la console n'a pas pu lire.
api-error-unknown = cet hôte a signalé un échec que la console ne sait pas décrire.
core-edit-index-out-of-range = erreur interne : une modification visait une ligne en dehors du fichier.
core-edit-line-break = une valeur ne peut pas contenir de saut de ligne ni d'octet nul.
core-edit-unsupported = cette modification ne peut pas être exprimée dans le format du fichier.
core-model-shape = la configuration fournie n'a pas la forme attendue.
core-model-unrepresentable = ce fichier contient quelque chose que l'éditeur ne peut pas représenter.
core-parse-malformed = ce fichier ne correspond pas au format attendu par son module.
ops-audit-failed = le journal d'audit n'a pas pu être lu.
ops-audit-unavailable = le journal d'audit n'a pas pu être écrit, l'opération a donc été refusée.
ops-denied = vous n'avez pas l'autorisation de faire cela.
ops-hash-conflict = le fichier a changé sur le disque depuis sa lecture ; relisez-le et réessayez.
ops-check-failed = le validateur externe a refusé le candidat.
ops-invalid-model = cette configuration n'est pas valide.
ops-no-service = ce module ne contrôle aucun service sur cet hôte, il ne peut donc pas être redémarré.
ops-no-target = ce module ne gère aucun fichier sur cet hôte.
ops-privsep-failed = l'assistant privilégié a refusé la requête ou n'a pas pu la terminer.
ops-service-failed = l'action sur le service ne s'est pas terminée.
ops-unknown-module = il n'y a aucun module de ce nom dans cette version.
ops-unsupported = cela n'est pas pris en charge dans cette version.
ops-commit-pending = une autre fenêtre commit-confirm est déjà en attente.
ops-update-running = une mise à jour est déjà en cours ; attendez qu'elle se termine, puis vérifiez la version en cours d'exécution.
ops-update-tag-invalid = ce n'est pas une version publiée ; elle doit ressembler à v1.2.3.
ops-update-not-newer = cette version n'est pas plus récente que la version en cours d'exécution ; rien n'a été lancé.
ops-no-backup = commit-confirm nécessite une sauvegarde conservée ; rien n'a été modifié.
ops-arm-failed-restored = commit-confirm n'a pas pu être armé, la modification a donc été annulée ; le contenu précédent est rétabli.
ops-arm-failed-unrestored = commit-confirm n'a pas pu être armé et la modification n'a PAS pu être annulée ; le nouveau contenu est toujours sur le disque. Restaurez la sauvegarde précédente maintenant.
ops-target-missing = le fichier géré n'existe pas ; créez-le (installez son paquet ou créez-le à la main), puis réessayez.
web-api-unexpected-outcome = l'opération s'est terminée mais son résultat n'a pas pu être affiché.
web-auth-ambiguous-credentials = envoyez soit un cookie de session, soit un jeton bearer, pas les deux.
web-auth-argon2-params = les paramètres argon2 configurés sont inutilisables.
web-auth-busy = trop de connexions sont en cours ; patientez un instant et réessayez.
web-auth-csrf-rejected = cette requête n'a pas passé ses vérifications inter-sites ; rechargez la page et réessayez.
web-auth-entropy-unavailable = le générateur de nombres aléatoires du système a échoué, aucun identifiant n'a donc pu être émis.
web-auth-hash-failed = le mot de passe n'a pas pu être haché.
web-auth-invalid-credentials = le nom d'utilisateur, le mot de passe ou le code n'était pas correct.
web-auth-password-change-required = changez votre mot de passe avant de faire quoi que ce soit d'autre.
web-auth-password-too-long = un mot de passe peut comporter au plus 128 caractères.
web-auth-password-too-short = un mot de passe doit comporter au moins 12 caractères.
web-auth-password-unchanged = le nouveau mot de passe doit différer de l'actuel.
web-auth-rate-limited = trop de tentatives ; patientez un instant et réessayez.
web-auth-session-limit = trop de sessions sont ouvertes ; attendez qu'une expire et reconnectez-vous.
web-auth-store-malformed = un fichier d'identifiants sur cet hôte n'est pas valide.
web-auth-store-unreadable = un fichier d'identifiants sur cet hôte n'a pas pu être lu.
web-auth-store-unwritable = un fichier d'identifiants sur cet hôte n'a pas pu être préparé pour l'écriture.
web-auth-store-write-failed = un fichier d'identifiants sur cet hôte n'a pas pu être écrit.
web-auth-token-limit = cet hôte détient déjà le nombre maximal de jetons api.
web-auth-token-unknown = ce jeton api n'existe pas, est révoqué ou a expiré.
web-auth-totp-secret-invalid = ce secret d'authentificateur n'est pas du base32 valide.
web-auth-unauthenticated = connectez-vous pour faire cela.
web-auth-user-exists = un utilisateur de ce nom existe déjà.
web-auth-user-name-invalid = ce nom d'utilisateur est inutilisable ; utilisez de 1 à 32 caractères parmi `a-z`, `0-9`, `.`, `_` ou `-`, en commençant par une lettre ou un chiffre.
web-auth-user-unknown = il n'y a aucun utilisateur de ce nom.
web-cert-renew-not-acme = le renouvellement nécessite `tls.bootstrap = "acme"` dans detent.toml.
web-cert-renew-unavailable = le client acme n'a pas reçu la demande de renouvellement ; réessayez plus tard.
web-denied-scope = cet identifiant ne porte pas la portée que cette action exige.
web-engine-stopped = le moteur d'opérations ne tourne plus ; réessayez quand le service sera de retour.
web-update-not-checked = aucune vérification de mise à jour n'a encore été faite sur cet hôte ; exécutez `detent update --check` en tant que root.
web-request-malformed = le corps de la requête n'a pas la forme attendue par ce point d'accès.
web-request-too-deep = le corps de la requête est imbriqué trop profondément.

## Sign in
login-title = connexion
login-panel-label = session
login-username-label = nom d'utilisateur
login-password-label = mot de passe
login-totp-label = code d'authentification
login-totp-description = six chiffres de l'application d'authentification enregistrée pour ce compte.
login-totp-reveal = utiliser un code d'authentification
login-submit = se connecter
login-submitting = connexion en cours
login-retry-after = trop de tentatives ; attendez {$seconds} secondes et réessayez.

## Change password
password-change-title = changez votre mot de passe
password-change-panel-label = mot de passe
password-change-intro = ce compte doit définir un nouveau mot de passe avant de pouvoir faire quoi que ce soit d'autre.
password-change-current-label = mot de passe actuel
password-change-new-label = nouveau mot de passe
password-change-new-description = de 12 à 128 caractères ; tous les caractères sont autorisés.
password-change-confirm-label = confirmez le nouveau mot de passe
password-change-mismatch = les deux nouveaux mots de passe ne sont pas identiques.
password-change-submit = changer le mot de passe
password-change-submitting = changement du mot de passe

## Session and scope
auth-checking = vérification de cette session
auth-sign-out = se déconnecter
scope-gate-read-only = cette session n'a qu'un accès en lecture ; elle ne peut rien modifier sur cet hôte.
scope-gate-signed-out = connectez-vous pour modifier quoi que ce soit sur cet hôte.

## Navigation
nav-label = sections
nav-dashboard = tableau de bord
nav-modules = modules
nav-services = services
nav-backups = sauvegardes
nav-audit = audit
nav-certificates = certificats
nav-settings = paramètres

## Routed pages
## Certificates and settings are still named placeholders: neither has an API
## to drive. Certificates waits on Phase 6 (ACME); settings waits on the user
## and token endpoints.
page-placeholder-body = cette section n'est pas encore construite.
page-dashboard-title = tableau de bord
page-modules-title = modules
page-module-detail-title = module {$module}
page-services-title = services
page-backups-title = sauvegardes
page-audit-title = journal d'audit
page-certificates-title = certificats
page-settings-title = paramètres
page-not-found-title = page introuvable
page-not-found-body = cette adresse ne désigne rien dans cette console.
page-not-found-home = aller au tableau de bord

## Pending commit
pending-commit-message = une modification de configuration attend d'être confirmée ; elle est annulée d'elle-même à la fermeture de cette fenêtre.
pending-commit-countdown-label = temps restant pour confirmer
pending-commit-confirm = confirmer la modification
pending-commit-confirming = confirmation…

## Shared page states
## Every section is a query away from its data, so loading, failure and "this
## host has none of these" are shared rather than re-worded per page.
state-loading = chargement
state-unknown = inconnu
value-no = non
value-yes = oui

## Dashboard
dashboard-host-panel = hôte
dashboard-host-hostname = nom d'hôte
dashboard-host-os = système d'exploitation
dashboard-host-init = système init
dashboard-host-distro = distribution
dashboard-host-ram = mémoire
dashboard-host-network-backend = backend réseau
dashboard-host-resolver-backend = backend de résolution
dashboard-host-notes = notes de détection
dashboard-cert-panel = certificat
dashboard-cert-fingerprint = empreinte
dashboard-cert-expires = expire
dashboard-cert-lifetime-used = durée de vie écoulée
dashboard-cert-expired = expiré ; remplacez ce certificat.
dashboard-cert-expiring-soon = expire dans moins de 30 jours ; prévoyez le renouvellement.
dashboard-cert-half = la moitié de la durée de vie du certificat est écoulée ; le renouvellement est planifié.
dashboard-cert-quarter = les trois quarts de la durée de vie du certificat sont écoulés ; renouvelez bientôt.
cert-renew-panel = renouvellement
cert-renew-now = renouveler maintenant
cert-renew-requested = renouvellement demandé. Le nouveau certificat est installé dès que l'AC l'émet.
dashboard-modules-panel = modules
dashboard-modules-count = {$count ->
    [one] {$count} module est compilé dans cette version.
   *[other] {$count} modules sont compilés dans cette version.
}
dashboard-audit-panel = activité récente
dashboard-view-all = tout afficher
dashboard-update-panel = mise à jour
dashboard-update-current = version en cours d'exécution
dashboard-update-published = publiée
dashboard-update-up-to-date = aucune version plus récente n'est proposée pour cette version.
dashboard-update-available = la version {$tag} est disponible pour cette version.
dashboard-update-security = cette version est signalée comme mise à jour de sécurité ; elle contourne le délai d'ancienneté.
dashboard-update-install = installer {$tag}
dashboard-update-confirm-title = installer cette mise à jour ?
dashboard-update-confirm-body = cela lance l'installation de {$tag} en arrière-plan. si elle réussit, le service detent redémarre et la page peut se déconnecter puis se reconnecter ; si le service redémarré n'est pas sain, la mise à jour est annulée.
dashboard-update-confirm-action = installer
dashboard-update-confirm-cancel = annuler
dashboard-update-started = la mise à jour vers {$version} a démarré en arrière-plan. le service redémarre si elle s'installe et la mise à jour est annulée s'il n'est pas sain ; la version en cours d'exécution montre le résultat.

## Modules
modules-panel-label = modules installés
modules-col-module = module
modules-col-targets = fichiers
modules-col-services = services
modules-col-commit-confirm = commit-confirm
modules-commit-confirm-required = requis
modules-commit-confirm-not-required = non requis
modules-empty = cette version n'a aucun module compilé.
modules-none = aucun

## One module
module-about-panel = module
module-configuration-panel = configuration
module-upstream-label = suit l'amont
module-targets-label = fichiers
module-services-label = services
module-current-hash-label = condensat sur le disque
module-security-notes-label = notes de sécurité
module-model-missing = le fichier de ce module n'existe pas encore sur cet hôte. le formulaire ci-dessous part des valeurs par défaut du module, et l'appliquer crée le fichier.
module-action-validate = valider
module-action-plan = planifier
module-action-apply = appliquer
module-action-discard = annuler les modifications
module-busy = en cours
module-validate-clean = cette configuration a passé toutes les vérifications que cet hôte exécute.
module-plan-title = modification prévue
module-plan-no-change = cette configuration correspond à ce qui est déjà sur le disque ; il n'y a rien à appliquer.
module-plan-diff-label = diff
module-plan-checks-label = vérifications amont
module-plan-check-passed = réussi
module-plan-check-failed = échoué
module-plan-check-exit = code de sortie {$code}
module-plan-services-label = services que cela affecterait
module-plan-apply = appliquer cette modification
module-apply-title = appliquer cette modification ?
module-apply-body = cela écrit {$path} sur cet hôte. le contenu actuel est d'abord sauvegardé.
module-apply-commit-confirm = ce module peut verrouiller un administrateur dehors, la modification arme donc une fenêtre commit-confirm : elle est annulée d'elle-même sauf si vous la confirmez avant l'échéance.
module-apply-service-label = ensuite
module-apply-service-none = laisser le service tranquille
module-apply-cancel = annuler
module-applied = la modification a été écrite dans {$path}.
module-applied-created = {$path} n'existait pas et a été créé.
module-mounts-off = les nouvelles entrées fstab n'ont pas été montées ([mounts] activate_new_entries est désactivé) ; elles prennent effet au prochain démarrage ou montage.
module-mounts-error = aucune unité de montage n'a été démarrée : {$reason}
module-mounts-none = il n'y a aucune nouvelle entrée fstab à monter.
module-mounts-units = unités de montage des nouvelles entrées fstab :
module-mount-state-mounted = monté
module-mount-state-already-mounted = déjà monté
module-mount-state-pending = montage en cours
module-mount-state-failed = échoué
module-mount-state-protected = refusé : chemin protégé
module-mount-state-stopped = démonté
module-cancel = annuler

## Services
services-panel-label = services
services-col-module = module
services-col-unit = unité
services-col-state = état
services-col-enabled = au démarrage
services-col-since = depuis
services-col-actions = actions
services-state-active = actif
services-state-inactive = inactif
services-state-failed = échoué
services-state-activating = démarrage
services-state-deactivating = arrêt
services-state-unknown = inconnu
services-action-restart = redémarrer
services-action-reload = recharger
services-action-start = démarrer
services-action-stop = arrêter
services-acted = {$unit} : {$detail}
services-empty = aucun module de cette version ne contrôle de service sur cet hôte.
services-confirm-title = {$action} {$unit} ?
services-confirm-body = cela agit immédiatement sur le service en cours d'exécution.
services-confirm-cancel = annuler

## Backups
backups-col-name = sauvegarde
backups-col-created = effectuée
backups-col-size = taille
backups-col-digest = condensat
backups-col-actions = actions
backups-action-restore = restaurer
backups-confirm-title = restaurer cette sauvegarde ?
backups-confirm-body = cela remplace {$target} par la copie conservée. le contenu actuel est d'abord sauvegardé.
backups-confirm-cancel = annuler
backups-restored = la sauvegarde a été restaurée.
backups-empty = rien n'a encore été sauvegardé pour ce module.
backups-module-panel = sauvegardes de {$module}

## Audit log
audit-panel-label = journal d'audit
audit-col-when = quand
audit-col-who = appelant
audit-col-how = identifiant
audit-col-op = opération
audit-col-module = module
audit-col-result = résultat
audit-filter-module-label = module
audit-filter-who-label = appelant
audit-filter-limit-label = lignes
audit-filter-apply = filtrer
audit-filter-clear = effacer
audit-empty = rien n'a encore été enregistré sur cet hôte.
audit-result-ok = ok
audit-result-denied = refusé
audit-result-error = échoué
audit-identity-local-user = utilisateur local
audit-identity-session = session
audit-identity-token = jeton api
audit-op-list-modules = lister les modules
audit-op-get-module = lire le module
audit-op-validate = valider
audit-op-plan = planifier
audit-op-apply = appliquer
audit-op-confirm-commit = confirmer le commit
audit-op-rollback-commit = annuler le commit
audit-op-list-backups = lister les sauvegardes
audit-op-restore = restaurer la sauvegarde
audit-op-service-status = lire l'état du service
audit-op-service-action = agir sur le service
audit-op-host-profile = lire le profil de l'hôte
audit-op-audit-query = lire le journal d'audit
audit-op-cert-status = lire l'état du certificat
audit-op-update-status = lire l'état de la mise à jour
audit-op-cert-renew = renouveler le certificat
audit-op-update-apply = installer la mise à jour
## Schema-driven module forms
## Chrome the form engine (web/src/forms) renders around a module's schema.
## Field captions come from the schema's own property names, and a field's
## tooltip and recommendation are Fluent ids in the *module's* locale file, not
## here — a missing one degrades to no tooltip and is never rendered raw.
forms-advanced-toggle = avancé
forms-badge-security-high = fort impact sur la sécurité
forms-badge-deprecated = obsolète depuis {$version}
forms-diagnostic-at-field = {$field} : {$message}
forms-diagnostic-unknown = cet hôte a signalé un résultat de vérification que cette version ne sait pas décrire ({$id}).
forms-item-add-caption = ajouter
forms-item-move-down-caption = bas
forms-item-move-up-caption = haut
forms-item-remove-caption = suppr
forms-list-empty = rien ici pour l'instant.
forms-option-none = aucun
forms-row-add = ajouter une ligne à {$field}
forms-row-label = ligne {$index}
forms-row-move-down = descendre la ligne {$index} de {$field}
forms-row-move-up = monter la ligne {$index} de {$field}
forms-row-remove = supprimer la ligne {$index} de {$field}
forms-tag-add = ajouter un élément à {$field}
forms-tag-item = élément {$index} de {$field}
forms-tag-move-down = descendre l'élément {$index} de {$field}
forms-tag-move-up = monter l'élément {$index} de {$field}
forms-tag-remove = supprimer l'élément {$index} de {$field}
forms-unsupported-note = cette version ne peut pas modifier cette valeur. elle est affichée telle que stockée et reste inchangée.
forms-version-unsupported = nécessite {$service} {$since}, installé {$installed}

## Form validation
## Mirrors the schema constraints for immediate feedback. The server is the
## authority: a clean pass here is not a promise that apply will succeed.
forms-error-enum = choisissez l'une des valeurs listées.
forms-error-format-ip = ce n'est pas une adresse ip valide.
forms-error-integer = utilisez un nombre entier.
forms-error-max-length = utilisez au plus {$max} caractères.
forms-error-maximum = utilisez {$max} ou moins.
forms-error-min-length = utilisez au moins {$min} caractères.
forms-error-minimum = utilisez {$min} ou plus.
forms-error-pattern = cette valeur ne correspond pas à la forme acceptée par ce champ.
forms-error-required = ce champ est obligatoire.
forms-error-type = cette valeur n'est pas du type de valeur que ce champ contient.
