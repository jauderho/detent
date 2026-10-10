# needs-review: machine-drafted French translation; not yet checked by a native speaker.
## detent CLI — fr
## Source: locales/en-US/cli.ftl. Same ids, same placeables. Identifiers — module ids,
## paths, unit names, digests, enum wire names such as `restart` or `active` — are
## interpolated verbatim and must not be translated.

## severity words, prefixed to every rendered diagnostic
cli-severity-error = erreur
cli-severity-warning = avertissement
cli-severity-recommendation = remarque

## yes/no, used wherever a flag is rendered
cli-yes = oui
cli-no = non

## progress notes, printed on stderr under --verbose
cli-note-settings = langue {$locale}, répertoire d'état {$state}, configuration {$config}
cli-note-operation = exécution de {$operation} pour {$module}

## failures that stop a command before the operations layer sees it
cli-bad-stdin = le modèle n'a pas pu être lu depuis stdin : {$reason}
cli-bad-json = le modèle sur stdin n'est pas du json valide : {$reason}
cli-bad-hash = `{$value}` n'est pas un condensat sha-256 de 64 caractères hexadécimaux.
cli-start-failed = l'assistant privilégié n'a pas pu être démarré : {$reason}
cli-monitor-stop = l'assistant privilégié ne s'est pas arrêté proprement : {$reason}
cli-monitor-busy = un autre moniteur detent possède déjà ce répertoire d'état ; réessayez via l'interface web ou exécutez `detent serve`.
cli-monitor-lock-unavailable = le verrou d'état dans {$path} ne peut pas être pris, cette commande ne peut donc rien modifier ; exécutez-la avec un utilisateur qui peut écrire dans ce répertoire, ou passez --state-root.
cli-commit-recovered = commit non confirmé {$commit} récupéré ; {$restored} cibles restaurées avec {$failures} échecs.
cli-commit-confirm-needs-serve = ce module exige commit-confirm ; utilisez l'interface web ou `detent serve` pour que la fenêtre de confirmation reste appliquée.
cli-config-load-failed = la configuration dans {$path} n'a pas pu être chargée : {$reason}
cli-no-command = aucune commande n'a été donnée.

## self-test probe and self-update (PLAN §2.9)
cli-self-test = version {$version}, fonctionnalités {$features}
cli-update-available = mise à jour disponible : {$tag} publiée {$published}
cli-update-security-available = mise à jour de sécurité disponible : {$tag} publiée {$published}
cli-update-none = aucune mise à jour disponible (actuelle {$current})
cli-update-held-young = {$tag} est plus récente que {$current} mais a moins de {$days} jour(s) ; le délai d'ancienneté la retient
cli-update-held-rejected = {$tag} est plus récente que {$current} mais a été annulée sur cet hôte ; elle est ignorée
cli-verify-bundle-ok = {$file} est attesté pour {$tag}
cli-update-failed = échec de la mise à jour : {$reason}
cli-update-installed = {$tag} installée ; le binaire remplacé est conservé dans {$previous}
cli-update-not-restarted = le service n'a pas été redémarré, donc le nouveau binaire ne tourne pas encore : {$reason}
cli-update-rolled-back = annulation effectuée : {$reason}
cli-update-rollback-failed = la mise à jour a échoué ({$reason}) et l'annulation a aussi échoué ({$error}) ; cet hôte demande votre attention

## config
cli-module-line = {$id}  {$name}
cli-no-model = ce module ne gère encore aucun fichier sur cet hôte, il n'y a donc aucun modèle à afficher.
cli-valid = cette configuration est valide.
cli-plan-no-change = {$module} est déjà ce que contient {$path} ; rien ne changerait.
cli-plan-service = appliquer ceci affecterait {$unit}.
cli-plan-hash = le fichier a maintenant pour condensat {$hash} ; passez-le comme --expect-hash pour refuser une modification concurrente.
cli-check-ran = le validateur amont {$program} a été exécuté ; réussi : {$passed}. {$detail}
cli-check-skipped = le validateur amont {$program} n'a pas été exécuté. {$detail}
cli-applied = {$module} a été écrit dans {$path}.
cli-applied-hash = son condensat était {$prev} et est maintenant {$new} ; sauvegarde conservée : {$backup}
cli-mounts-off = mounts : l'activation est désactivée ([mounts] activate_new_entries) ; les nouvelles entrées fstab prennent effet au prochain démarrage ou montage.
cli-mounts-error = mounts : aucune unité de montage n'a été démarrée : {$reason}
cli-mounts-none = mounts : aucune nouvelle entrée fstab à monter.
cli-mounts-unit = montage {$mountpoint} ({$unit}) : {$state}
cli-mounts-unit-detail = montage {$mountpoint} ({$unit}) : {$state} : {$detail}
cli-commit-armed = le commit {$id} doit être confirmé dans les {$seconds} secondes, avant {$deadline}, sinon il est annulé.
cli-commit-confirmed = le commit {$id} est confirmé et ne sera pas annulé.
cli-commit-rolled-back = le commit {$id} a été annulé ; {$targets} cibles ont été restaurées.

## backups
cli-no-backups = aucune sauvegarde n'a encore été conservée pour ce module.
cli-backup-line = {$id}  {$name}  {$bytes} octets  {$digest}
cli-restored = la cible {$target} a été restaurée et a maintenant pour condensat {$hash}.

## services
cli-service-status = {$unit} est {$state} ; démarre au boot : {$enabled}
cli-serviced = {$unit} a reçu la demande de {$action} ; en cours d'exécution : {$active}

## host
cli-host-profile = {$hostname} : {$os}, init {$init}, {$ram} Mio de ram
cli-host-service-version = le {$service} installé est en version {$version}
cli-host-backends = backend réseau {$network}, backend de résolution {$resolver}, distribution {$distro} {$version}
cli-host-note = note de détection : {$note}

## audit
cli-no-audit = le journal d'audit n'a aucun enregistrement correspondant.
cli-audit-line = {$ts}  {$who}  {$op}  {$module}  {$result}  {$error}
cli-audit-verified = la chaîne d'audit est intacte jusqu'à l'enregistrement {$sequence} ; condensat de tête {$hash}
cli-audit-broken = la chaîne d'audit n'a pas pu être vérifiée : {$reason}

## --dryrun
cli-dryrun-apply = simulation : voici ce qui serait écrit dans {$path} pour {$module}.
cli-dryrun-operation = simulation : {$operation} serait exécuté pour {$module}.
cli-dryrun-nothing = simulation : rien n'a été modifié.
cli-dryrun-serve = simulation : le moniteur et le worker démarreraient avec {$modules} modules et {$targets} cibles, enracinés dans {$state}.
cli-dryrun-serve-mounts = simulation : après un apply de mounts, le runner démarrerait les unités de montage des nouvelles entrées fstab (mounts.activate_new_entries = true).
cli-dryrun-cert-renew = simulation : demanderait au serveur à {$address} (en tant que {$name}) de renouveler son certificat maintenant ; rien n'a été envoyé.

## serve
cli-serve-monitor = le worker a démarré avec le pid {$pid} ; privilèges abandonnés : {$dropped}
cli-serve-worker = le worker tourne ; son serveur http arrive en phase 4. handshake : {$greeted}
cli-serve-failed = le moniteur et le worker n'ont pas pu être démarrés : {$reason}
cli-serve-stopped = la paire s'est arrêtée de façon inattendue : {$reason} {$status}
cli-serve-privileged-port = le port {$port} nécessite cap_net_bind_service ou un socket transmis par le moniteur, ce que cette version ne prend pas en charge ; utilisez un port à partir de 1024, ou placez un reverse proxy devant.
cli-serve-privilege-mode = le mode de privilège configuré ne correspond pas à ce processus, le service n'a donc pas démarré : {$reason}
cli-serve-acme-unsupported = cette version n'a aucun fournisseur dns-01 (fonctionnalité acme-dns-providers), elle ne peut donc pas obtenir de certificats acme ; définissez tls.bootstrap sur "self-signed" dans {$path}.
cli-serve-acme-setting-missing = tls.bootstrap vaut "acme", mais {$setting} n'est pas défini dans {$path}.
cli-serve-acme-path-outside = {$setting} ({$value}) n'est pas sous le répertoire d'état {$root} : les processus confinés n'y écrivent que là.
cli-serve-acme-credentials-dir = le répertoire d'identifiants acme {$path} n'a pas pu être préparé : {$reason}
cli-serve-secrets-failed = le fichier de secrets {$path} a été refusé : {$reason}
cli-serve-acme-secret-missing = acme.provider est défini, mais {$path} n'a aucun secret dns_provider dans sa table [acme].
cli-serve-acme-provider-invalid = le fournisseur dns-01 dans acme.provider est inutilisable : {$reason}
cli-serve-acme-providers-not-built = cette version n'a aucun fournisseur dns-01 (fonctionnalité acme-dns-providers) ; retirez [acme.provider] de {$path}.
cli-serve-handshake-failed = le worker n'a pas pu terminer son handshake avec le moniteur.
cli-serve-auth-failed = le magasin des comptes, jetons et sessions n'a pas pu être ouvert : {$reason}
cli-serve-tls-failed = le certificat tls n'a pas pu être préparé : {$reason}
cli-serve-cert-fingerprint = empreinte du certificat d'amorçage tls (sha-256) : {$fingerprint}
cli-serve-web-failed = le serveur web n'a pas pu démarrer : {$reason}
cli-serve-web-stopped = le serveur web ne s'est pas arrêté proprement : {$reason}
cli-serve-listening = écoute sur {$addr}
cli-serve-confinement-degraded = confinement dégradé : {$detail}
cli-mcp-missing-token = {$var} n'est pas défini ; créez-en un avec `detent token create` et exportez-le avant de démarrer le serveur mcp.
cli-mcp-serve-failed = le serveur mcp n'a pas pu démarrer : {$reason}
cli-mcp-listening = mcp sert {$transport}
cli-mcp-http-needs-privsep = le transport http de mcp ne peut pas s'exécuter en root ni avec des capabilities : l'analyseur réseau tournerait avec des pouvoirs proches de root ; exécutez-le en utilisateur non root sans capabilities ou utilisez le transport stdio.
cli-mcp-bind-not-loopback = la liaison http de mcp doit être en bouclage (127.0.0.1 ou ::1) ; le bearer circule en clair sur le réseau.
cli-dryrun-mcp = simulation : mcp servirait {$transport} sur {$addr} avec la portée {$scope}.

## setup, user, token
cli-setup-exists = un utilisateur nommé `{$name}` existe déjà sur cet hôte ; passez --force pour l'écraser.
cli-setup-created = le compte administrateur `{$name}` a été créé.
cli-user-created = le compte `{$name}` a été créé.
cli-user-passwd = le mot de passe de `{$name}` a été modifié.
cli-user-removed = le compte `{$name}` a été supprimé.
cli-totp-uri = ajoutez ceci à votre application d'authentification : {$uri}
cli-totp-secret = ou saisissez cette clé dedans : {$secret}
cli-totp-code-prompt = code de votre authentificateur :
cli-totp-code-empty = un code ne peut pas être vide.
cli-totp-code-wrong = ce code n'est pas valide, le second facteur n'a donc pas été activé.
cli-user-totp-enabled = le second facteur de `{$name}` a été activé.
cli-totp-disable-prompt = désactiver le second facteur de `{$name}` ? [y/N]
cli-totp-disable-cancelled = le second facteur de `{$name}` a été laissé activé.
cli-user-totp-disabled = le second facteur de `{$name}` a été désactivé.
cli-token-created = le jeton {$id} ({$label}) a été créé ; il ne sera plus affiché : {$token}
cli-token-revoked = le jeton {$id} a été révoqué.
cli-token-no-tokens = aucun jeton n'a été émis.
cli-token-line = {$id}  {$label}  {$scopes}  {$created}  {$expires}
cli-credential-failed = la requête n'a pas pu être terminée : {$reason}
cli-audit-failed = la modification a été faite, mais son enregistrement d'audit n'a pas pu être écrit : {$reason}
cli-state-command-as-root = detent {$command} ne doit pas s'exécuter en root : les fichiers qu'il écrit appartiendraient à root et le service ne pourrait pas les lire. Exécutez-le plutôt avec le compte du service : sudo -u {$account} detent {$command}

## cert status
cli-cert-source = source : {$source}
cli-cert-fingerprint = empreinte (sha-256) : {$fingerprint}
cli-cert-not-after = expire : {$not_after}
cli-cert-not-after-unknown = expiration : inconnue (le certificat n'a pas pu être analysé).
cli-cert-lifetime = durée de vie écoulée : {$percent} (avertissement : {$warning}).
cli-cert-lifetime-no-warning = durée de vie écoulée : {$percent} (pas d'avertissement).
cli-cert-lifetime-unknown = durée de vie écoulée : inconnue (le certificat n'a pas pu être analysé).
cli-cert-missing = aucun certificat n'est stocké dans {$path} ; démarrez le serveur une fois pour qu'il en écrive un.
cli-cert-unreadable = le certificat dans {$path} n'a pas pu être lu : {$reason}

## cert renew
cli-cert-renew-requested = renouvellement demandé : le serveur a demandé à son client ACME de renouveler maintenant. Vérifiez le résultat avec `detent cert status`.
cli-cert-renew-token-refused = le jeton a été refusé (HTTP {$status}) ; il nécessite la portée write : `detent token create <name> --write`.
cli-cert-renew-not-acme = le serveur n'exécute aucun processus ACME (`tls.bootstrap` n'est pas `acme`), il n'y a donc rien à renouveler.
cli-cert-renew-server-error = le serveur a répondu HTTP {$status} : {$message_id}
cli-cert-renew-server-error-bare = le serveur a répondu HTTP {$status}.
cli-cert-renew-unreachable = impossible de communiquer avec le serveur à {$address} : {$reason}
cli-cert-renew-no-token = pas de jeton API : passez --token-file <path> ou définissez {$var}. Créez un jeton d'écriture avec `detent token create <name> --write`.
cli-cert-renew-bad-token = le jeton provenant de {$source} a été refusé : {$reason}
cli-cert-renew-ca-unreadable = le fichier CA {$path} n'a pas pu être lu : {$reason}

## password entry (setup, user add, user passwd)
cli-password-prompt = mot de passe :
cli-password-confirm = confirmez le mot de passe :
cli-password-mismatch = les mots de passe ne correspondent pas.
cli-password-empty = un mot de passe ne peut pas être vide.

## doctor
cli-status-ok = ok
cli-status-warn = attention
cli-status-fail = échec
cli-doctor-modules = modules compilés dans cette version : {$detail}
cli-doctor-state-root = répertoire d'état {$detail}
cli-doctor-config = fichier de configuration {$detail}
cli-doctor-privsep = la séparation des privilèges peut lancer une paire fonctionnelle : {$detail}
cli-doctor-landlock = landlock : {$detail}
cli-doctor-seccomp = seccomp : {$detail}
cli-doctor-confinement = confinement du bac à sable : {$detail}
cli-doctor-serve-confinement = confinement au dernier démarrage de serve : {$detail}
cli-doctor-mounts = activation des montages après un apply de fstab : {$detail}
cli-doctor-privilege-mode = mode de privilège : {$detail}
cli-doctor-service-account = compte de service : {$detail}
cli-doctor-state-owner = propriétaire du répertoire d'état : {$detail}
cli-doctor-backups-dir = répertoire des sauvegardes : {$detail}
cli-doctor-polkit-rule = règle polkit : {$detail}
cli-doctor-polkit-daemon = démon polkit : {$detail}
cli-doctor-unit-capabilities = identité et capabilities de l'unité de service : {$detail}
