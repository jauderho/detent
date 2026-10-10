# needs-review: machine-drafted French translation; not yet checked by a native speaker.
## detent-core — fr
## Source: locales/en-US/core.ftl. Same ids, same placeables. Code-like tokens
## (directive names, paths, flags, option values) stay untranslated.

## chrony module — display name, security notes, schema tooltips
chrony-name = chrony
chrony-note-precedence = ce fichier remplace les valeurs par défaut compilées ; une valeur erronée modifie silencieusement la façon dont l'hôte tient l'heure.
chrony-tip-settings = les directives de chrony.conf que ce module modélise, dans l'ordre du fichier ; tout le reste du fichier est conservé tel quel.
chrony-tip-key = le nom de la directive, un seul mot, insensible à la casse.
chrony-tip-value = la valeur de cette directive, jusqu'à la fin de la ligne ; vide pour les directives sans valeur comme `rtcsync`.
chrony-rec-value = préférez une valeur explicite plutôt que de vous fier à la valeur par défaut compilée.

## chrony module — validation diagnostics
chrony-privileged-directive = `{$key}` définit un fichier que chronyd écrit en tant que root, ou l'utilisateur sous lequel il s'exécute. Vérifiez la valeur avant de l'appliquer.
chrony-invalid-key = `{$key}` n'est pas un nom de directive chrony valide.
chrony-duplicate-key = `{$key}` est défini plusieurs fois ; la dernière valeur l'emporte.
chrony-too-many-settings = ce fichier contient {$count} paramètres ; répartissez-les dans des fichiers drop-in sous /etc/chrony/conf.d.
chrony-allow-open = `allow {$value}` sert l'heure à tout Internet ; n'autorisez que les réseaux qui en ont besoin.
chrony-missing-makestep = makestep n'est pas défini ; au démarrage, l'horloge peut dériver sans limite au lieu d'être remise dans la plage.
chrony-missing-rtcsync = rtcsync n'est pas défini ; l'horloge matérielle dérivera par rapport à l'horloge système.
chrony-rec-nts = le pool {$pool} est utilisé sans l'option nts ; préférez des sources compatibles nts pour que l'heure ne puisse pas être falsifiée.
chrony-cmdport-open = cmdport vaut {$port} ; définissez cmdport 0 sauf si chronyc doit joindre cet hôte par le réseau.
chrony-external-directive = `{$key}` charge des fichiers externes ou exécute un programme externe ; ce module refuse les directives qui franchissent sa limite de fichiers configurée.

## dhcp module — display name, security notes, schema tooltips
dhcp-name = dhcp
dhcp-note-commit-confirm = une mauvaise modification DHCP coupe du réseau tous les clients, et vous avec ; vérifiez attentivement le diff avant de confirmer.
dhcp-tip-dnsmasq = les paramètres `key=value` de /etc/dnsmasq.conf, dans l'ordre du fichier ; les commentaires et les lignes inconnues sont conservés tels quels.
dhcp-tip-kea-v4 = le sous-ensemble géré du serveur Kea DHCPv4 (`Dhcp4`) ; les options Kea inconnues sont conservées telles quelles.
dhcp-tip-kea-v6 = le sous-ensemble géré du serveur Kea DHCPv6 (`Dhcp6`) ; les options Kea inconnues sont conservées telles quelles.
dhcp-tip-key = le nom de l'option dnsmasq, un seul mot, sans espace.
dhcp-tip-value = la valeur après `=` ; un simple indicateur comme `domain-needed` n'a pas de valeur.
dhcp-tip-interfaces = les interfaces sur lesquelles le serveur Kea écoute ; une liste vide signifie que le serveur répond sur toutes les interfaces.
dhcp-tip-valid-lifetime = la durée de bail par défaut en secondes ; 3600 est une valeur raisonnable pour la plupart des réseaux.
dhcp-tip-subnets = les sous-réseaux dans lesquels le serveur attribue des adresses.
dhcp-tip-id = l'identifiant stable de sous-réseau de Kea ; gardez-le stable d'une modification à l'autre, les baux en dépendent.
dhcp-tip-subnet = le préfixe du sous-réseau en notation CIDR, p. ex. `192.168.1.0/24`.
dhcp-tip-pools = les plages d'adresses dynamiques du sous-réseau.
dhcp-tip-routers = l'option routeurs (passerelle par défaut) transmise aux clients.
dhcp-tip-domain-servers = les serveurs DNS (`domain-name-servers`) transmis aux clients.
dhcp-tip-pool = une plage sous la forme d'un intervalle `192.168.1.100 - 192.168.1.200` ou d'un préfixe `192.168.1.0/24`.

## dhcp module — validation diagnostics
dhcp-empty-key = un paramètre dnsmasq a un nom d'option vide.
dhcp-invalid-key = `{$key}` n'est pas un nom d'option dnsmasq valide ; il doit être un seul mot sans espace, `=` ni `#`.
dhcp-malformed-cidr = `{$value}` n'est pas un préfixe CIDR valide, p. ex. `192.168.1.0/24`.
dhcp-malformed-pool = `{$value}` n'est pas une plage valide ; utilisez un intervalle comme `192.168.1.100 - 192.168.1.200` ou un préfixe CIDR.
dhcp-external-directive = `{$key}` charge des fichiers externes ou exécute des commandes ; ce module ne créera ni ne modifiera de directives qui franchissent sa limite de fichiers configurée.
dhcp-authoritative-set = `dhcp-authoritative` fait de dnsmasq le seul serveur DHCP du segment ; ne l'activez que s'il n'existe aucun autre serveur DHCP.
dhcp-kea-interfaces-empty = {$server} n'a aucune interface configurée et écoutera sur toutes les interfaces ; nommez explicitement les interfaces.
dhcp-rec-rebind = domain-needed et bogus-priv ne sont pas tous deux définis ; ils filtrent les attaques par rebind et les requêtes A en amont pour les adresses privées.
dhcp-rec-lifetime = {$server} a valid-lifetime {$lifetime} ; gardez-la entre 300 et 86400 secondes pour que les baux se renouvellent de façon prévisible.

## hosts module — display name, security notes, schema tooltips
hosts-name = hosts
hosts-note-spoofing = les entrées ici remplacent le dns ; une entrée erronée ou malveillante redirige silencieusement les résolutions.
hosts-tip-entries = les correspondances adresse-nom de /etc/hosts, dans l'ordre du fichier.
hosts-tip-ip = l'adresse vers laquelle les noms ci-dessous se résolvent.
hosts-tip-hostnames = les noms qui se résolvent vers cette adresse, le nom canonique en premier.
hosts-tip-comment = le commentaire en fin de ligne de cette entrée, le cas échéant.

## hosts module — validation diagnostics
hosts-invalid-hostname = `{$name}` n'est pas un nom d'hôte valide.
hosts-duplicate-canonical = `{$name}` est le nom canonique de plusieurs entrées.
hosts-no-hostnames = cette entrée n'a aucun nom d'hôte.
hosts-hostname-is-ip = `{$name}` est une adresse littérale, pas un nom d'hôte.
hosts-ipv6-zone-unsupported = `{$name}` porte un identifiant de zone ipv6, que /etc/hosts ne prend pas en charge.
hosts-hostname-multiple-ips = `{$name}` se résout vers plusieurs adresses de la même famille.
hosts-localhost-not-loopback = `localhost` pointe vers `{$ip}`, qui n'est pas une adresse de bouclage.
hosts-missing-localhost = il n'y a aucune entrée `localhost`.
hosts-missing-ipv6-localhost = il n'y a aucune entrée `localhost` ipv6.
hosts-too-many-entries = ce fichier contient {$count} entrées ; envisagez plutôt le dns.

## mounts module — display name, security notes, schema tooltips
mounts-name = mounts
mounts-note-boot = un /etc/fstab erroné peut rendre l'hôte impossible à démarrer au prochain redémarrage ; chaque modification demande une seconde confirmation. La confirmation ne peut pas détecter une entrée erronée, car rien ne lit le fichier avant le prochain démarrage.
mounts-tip-entries = les entrées de montage de /etc/fstab, dans l'ordre du fichier.
mounts-tip-spec = ce qui est monté : un périphérique, `UUID=...`/`LABEL=...`, un export nfs, ou `none` pour le swap.
mounts-tip-mountpoint = l'endroit où le système de fichiers est monté, ou `none`/`swap` pour le swap.
mounts-tip-fstype = le type de système de fichiers, p. ex. ext4, ou `swap`.
mounts-tip-options = les options de montage séparées par des virgules, p. ex. defaults,nosuid.
mounts-tip-dump = la fréquence de sauvegarde dump(8) ; presque toujours 0.
mounts-tip-pass = le numéro de passe fsck : 1 pour la racine, 2 pour les autres systèmes de fichiers vérifiés, 0 pour ignorer.
mounts-rec-options = protégez les données inscriptibles par les utilisateurs avec nosuid, nodev et noexec ; préférez x-systemd.automount pour les systèmes de fichiers réseau.

## mounts module — validation diagnostics
mounts-empty-spec = l'entrée {$index} a une spec vide (première colonne).
mounts-empty-mountpoint = l'entrée {$index} a un point de montage vide (deuxième colonne).
mounts-invalid-fstype = `{$fstype}` n'est pas un type de système de fichiers valide.
mounts-pass-too-high = l'entrée {$index} a la passe `{$pass}` ; fsck exécute au plus 2 passes.
mounts-root-pass = le système de fichiers racine devrait avoir la passe 1, et non `{$pass}`.
mounts-missing-nofail = `{$mountpoint}` est un média amovible sans `nofail` ; le démarrage se bloque quand il est débranché.
mounts-missing-boot-escape = `{$mountpoint}` n'a ni nofail ni noauto ; un montage en échec peut retarder le démarrage.
mounts-critical-noauto = `{$mountpoint}` est requis pour le démarrage mais a noauto, donc le système peut continuer sans lui.
mounts-missing-guards = `{$mountpoint}` monte des données inscriptibles par les utilisateurs sans `{$missing}` ; ajoutez-les.
mounts-network-automount = `{$mountpoint}` est un système de fichiers réseau sans `x-systemd.automount` ; le démarrage attend le réseau.
mounts-noauto-without-user = `noauto` sans `user` : seul root peut le monter, ce qui va à l'encontre de l'objectif.
mounts-relative-mountpoint = l'entrée {$index} monte sur `{$mountpoint}`, qui n'est pas un chemin absolu.
mounts-no-root-entry = aucune entrée ne monte `/` ; vérifiez que le système de fichiers racine est monté autrement.

## network module — display name, security notes, schema tooltips
network-name = network
network-note-precedence = une mauvaise configuration réseau peut couper l'administrateur de cet hôte ; chaque modification demande une seconde confirmation.
network-tip-interfaces = les interfaces que cet hôte configure, dans l'ordre du fichier.
network-tip-iface-name = le nom de l'interface, p. ex. eth0.
network-tip-iface-dhcp-v4 = indique si cette interface obtient son adresse IPv4 par DHCP.
network-tip-iface-dhcp-v6 = indique si cette interface obtient son adresse IPv6 par DHCP.
network-tip-iface-addresses = adresses statiques en notation CIDR, p. ex. 192.168.1.10/24.
network-tip-iface-gateway-v4 = la passerelle par défaut pour IPv4, en adressage statique.
network-tip-iface-gateway-v6 = la passerelle par défaut pour IPv6, en adressage statique.
network-tip-iface-dns = serveurs DNS de cette interface.
network-tip-iface-routes = routes statiques de cette interface.
network-tip-iface-vlan = paramètres VLAN de cette interface, lorsqu'elle est un VLAN.
network-tip-iface-bridge = paramètres de pont de cette interface, lorsqu'elle est un pont.
network-tip-route-to = le CIDR de destination ou default.
network-tip-route-via = l'IP du saut suivant.
network-tip-vlan-link = le lien parent de ce VLAN, p. ex. eth0.
network-tip-vlan-id = l'identifiant VLAN, 1–4094.
network-tip-bridge-members = noms des interfaces membres de ce pont.

## network module — validation diagnostics
network-invalid-cidr = `{$value}` n'est pas une adresse CIDR valide.
network-invalid-ip = `{$value}` n'est pas une adresse IP valide.
network-gateway-outside-subnet = la passerelle `{$gateway}` est en dehors des sous-réseaux de cette interface.
network-vlan-range = l'identifiant VLAN `{$id}` est en dehors de 1–4094.
network-duplicate-interface = l'interface `{$name}` apparaît plusieurs fois.
network-interface-order = l'interface `{$name}` doit venir avant les interfaces qui la précèdent : classez les interfaces par nom.
network-injection = `{$value}` contient un saut de ligne ou un octet nul.
network-static-no-gateway = cette interface à adressage statique n'a pas de passerelle.
network-static-no-dns = cette interface à adressage statique n'a pas de serveurs DNS.
network-dhcp-static-mixed = cette interface a à la fois des adresses DHCP et statiques.
network-rec-ipv6-privacy = activez les extensions de confidentialité IPv6 lorsque DHCPv6 est actif.
network-rec-ra-accept = n'acceptez les annonces de routeur que lorsque DHCPv6 est explicitement géré.
network-rec-no-promisc = cette interface ne devrait pas fonctionner en mode promiscuous.

## nfs module — display name, security notes, schema tooltips
nfs-name = nfs
nfs-note-live-state = les exports sont appliqués par le noyau à chaque montage ; une ligne erronée modifie silencieusement quels hôtes peuvent lire quels systèmes de fichiers.
nfs-tip-entries = les exports de /etc/exports, dans l'ordre du fichier.
nfs-tip-path = le point d'export : un chemin de répertoire absolu sur cet hôte.
nfs-tip-clients = les hôtes autorisés à monter cet export, dans l'ordre de correspondance ; la première spécification qui correspond l'emporte.
nfs-tip-host = la spécification du client : un nom, une adresse, adresse/masque, un joker, `*` (tous les clients) ou @netgroup.
nfs-tip-options = les options d'export de ce client, séparées par des virgules ; une liste vide reprend les valeurs par défaut du fichier.
nfs-rec-options = indiquez explicitement rw/ro, sync/async, root_squash et la gestion de subtree ; les valeurs par défaut changent d'une version de nfs-utils à l'autre.

## nfs module — validation diagnostics
nfs-empty-path = un point d'export est vide.
nfs-relative-path = `{$path}` n'est pas absolu ; un point d'export doit commencer par `/`.
nfs-empty-host = un client de `{$path}` n'a aucune spécification d'hôte.
nfs-bad-host = `{$host}` n'est pas une spécification de client valide ; elle commence par `-` ou contient une syntaxe qui tronquerait la ligne.
nfs-bad-path = `{$path}` contient une syntaxe qui tronquerait la ligne d'export.
nfs-bad-continuation = `{$path}` se terminerait par une barre oblique inverse de continuation et fusionnerait la ligne suivante.
nfs-invalid-option = `{$option}` n'est pas une option d'export valide ; les options sont des jetons simples sans espace ni parenthèses.
nfs-no-root-squash = `{$host}` monte avec no_root_squash et conserve les privilèges root sur l'export.
nfs-sec-sys-only = `{$host}` utilise la valeur par défaut sec=sys ou ne négocie que sec=sys ; ajoutez krb5p pour une protection cryptographique.
nfs-world-export = `{$host}` est accessible en lecture-écriture à tous les clients.
nfs-subtree-undecided = `{$host}` n'indique ni subtree_check ni no_subtree_check ; la valeur par défaut a changé en amont, précisez donc votre choix.
nfs-root-squash-undecided = `{$host}` n'indique ni root_squash ni no_root_squash ; précisez votre choix.
nfs-sync-undecided = `{$host}` n'indique ni sync ni async ; préférez sync, qui valide les écritures sur un stockage stable.

## resolver module — display name, security notes, schema tooltips
resolver-name = resolver
resolver-note-managed-symlink = sur cet hôte, /etc/resolv.conf est géré par un backend de résolution ; detent refuse de modifier la cible d'un lien symbolique géré et configure le backend à la place.
resolver-tip-resolv = les directives de /etc/resolv.conf que ce module modélise ; tout le reste du fichier est conservé tel quel.
resolver-tip-resolved = les paramètres de systemd-resolved, dans l'ordre du fichier. Les modifier redémarre systemd-resolved.
resolver-tip-unbound = les éléments de unbound.conf que ce module modélise, dans l'ordre du fichier. Les modifier redémarre unbound.

## resolver module — validation diagnostics
resolver-no-nameserver = aucun serveur de noms n'est configuré.
resolver-duplicate-nameserver = `{$ip}` apparaît comme serveur de noms plusieurs fois.
resolver-too-many-nameservers = ce fichier liste {$count} serveurs de noms ; glibc en lit au plus {$max}.
resolver-invalid-domain = `{$domain}` n'est pas un nom de domaine valide.
resolver-unknown-option = `{$option}` n'est pas une option acceptée par l'analyseur resolv.conf de glibc.
resolver-search-and-domain = `search` et `domain` sont tous deux présents ; glibc ignore `domain` lorsque `search` est défini.
resolver-no-config = ce modèle ne configure aucun backend de résolution.
resolver-backend-missing = ces paramètres configurent {$service}, qui n'a pas été détecté sur cet hôte.
resolver-rec-dnssec = DNSSEC est réglé sur allow-downgrade ; `DNSSEC=yes` valide strictement et est recommandé lorsque les données en amont le permettent.
resolver-rec-dot = DNSOverTLS est opportuniste, ce qui retombe en clair ; `DNSOverTLS=yes` exige TLS à la place.
resolver-unknown-hardening = `{$key}` n'est pas une directive que ce module modélise pour unbound.
resolver-unbound-misplaced = `{$key}` appartient à la section {$section} de unbound.conf, pas ici.
resolver-invalid-forward-addr = `{$addr}` n'est pas une forward-addr valide de la forme ip[@port][#auth-name].
resolver-invalid-forward-name = `{$name}` n'est pas un nom de forward-zone valide.
resolver-forward-tls-no-auth = cette zone transfère via TLS sans `#auth-name` sur sa forward-addr, donc la connexion TLS n'est pas authentifiée.
resolver-rec-hardening = `{$key}` est désactivé ; l'activer renforce unbound contre l'usurpation en amont et l'abus de délégation.
resolver-forward-zone-unnamed = une forward-zone: sans name: ne transfère rien et affaiblit la configuration ; donnez un nom à chaque zone.

## samba module — display name, security notes, schema tooltips
samba-name = samba
samba-note-guest-access = l'accès invité est accordé par partage au moment de la connexion ; une valeur erronée expose des fichiers sans mot de passe.
samba-tip-entries = les entrées de smb.conf que ce module modélise, dans l'ordre du fichier : en-têtes `[section]` et directives.
samba-tip-section = le nom de section d'un en-tête `[section]` ; vide pour une simple ligne de directive.
samba-tip-key = le nom du paramètre, insensible à la casse et possiblement en plusieurs mots (`guest ok`).
samba-tip-value = la valeur du paramètre, jusqu'à la fin de la ligne ; les macros `%` sont conservées telles quelles.
samba-rec-value = préférez une valeur durcie explicite plutôt que la valeur par défaut compilée en amont.

## samba module — validation diagnostics
samba-empty-key = une directive n'a pas de nom de paramètre.
samba-empty-section = un en-tête de section est vide.
samba-bad-key = `{$key}` serait analysé comme une section ou un commentaire, et non comme une clé de directive.
samba-bad-value = `{$value}` se termine par `\` et absorberait la ligne suivante.
samba-bad-section = `{$section}` contient `[` ou `]` ou se termine par `\` et ne serait pas réécrit à l'identique.
samba-guest-ok = `guest ok` vaut {$value} ; des clients non authentifiés peuvent se connecter à chaque partage qui en hérite.
samba-map-to-guest = `map to guest` vaut {$value} ; toute valeur autre que Never transforme les connexions échouées en sessions invité.
samba-min-protocol = `server min protocol` vaut {$value} ; définissez au moins SMB3_00 et abandonnez les niveaux de protocole de l'époque SMB1.
samba-smb-encrypt = `smb encrypt` vaut {$value} ; définissez required pour que le trafic SMB ne circule pas en clair.
samba-restrict-anonymous = `restrict anonymous` vaut {$value} ; 2 masque la liste des partages aux utilisateurs anonymes.
samba-rec-server-signing = `server signing` vaut {$value} ; définissez mandatory pour que le trafic SMB soit signé cryptographiquement.
samba-rec-load-printers = `load printers` vaut {$value} ; définissez no sauf si cet hôte partage réellement des imprimantes.
samba-rec-interfaces = aucune directive `interfaces` n'est définie ; liez samba à des adresses explicites plutôt que de l'écouter sur toutes les interfaces.
samba-writable-exposure = ce partage autorise l'écriture via writeable, read only ou write list ; confirmez que chaque client doit avoir un accès en écriture.
samba-root-command = `{$key}` exécute une commande avec les privilèges root à chaque connexion correspondante.
samba-client-command = `{$key}` permet à un client de faire exécuter une commande à samba ; le client contrôle ce que reçoit la commande.
samba-usershare-guests = `usershare allow guests` vaut {$value} ; les utilisateurs peuvent publier des partages que n'importe qui ouvre sans mot de passe.
samba-wide-links = `wide links` vaut {$value} ; les liens symboliques peuvent faire sortir les clients du partage.

## module template — copy-me example
TEMPLATE-name = modèle de module
TEMPLATE-note-precedence = ce module fictif est un exemple vérifié à la compilation pour les nouveaux modules de configuration.
TEMPLATE-tip-settings = les paramètres que ce module fictif modélise, dans l'ordre du fichier.
TEMPLATE-tip-key = le nom de la directive, un seul mot, sans espace.
TEMPLATE-tip-value = la valeur de la directive, jusqu'à la fin de la ligne.
TEMPLATE-rec-value = préférez une valeur explicite plutôt que de vous fier à une valeur par défaut en amont.
TEMPLATE-invalid-key = `{$key}` n'est pas un nom de directive valide.
TEMPLATE-duplicate-key = `{$key}` est défini plusieurs fois ; la dernière valeur l'emporte.
TEMPLATE-too-many-settings = ce fichier contient {$count} paramètres ; répartissez les grandes configurations en fichiers plus petits.

## detent-core — parse, model, and edit errors
## These are the failures a module's own document model can raise, so they are
## prefixed `core-` rather than with a module id.
core-parse-malformed = ce fichier ne correspond pas au format attendu par `{$module}` : {$reason}
core-model-shape = la configuration fournie n'a pas la forme attendue : {$reason}
core-model-unrepresentable = ce fichier contient quelque chose que l'éditeur ne peut pas représenter : {$reason}
core-edit-line-break = une valeur ne peut pas contenir de saut de ligne ni d'octet nul ; `{$value}` en contient.
core-edit-index-out-of-range = erreur interne : la ligne {$index} est en dehors d'un fichier de {$len} lignes.
core-edit-unsupported = cette modification ne peut pas être exprimée dans le format du fichier : {$reason}

## detent-core — version-gated options
core-version-too-old = `{$option}` nécessite {$service} {$since} ou plus récent ; cet hôte a {$installed}.
core-version-unknown = la version installée de {$service} est inconnue, donc `{$option}` (nécessite {$service} {$since} ou plus récent) peut ne pas fonctionner.

## operations layer — errors surfaced by detent-ops
ops-unknown-module = il n'y a aucun module nommé `{$module}` dans cette version.
ops-invalid-model = la configuration de `{$module}` n'est pas valide : {$reason}
ops-check-failed = le validateur externe `{$program}` a refusé le candidat : {$reason}
ops-hash-conflict = `{$path}` a changé sur le disque depuis sa lecture ; relisez-le et réessayez.
ops-privsep-failed = l'assistant privilégié a refusé la requête ou n'a pas pu la terminer : {$reason}
ops-service-failed = l'action sur le service ne s'est pas terminée : {$reason}
ops-no-target = `{$module}` ne gère aucun fichier sur cet hôte.
ops-no-service = `{$module}` ne contrôle aucun service sur cet hôte, il ne peut donc pas être redémarré.
ops-audit-failed = le journal d'audit n'a pas pu être lu : {$reason}
ops-audit-unavailable = le journal d'audit n'a pas pu être écrit, l'opération a donc été refusée : {$reason}
ops-unsupported = {$what} n'est pas pris en charge dans cette version.
ops-commit-pending = une autre fenêtre commit-confirm est déjà en attente.
ops-update-running = une mise à jour est déjà en cours ; attendez qu'elle se termine, puis vérifiez la version en cours d'exécution.
ops-update-tag-invalid = ce n'est pas une version publiée ; elle doit ressembler à v1.2.3.
ops-update-not-newer = cette version n'est pas plus récente que la version en cours d'exécution ; rien n'a été lancé.
ops-no-backup = commit-confirm nécessite une sauvegarde conservée ; rien n'a été modifié.
ops-arm-failed-restored = commit-confirm n'a pas pu être armé, la modification a donc été annulée ; le contenu précédent est rétabli.
ops-arm-failed-unrestored = commit-confirm n'a pas pu être armé et la modification n'a PAS pu être annulée ; le nouveau contenu est toujours sur le disque. Restaurez la sauvegarde précédente maintenant.
ops-target-missing = le fichier géré n'existe pas ; créez-le (installez son paquet ou créez-le à la main), puis réessayez.
ops-denied = vous n'avez pas l'autorisation de faire cela.

## detent-web — configuration, TLS, the operations bridge, and the listener
web-config-unreadable = `{$path}` n'a pas pu être lu : {$reason}
web-config-malformed = `{$path}` n'est pas une configuration detent valide : {$reason}
web-config-zero-value = `{$field}` doit être supérieur à zéro.
web-config-weak-argon2 = `auth.argon2.m_kib` vaut {$m}, en dessous du minimum de {$min} kib.
web-tls-generate-failed = le certificat d'amorçage n'a pas pu être généré : {$reason}
web-tls-key-rejected = le certificat et sa clé privée ont été rejetés : {$reason}
web-tls-store-unreadable = `{$path}` n'a pas pu être lu : {$reason}
web-tls-store-unwritable = `{$path}` n'a pas pu être préparé pour l'écriture : {$reason}
web-tls-store-write-failed = `{$path}` n'a pas pu être écrit : {$reason}
web-tls-acme-pem-rejected = le certificat ou la clé émis n'était pas un PEM utilisable.
web-engine-stopped = le moteur d'opérations ne tourne plus ; réessayez quand le service sera de retour.
web-cert-renew-not-acme = le renouvellement nécessite `tls.bootstrap = "acme"` dans detent.toml.
web-cert-renew-unavailable = le client acme n'a pas reçu la demande de renouvellement ; réessayez plus tard.
web-update-not-checked = aucune vérification de mise à jour n'a encore été faite sur cet hôte ; exécutez `detent update --check` en tant que root.
web-server-bind-failed = `{$addr}` n'a pas pu être mis en écoute : {$reason}
web-server-address-unknown = l'adresse d'écoute n'a pas pu être relue : {$reason}

## detent-web — auth: passwords, sessions, api tokens, totp, csrf
web-auth-entropy-unavailable = le générateur de nombres aléatoires du système a échoué, aucun identifiant n'a donc pu être émis.
web-auth-argon2-params = les paramètres argon2 configurés sont inutilisables : {$reason}
web-auth-hash-failed = le mot de passe n'a pas pu être haché.
web-auth-password-too-short = un mot de passe doit comporter au moins 12 caractères.
web-auth-password-too-long = un mot de passe peut comporter au plus 128 caractères.
web-auth-password-unchanged = le nouveau mot de passe doit différer de l'actuel.
web-auth-password-change-required = changez votre mot de passe avant de faire quoi que ce soit d'autre.
web-auth-user-name-invalid = `{$name}` n'est pas un nom d'utilisateur utilisable ; utilisez de 1 à 32 caractères parmi `a-z`, `0-9`, `.`, `_` ou `-`, en commençant par une lettre ou un chiffre.
web-auth-user-exists = un utilisateur nommé `{$name}` existe déjà.
web-auth-user-unknown = il n'y a aucun utilisateur nommé `{$name}`.
web-auth-invalid-credentials = le nom d'utilisateur, le mot de passe ou le code n'était pas correct.
web-auth-rate-limited = trop de tentatives ; attendez {$seconds} secondes et réessayez.
web-auth-session-limit = trop de sessions sont ouvertes ; attendez qu'une expire et reconnectez-vous.
web-auth-busy = trop de connexions sont en cours ; patientez un instant et réessayez.
web-auth-unauthenticated = connectez-vous pour faire cela.
web-auth-ambiguous-credentials = envoyez soit un cookie de session, soit un jeton bearer, pas les deux.
web-auth-csrf-rejected = cette requête n'a pas passé ses vérifications inter-sites.
web-auth-token-unknown = ce jeton api n'existe pas, est révoqué ou a expiré.
web-auth-token-limit = cet hôte détient déjà le nombre maximal de jetons api.
web-auth-totp-secret-invalid = ce secret d'authentificateur n'est pas du base32 valide.
web-auth-store-unreadable = `{$path}` n'a pas pu être lu : {$reason}
web-auth-store-unwritable = `{$path}` n'a pas pu être préparé pour l'écriture : {$reason}
web-auth-store-write-failed = `{$path}` n'a pas pu être écrit : {$reason}
web-auth-store-malformed = `{$path}` n'est pas un fichier d'identifiants detent valide : {$reason}
web-denied-scope = cet identifiant ne porte pas la portée `{$scope}`.

## detent-web — the api surface
web-request-malformed = le corps de la requête n'a pas la forme attendue par ce point d'accès.
web-request-too-deep = le corps de la requête est imbriqué trop profondément.
web-api-unexpected-outcome = l'opération s'est terminée mais son résultat n'a pas pu être affiché.
