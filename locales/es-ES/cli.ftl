# needs-review: machine-drafted Spanish translation; not yet checked by a native speaker.
## detent CLI — es
## Source: locales/en-US/cli.ftl. Same ids, same placeables. Identifiers — module ids,
## paths, unit names, digests, enum wire names such as `restart` or `active` — are
## interpolated verbatim and must not be translated.

## severity words, prefixed to every rendered diagnostic
cli-severity-error = error
cli-severity-warning = advertencia
cli-severity-recommendation = nota

## yes/no, used wherever a flag is rendered
cli-yes = sí
cli-no = no

## progress notes, printed on stderr under --verbose
cli-note-settings = idioma {$locale}, raíz de estado {$state}, configuración {$config}
cli-note-operation = ejecutando {$operation} para {$module}

## failures that stop a command before the operations layer sees it
cli-bad-stdin = no se pudo leer el modelo desde stdin: {$reason}
cli-bad-json = el modelo de stdin no es json válido: {$reason}
cli-bad-hash = `{$value}` no es un resumen sha-256 de 64 caracteres hexadecimales.
cli-start-failed = no se pudo iniciar el ayudante privilegiado: {$reason}
cli-monitor-stop = el ayudante privilegiado no se detuvo limpiamente: {$reason}
cli-monitor-busy = otro monitor de detent ya posee esta raíz de estado; inténtalo de nuevo desde la interfaz web o ejecuta `detent serve`.
cli-monitor-lock-unavailable = no se puede tomar el bloqueo de estado en {$path}, así que este comando no puede cambiar nada; ejecútalo como un usuario que pueda escribir en ese directorio, o pasa --state-root.
cli-commit-recovered = se recuperó el commit sin confirmar {$commit}; se restauraron {$restored} destinos con {$failures} fallos.
cli-commit-confirm-needs-serve = este módulo requiere commit-confirm; usa la interfaz web o `detent serve` para que se siga aplicando la ventana de confirmación.
cli-config-load-failed = no se pudo cargar la configuración de {$path}: {$reason}
cli-no-command = no se indicó ningún comando.

## self-test probe and self-update (PLAN §2.9)
cli-self-test = versión {$version}, funciones {$features}
cli-update-available = actualización disponible: {$tag} publicada {$published}
cli-update-security-available = actualización de seguridad disponible: {$tag} publicada {$published}
cli-update-none = ninguna actualización disponible (actual {$current})
cli-update-held-young = {$tag} es más reciente que {$current} pero tiene menos de {$days} día(s); el filtro de antigüedad la retiene
cli-update-held-rejected = {$tag} es más reciente que {$current} pero se revirtió en este host; se omite
cli-verify-bundle-ok = {$file} está certificado para {$tag}
cli-update-failed = la actualización falló: {$reason}
cli-update-installed = se instaló {$tag}; el binario reemplazado se conserva en {$previous}
cli-update-not-restarted = el servicio no se reinició, así que el binario nuevo aún no se está ejecutando: {$reason}
cli-update-rolled-back = revertido: {$reason}
cli-update-rollback-failed = la actualización falló ({$reason}) y la reversión también falló ({$error}); este host requiere atención

## config
cli-module-line = {$id}  {$name}
cli-no-model = este módulo todavía no gestiona ningún archivo en este host, así que no hay modelo que mostrar.
cli-valid = esta configuración es válida.
cli-plan-no-change = {$module} ya es lo que contiene {$path}; no cambiaría nada.
cli-plan-service = aplicar esto afectaría a {$unit}.
cli-plan-hash = el archivo ahora tiene el resumen {$hash}; pásalo como --expect-hash para rechazar una edición concurrente.
cli-check-ran = se ejecutó el validador de origen {$program}; superado: {$passed}. {$detail}
cli-check-skipped = no se ejecutó el validador de origen {$program}. {$detail}
cli-applied = {$module} se escribió en {$path}.
cli-applied-hash = tenía el resumen {$prev} y ahora tiene {$new}; copia de seguridad conservada: {$backup}
cli-mounts-off = mounts: la activación está desactivada ([mounts] activate_new_entries); las nuevas entradas de fstab surten efecto en el siguiente arranque o montaje.
cli-mounts-error = mounts: no se inició ninguna unidad de montaje: {$reason}
cli-mounts-none = mounts: no hay ninguna entrada nueva de fstab que montar.
cli-mounts-unit = montaje {$mountpoint} ({$unit}): {$state}
cli-mounts-unit-detail = montaje {$mountpoint} ({$unit}): {$state}: {$detail}
cli-commit-armed = el commit {$id} debe confirmarse en {$seconds} segundos, antes de {$deadline}, o se revierte.
cli-commit-confirmed = el commit {$id} está confirmado y no se revertirá.
cli-commit-rolled-back = el commit {$id} se revirtió; se restauraron {$targets} destinos.

## backups
cli-no-backups = todavía no se ha conservado ninguna copia de seguridad de este módulo.
cli-backup-line = {$id}  {$name}  {$bytes} bytes  {$digest}
cli-restored = el destino {$target} se restauró y ahora tiene el resumen {$hash}.

## services
cli-service-status = {$unit} está {$state}; arranca al iniciar: {$enabled}
cli-serviced = se pidió a {$unit} que hiciera {$action}; en ejecución ahora: {$active}

## host
cli-host-profile = {$hostname}: {$os}, init {$init}, {$ram} MiB de ram
cli-host-service-version = el {$service} instalado es la versión {$version}
cli-host-backends = backend de red {$network}, backend de resolución {$resolver}, distribución {$distro} {$version}
cli-host-note = nota de detección: {$note}

## audit
cli-no-audit = el registro de auditoría no tiene registros coincidentes.
cli-audit-line = {$ts}  {$who}  {$op}  {$module}  {$result}  {$error}
cli-audit-verified = la cadena de auditoría está intacta hasta el registro {$sequence}; resumen de cabecera {$hash}
cli-audit-broken = no se pudo verificar la cadena de auditoría: {$reason}

## --dryrun
cli-dryrun-apply = simulacro: esto es lo que se escribiría en {$path} para {$module}.
cli-dryrun-operation = simulacro: se ejecutaría {$operation} para {$module}.
cli-dryrun-nothing = simulacro: no se cambió nada.
cli-dryrun-serve = simulacro: el monitor y el worker arrancarían con {$modules} módulos y {$targets} destinos, con raíz en {$state}.
cli-dryrun-serve-mounts = simulacro: tras un apply de mounts, el runner iniciaría las unidades de montaje de las nuevas entradas de fstab (mounts.activate_new_entries = true).
cli-dryrun-cert-renew = simulacro: pediría al servidor en {$address} (como {$name}) que renovara su certificado ahora; no se envió nada.

## serve
cli-serve-monitor = el worker arrancó con el pid {$pid}; privilegios descartados: {$dropped}
cli-serve-worker = el worker se está ejecutando; su servidor http llega en la fase 4. handshake: {$greeted}
cli-serve-failed = no se pudieron iniciar el monitor y el worker: {$reason}
cli-serve-stopped = el par se detuvo inesperadamente: {$reason} {$status}
cli-serve-privileged-port = el puerto {$port} necesita cap_net_bind_service o un socket pasado por el monitor, y esta compilación no admite ninguno de los dos; usa un puerto de 1024 o superior, o pon un proxy inverso delante.
cli-serve-privilege-mode = el modo de privilegios configurado no coincide con este proceso, así que el servicio no arrancó: {$reason}
cli-serve-acme-unsupported = esta compilación no tiene proveedores dns-01 (función acme-dns-providers), así que no puede obtener certificados acme; define tls.bootstrap como "self-signed" en {$path}.
cli-serve-acme-setting-missing = tls.bootstrap es "acme", pero {$setting} no está definido en {$path}.
cli-serve-acme-path-outside = {$setting} ({$value}) no está bajo la raíz de estado {$root}: los procesos confinados solo escriben ahí.
cli-serve-acme-credentials-dir = no se pudo preparar el directorio de credenciales acme {$path}: {$reason}
cli-serve-secrets-failed = se rechazó el archivo de secretos {$path}: {$reason}
cli-serve-acme-secret-missing = acme.provider está definido, pero {$path} no tiene ningún secreto dns_provider en su tabla [acme].
cli-serve-acme-provider-invalid = no se puede usar el proveedor dns-01 de acme.provider: {$reason}
cli-serve-acme-providers-not-built = esta compilación no tiene proveedores dns-01 (función acme-dns-providers); quita [acme.provider] de {$path}.
cli-serve-handshake-failed = el worker no pudo completar su handshake con el monitor.
cli-serve-auth-failed = no se pudo abrir el almacén de cuentas, tokens y sesiones: {$reason}
cli-serve-tls-failed = no se pudo preparar el certificado tls: {$reason}
cli-serve-cert-fingerprint = huella del certificado de arranque tls (sha-256): {$fingerprint}
cli-serve-web-failed = no se pudo iniciar el servidor web: {$reason}
cli-serve-web-stopped = el servidor web no se detuvo limpiamente: {$reason}
cli-serve-listening = escuchando en {$addr}
cli-serve-confinement-degraded = confinamiento degradado: {$detail}
cli-mcp-missing-token = {$var} no está definido; crea uno con `detent token create` y expórtalo antes de iniciar el servidor mcp.
cli-mcp-serve-failed = no se pudo iniciar el servidor mcp: {$reason}
cli-mcp-listening = mcp sirviendo {$transport}
cli-mcp-http-needs-privsep = el transporte http de mcp no puede ejecutarse como root ni con capabilities: el analizador de red correría con poder similar al de root; ejecútalo como usuario sin privilegios y sin capabilities, o usa el transporte stdio.
cli-mcp-bind-not-loopback = el enlace http de mcp debe ser loopback (127.0.0.1 o ::1); el bearer viaja en texto plano por la red.
cli-dryrun-mcp = simulacro: mcp serviría {$transport} en {$addr} con el ámbito {$scope}.

## setup, user, token
cli-setup-exists = ya existe un usuario llamado `{$name}` en este host; pasa --force para sobrescribirlo.
cli-setup-created = se creó la cuenta de administrador `{$name}`.
cli-user-created = se creó la cuenta `{$name}`.
cli-user-passwd = se cambió la contraseña de `{$name}`.
cli-user-removed = se eliminó la cuenta `{$name}`.
cli-totp-uri = añade esto a tu aplicación de autenticación: {$uri}
cli-totp-secret = o escribe esta clave en ella: {$secret}
cli-totp-code-prompt = código de tu autenticador:
cli-totp-code-empty = un código no puede estar vacío.
cli-totp-code-wrong = ese código no es válido, así que no se activó el segundo factor.
cli-user-totp-enabled = se activó el segundo factor de `{$name}`.
cli-totp-disable-prompt = ¿desactivar el segundo factor de `{$name}`? [y/N]
cli-totp-disable-cancelled = el segundo factor de `{$name}` se dejó activado.
cli-user-totp-disabled = se desactivó el segundo factor de `{$name}`.
cli-token-created = se creó el token {$id} ({$label}); no se volverá a mostrar: {$token}
cli-token-revoked = se revocó el token {$id}.
cli-token-no-tokens = no se ha emitido ningún token.
cli-token-line = {$id}  {$label}  {$scopes}  {$created}  {$expires}
cli-credential-failed = no se pudo completar la solicitud: {$reason}
cli-audit-failed = el cambio se hizo, pero no se pudo escribir su registro de auditoría: {$reason}
cli-state-command-as-root = detent {$command} no debe ejecutarse como root: los archivos que escribe pertenecerían a root y el servicio no podría leerlos. Ejecútalo en su lugar con la cuenta del servicio: sudo -u {$account} detent {$command}

## cert status
cli-cert-source = origen: {$source}
cli-cert-fingerprint = huella (sha-256): {$fingerprint}
cli-cert-not-after = caduca: {$not_after}
cli-cert-not-after-unknown = caducidad: desconocida (el certificado no se pudo analizar).
cli-cert-lifetime = vida útil consumida: {$percent} (advertencia: {$warning}).
cli-cert-lifetime-no-warning = vida útil consumida: {$percent} (sin advertencia).
cli-cert-lifetime-unknown = vida útil consumida: desconocida (el certificado no se pudo analizar).
cli-cert-missing = no hay ningún certificado almacenado en {$path}; inicia el servidor una vez para que escriba uno.
cli-cert-unreadable = no se pudo leer el certificado de {$path}: {$reason}

## cert renew
cli-cert-renew-requested = renovación solicitada: el servidor pidió a su cliente ACME que renovara ahora. Comprueba el resultado con `detent cert status`.
cli-cert-renew-token-refused = se rechazó el token (HTTP {$status}); necesita el ámbito write: `detent token create <name> --write`.
cli-cert-renew-not-acme = el servidor no ejecuta ningún proceso ACME (`tls.bootstrap` no es `acme`), así que no hay nada que renovar.
cli-cert-renew-server-error = el servidor respondió HTTP {$status}: {$message_id}
cli-cert-renew-server-error-bare = el servidor respondió HTTP {$status}.
cli-cert-renew-unreachable = no se pudo comunicar con el servidor en {$address}: {$reason}
cli-cert-renew-no-token = no hay token de API: pasa --token-file <path> o define {$var}. Crea un token de escritura con `detent token create <name> --write`.
cli-cert-renew-bad-token = se rechazó el token de {$source}: {$reason}
cli-cert-renew-ca-unreadable = no se pudo leer el archivo CA {$path}: {$reason}

## password entry (setup, user add, user passwd)
cli-password-prompt = contraseña:
cli-password-confirm = confirma la contraseña:
cli-password-mismatch = las contraseñas no coinciden.
cli-password-empty = una contraseña no puede estar vacía.

## doctor
cli-status-ok = ok
cli-status-warn = aviso
cli-status-fail = fallo
cli-doctor-modules = módulos compilados en esta compilación: {$detail}
cli-doctor-state-root = directorio de estado {$detail}
cli-doctor-config = archivo de configuración {$detail}
cli-doctor-privsep = la separación de privilegios puede crear un par funcional: {$detail}
cli-doctor-landlock = landlock: {$detail}
cli-doctor-seccomp = seccomp: {$detail}
cli-doctor-confinement = confinamiento del sandbox: {$detail}
cli-doctor-serve-confinement = confinamiento en el último arranque de serve: {$detail}
cli-doctor-mounts = activación de montajes tras un apply de fstab: {$detail}
cli-doctor-privilege-mode = modo de privilegios: {$detail}
cli-doctor-service-account = cuenta de servicio: {$detail}
cli-doctor-state-owner = propietario del directorio de estado: {$detail}
cli-doctor-backups-dir = directorio de copias de seguridad: {$detail}
cli-doctor-polkit-rule = regla de polkit: {$detail}
cli-doctor-polkit-daemon = demonio de polkit: {$detail}
cli-doctor-unit-capabilities = identidad y capabilities de la unidad de servicio: {$detail}
