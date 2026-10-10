# needs-review: machine-drafted Spanish translation; not yet checked by a native speaker.
## detent-core — es
## Source: locales/en-US/core.ftl. Same ids, same placeables. Code-like tokens
## (directive names, paths, flags, option values) stay untranslated.

## chrony module — display name, security notes, schema tooltips
chrony-name = chrony
chrony-note-precedence = este archivo anula los valores predeterminados compilados; un valor incorrecto cambia en silencio cómo mantiene la hora el host.
chrony-tip-settings = las directivas de chrony.conf que modela este módulo, en el orden del archivo; todo lo demás del archivo se conserva intacto.
chrony-tip-key = el nombre de la directiva, una sola palabra, sin distinguir mayúsculas de minúsculas.
chrony-tip-value = el valor de esta directiva, hasta el final de la línea; vacío para directivas sin valor como `rtcsync`.
chrony-rec-value = prefiere un valor explícito en lugar de depender del valor predeterminado compilado.

## chrony module — validation diagnostics
chrony-privileged-directive = `{$key}` define un archivo que chronyd escribe como root, o el usuario con el que se ejecuta. Comprueba el valor antes de aplicarlo.
chrony-invalid-key = `{$key}` no es un nombre de directiva de chrony válido.
chrony-duplicate-key = `{$key}` está definido más de una vez; prevalece el último valor.
chrony-too-many-settings = este archivo tiene {$count} ajustes; divídelo en archivos drop-in en /etc/chrony/conf.d.
chrony-allow-open = `allow {$value}` sirve la hora a todo Internet; permite solo las redes que la necesitan.
chrony-missing-makestep = makestep no está definido; al arrancar, el reloj puede desviarse sin límite en lugar de ajustarse al rango.
chrony-missing-rtcsync = rtcsync no está definido; el reloj de hardware se desviará respecto al reloj del sistema.
chrony-rec-nts = el pool {$pool} se usa sin la opción nts; prefiere fuentes compatibles con nts para que no se pueda falsificar la hora.
chrony-cmdport-open = cmdport es {$port}; define cmdport 0 salvo que chronyc deba llegar a este host por la red.
chrony-external-directive = `{$key}` carga archivos externos o ejecuta un programa externo; este módulo rechaza las directivas que cruzan su límite de archivos configurado.

## dhcp module — display name, security notes, schema tooltips
dhcp-name = dhcp
dhcp-note-commit-confirm = un cambio DHCP incorrecto deja sin red a todos los clientes, y a ti con ellos; revisa el diff con cuidado antes de confirmar.
dhcp-tip-dnsmasq = los ajustes `key=value` de /etc/dnsmasq.conf, en el orden del archivo; los comentarios y las líneas desconocidas se conservan intactos.
dhcp-tip-kea-v4 = el subconjunto gestionado del servidor Kea DHCPv4 (`Dhcp4`); las opciones de Kea desconocidas se conservan intactas.
dhcp-tip-kea-v6 = el subconjunto gestionado del servidor Kea DHCPv6 (`Dhcp6`); las opciones de Kea desconocidas se conservan intactas.
dhcp-tip-key = el nombre de la opción de dnsmasq, una sola palabra, sin espacios.
dhcp-tip-value = el valor después de `=`; un indicador simple como `domain-needed` no tiene valor.
dhcp-tip-interfaces = las interfaces en las que escucha el servidor Kea; una lista vacía significa que el servidor responde en todas las interfaces.
dhcp-tip-valid-lifetime = la duración predeterminada de la concesión en segundos; 3600 es un valor razonable para la mayoría de las redes.
dhcp-tip-subnets = las subredes de las que el servidor asigna direcciones.
dhcp-tip-id = el identificador estable de subred de Kea; mantenlo estable entre ediciones, las concesiones se indexan por él.
dhcp-tip-subnet = el prefijo de la subred en formato CIDR, p. ej. `192.168.1.0/24`.
dhcp-tip-pools = los pools de direcciones dinámicas de la subred.
dhcp-tip-routers = la opción de routers (puerta de enlace predeterminada) que se entrega a los clientes.
dhcp-tip-domain-servers = los servidores DNS (`domain-name-servers`) que se entregan a los clientes.
dhcp-tip-pool = un pool como rango `192.168.1.100 - 192.168.1.200` o como prefijo `192.168.1.0/24`.

## dhcp module — validation diagnostics
dhcp-empty-key = un ajuste de dnsmasq tiene un nombre de opción vacío.
dhcp-invalid-key = `{$key}` no es un nombre de opción de dnsmasq válido; debe ser una sola palabra sin espacios, `=` ni `#`.
dhcp-malformed-cidr = `{$value}` no es un prefijo CIDR válido, p. ej. `192.168.1.0/24`.
dhcp-malformed-pool = `{$value}` no es un pool válido; usa un rango como `192.168.1.100 - 192.168.1.200` o un prefijo CIDR.
dhcp-external-directive = `{$key}` carga archivos externos o ejecuta comandos; este módulo no creará ni modificará directivas que cruzan su límite de archivos configurado.
dhcp-authoritative-set = `dhcp-authoritative` convierte a dnsmasq en el único servidor DHCP del segmento; actívalo solo cuando no exista otro servidor DHCP.
dhcp-kea-interfaces-empty = {$server} no tiene interfaces configuradas y escuchará en todas las interfaces; nombra las interfaces explícitamente.
dhcp-rec-rebind = domain-needed y bogus-priv no están ambos definidos; filtran los ataques de rebind y las consultas A ascendentes de direcciones privadas.
dhcp-rec-lifetime = {$server} tiene valid-lifetime {$lifetime}; mantenlo entre 300 y 86400 segundos para que las concesiones se renueven de forma predecible.

## hosts module — display name, security notes, schema tooltips
hosts-name = hosts
hosts-note-spoofing = las entradas de aquí anulan el dns; una entrada incorrecta o maliciosa redirige las consultas en silencio.
hosts-tip-entries = las asignaciones de dirección a nombre de /etc/hosts, en el orden del archivo.
hosts-tip-ip = la dirección a la que se resuelven los nombres siguientes.
hosts-tip-hostnames = los nombres que se resuelven a esta dirección, con el nombre canónico primero.
hosts-tip-comment = el comentario en línea de esta entrada, si lo hay.

## hosts module — validation diagnostics
hosts-invalid-hostname = `{$name}` no es un nombre de host válido.
hosts-duplicate-canonical = `{$name}` es el nombre canónico de más de una entrada.
hosts-no-hostnames = esta entrada no tiene nombres de host.
hosts-hostname-is-ip = `{$name}` es un literal de dirección, no un nombre de host.
hosts-ipv6-zone-unsupported = `{$name}` lleva un id de zona ipv6, que /etc/hosts no admite.
hosts-hostname-multiple-ips = `{$name}` se resuelve a más de una dirección de la misma familia.
hosts-localhost-not-loopback = `localhost` apunta a `{$ip}`, que no es una dirección de loopback.
hosts-missing-localhost = no hay ninguna entrada `localhost`.
hosts-missing-ipv6-localhost = no hay ninguna entrada `localhost` de ipv6.
hosts-too-many-entries = este archivo tiene {$count} entradas; considera usar dns en su lugar.

## mounts module — display name, security notes, schema tooltips
mounts-name = mounts
mounts-note-boot = un /etc/fstab incorrecto puede dejar el host sin poder arrancar en el siguiente reinicio; cada cambio necesita una segunda confirmación. La confirmación no puede detectar una entrada incorrecta, porque nada lee el archivo antes del siguiente arranque.
mounts-tip-entries = las entradas de montaje de /etc/fstab, en el orden del archivo.
mounts-tip-spec = lo que se monta: un dispositivo, `UUID=...`/`LABEL=...`, una exportación nfs, o `none` para el swap.
mounts-tip-mountpoint = dónde se monta el sistema de archivos, o `none`/`swap` para el swap.
mounts-tip-fstype = el tipo de sistema de archivos, p. ej. ext4, o `swap`.
mounts-tip-options = las opciones de montaje separadas por comas, p. ej. defaults,nosuid.
mounts-tip-dump = la frecuencia de copia de seguridad de dump(8); casi siempre 0.
mounts-tip-pass = el número de pasada de fsck: 1 para la raíz, 2 para los demás sistemas de archivos comprobados, 0 para omitir.
mounts-rec-options = protege los datos escribibles por los usuarios con nosuid, nodev y noexec; prefiere x-systemd.automount en los sistemas de archivos de red.

## mounts module — validation diagnostics
mounts-empty-spec = la entrada {$index} tiene una spec vacía (primera columna).
mounts-empty-mountpoint = la entrada {$index} tiene un punto de montaje vacío (segunda columna).
mounts-invalid-fstype = `{$fstype}` no es un tipo de sistema de archivos válido.
mounts-pass-too-high = la entrada {$index} tiene pasada `{$pass}`; fsck ejecuta como máximo 2 pasadas.
mounts-root-pass = el sistema de archivos raíz debería tener pasada 1, no `{$pass}`.
mounts-missing-nofail = `{$mountpoint}` es un medio extraíble sin `nofail`; el arranque se bloquea cuando se desconecta.
mounts-missing-boot-escape = `{$mountpoint}` no tiene ni nofail ni noauto; un montaje fallido puede retrasar el arranque.
mounts-critical-noauto = `{$mountpoint}` es necesario para el arranque pero tiene noauto, así que el sistema puede continuar sin él.
mounts-missing-guards = `{$mountpoint}` monta datos escribibles por los usuarios sin `{$missing}`; añádelos.
mounts-network-automount = `{$mountpoint}` es un sistema de archivos de red sin `x-systemd.automount`; el arranque espera a la red.
mounts-noauto-without-user = `noauto` sin `user`: solo root puede montarlo, lo que anula el propósito.
mounts-relative-mountpoint = la entrada {$index} monta en `{$mountpoint}`, que no es una ruta absoluta.
mounts-no-root-entry = ninguna entrada monta `/`; comprueba que el sistema de archivos raíz se monta de otra forma.

## network module — display name, security notes, schema tooltips
network-name = network
network-note-precedence = una configuración de red incorrecta puede dejar al administrador sin acceso a este host; cada cambio necesita una segunda confirmación.
network-tip-interfaces = las interfaces que configura este host, en el orden del archivo.
network-tip-iface-name = el nombre de la interfaz, p. ej. eth0.
network-tip-iface-dhcp-v4 = si esta interfaz obtiene su dirección IPv4 por DHCP.
network-tip-iface-dhcp-v6 = si esta interfaz obtiene su dirección IPv6 por DHCP.
network-tip-iface-addresses = direcciones estáticas en notación CIDR, p. ej. 192.168.1.10/24.
network-tip-iface-gateway-v4 = la puerta de enlace predeterminada para IPv4, con direccionamiento estático.
network-tip-iface-gateway-v6 = la puerta de enlace predeterminada para IPv6, con direccionamiento estático.
network-tip-iface-dns = servidores DNS de esta interfaz.
network-tip-iface-routes = rutas estáticas de esta interfaz.
network-tip-iface-vlan = ajustes de VLAN de esta interfaz, cuando es una VLAN.
network-tip-iface-bridge = ajustes de puente de esta interfaz, cuando es un puente.
network-tip-route-to = el CIDR de destino o default.
network-tip-route-via = la IP del siguiente salto.
network-tip-vlan-link = el enlace padre de esta VLAN, p. ej. eth0.
network-tip-vlan-id = el id de VLAN, 1–4094.
network-tip-bridge-members = nombres de las interfaces miembro de este puente.

## network module — validation diagnostics
network-invalid-cidr = `{$value}` no es una dirección CIDR válida.
network-invalid-ip = `{$value}` no es una dirección IP válida.
network-gateway-outside-subnet = la puerta de enlace `{$gateway}` está fuera de las subredes de esta interfaz.
network-vlan-range = el id de VLAN `{$id}` está fuera de 1–4094.
network-duplicate-interface = la interfaz `{$name}` aparece más de una vez.
network-interface-order = la interfaz `{$name}` debe ir antes de las interfaces que la preceden: ordena las interfaces por nombre.
network-injection = `{$value}` contiene un salto de línea o un byte nulo.
network-static-no-gateway = esta interfaz con direccionamiento estático no tiene puerta de enlace.
network-static-no-dns = esta interfaz con direccionamiento estático no tiene servidores DNS.
network-dhcp-static-mixed = esta interfaz tiene direcciones DHCP y estáticas a la vez.
network-rec-ipv6-privacy = activa las extensiones de privacidad de IPv6 cuando DHCPv6 está activo.
network-rec-ra-accept = acepta anuncios de router solo cuando DHCPv6 se gestiona explícitamente.
network-rec-no-promisc = esta interfaz no debería funcionar en modo promiscuo.

## nfs module — display name, security notes, schema tooltips
nfs-name = nfs
nfs-note-live-state = el kernel aplica las exportaciones en cada montaje; una línea incorrecta cambia en silencio qué hosts pueden leer qué sistemas de archivos.
nfs-tip-entries = las exportaciones de /etc/exports, en el orden del archivo.
nfs-tip-path = el punto de exportación: una ruta de directorio absoluta en este host.
nfs-tip-clients = los hosts que pueden montar esta exportación, en orden de coincidencia; prevalece la primera especificación que coincide.
nfs-tip-host = la especificación del cliente: un nombre, una dirección, dirección/máscara, un comodín, `*` (todos los clientes) o @netgroup.
nfs-tip-options = las opciones de exportación de este cliente, separadas por comas; una lista vacía toma los valores predeterminados del archivo.
nfs-rec-options = indica explícitamente rw/ro, sync/async, root_squash y el manejo de subtree; los valores predeterminados cambian entre versiones de nfs-utils.

## nfs module — validation diagnostics
nfs-empty-path = un punto de exportación está vacío.
nfs-relative-path = `{$path}` no es absoluto; un punto de exportación debe empezar por `/`.
nfs-empty-host = un cliente de `{$path}` no tiene especificación de host.
nfs-bad-host = `{$host}` no es una especificación de cliente válida; empieza por `-` o contiene sintaxis que truncaría la línea.
nfs-bad-path = `{$path}` contiene sintaxis que truncaría la línea de exportación.
nfs-bad-continuation = `{$path}` terminaría con una barra invertida de continuación y absorbería la línea siguiente.
nfs-invalid-option = `{$option}` no es una opción de exportación válida; las opciones son tokens simples sin espacios ni paréntesis.
nfs-no-root-squash = `{$host}` monta con no_root_squash y conserva los privilegios de root en la exportación.
nfs-sec-sys-only = `{$host}` usa el valor predeterminado sec=sys o solo negocia sec=sys; añade krb5p para protección criptográfica.
nfs-world-export = `{$host}` es accesible en lectura y escritura para todos los clientes.
nfs-subtree-undecided = `{$host}` no indica ni subtree_check ni no_subtree_check; el valor predeterminado cambió en origen, así que indica cuál quieres.
nfs-root-squash-undecided = `{$host}` no indica ni root_squash ni no_root_squash; indica cuál quieres.
nfs-sync-undecided = `{$host}` no indica ni sync ni async; prefiere sync, que confirma las escrituras en almacenamiento estable.

## resolver module — display name, security notes, schema tooltips
resolver-name = resolver
resolver-note-managed-symlink = en este host /etc/resolv.conf lo gestiona un backend de resolución; detent se niega a editar el destino de un enlace simbólico gestionado y configura el backend en su lugar.
resolver-tip-resolv = las directivas de /etc/resolv.conf que modela este módulo; todo lo demás del archivo se conserva intacto.
resolver-tip-resolved = los ajustes de systemd-resolved, en el orden del archivo. Cambiarlos reinicia systemd-resolved.
resolver-tip-unbound = los elementos de unbound.conf que modela este módulo, en el orden del archivo. Cambiarlos reinicia unbound.

## resolver module — validation diagnostics
resolver-no-nameserver = no hay ningún servidor de nombres configurado.
resolver-duplicate-nameserver = `{$ip}` aparece como servidor de nombres más de una vez.
resolver-too-many-nameservers = este archivo lista {$count} servidores de nombres; glibc lee como máximo {$max}.
resolver-invalid-domain = `{$domain}` no es un nombre de dominio válido.
resolver-unknown-option = `{$option}` no es una opción que acepte el analizador de resolv.conf de glibc.
resolver-search-and-domain = `search` y `domain` están presentes a la vez; glibc ignora `domain` cuando `search` está definido.
resolver-no-config = este modelo no configura ningún backend de resolución.
resolver-backend-missing = estos ajustes configuran {$service}, que no se detectó en este host.
resolver-rec-dnssec = DNSSEC está en allow-downgrade; `DNSSEC=yes` valida de forma estricta y se recomienda cuando los datos de origen lo permiten.
resolver-rec-dot = DNSOverTLS es oportunista, lo que degrada a texto plano; `DNSOverTLS=yes` exige TLS en su lugar.
resolver-unknown-hardening = `{$key}` no es una directiva que este módulo modele para unbound.
resolver-unbound-misplaced = `{$key}` pertenece a la sección {$section} de unbound.conf, no aquí.
resolver-invalid-forward-addr = `{$addr}` no es una forward-addr válida con el formato ip[@port][#auth-name].
resolver-invalid-forward-name = `{$name}` no es un nombre de forward-zone válido.
resolver-forward-tls-no-auth = esta zona reenvía por TLS sin un `#auth-name` en su forward-addr, así que la conexión TLS no está autenticada.
resolver-rec-hardening = `{$key}` está desactivado; activarlo refuerza unbound frente a la suplantación ascendente y el abuso de delegaciones.
resolver-forward-zone-unnamed = una forward-zone: sin name: no reenvía nada y debilita la configuración; da un nombre a cada zona.

## samba module — display name, security notes, schema tooltips
samba-name = samba
samba-note-guest-access = el acceso de invitado se concede por recurso compartido al conectar; un valor incorrecto expone archivos sin contraseña.
samba-tip-entries = las entradas de smb.conf que modela este módulo, en el orden del archivo: encabezados `[section]` y directivas por igual.
samba-tip-section = el nombre de sección de un encabezado `[section]`; vacío para una línea de directiva simple.
samba-tip-key = el nombre del parámetro, sin distinguir mayúsculas de minúsculas y posiblemente de varias palabras (`guest ok`).
samba-tip-value = el valor del parámetro, hasta el final de la línea; las macros `%` se conservan literalmente.
samba-rec-value = prefiere un valor reforzado explícito en lugar de depender del valor predeterminado compilado en origen.

## samba module — validation diagnostics
samba-empty-key = una directiva no tiene nombre de parámetro.
samba-empty-section = un encabezado de sección está vacío.
samba-bad-key = `{$key}` se interpretaría como una sección o un comentario, no como una clave de directiva.
samba-bad-value = `{$value}` termina en `\` y absorbería la línea siguiente.
samba-bad-section = `{$section}` contiene `[` o `]` o termina en `\` y no se reescribiría idéntico.
samba-guest-ok = `guest ok` es {$value}; los clientes sin autenticar pueden conectarse a todos los recursos compartidos que lo heredan.
samba-map-to-guest = `map to guest` es {$value}; cualquier valor distinto de Never convierte los inicios de sesión fallidos en sesiones de invitado.
samba-min-protocol = `server min protocol` es {$value}; define al menos SMB3_00 y descarta los niveles de protocolo de la era SMB1.
samba-smb-encrypt = `smb encrypt` es {$value}; define required para que el tráfico SMB no viaje sin cifrar.
samba-restrict-anonymous = `restrict anonymous` es {$value}; 2 oculta la lista de recursos compartidos a los usuarios anónimos.
samba-rec-server-signing = `server signing` es {$value}; define mandatory para que el tráfico SMB esté firmado criptográficamente.
samba-rec-load-printers = `load printers` es {$value}; define no salvo que este host comparta impresoras de verdad.
samba-rec-interfaces = no hay ninguna directiva `interfaces` definida; enlaza samba a direcciones explícitas en lugar de escuchar en todas las interfaces.
samba-writable-exposure = este recurso compartido permite escrituras mediante writeable, read only o write list; confirma que todos los clientes deben tener acceso de escritura.
samba-root-command = `{$key}` ejecuta un comando con privilegios de root en cada conexión que coincide.
samba-client-command = `{$key}` permite que un cliente haga que samba ejecute un comando; el cliente controla lo que recibe el comando.
samba-usershare-guests = `usershare allow guests` es {$value}; los usuarios pueden publicar recursos compartidos que cualquiera abre sin contraseña.
samba-wide-links = `wide links` es {$value}; los enlaces simbólicos pueden sacar a los clientes del recurso compartido.

## module template — copy-me example
TEMPLATE-name = plantilla de módulo
TEMPLATE-note-precedence = este módulo ficticio es un ejemplo comprobado en compilación para los nuevos módulos de configuración.
TEMPLATE-tip-settings = los ajustes que modela este módulo ficticio, en el orden del archivo.
TEMPLATE-tip-key = el nombre de la directiva, una sola palabra, sin espacios.
TEMPLATE-tip-value = el valor de la directiva, hasta el final de la línea.
TEMPLATE-rec-value = prefiere un valor explícito en lugar de depender de un valor predeterminado de origen.
TEMPLATE-invalid-key = `{$key}` no es un nombre de directiva válido.
TEMPLATE-duplicate-key = `{$key}` está definido más de una vez; prevalece el último valor.
TEMPLATE-too-many-settings = este archivo tiene {$count} ajustes; divide las configuraciones grandes en archivos más pequeños.

## detent-core — parse, model, and edit errors
## These are the failures a module's own document model can raise, so they are
## prefixed `core-` rather than with a module id.
core-parse-malformed = este archivo no coincide con el formato que espera `{$module}`: {$reason}
core-model-shape = la configuración suministrada no tiene la forma esperada: {$reason}
core-model-unrepresentable = este archivo contiene algo que el editor no puede representar: {$reason}
core-edit-line-break = un valor no puede contener un salto de línea ni un byte nulo; `{$value}` sí.
core-edit-index-out-of-range = error interno: la línea {$index} está fuera de un archivo de {$len} líneas.
core-edit-unsupported = esta edición no se puede expresar en el formato del archivo: {$reason}

## detent-core — version-gated options
core-version-too-old = `{$option}` necesita {$service} {$since} o posterior; este host tiene {$installed}.
core-version-unknown = la versión instalada de {$service} es desconocida, así que `{$option}` (necesita {$service} {$since} o posterior) puede no funcionar.

## operations layer — errors surfaced by detent-ops
ops-unknown-module = no hay ningún módulo llamado `{$module}` en esta compilación.
ops-invalid-model = la configuración de `{$module}` no es válida: {$reason}
ops-check-failed = el validador externo `{$program}` rechazó al candidato: {$reason}
ops-hash-conflict = `{$path}` cambió en el disco desde que se leyó; vuelve a leerlo e inténtalo de nuevo.
ops-privsep-failed = el ayudante privilegiado rechazó la solicitud o no pudo completarla: {$reason}
ops-service-failed = la acción sobre el servicio no se completó: {$reason}
ops-no-target = `{$module}` no gestiona ningún archivo en este host.
ops-no-service = `{$module}` no controla ningún servicio en este host, así que no se puede reiniciar.
ops-audit-failed = no se pudo leer el registro de auditoría: {$reason}
ops-audit-unavailable = no se pudo escribir el registro de auditoría, así que se rechazó la operación: {$reason}
ops-unsupported = {$what} no está admitido en esta compilación.
ops-commit-pending = ya hay otra ventana commit-confirm pendiente.
ops-update-running = ya hay una actualización en curso; espera a que termine y luego comprueba la versión en ejecución.
ops-update-tag-invalid = eso no es una versión publicada; debe tener el aspecto v1.2.3.
ops-update-not-newer = esa versión no es más reciente que la versión en ejecución; no se inició nada.
ops-no-backup = commit-confirm requiere una copia de seguridad retenida; no se cambió nada.
ops-arm-failed-restored = no se pudo armar commit-confirm, así que se deshizo el cambio; el contenido anterior ha vuelto.
ops-arm-failed-unrestored = no se pudo armar commit-confirm y NO se pudo deshacer el cambio; el contenido nuevo sigue en el disco. Restaura ahora la copia de seguridad anterior.
ops-target-missing = el archivo gestionado no existe; créalo (instala su paquete o créalo a mano) y vuelve a intentarlo.
ops-denied = no tienes permiso para hacer eso.

## detent-web — configuration, TLS, the operations bridge, and the listener
web-config-unreadable = no se pudo leer `{$path}`: {$reason}
web-config-malformed = `{$path}` no es una configuración de detent válida: {$reason}
web-config-zero-value = `{$field}` debe ser mayor que cero.
web-config-weak-argon2 = `auth.argon2.m_kib` es {$m}, por debajo del mínimo de {$min} kib.
web-tls-generate-failed = no se pudo generar el certificado de arranque: {$reason}
web-tls-key-rejected = se rechazaron el certificado y su clave privada: {$reason}
web-tls-store-unreadable = no se pudo leer `{$path}`: {$reason}
web-tls-store-unwritable = no se pudo preparar `{$path}` para escritura: {$reason}
web-tls-store-write-failed = no se pudo escribir `{$path}`: {$reason}
web-tls-acme-pem-rejected = el certificado o la clave emitidos no eran un PEM utilizable.
web-engine-stopped = el motor de operaciones ya no se está ejecutando; vuelve a intentarlo cuando el servicio esté de nuevo.
web-cert-renew-not-acme = la renovación necesita `tls.bootstrap = "acme"` en detent.toml.
web-cert-renew-unavailable = el cliente acme no recibió la solicitud de renovación; inténtalo de nuevo más tarde.
web-update-not-checked = todavía no se ha comprobado si hay actualizaciones en este host; ejecuta `detent update --check` como root.
web-server-bind-failed = no se pudo escuchar en `{$addr}`: {$reason}
web-server-address-unknown = no se pudo volver a leer la dirección de escucha: {$reason}

## detent-web — auth: passwords, sessions, api tokens, totp, csrf
web-auth-entropy-unavailable = el generador de números aleatorios del sistema falló, así que no se pudo emitir ninguna credencial.
web-auth-argon2-params = los parámetros de argon2 configurados no son utilizables: {$reason}
web-auth-hash-failed = no se pudo calcular el hash de la contraseña.
web-auth-password-too-short = una contraseña debe tener al menos 12 caracteres.
web-auth-password-too-long = una contraseña puede tener como máximo 128 caracteres.
web-auth-password-unchanged = la nueva contraseña debe ser distinta de la actual.
web-auth-password-change-required = cambia tu contraseña antes de hacer cualquier otra cosa.
web-auth-user-name-invalid = `{$name}` no es un nombre de usuario utilizable; usa de 1 a 32 caracteres entre `a-z`, `0-9`, `.`, `_` o `-`, empezando por una letra o un dígito.
web-auth-user-exists = ya existe un usuario llamado `{$name}`.
web-auth-user-unknown = no hay ningún usuario llamado `{$name}`.
web-auth-invalid-credentials = el nombre de usuario, la contraseña o el código no eran correctos.
web-auth-rate-limited = demasiados intentos; espera {$seconds} segundos e inténtalo de nuevo.
web-auth-session-limit = hay demasiadas sesiones abiertas; espera a que una caduque e inicia sesión de nuevo.
web-auth-busy = hay demasiados inicios de sesión en curso; espera un momento e inténtalo de nuevo.
web-auth-unauthenticated = inicia sesión para hacer eso.
web-auth-ambiguous-credentials = envía una cookie de sesión o un token bearer, no ambos.
web-auth-csrf-rejected = esta solicitud no superó sus comprobaciones entre sitios.
web-auth-token-unknown = ese token de api no existe, está revocado o ha caducado.
web-auth-token-limit = este host ya tiene el número máximo de tokens de api.
web-auth-totp-secret-invalid = ese secreto del autenticador no es base32 válido.
web-auth-store-unreadable = no se pudo leer `{$path}`: {$reason}
web-auth-store-unwritable = no se pudo preparar `{$path}` para escritura: {$reason}
web-auth-store-write-failed = no se pudo escribir `{$path}`: {$reason}
web-auth-store-malformed = `{$path}` no es un archivo de credenciales de detent válido: {$reason}
web-denied-scope = esta credencial no incluye el ámbito `{$scope}`.

## detent-web — the api surface
web-request-malformed = el cuerpo de la solicitud no tiene la forma que espera este endpoint.
web-request-too-deep = el cuerpo de la solicitud está anidado con demasiada profundidad.
web-api-unexpected-outcome = la operación se completó pero no se pudo mostrar su resultado.
