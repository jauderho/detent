# needs-review: machine-drafted Spanish translation; not yet checked by a native speaker.
## detent web admin UI — es
## Source: locales/en-US/web.ftl. Same ids, same placeables.

## Status bar
status-brand = detent
status-online = sistema en línea
status-clock-label = utc
status-mode-label = modo
theme-toggle-aria = alternar entre modo claro y oscuro
theme-toggle-title = alternar claro / oscuro

## catfu component layer
## Chrome the shared components render themselves. Content strings (field
## captions, table headers, banner copy) are supplied by the calling page.
component-countdown-remaining = tiempo restante
component-field-info = más información
component-modal-close = cerrar
component-switch-off = desactivado
component-switch-on = activado
component-table-empty = sin registros

## API failures
## docs/API.md: every failure is `{ code, message_id }`, and `message_id` is a
## Fluent id. src/api/messages.ts resolves it here; an id this build does not
## know falls back to `api-error-unknown`, so an id is never rendered raw.
##
## The first three are the console's own — a failure that never reached a
## server has no `message_id` to resolve. The rest mirror the ids the server
## sends, argument-free: locales/en-US/core.ftl interpolates `{$path}`,
## `{$reason}` and friends, and the API deliberately sends none of them.
api-error-network = la consola no pudo llegar a este host.
api-error-malformed = este host envió una respuesta que la consola no pudo leer.
api-error-unknown = este host informó de un fallo que la consola no sabe describir.
core-edit-index-out-of-range = error interno: una edición apuntaba a una línea fuera del archivo.
core-edit-line-break = un valor no puede contener un salto de línea ni un byte nulo.
core-edit-unsupported = esta edición no se puede expresar en el formato del archivo.
core-model-shape = la configuración suministrada no tiene la forma esperada.
core-model-unrepresentable = este archivo contiene algo que el editor no puede representar.
core-parse-malformed = este archivo no coincide con el formato que espera su módulo.
ops-audit-failed = no se pudo leer el registro de auditoría.
ops-audit-unavailable = no se pudo escribir el registro de auditoría, así que se rechazó la operación.
ops-denied = no tienes permiso para hacer eso.
ops-hash-conflict = el archivo cambió en el disco desde que se leyó; vuelve a leerlo e inténtalo de nuevo.
ops-check-failed = el validador externo rechazó al candidato.
ops-invalid-model = esa configuración no es válida.
ops-no-service = este módulo no controla ningún servicio en este host, así que no se puede reiniciar.
ops-no-target = este módulo no gestiona ningún archivo en este host.
ops-privsep-failed = el ayudante privilegiado rechazó la solicitud o no pudo completarla.
ops-service-failed = la acción sobre el servicio no se completó.
ops-unknown-module = no hay ningún módulo con ese nombre en esta compilación.
ops-unsupported = eso no está admitido en esta compilación.
ops-commit-pending = ya hay otra ventana commit-confirm pendiente.
ops-update-running = ya hay una actualización en curso; espera a que termine y luego comprueba la versión en ejecución.
ops-update-tag-invalid = eso no es una versión publicada; debe tener el aspecto v1.2.3.
ops-update-not-newer = esa versión no es más reciente que la versión en ejecución; no se inició nada.
ops-no-backup = commit-confirm requiere una copia de seguridad retenida; no se cambió nada.
ops-arm-failed-restored = no se pudo armar commit-confirm, así que se deshizo el cambio; el contenido anterior ha vuelto.
ops-arm-failed-unrestored = no se pudo armar commit-confirm y NO se pudo deshacer el cambio; el contenido nuevo sigue en el disco. Restaura ahora la copia de seguridad anterior.
ops-target-missing = el archivo gestionado no existe; créalo (instala su paquete o créalo a mano) y vuelve a intentarlo.
web-api-unexpected-outcome = la operación se completó pero no se pudo mostrar su resultado.
web-auth-ambiguous-credentials = envía una cookie de sesión o un token bearer, no ambos.
web-auth-argon2-params = los parámetros de argon2 configurados no son utilizables.
web-auth-busy = hay demasiados inicios de sesión en curso; espera un momento e inténtalo de nuevo.
web-auth-csrf-rejected = esta solicitud no superó sus comprobaciones entre sitios; recarga la página e inténtalo de nuevo.
web-auth-entropy-unavailable = el generador de números aleatorios del sistema falló, así que no se pudo emitir ninguna credencial.
web-auth-hash-failed = no se pudo calcular el hash de la contraseña.
web-auth-invalid-credentials = el nombre de usuario, la contraseña o el código no eran correctos.
web-auth-password-change-required = cambia tu contraseña antes de hacer cualquier otra cosa.
web-auth-password-too-long = una contraseña puede tener como máximo 128 caracteres.
web-auth-password-too-short = una contraseña debe tener al menos 12 caracteres.
web-auth-password-unchanged = la nueva contraseña debe ser distinta de la actual.
web-auth-rate-limited = demasiados intentos; espera un momento e inténtalo de nuevo.
web-auth-session-limit = hay demasiadas sesiones abiertas; espera a que una caduque e inicia sesión de nuevo.
web-auth-store-malformed = un archivo de credenciales de este host no es válido.
web-auth-store-unreadable = no se pudo leer un archivo de credenciales de este host.
web-auth-store-unwritable = no se pudo preparar para escritura un archivo de credenciales de este host.
web-auth-store-write-failed = no se pudo escribir un archivo de credenciales de este host.
web-auth-token-limit = este host ya tiene el número máximo de tokens de api.
web-auth-token-unknown = ese token de api no existe, está revocado o ha caducado.
web-auth-totp-secret-invalid = ese secreto del autenticador no es base32 válido.
web-auth-unauthenticated = inicia sesión para hacer eso.
web-auth-user-exists = ya existe un usuario con ese nombre.
web-auth-user-name-invalid = ese nombre de usuario no es utilizable; usa de 1 a 32 caracteres entre `a-z`, `0-9`, `.`, `_` o `-`, empezando por una letra o un dígito.
web-auth-user-unknown = no hay ningún usuario con ese nombre.
web-cert-renew-not-acme = la renovación necesita `tls.bootstrap = "acme"` en detent.toml.
web-cert-renew-unavailable = el cliente acme no recibió la solicitud de renovación; inténtalo de nuevo más tarde.
web-denied-scope = esta credencial no incluye el ámbito que necesita esa acción.
web-engine-stopped = el motor de operaciones ya no se está ejecutando; vuelve a intentarlo cuando el servicio esté de nuevo.
web-update-not-checked = todavía no se ha comprobado si hay actualizaciones en este host; ejecuta `detent update --check` como root.
web-request-malformed = el cuerpo de la solicitud no tiene la forma que espera este endpoint.
web-request-too-deep = el cuerpo de la solicitud está anidado con demasiada profundidad.

## Sign in
login-title = iniciar sesión
login-panel-label = sesión
login-username-label = nombre de usuario
login-password-label = contraseña
login-totp-label = código del autenticador
login-totp-description = seis dígitos del autenticador registrado para esta cuenta.
login-totp-reveal = usar un código del autenticador
login-submit = iniciar sesión
login-submitting = iniciando sesión
login-retry-after = demasiados intentos; espera {$seconds} segundos e inténtalo de nuevo.

## Change password
password-change-title = cambia tu contraseña
password-change-panel-label = contraseña
password-change-intro = esta cuenta debe definir una contraseña nueva antes de poder hacer cualquier otra cosa.
password-change-current-label = contraseña actual
password-change-new-label = contraseña nueva
password-change-new-description = de 12 a 128 caracteres; se permite cualquier carácter.
password-change-confirm-label = confirma la contraseña nueva
password-change-mismatch = las dos contraseñas nuevas no son iguales.
password-change-submit = cambiar contraseña
password-change-submitting = cambiando contraseña

## Session and scope
auth-checking = comprobando esta sesión
auth-sign-out = cerrar sesión
scope-gate-read-only = esta sesión solo tiene acceso de lectura; no puede cambiar nada en este host.
scope-gate-signed-out = inicia sesión para cambiar algo en este host.

## Navigation
nav-label = secciones
nav-dashboard = panel
nav-modules = módulos
nav-services = servicios
nav-backups = copias de seguridad
nav-audit = auditoría
nav-certificates = certificados
nav-settings = ajustes

## Routed pages
## Certificates and settings are still named placeholders: neither has an API
## to drive. Certificates waits on Phase 6 (ACME); settings waits on the user
## and token endpoints.
page-placeholder-body = esta sección aún no está construida.
page-dashboard-title = panel
page-modules-title = módulos
page-module-detail-title = módulo {$module}
page-services-title = servicios
page-backups-title = copias de seguridad
page-audit-title = registro de auditoría
page-certificates-title = certificados
page-settings-title = ajustes
page-not-found-title = página no encontrada
page-not-found-body = esa dirección no corresponde a nada en esta consola.
page-not-found-home = ir al panel

## Pending commit
pending-commit-message = un cambio de configuración está esperando confirmación; se revierte solo cuando esta ventana se cierra.
pending-commit-countdown-label = tiempo restante para confirmar
pending-commit-confirm = confirmar cambio
pending-commit-confirming = confirmando…

## Shared page states
## Every section is a query away from its data, so loading, failure and "this
## host has none of these" are shared rather than re-worded per page.
state-loading = cargando
state-unknown = desconocido
value-no = no
value-yes = sí

## Dashboard
dashboard-host-panel = host
dashboard-host-hostname = nombre de host
dashboard-host-os = sistema operativo
dashboard-host-init = sistema init
dashboard-host-distro = distribución
dashboard-host-ram = memoria
dashboard-host-network-backend = backend de red
dashboard-host-resolver-backend = backend de resolución
dashboard-host-notes = notas de detección
dashboard-cert-panel = certificado
dashboard-cert-fingerprint = huella
dashboard-cert-expires = caduca
dashboard-cert-lifetime-used = vida útil consumida
dashboard-cert-expired = caducado; sustituye este certificado.
dashboard-cert-expiring-soon = caduca en menos de 30 días; planifica la renovación.
dashboard-cert-half = se ha consumido la mitad de la vida útil del certificado; la renovación está programada.
dashboard-cert-quarter = se han consumido tres cuartas partes de la vida útil del certificado; renueva pronto.
cert-renew-panel = renovación
cert-renew-now = renovar ahora
cert-renew-requested = renovación solicitada. El certificado nuevo se instala cuando la AC lo emita.
dashboard-modules-panel = módulos
dashboard-modules-count = {$count ->
    [one] un módulo está compilado en esta compilación.
   *[other] {$count} módulos están compilados en esta compilación.
}
dashboard-audit-panel = actividad reciente
dashboard-view-all = ver todo
dashboard-update-panel = actualización
dashboard-update-current = versión en ejecución
dashboard-update-published = publicada
dashboard-update-up-to-date = no se ofrece ninguna versión más reciente para esta compilación.
dashboard-update-available = la versión {$tag} está disponible para esta compilación.
dashboard-update-security = esta versión está marcada como actualización de seguridad; omite el filtro de antigüedad.
dashboard-update-install = instalar {$tag}
dashboard-update-confirm-title = ¿instalar esta actualización?
dashboard-update-confirm-body = esto empieza a instalar {$tag} en segundo plano. si se instala, el servicio detent se reinicia y la página puede desconectarse y volver a conectarse; si el servicio reiniciado no está sano, la actualización se revierte.
dashboard-update-confirm-action = instalar
dashboard-update-confirm-cancel = cancelar
dashboard-update-started = la actualización a {$version} empezó en segundo plano. el servicio se reinicia si se instala y se revierte si no está sano; la versión en ejecución muestra el resultado.

## Modules
modules-panel-label = módulos instalados
modules-col-module = módulo
modules-col-targets = archivos
modules-col-services = servicios
modules-col-commit-confirm = commit-confirm
modules-commit-confirm-required = obligatorio
modules-commit-confirm-not-required = no obligatorio
modules-empty = esta compilación no tiene ningún módulo compilado.
modules-none = ninguno

## One module
module-about-panel = módulo
module-configuration-panel = configuración
module-upstream-label = sigue el origen
module-targets-label = archivos
module-services-label = servicios
module-current-hash-label = resumen en disco
module-security-notes-label = notas de seguridad
module-model-missing = el archivo de este módulo todavía no existe en este host. el formulario de abajo parte de los valores predeterminados del propio módulo, y aplicarlo crea el archivo.
module-action-validate = validar
module-action-plan = planificar
module-action-apply = aplicar
module-action-discard = descartar ediciones
module-busy = trabajando
module-validate-clean = esta configuración superó todas las comprobaciones que ejecuta este host.
module-plan-title = cambio planificado
module-plan-no-change = esta configuración coincide con lo que ya hay en disco; no hay nada que aplicar.
module-plan-diff-label = diff
module-plan-checks-label = comprobaciones de origen
module-plan-check-passed = superada
module-plan-check-failed = fallida
module-plan-check-exit = salida {$code}
module-plan-services-label = servicios a los que afectaría
module-plan-apply = aplicar este cambio
module-apply-title = ¿aplicar este cambio?
module-apply-body = esto escribe {$path} en este host. primero se hace una copia de seguridad del contenido actual.
module-apply-commit-confirm = este módulo puede dejar fuera a un administrador, así que el cambio arma una ventana commit-confirm: se revierte solo salvo que lo confirmes antes del plazo.
module-apply-service-label = después
module-apply-service-none = dejar el servicio como está
module-apply-cancel = cancelar
module-applied = el cambio se escribió en {$path}.
module-applied-created = {$path} no existía y se creó.
module-mounts-off = las nuevas entradas de fstab no se montaron ([mounts] activate_new_entries está desactivado); surten efecto en el siguiente arranque o montaje.
module-mounts-error = no se inició ninguna unidad de montaje: {$reason}
module-mounts-none = no hay ninguna entrada nueva de fstab que montar.
module-mounts-units = unidades de montaje de las nuevas entradas de fstab:
module-mount-state-mounted = montado
module-mount-state-already-mounted = ya montado
module-mount-state-pending = aún montando
module-mount-state-failed = fallido
module-mount-state-protected = rechazado: ruta protegida
module-mount-state-stopped = desmontado
module-cancel = cancelar

## Services
services-panel-label = servicios
services-col-module = módulo
services-col-unit = unidad
services-col-state = estado
services-col-enabled = al arrancar
services-col-since = desde
services-col-actions = acciones
services-state-active = activo
services-state-inactive = inactivo
services-state-failed = fallido
services-state-activating = arrancando
services-state-deactivating = deteniéndose
services-state-unknown = desconocido
services-action-restart = reiniciar
services-action-reload = recargar
services-action-start = iniciar
services-action-stop = detener
services-acted = {$unit}: {$detail}
services-empty = ningún módulo de esta compilación controla un servicio en este host.
services-confirm-title = ¿{$action} {$unit}?
services-confirm-body = esto actúa de inmediato sobre el servicio en ejecución.
services-confirm-cancel = cancelar

## Backups
backups-col-name = copia de seguridad
backups-col-created = realizada
backups-col-size = tamaño
backups-col-digest = resumen
backups-col-actions = acciones
backups-action-restore = restaurar
backups-confirm-title = ¿restaurar esta copia de seguridad?
backups-confirm-body = esto reemplaza {$target} por la copia retenida. primero se hace una copia de seguridad del contenido actual.
backups-confirm-cancel = cancelar
backups-restored = la copia de seguridad se restauró.
backups-empty = todavía no se ha hecho ninguna copia de seguridad de este módulo.
backups-module-panel = copias de seguridad de {$module}

## Audit log
audit-panel-label = registro de auditoría
audit-col-when = cuándo
audit-col-who = solicitante
audit-col-how = credencial
audit-col-op = operación
audit-col-module = módulo
audit-col-result = resultado
audit-filter-module-label = módulo
audit-filter-who-label = solicitante
audit-filter-limit-label = filas
audit-filter-apply = filtrar
audit-filter-clear = limpiar
audit-empty = todavía no se ha registrado nada en este host.
audit-result-ok = ok
audit-result-denied = denegado
audit-result-error = fallido
audit-identity-local-user = usuario local
audit-identity-session = sesión
audit-identity-token = token de api
audit-op-list-modules = listar módulos
audit-op-get-module = leer módulo
audit-op-validate = validar
audit-op-plan = planificar
audit-op-apply = aplicar
audit-op-confirm-commit = confirmar commit
audit-op-rollback-commit = revertir commit
audit-op-list-backups = listar copias de seguridad
audit-op-restore = restaurar copia de seguridad
audit-op-service-status = leer estado del servicio
audit-op-service-action = actuar sobre el servicio
audit-op-host-profile = leer perfil del host
audit-op-audit-query = leer registro de auditoría
audit-op-cert-status = leer estado del certificado
audit-op-update-status = leer estado de la actualización
audit-op-cert-renew = renovar certificado
audit-op-update-apply = instalar actualización
## Schema-driven module forms
## Chrome the form engine (web/src/forms) renders around a module's schema.
## Field captions come from the schema's own property names, and a field's
## tooltip and recommendation are Fluent ids in the *module's* locale file, not
## here — a missing one degrades to no tooltip and is never rendered raw.
forms-advanced-toggle = avanzado
forms-badge-security-high = alto impacto en la seguridad
forms-badge-deprecated = obsoleto desde {$version}
forms-diagnostic-at-field = {$field}: {$message}
forms-diagnostic-unknown = este host informó de un resultado de comprobación que esta compilación no sabe describir ({$id}).
forms-item-add-caption = añadir
forms-item-move-down-caption = bajar
forms-item-move-up-caption = subir
forms-item-remove-caption = quitar
forms-list-empty = todavía no hay nada aquí.
forms-option-none = ninguno
forms-row-add = añadir una fila a {$field}
forms-row-label = fila {$index}
forms-row-move-down = bajar la fila {$index} de {$field}
forms-row-move-up = subir la fila {$index} de {$field}
forms-row-remove = quitar la fila {$index} de {$field}
forms-tag-add = añadir un elemento a {$field}
forms-tag-item = elemento {$index} de {$field}
forms-tag-move-down = bajar el elemento {$index} de {$field}
forms-tag-move-up = subir el elemento {$index} de {$field}
forms-tag-remove = quitar el elemento {$index} de {$field}
forms-unsupported-note = esta compilación no puede editar este valor. se muestra tal como está almacenado y se deja sin cambios.
forms-version-unsupported = necesita {$service} {$since}, instalado {$installed}

## Form validation
## Mirrors the schema constraints for immediate feedback. The server is the
## authority: a clean pass here is not a promise that apply will succeed.
forms-error-enum = elige uno de los valores listados.
forms-error-format-ip = esta no es una dirección ip válida.
forms-error-integer = usa un número entero.
forms-error-max-length = usa como máximo {$max} caracteres.
forms-error-maximum = usa {$max} o menos.
forms-error-min-length = usa al menos {$min} caracteres.
forms-error-minimum = usa {$min} o más.
forms-error-pattern = este valor no coincide con la forma que acepta este campo.
forms-error-required = este campo es obligatorio.
forms-error-type = este valor no es del tipo de valor que contiene este campo.
