# needs-review: machine-drafted Russian translation; not yet checked by a native speaker.
## detent web admin UI — ru-RU
## Source: locales/en-US/web.ftl. Same ids, same placeables.

## Status bar
status-brand = detent
status-online = система в сети
status-clock-label = utc
status-mode-label = режим
theme-toggle-aria = переключить светлый и тёмный режим
theme-toggle-title = переключить светлый / тёмный

## catfu component layer
## Chrome the shared components render themselves. Content strings (field
## captions, table headers, banner copy) are supplied by the calling page.
component-countdown-remaining = осталось времени
component-field-info = подробнее
component-modal-close = закрыть
component-switch-off = выкл.
component-switch-on = вкл.
component-table-empty = нет записей

## API failures
## docs/API.md: every failure is `{ code, message_id }`, and `message_id` is a
## Fluent id. src/api/messages.ts resolves it here; an id this build does not
## know falls back to `api-error-unknown`, so an id is never rendered raw.
##
## The first three are the console's own — a failure that never reached a
## server has no `message_id` to resolve. The rest mirror the ids the server
## sends, argument-free: locales/en-US/core.ftl interpolates `{$path}`,
## `{$reason}` and friends, and the API deliberately sends none of them.
api-error-network = консоль не смогла связаться с этим хостом.
api-error-malformed = этот хост прислал ответ, который консоль не смогла прочитать.
api-error-unknown = этот хост сообщил о сбое, для которого у консоли нет описания.
core-edit-index-out-of-range = внутренняя ошибка: правка обратилась к строке вне файла.
core-edit-line-break = значение не может содержать перевод строки или нулевой байт.
core-edit-unsupported = эту правку нельзя выразить в формате файла.
core-model-shape = переданная конфигурация имеет не ту структуру, которая ожидалась.
core-model-unrepresentable = этот файл содержит то, что редактор не может представить.
core-parse-malformed = этот файл не соответствует формату, которого ожидает его модуль.
ops-audit-failed = не удалось прочитать журнал аудита.
ops-audit-unavailable = не удалось записать журнал аудита, поэтому операция отклонена.
ops-denied = у вас нет права на это действие.
ops-hash-conflict = файл изменился на диске после чтения; прочитайте его заново и повторите попытку.
ops-check-failed = внешний валидатор отклонил кандидата.
ops-invalid-model = эта конфигурация недопустима.
ops-no-service = этот модуль не управляет ни одной службой на этом хосте, поэтому её нельзя перезапустить.
ops-no-target = этот модуль не управляет ни одним файлом на этом хосте.
ops-privsep-failed = привилегированный помощник отказал или не смог выполнить запрос.
ops-service-failed = действие над службой не завершилось.
ops-unknown-module = в этой сборке нет модуля с таким именем.
ops-unsupported = это не поддерживается в этой сборке.
ops-commit-pending = другое окно commit-confirm уже ожидает подтверждения.
ops-update-running = обновление уже выполняется; дождитесь его завершения, затем проверьте запущенную версию.
ops-update-tag-invalid = это не версия выпуска; она должна иметь вид v1.2.3.
ops-update-not-newer = этот выпуск не новее запущенной версии; ничего не запущено.
ops-no-backup = commit-confirm требует сохранённой резервной копии; ничего не изменено.
ops-arm-failed-restored = commit-confirm не удалось взвести, поэтому изменение отменено; прежнее содержимое возвращено.
ops-arm-failed-unrestored = commit-confirm не удалось взвести, и изменение НЕ удалось отменить; новое содержимое всё ещё на диске. Немедленно восстановите предыдущую резервную копию.
ops-target-missing = управляемого файла не существует; создайте его (установите его пакет или создайте вручную) и повторите попытку.
web-api-unexpected-outcome = операция выполнена, но её результат не удалось отобразить.
web-auth-ambiguous-credentials = отправьте либо cookie сеанса, либо токен bearer, но не оба сразу.
web-auth-argon2-params = настроенные параметры argon2 непригодны.
web-auth-busy = выполняется слишком много входов; подождите немного и повторите попытку.
web-auth-csrf-rejected = этот запрос не прошёл межсайтовые проверки; перезагрузите страницу и повторите попытку.
web-auth-entropy-unavailable = системный генератор случайных чисел дал сбой, поэтому учётные данные не могли быть выданы.
web-auth-hash-failed = не удалось вычислить хеш пароля.
web-auth-invalid-credentials = имя пользователя, пароль или код были неверны.
web-auth-password-change-required = смените пароль, прежде чем делать что-либо ещё.
web-auth-password-too-long = пароль может содержать не более 128 символов.
web-auth-password-too-short = пароль должен содержать не менее 12 символов.
web-auth-password-unchanged = новый пароль должен отличаться от текущего.
web-auth-rate-limited = слишком много попыток; подождите немного и повторите попытку.
web-auth-session-limit = открыто слишком много сеансов; дождитесь истечения одного из них и войдите снова.
web-auth-store-malformed = один из файлов учётных данных на этом хосте недопустим.
web-auth-store-unreadable = не удалось прочитать один из файлов учётных данных на этом хосте.
web-auth-store-unwritable = не удалось подготовить к записи один из файлов учётных данных на этом хосте.
web-auth-store-write-failed = не удалось записать один из файлов учётных данных на этом хосте.
web-auth-token-limit = на этом хосте уже выдано максимальное число api-токенов.
web-auth-token-unknown = этого api-токена не существует, он отозван или истёк.
web-auth-totp-secret-invalid = этот секрет аутентификатора не является допустимым base32.
web-auth-unauthenticated = войдите, чтобы сделать это.
web-auth-user-exists = пользователь с таким именем уже существует.
web-auth-user-name-invalid = это имя пользователя не подходит; используйте от 1 до 32 символов из `a-z`, `0-9`, `.`, `_` или `-`, начиная с буквы или цифры.
web-auth-user-unknown = пользователя с таким именем нет.
web-cert-renew-not-acme = для продления нужно `tls.bootstrap = "acme"` в detent.toml.
web-cert-renew-unavailable = клиент acme не получил запрос на продление; повторите попытку позже.
web-denied-scope = у этих учётных данных нет области действия, которая нужна для этого действия.
web-engine-stopped = механизм операций больше не работает; повторите попытку, когда служба вернётся.
web-update-not-checked = на этом хосте проверка обновлений ещё не выполнялась; запустите `detent update --check` от имени root.
web-request-malformed = тело запроса не имеет структуры, которой ожидает эта конечная точка.
web-request-too-deep = тело запроса слишком глубоко вложено.

## Sign in
login-title = вход
login-panel-label = сеанс
login-username-label = имя пользователя
login-password-label = пароль
login-totp-label = код аутентификатора
login-totp-description = шесть цифр из аутентификатора, привязанного к этой учётной записи.
login-totp-reveal = использовать код аутентификатора
login-submit = войти
login-submitting = выполняется вход
login-retry-after = слишком много попыток; подождите {$seconds} с и повторите попытку.

## Change password
password-change-title = смена пароля
password-change-panel-label = пароль
password-change-intro = этой учётной записи нужно задать новый пароль, прежде чем она сможет делать что-либо ещё.
password-change-current-label = текущий пароль
password-change-new-label = новый пароль
password-change-new-description = от 12 до 128 символов; допускаются любые символы.
password-change-confirm-label = подтвердите новый пароль
password-change-mismatch = два новых пароля не совпадают.
password-change-submit = сменить пароль
password-change-submitting = пароль меняется

## Session and scope
auth-checking = проверка этого сеанса
auth-sign-out = выйти
scope-gate-read-only = у этого сеанса только доступ на чтение; он не может ничего менять на этом хосте.
scope-gate-signed-out = войдите, чтобы что-либо менять на этом хосте.

## Navigation
nav-label = разделы
nav-dashboard = панель
nav-modules = модули
nav-services = службы
nav-backups = резервные копии
nav-audit = аудит
nav-certificates = сертификаты
nav-settings = настройки

## Routed pages
## Certificates and settings are still named placeholders: neither has an API
## to drive. Certificates waits on Phase 6 (ACME); settings waits on the user
## and token endpoints.
page-placeholder-body = этот раздел ещё не готов.
page-dashboard-title = панель
page-modules-title = модули
page-module-detail-title = модуль {$module}
page-services-title = службы
page-backups-title = резервные копии
page-audit-title = журнал аудита
page-certificates-title = сертификаты
page-settings-title = настройки
page-not-found-title = нет такой страницы
page-not-found-body = этот адрес ничему не соответствует в этой консоли.
page-not-found-home = перейти на панель

## Pending commit
pending-commit-message = изменение конфигурации ожидает подтверждения; когда это окно закроется, оно откатится само.
pending-commit-countdown-label = осталось времени на подтверждение
pending-commit-confirm = подтвердить изменение
pending-commit-confirming = подтверждение…

## Shared page states
## Every section is a query away from its data, so loading, failure and "this
## host has none of these" are shared rather than re-worded per page.
state-loading = загрузка
state-unknown = неизвестно
value-no = нет
value-yes = да

## Dashboard
dashboard-host-panel = хост
dashboard-host-hostname = имя хоста
dashboard-host-os = операционная система
dashboard-host-init = система инициализации
dashboard-host-distro = дистрибутив
dashboard-host-ram = память
dashboard-host-network-backend = сетевой бэкенд
dashboard-host-resolver-backend = бэкенд резолвера
dashboard-host-notes = примечания обнаружения
dashboard-cert-panel = сертификат
dashboard-cert-fingerprint = отпечаток
dashboard-cert-expires = истекает
dashboard-cert-lifetime-used = использовано срока действия
dashboard-cert-expired = срок действия истёк; замените этот сертификат.
dashboard-cert-expiring-soon = истекает в течение 30 дней; запланируйте продление.
dashboard-cert-half = использована половина срока действия сертификата; продление запланировано.
dashboard-cert-quarter = использовано три четверти срока действия сертификата; продлите его в ближайшее время.
cert-renew-panel = продление
cert-renew-now = продлить сейчас
cert-renew-requested = продление запрошено. Новый сертификат будет установлен, когда CA его выдаст.
dashboard-modules-panel = модули
dashboard-modules-count = {$count ->
    [one] в эту сборку скомпилирован {$count} модуль.
    [few] в эту сборку скомпилировано {$count} модуля.
    [many] в эту сборку скомпилировано {$count} модулей.
   *[other] в эту сборку скомпилировано {$count} модуля.
}
dashboard-audit-panel = недавняя активность
dashboard-view-all = показать все
dashboard-update-panel = обновление
dashboard-update-current = запущенная версия
dashboard-update-published = опубликовано
dashboard-update-up-to-date = для этой сборки нет более нового выпуска.
dashboard-update-available = для этой сборки доступен выпуск {$tag}.
dashboard-update-security = этот выпуск помечен как обновление безопасности; возрастной барьер он обходит.
dashboard-update-install = установить {$tag}
dashboard-update-confirm-title = установить это обновление?
dashboard-update-confirm-body = это запускает установку {$tag} в фоне. если установка пройдёт, служба detent перезапустится, а страница может отключиться и подключиться снова; если перезапущенная служба окажется неработоспособной, обновление откатится.
dashboard-update-confirm-action = установить
dashboard-update-confirm-cancel = отмена
dashboard-update-started = обновление до {$version} запущено в фоне. служба перезапустится, если оно установится, и откатится, если окажется неработоспособной; результат покажет запущенная версия.

## Modules
modules-panel-label = установленные модули
modules-col-module = модуль
modules-col-targets = файлы
modules-col-services = службы
modules-col-commit-confirm = commit-confirm
modules-commit-confirm-required = требуется
modules-commit-confirm-not-required = не требуется
modules-empty = в эту сборку не скомпилировано ни одного модуля.
modules-none = нет

## One module
module-about-panel = модуль
module-configuration-panel = конфигурация
module-upstream-label = следует за upstream
module-targets-label = файлы
module-services-label = службы
module-current-hash-label = дайджест на диске
module-security-notes-label = примечания по безопасности
module-model-missing = файла этого модуля на этом хосте ещё нет. форма ниже начинается со значений по умолчанию самого модуля, а её применение создаёт файл.
module-action-validate = проверить
module-action-plan = спланировать
module-action-apply = применить
module-action-discard = отменить правки
module-busy = выполняется
module-validate-clean = эта конфигурация прошла все проверки, которые выполняет этот хост.
module-plan-title = запланированное изменение
module-plan-no-change = эта конфигурация совпадает с тем, что уже на диске; применять нечего.
module-plan-diff-label = diff
module-plan-checks-label = вышестоящие проверки
module-plan-check-passed = пройдена
module-plan-check-failed = не пройдена
module-plan-check-exit = код выхода {$code}
module-plan-services-label = службы, которые это затронет
module-plan-apply = применить это изменение
module-apply-title = применить это изменение?
module-apply-body = это записывает {$path} на этом хосте. сначала текущее содержимое сохраняется в резервной копии.
module-apply-commit-confirm = этот модуль может закрыть доступ администратору, поэтому изменение взводит окно commit-confirm: оно откатится само, если вы не подтвердите его до крайнего срока.
module-apply-service-label = после этого
module-apply-service-none = не трогать службу
module-apply-cancel = отмена
module-applied = изменение записано в {$path}.
module-applied-created = {$path} не существовал и был создан.
module-mounts-off = новые записи fstab не смонтированы ([mounts] activate_new_entries выключено); они вступят в силу при следующей загрузке или монтировании.
module-mounts-error = ни один юнит монтирования не запущен: {$reason}
module-mounts-none = нет новых записей fstab для монтирования.
module-mounts-units = юниты монтирования новых записей fstab:
module-mount-state-mounted = смонтировано
module-mount-state-already-mounted = уже смонтировано
module-mount-state-pending = ещё монтируется
module-mount-state-failed = сбой
module-mount-state-protected = отказано: защищённый путь
module-mount-state-stopped = размонтировано
module-cancel = отмена

## Services
services-panel-label = службы
services-col-module = модуль
services-col-unit = юнит
services-col-state = состояние
services-col-enabled = при загрузке
services-col-since = с
services-col-actions = действия
services-state-active = активна
services-state-inactive = неактивна
services-state-failed = сбой
services-state-activating = запускается
services-state-deactivating = останавливается
services-state-unknown = неизвестно
services-action-restart = перезапустить
services-action-reload = перечитать
services-action-start = запустить
services-action-stop = остановить
services-acted = {$unit}: {$detail}
services-empty = ни один модуль этой сборки не управляет службой на этом хосте.
services-confirm-title = {$action} {$unit}?
services-confirm-body = это сразу действует на работающую службу.
services-confirm-cancel = отмена

## Backups
backups-col-name = копия
backups-col-created = создана
backups-col-size = размер
backups-col-digest = дайджест
backups-col-actions = действия
backups-action-restore = восстановить
backups-confirm-title = восстановить эту резервную копию?
backups-confirm-body = это заменяет {$target} сохранённой копией. сначала текущее содержимое сохраняется в резервной копии.
backups-confirm-cancel = отмена
backups-restored = резервная копия восстановлена.
backups-empty = для этого модуля пока ничего не сохранено в резервных копиях.
backups-module-panel = резервные копии {$module}

## Audit log
audit-panel-label = журнал аудита
audit-col-when = когда
audit-col-who = вызывающий
audit-col-how = учётные данные
audit-col-op = операция
audit-col-module = модуль
audit-col-result = результат
audit-filter-module-label = модуль
audit-filter-who-label = вызывающий
audit-filter-limit-label = строк
audit-filter-apply = фильтр
audit-filter-clear = сбросить
audit-empty = на этом хосте пока ничего не записано.
audit-result-ok = ок
audit-result-denied = отказано
audit-result-error = сбой
audit-identity-local-user = локальный пользователь
audit-identity-session = сеанс
audit-identity-token = api-токен
audit-op-list-modules = список модулей
audit-op-get-module = чтение модуля
audit-op-validate = проверка
audit-op-plan = планирование
audit-op-apply = применение
audit-op-confirm-commit = подтверждение коммита
audit-op-rollback-commit = откат коммита
audit-op-list-backups = список резервных копий
audit-op-restore = восстановление копии
audit-op-service-status = чтение состояния службы
audit-op-service-action = действие над службой
audit-op-host-profile = чтение профиля хоста
audit-op-audit-query = чтение журнала аудита
audit-op-cert-status = чтение состояния сертификата
audit-op-update-status = чтение состояния обновления
audit-op-cert-renew = продление сертификата
audit-op-update-apply = установка обновления
## Schema-driven module forms
## Chrome the form engine (web/src/forms) renders around a module's schema.
## Field captions come from the schema's own property names, and a field's
## tooltip and recommendation are Fluent ids in the *module's* locale file, not
## here — a missing one degrades to no tooltip and is never rendered raw.
forms-advanced-toggle = дополнительно
forms-badge-security-high = высокое влияние на безопасность
forms-badge-deprecated = устарело в {$version}
forms-diagnostic-at-field = {$field}: {$message}
forms-diagnostic-unknown = этот хост сообщил результат проверки, для которого у этой сборки нет описания ({$id}).
forms-item-add-caption = доб.
forms-item-move-down-caption = вниз
forms-item-move-up-caption = вверх
forms-item-remove-caption = удал.
forms-list-empty = здесь пока ничего нет.
forms-option-none = нет
forms-row-add = добавить строку в {$field}
forms-row-label = строка {$index}
forms-row-move-down = переместить строку {$index} поля {$field} вниз
forms-row-move-up = переместить строку {$index} поля {$field} вверх
forms-row-remove = удалить строку {$index} поля {$field}
forms-tag-add = добавить элемент в {$field}
forms-tag-item = элемент {$index} поля {$field}
forms-tag-move-down = переместить элемент {$index} поля {$field} вниз
forms-tag-move-up = переместить элемент {$index} поля {$field} вверх
forms-tag-remove = удалить элемент {$index} поля {$field}
forms-unsupported-note = эта сборка не может редактировать это значение. оно показано как сохранено и остаётся без изменений.
forms-version-unsupported = требуется {$service} {$since}, установлен {$installed}

## Form validation
## Mirrors the schema constraints for immediate feedback. The server is the
## authority: a clean pass here is not a promise that apply will succeed.
forms-error-enum = выберите одно из перечисленных значений.
forms-error-format-ip = это не допустимый ip-адрес.
forms-error-integer = используйте целое число.
forms-error-max-length = используйте не более {$max} символов.
forms-error-maximum = используйте {$max} или меньше.
forms-error-min-length = используйте не менее {$min} символов.
forms-error-minimum = используйте {$min} или больше.
forms-error-pattern = это значение не соответствует форме, которую принимает это поле.
forms-error-required = это поле обязательно.
forms-error-type = это значение не того вида, который хранит это поле.
