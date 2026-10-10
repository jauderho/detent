# needs-review: machine-drafted Russian translation; not yet checked by a native speaker.
## detent CLI — ru-RU
## Source: locales/en-US/cli.ftl. Same ids, same placeables. Identifiers — module ids,
## paths, unit names, digests, enum wire names such as `restart` or `active` — are
## interpolated verbatim and must not be translated.

## severity words, prefixed to every rendered diagnostic
cli-severity-error = ошибка
cli-severity-warning = предупреждение
cli-severity-recommendation = примечание

## yes/no, used wherever a flag is rendered
cli-yes = да
cli-no = нет

## progress notes, printed on stderr under --verbose
cli-note-settings = локаль {$locale}, корень состояния {$state}, конфигурация {$config}
cli-note-operation = выполняется {$operation} для {$module}

## failures that stop a command before the operations layer sees it
cli-bad-stdin = не удалось прочитать модель из stdin: {$reason}
cli-bad-json = модель в stdin не является допустимым json: {$reason}
cli-bad-hash = `{$value}` не является дайджестом sha-256 из 64 шестнадцатеричных символов.
cli-start-failed = не удалось запустить привилегированный помощник: {$reason}
cli-monitor-stop = привилегированный помощник остановился некорректно: {$reason}
cli-monitor-busy = другой монитор detent уже владеет этим корнем состояния; повторите через веб-интерфейс или запустите `detent serve`.
cli-monitor-lock-unavailable = блокировку состояния в {$path} не удаётся взять, поэтому эта команда ничего не может изменить; запустите её от имени пользователя, который может писать в этот каталог, или передайте --state-root.
cli-commit-recovered = неподтверждённый коммит {$commit} восстановлен; целей возвращено: {$restored}, ошибок: {$failures}.
cli-commit-confirm-needs-serve = этот модуль требует commit-confirm; используйте веб-интерфейс или `detent serve`, чтобы окно подтверждения продолжало действовать.
cli-config-load-failed = не удалось загрузить конфигурацию из {$path}: {$reason}
cli-no-command = команда не указана.

## self-test probe and self-update (PLAN §2.9)
cli-self-test = версия {$version}, возможности {$features}
cli-update-available = доступно обновление: {$tag}, опубликовано {$published}
cli-update-security-available = доступно обновление безопасности: {$tag}, опубликовано {$published}
cli-update-none = обновлений нет (текущая версия {$current})
cli-update-held-young = {$tag} новее, чем {$current}, но младше {$days} дн.; его удерживает возрастной барьер
cli-update-held-rejected = {$tag} новее, чем {$current}, но на этом хосте был откачен; он пропускается
cli-verify-bundle-ok = {$file} подтверждён для {$tag}
cli-update-failed = обновление не удалось: {$reason}
cli-update-installed = {$tag} установлен; заменённый бинарный файл сохранён в {$previous}
cli-update-not-restarted = служба не перезапущена, поэтому новый бинарный файл ещё не работает: {$reason}
cli-update-rolled-back = откат выполнен: {$reason}
cli-update-rollback-failed = обновление не удалось ({$reason}), и откат тоже не удался ({$error}); этому хосту требуется внимание

## config
cli-module-line = {$id}  {$name}
cli-no-model = этот модуль пока не управляет ни одним файлом на этом хосте, поэтому показывать нечего.
cli-valid = эта конфигурация допустима.
cli-plan-no-change = {$module} уже совпадает с содержимым {$path}; ничего не изменится.
cli-plan-service = применение затронет {$unit}.
cli-plan-hash = хеш файла теперь {$hash}; передайте его как --expect-hash, чтобы отклонить конкурирующую правку.
cli-check-ran = вышестоящий валидатор {$program} запущен; пройден: {$passed}. {$detail}
cli-check-skipped = вышестоящий валидатор {$program} не запускался. {$detail}
cli-applied = {$module} записан в {$path}.
cli-applied-hash = хеш был {$prev}, теперь {$new}; резервная копия сохранена: {$backup}
cli-mounts-off = mounts: активация выключена ([mounts] activate_new_entries); новые записи fstab вступят в силу при следующей загрузке или монтировании.
cli-mounts-error = mounts: ни один юнит монтирования не запущен: {$reason}
cli-mounts-none = mounts: нет новых записей fstab для монтирования.
cli-mounts-unit = монтирование {$mountpoint} ({$unit}): {$state}
cli-mounts-unit-detail = монтирование {$mountpoint} ({$unit}): {$state}: {$detail}
cli-commit-armed = коммит {$id} нужно подтвердить в течение {$seconds} с, до {$deadline}, иначе он будет откачен.
cli-commit-confirmed = коммит {$id} подтверждён и откатываться не будет.
cli-commit-rolled-back = коммит {$id} откачен; целей возвращено: {$targets}.

## backups
cli-no-backups = для этого модуля пока не сохранено ни одной резервной копии.
cli-backup-line = {$id}  {$name}  {$bytes} Б  {$digest}
cli-restored = цель {$target} возвращена, её хеш теперь {$hash}.

## services
cli-service-status = {$unit}: {$state}; запускается при загрузке: {$enabled}
cli-serviced = для {$unit} запрошено действие {$action}; работает сейчас: {$active}

## host
cli-host-profile = {$hostname}: {$os}, init {$init}, {$ram} МиБ ОЗУ
cli-host-service-version = установленный {$service} имеет версию {$version}
cli-host-backends = сетевой бэкенд {$network}, бэкенд резолвера {$resolver}, дистрибутив {$distro} {$version}
cli-host-note = примечание обнаружения: {$note}

## audit
cli-no-audit = в журнале аудита нет подходящих записей.
cli-audit-line = {$ts}  {$who}  {$op}  {$module}  {$result}  {$error}
cli-audit-verified = цепочка аудита цела до записи {$sequence}; дайджест головы {$hash}
cli-audit-broken = не удалось проверить цепочку аудита: {$reason}

## --dryrun
cli-dryrun-apply = пробный запуск: вот что было бы записано в {$path} для {$module}.
cli-dryrun-operation = пробный запуск: {$operation} было бы выполнено для {$module}.
cli-dryrun-nothing = пробный запуск: ничего не изменено.
cli-dryrun-serve = пробный запуск: монитор и воркер запустились бы (модулей: {$modules}, целей: {$targets}), корень {$state}.
cli-dryrun-serve-mounts = пробный запуск: после применения mounts раннер запустил бы юниты монтирования новых записей fstab (mounts.activate_new_entries = true).
cli-dryrun-cert-renew = пробный запуск: попросил бы сервер по адресу {$address} (как {$name}) продлить его сертификат сейчас; ничего не отправлено.

## serve
cli-serve-monitor = воркер запущен с pid {$pid}; привилегии сброшены: {$dropped}
cli-serve-worker = воркер работает; его http-сервер появится в фазе 4. handshake: {$greeted}
cli-serve-failed = не удалось запустить монитор и воркер: {$reason}
cli-serve-stopped = пара неожиданно остановилась: {$reason} {$status}
cli-serve-privileged-port = порту {$port} нужен cap_net_bind_service или сокет, переданный монитором, а эта сборка не поддерживает ни то, ни другое; используйте порт 1024 или выше либо поставьте перед сервисом обратный прокси.
cli-serve-privilege-mode = настроенный режим привилегий не соответствует этому процессу, поэтому служба не запущена: {$reason}
cli-serve-acme-unsupported = в этой сборке нет провайдеров dns-01 (возможность acme-dns-providers), поэтому она не может получать сертификаты acme; задайте tls.bootstrap равным "self-signed" в {$path}.
cli-serve-acme-setting-missing = tls.bootstrap равен "acme", но {$setting} не задан в {$path}.
cli-serve-acme-path-outside = {$setting} ({$value}) находится не в корне состояния {$root}: изолированные процессы пишут только туда.
cli-serve-acme-credentials-dir = не удалось подготовить каталог учётных данных acme {$path}: {$reason}
cli-serve-secrets-failed = файл секретов {$path} отклонён: {$reason}
cli-serve-acme-secret-missing = acme.provider задан, но в таблице [acme] файла {$path} нет секрета dns_provider.
cli-serve-acme-provider-invalid = провайдер dns-01 из acme.provider нельзя использовать: {$reason}
cli-serve-acme-providers-not-built = в этой сборке нет провайдеров dns-01 (возможность acme-dns-providers); удалите [acme.provider] из {$path}.
cli-serve-handshake-failed = воркер не смог завершить handshake с монитором.
cli-serve-auth-failed = не удалось открыть хранилище учётных записей, токенов и сеансов: {$reason}
cli-serve-tls-failed = не удалось подготовить tls-сертификат: {$reason}
cli-serve-cert-fingerprint = отпечаток начального tls-сертификата (sha-256): {$fingerprint}
cli-serve-web-failed = веб-сервер не удалось запустить: {$reason}
cli-serve-web-stopped = веб-сервер остановился некорректно: {$reason}
cli-serve-listening = слушает на {$addr}
cli-serve-confinement-degraded = изоляция ослаблена: {$detail}
cli-mcp-missing-token = {$var} не задана; создайте токен командой `detent token create` и экспортируйте его перед запуском mcp-сервера.
cli-mcp-serve-failed = не удалось запустить mcp-сервер: {$reason}
cli-mcp-listening = mcp обслуживает {$transport}
cli-mcp-http-needs-privsep = http-транспорт mcp нельзя запускать от root или с capabilities: сетевой разборщик работал бы с правами, близкими к root; запустите от обычного пользователя без capabilities или используйте транспорт stdio.
cli-mcp-bind-not-loopback = привязка http для mcp должна быть loopback (127.0.0.1 или ::1); bearer передаётся по сети открытым текстом.
cli-dryrun-mcp = пробный запуск: mcp обслуживал бы {$transport} на {$addr} с областью {$scope}.

## setup, user, token
cli-setup-exists = пользователь с именем `{$name}` уже существует на этом хосте; передайте --force, чтобы перезаписать его.
cli-setup-created = учётная запись администратора `{$name}` создана.
cli-user-created = учётная запись `{$name}` создана.
cli-user-passwd = пароль для `{$name}` изменён.
cli-user-removed = учётная запись `{$name}` удалена.
cli-totp-uri = добавьте это в ваше приложение-аутентификатор: {$uri}
cli-totp-secret = или введите в него этот ключ: {$secret}
cli-totp-code-prompt = код из вашего аутентификатора:
cli-totp-code-empty = код не может быть пустым.
cli-totp-code-wrong = этот код недействителен, поэтому второй фактор не включён.
cli-user-totp-enabled = второй фактор для `{$name}` включён.
cli-totp-disable-prompt = выключить второй фактор для `{$name}`? [y/N]
cli-totp-disable-cancelled = второй фактор для `{$name}` оставлен включённым.
cli-user-totp-disabled = второй фактор для `{$name}` выключен.
cli-token-created = токен {$id} ({$label}) создан; повторно он показан не будет: {$token}
cli-token-revoked = токен {$id} отозван.
cli-token-no-tokens = ни одного токена не выдано.
cli-token-line = {$id}  {$label}  {$scopes}  {$created}  {$expires}
cli-credential-failed = не удалось выполнить запрос: {$reason}
cli-audit-failed = изменение выполнено, но запись об этом в журнал аудита не удалось сделать: {$reason}
cli-state-command-as-root = detent {$command} нельзя запускать от root: записанные им файлы принадлежали бы root, и служба не смогла бы их прочитать. Запустите его от учётной записи службы: sudo -u {$account} detent {$command}

## cert status
cli-cert-source = источник: {$source}
cli-cert-fingerprint = отпечаток (sha-256): {$fingerprint}
cli-cert-not-after = истекает: {$not_after}
cli-cert-not-after-unknown = срок действия: неизвестен (сертификат не удалось разобрать).
cli-cert-lifetime = использовано срока действия: {$percent} (предупреждение: {$warning}).
cli-cert-lifetime-no-warning = использовано срока действия: {$percent} (без предупреждения).
cli-cert-lifetime-unknown = использовано срока действия: неизвестно (сертификат не удалось разобрать).
cli-cert-missing = в {$path} нет сохранённого сертификата; запустите сервер один раз, чтобы он его записал.
cli-cert-unreadable = не удалось прочитать сертификат из {$path}: {$reason}

## cert renew
cli-cert-renew-requested = продление запрошено: сервер попросил свой клиент ACME продлить сертификат сейчас. Проверьте результат командой `detent cert status`.
cli-cert-renew-token-refused = токен отклонён (HTTP {$status}); ему нужна область записи: `detent token create <name> --write`.
cli-cert-renew-not-acme = сервер не запускает процесс ACME (`tls.bootstrap` не равен `acme`), поэтому продлевать нечего.
cli-cert-renew-server-error = сервер ответил HTTP {$status}: {$message_id}
cli-cert-renew-server-error-bare = сервер ответил HTTP {$status}.
cli-cert-renew-unreachable = не удалось связаться с сервером по адресу {$address}: {$reason}
cli-cert-renew-no-token = нет API-токена: передайте --token-file <path> или задайте {$var}. Создайте токен с правом записи командой `detent token create <name> --write`.
cli-cert-renew-bad-token = токен из {$source} отклонён: {$reason}
cli-cert-renew-ca-unreadable = не удалось прочитать файл CA {$path}: {$reason}

## password entry (setup, user add, user passwd)
cli-password-prompt = пароль:
cli-password-confirm = подтвердите пароль:
cli-password-mismatch = пароли не совпали.
cli-password-empty = пароль не может быть пустым.

## doctor
cli-status-ok = ок
cli-status-warn = предупр.
cli-status-fail = сбой
cli-doctor-modules = модули, скомпилированные в эту сборку: {$detail}
cli-doctor-state-root = каталог состояния {$detail}
cli-doctor-config = файл конфигурации {$detail}
cli-doctor-privsep = разделение привилегий может создать рабочую пару: {$detail}
cli-doctor-landlock = landlock: {$detail}
cli-doctor-seccomp = seccomp: {$detail}
cli-doctor-confinement = изоляция песочницы: {$detail}
cli-doctor-serve-confinement = изоляция при последнем запуске serve: {$detail}
cli-doctor-mounts = активация монтирования после применения fstab: {$detail}
cli-doctor-privilege-mode = режим привилегий: {$detail}
cli-doctor-service-account = учётная запись службы: {$detail}
cli-doctor-state-owner = владелец каталога состояния: {$detail}
cli-doctor-backups-dir = каталог резервных копий: {$detail}
cli-doctor-polkit-rule = правило polkit: {$detail}
cli-doctor-polkit-daemon = демон polkit: {$detail}
cli-doctor-unit-capabilities = идентичность и capabilities юнита службы: {$detail}
