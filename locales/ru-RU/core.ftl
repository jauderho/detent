# needs-review: machine-drafted Russian translation; not yet checked by a native speaker.
## detent-core — ru-RU
## Source: locales/en-US/core.ftl. Same ids, same placeables.

## chrony module — display name, security notes, schema tooltips
chrony-name = chrony
chrony-note-precedence = этот файл переопределяет значения по умолчанию, зашитые при сборке; неверное значение незаметно меняет способ, которым хост отсчитывает время.
chrony-tip-settings = директивы chrony.conf, которые моделирует этот модуль, в порядке следования в файле; всё остальное в файле сохраняется без изменений.
chrony-tip-key = имя директивы, одно слово, без учёта регистра.
chrony-tip-value = значение этой директивы до конца строки; пусто для директив без значения, например `rtcsync`.
chrony-rec-value = лучше задать явное значение, чем полагаться на значение по умолчанию, зашитое при сборке.

## chrony module — validation diagnostics
chrony-privileged-directive = `{$key}` задаёт файл, который chronyd записывает от имени root, или пользователя, от имени которого он работает. Проверьте значение перед применением.
chrony-invalid-key = `{$key}` не является допустимым именем директивы chrony.
chrony-duplicate-key = `{$key}` задан более одного раза; действует последнее значение.
chrony-too-many-settings = настроек в этом файле: {$count}; разделите его на drop-in файлы в /etc/chrony/conf.d.
chrony-allow-open = `allow {$value}` раздаёт время всему интернету; разрешайте только те сети, которым оно нужно.
chrony-missing-makestep = makestep не задан; при запуске часы могут разойтись без ограничений, вместо того чтобы быть переведены скачком в допустимый диапазон.
chrony-missing-rtcsync = rtcsync не задан; аппаратные часы будут расходиться с системными.
chrony-rec-nts = пул {$pool} используется без параметра nts; предпочитайте источники с поддержкой nts, чтобы время нельзя было подделать.
chrony-cmdport-open = cmdport равен {$port}; задайте cmdport 0, если только chronyc не должен подключаться к этому хосту по сети.
chrony-external-directive = `{$key}` загружает внешние файлы или запускает внешнюю программу; этот модуль отклоняет директивы, выходящие за настроенную границу файлов.

## dhcp module — display name, security notes, schema tooltips
dhcp-name = dhcp
dhcp-note-commit-confirm = неверное изменение DHCP отключает от сети всех клиентов и вас в том числе; внимательно проверьте diff перед подтверждением.
dhcp-tip-dnsmasq = настройки `key=value` из /etc/dnsmasq.conf в порядке следования в файле; комментарии и неизвестные строки сохраняются без изменений.
dhcp-tip-kea-v4 = управляемое подмножество сервера Kea DHCPv4 (`Dhcp4`); неизвестные параметры Kea сохраняются без изменений.
dhcp-tip-kea-v6 = управляемое подмножество сервера Kea DHCPv6 (`Dhcp6`); неизвестные параметры Kea сохраняются без изменений.
dhcp-tip-key = имя параметра dnsmasq, одно слово, без пробельных символов.
dhcp-tip-value = значение после `=`; у простого флага, такого как `domain-needed`, значения нет.
dhcp-tip-interfaces = интерфейсы, на которых слушает сервер Kea; пустой список означает, что сервер отвечает на всех интерфейсах.
dhcp-tip-valid-lifetime = срок аренды по умолчанию в секундах; 3600 — разумное значение для большинства сетей.
dhcp-tip-subnets = подсети, из которых сервер выдаёт адреса.
dhcp-tip-id = постоянный идентификатор подсети в Kea; не меняйте его при правках, аренды привязаны к нему.
dhcp-tip-subnet = префикс подсети в формате CIDR, например `192.168.1.0/24`.
dhcp-tip-pools = динамические пулы адресов подсети.
dhcp-tip-routers = параметр маршрутизаторов (шлюз по умолчанию), передаваемый клиентам.
dhcp-tip-domain-servers = DNS-серверы (`domain-name-servers`), передаваемые клиентам.
dhcp-tip-pool = пул в виде диапазона `192.168.1.100 - 192.168.1.200` или префикса `192.168.1.0/24`.

## dhcp module — validation diagnostics
dhcp-empty-key = у одной из настроек dnsmasq пустое имя параметра.
dhcp-invalid-key = `{$key}` не является допустимым именем параметра dnsmasq; это должно быть одно слово без пробельных символов, `=` и `#`.
dhcp-malformed-cidr = `{$value}` не является допустимым префиксом CIDR, например `192.168.1.0/24`.
dhcp-malformed-pool = `{$value}` не является допустимым пулом; используйте диапазон вида `192.168.1.100 - 192.168.1.200` или префикс CIDR.
dhcp-external-directive = `{$key}` загружает внешние файлы или запускает команды; этот модуль не создаёт и не изменяет директивы, выходящие за настроенную границу файлов.
dhcp-authoritative-set = `dhcp-authoritative` делает dnsmasq единственным DHCP-сервером в сегменте; задавайте его, только если другого DHCP-сервера нет.
dhcp-kea-interfaces-empty = для {$server} не настроено ни одного интерфейса, и он будет слушать на всех интерфейсах; укажите интерфейсы явно.
dhcp-rec-rebind = domain-needed и bogus-priv заданы не оба; они отсекают атаки rebind и вышестоящие A-запросы для частных адресов.
dhcp-rec-lifetime = у {$server} valid-lifetime равен {$lifetime}; держите его в пределах от 300 до 86400 секунд, чтобы аренды обновлялись предсказуемо.

## hosts module — display name, security notes, schema tooltips
hosts-name = hosts
hosts-note-spoofing = записи здесь переопределяют dns; неверная или вредоносная запись незаметно перенаправляет запросы.
hosts-tip-entries = соответствия адресов именам в /etc/hosts в порядке следования в файле.
hosts-tip-ip = адрес, в который разрешаются приведённые ниже имена.
hosts-tip-hostnames = имена, разрешающиеся в этот адрес; каноническое имя первое.
hosts-tip-comment = встроенный комментарий к этой записи, если он есть.

## hosts module — validation diagnostics
hosts-invalid-hostname = `{$name}` не является допустимым именем хоста.
hosts-duplicate-canonical = `{$name}` является каноническим именем более чем одной записи.
hosts-no-hostnames = в этой записи нет имён хостов.
hosts-hostname-is-ip = `{$name}` — это адрес, а не имя хоста.
hosts-ipv6-zone-unsupported = `{$name}` содержит идентификатор зоны ipv6, который /etc/hosts не поддерживает.
hosts-hostname-multiple-ips = `{$name}` разрешается более чем в один адрес одного семейства.
hosts-localhost-not-loopback = `localhost` указывает на `{$ip}`, а это не адрес loopback.
hosts-missing-localhost = записи `localhost` нет.
hosts-missing-ipv6-localhost = записи ipv6 `localhost` нет.
hosts-too-many-entries = записей в этом файле: {$count}; подумайте об использовании dns.

## mounts module — display name, security notes, schema tooltips
mounts-name = mounts
mounts-note-boot = неверный /etc/fstab может оставить хост незагружаемым после следующей перезагрузки; каждое изменение требует второго подтверждения. Подтверждение не может выявить неверную запись, потому что до следующей загрузки файл никто не читает.
mounts-tip-entries = записи монтирования в /etc/fstab в порядке следования в файле.
mounts-tip-spec = что монтируется: устройство, `UUID=...`/`LABEL=...`, экспорт nfs или `none` для swap.
mounts-tip-mountpoint = куда монтируется файловая система, либо `none`/`swap` для swap.
mounts-tip-fstype = тип файловой системы, например ext4, либо `swap`.
mounts-tip-options = параметры монтирования через запятую, например defaults,nosuid.
mounts-tip-dump = частота резервного копирования dump(8); почти всегда 0.
mounts-tip-pass = номер прохода fsck: 1 для корневой, 2 для остальных проверяемых файловых систем, 0 — пропустить.
mounts-rec-options = защитите данные, доступные пользователям для записи, параметрами nosuid, nodev и noexec; для сетевых файловых систем предпочитайте x-systemd.automount.

## mounts module — validation diagnostics
mounts-empty-spec = у записи {$index} пустая spec (первый столбец).
mounts-empty-mountpoint = у записи {$index} пустая точка монтирования (второй столбец).
mounts-invalid-fstype = `{$fstype}` не является допустимым типом файловой системы.
mounts-pass-too-high = у записи {$index} pass равен `{$pass}`; fsck выполняет не более 2 проходов.
mounts-root-pass = у корневой файловой системы pass должен быть 1, а не `{$pass}`.
mounts-missing-nofail = `{$mountpoint}` — съёмный носитель без `nofail`; загрузка зависает, когда он отключён.
mounts-missing-boot-escape = у `{$mountpoint}` нет ни nofail, ни noauto; сбой монтирования может задержать загрузку.
mounts-critical-noauto = `{$mountpoint}` необходим для загрузки, но у него есть noauto, поэтому система может продолжить работу без него.
mounts-missing-guards = `{$mountpoint}` монтирует данные, доступные пользователям для записи, без `{$missing}`; добавьте их.
mounts-network-automount = `{$mountpoint}` — сетевая файловая система без `x-systemd.automount`; загрузка ждёт сеть.
mounts-noauto-without-user = `noauto` без `user`: смонтировать её может только root, что лишает смысла.
mounts-relative-mountpoint = запись {$index} монтируется в `{$mountpoint}`, а это не абсолютный путь.
mounts-no-root-entry = ни одна запись не монтирует `/`; убедитесь, что корневая файловая система монтируется другим способом.

## network module — display name, security notes, schema tooltips
network-name = network
network-note-precedence = неверная сетевая конфигурация может отрезать администратора от этого хоста; каждое изменение требует второго подтверждения.
network-tip-interfaces = интерфейсы, которые настраивает этот хост, в порядке следования в файле.
network-tip-iface-name = имя интерфейса, например eth0.
network-tip-iface-dhcp-v4 = получает ли этот интерфейс адрес IPv4 по DHCP.
network-tip-iface-dhcp-v6 = получает ли этот интерфейс адрес IPv6 по DHCP.
network-tip-iface-addresses = статические адреса в нотации CIDR, например 192.168.1.10/24.
network-tip-iface-gateway-v4 = шлюз по умолчанию для IPv4 при статической адресации.
network-tip-iface-gateway-v6 = шлюз по умолчанию для IPv6 при статической адресации.
network-tip-iface-dns = DNS-серверы для этого интерфейса.
network-tip-iface-routes = статические маршруты для этого интерфейса.
network-tip-iface-vlan = настройки VLAN для этого интерфейса, если он является VLAN.
network-tip-iface-bridge = настройки моста для этого интерфейса, если он является мостом.
network-tip-route-to = целевой CIDR или default.
network-tip-route-via = IP следующего перехода.
network-tip-vlan-link = родительский интерфейс этой VLAN, например eth0.
network-tip-vlan-id = идентификатор VLAN, 1–4094.
network-tip-bridge-members = имена интерфейсов — участников этого моста.

## network module — validation diagnostics
network-invalid-cidr = `{$value}` не является допустимым адресом CIDR.
network-invalid-ip = `{$value}` не является допустимым IP-адресом.
network-gateway-outside-subnet = шлюз `{$gateway}` находится вне подсетей этого интерфейса.
network-vlan-range = идентификатор VLAN `{$id}` вне диапазона 1–4094.
network-duplicate-interface = интерфейс `{$name}` встречается более одного раза.
network-interface-order = интерфейс `{$name}` должен стоять раньше интерфейсов выше него: перечисляйте интерфейсы в порядке имён.
network-injection = `{$value}` содержит перевод строки или нулевой байт.
network-static-no-gateway = у этого интерфейса со статической адресацией нет шлюза.
network-static-no-dns = у этого интерфейса со статической адресацией нет DNS-серверов.
network-dhcp-static-mixed = у этого интерфейса есть и DHCP-адреса, и статические.
network-rec-ipv6-privacy = включите расширения приватности IPv6, когда включён DHCPv6.
network-rec-ra-accept = принимайте объявления маршрутизатора, только если DHCPv6 управляется явно.
network-rec-no-promisc = этот интерфейс не должен работать в неразборчивом режиме.

## nfs module — display name, security notes, schema tooltips
nfs-name = nfs
nfs-note-live-state = экспорты применяются ядром при каждом монтировании; неверная строка незаметно меняет то, какие хосты могут читать какие файловые системы.
nfs-tip-entries = экспорты из /etc/exports в порядке следования в файле.
nfs-tip-path = точка экспорта: абсолютный путь к каталогу на этом хосте.
nfs-tip-clients = хосты, которым разрешено монтировать этот экспорт, в порядке сопоставления; побеждает первая подходящая спецификация.
nfs-tip-host = спецификация клиента: имя, адрес, адрес/маска сети, шаблон, `*` (все клиенты) или @netgroup.
nfs-tip-options = параметры экспорта для этого клиента через запятую; пустой список означает значения по умолчанию из файла.
nfs-rec-options = задавайте rw/ro, sync/async, root_squash и обработку поддеревьев явно; значения по умолчанию меняются между выпусками nfs-utils.

## nfs module — validation diagnostics
nfs-empty-path = точка экспорта пуста.
nfs-relative-path = `{$path}` не абсолютный путь; точка экспорта должна начинаться с `/`.
nfs-empty-host = у клиента `{$path}` нет спецификации хоста.
nfs-bad-host = `{$host}` не является допустимой спецификацией клиента; она начинается с `-` или содержит синтаксис, который обрезал бы строку.
nfs-bad-path = `{$path}` содержит синтаксис, который обрезал бы строку экспорта.
nfs-bad-continuation = `{$path}` заканчивался бы обратной косой чертой продолжения и склеил бы следующую строку.
nfs-invalid-option = `{$option}` не является допустимым параметром экспорта; параметры — это простые токены без пробельных символов и скобок.
nfs-no-root-squash = `{$host}` монтирует с no_root_squash и сохраняет права root на экспорте.
nfs-sec-sys-only = `{$host}` использует sec=sys по умолчанию или согласовывает только sec=sys; добавьте krb5p для криптографической защиты.
nfs-world-export = `{$host}` доступен для чтения и записи каждому клиенту.
nfs-subtree-undecided = `{$host}` не задаёт ни subtree_check, ни no_subtree_check; значение по умолчанию изменилось в upstream, поэтому укажите, какое вам нужно.
nfs-root-squash-undecided = `{$host}` не задаёт ни root_squash, ни no_root_squash; укажите, какое вам нужно.
nfs-sync-undecided = `{$host}` не задаёт ни sync, ни async; предпочитайте sync, который фиксирует записи в стабильном хранилище.

## resolver module — display name, security notes, schema tooltips
resolver-name = resolver
resolver-note-managed-symlink = на этом хосте /etc/resolv.conf управляется бэкендом резолвера; detent отказывается править цель управляемой символической ссылки и настраивает бэкенд.
resolver-tip-resolv = директивы /etc/resolv.conf, которые моделирует этот модуль; всё остальное в файле сохраняется без изменений.
resolver-tip-resolved = настройки systemd-resolved в порядке следования в файле. Их изменение перезапускает systemd-resolved.
resolver-tip-unbound = элементы unbound.conf, которые моделирует этот модуль, в порядке следования в файле. Их изменение перезапускает unbound.

## resolver module — validation diagnostics
resolver-no-nameserver = не настроено ни одного nameserver.
resolver-duplicate-nameserver = `{$ip}` указан как nameserver более одного раза.
resolver-too-many-nameservers = nameserver в этом файле: {$count}; glibc читает не более {$max}.
resolver-invalid-domain = `{$domain}` не является допустимым доменным именем.
resolver-unknown-option = `{$option}` не является параметром, который принимает разборщик resolv.conf в glibc.
resolver-search-and-domain = присутствуют и `search`, и `domain`; glibc игнорирует `domain`, когда задан `search`.
resolver-no-config = эта модель не настраивает ни одного бэкенда резолвера.
resolver-backend-missing = эти настройки относятся к {$service}, который не обнаружен на этом хосте.
resolver-rec-dnssec = для DNSSEC задано allow-downgrade; `DNSSEC=yes` проверяет строго и рекомендуется, когда вышестоящие данные это позволяют.
resolver-rec-dot = DNSOverTLS оппортунистический, то есть откатывается к открытому тексту; `DNSOverTLS=yes` требует TLS.
resolver-unknown-hardening = `{$key}` не является директивой, которую этот модуль моделирует для unbound.
resolver-unbound-misplaced = `{$key}` относится к разделу {$section} файла unbound.conf, а не сюда.
resolver-invalid-forward-addr = `{$addr}` не является допустимым forward-addr вида ip[@порт][#auth-name].
resolver-invalid-forward-name = `{$name}` не является допустимым именем forward-zone.
resolver-forward-tls-no-auth = эта зона пересылает запросы по TLS без `#auth-name` в forward-addr, поэтому TLS-соединение не аутентифицируется.
resolver-rec-hardening = `{$key}` отключён; его включение защищает unbound от подмены вышестоящих данных и злоупотребления делегированием.
resolver-forward-zone-unnamed = forward-zone: без name: ничего не пересылает и ослабляет конфигурацию; задайте имя каждой зоне.

## samba module — display name, security notes, schema tooltips
samba-name = samba
samba-note-guest-access = гостевой доступ предоставляется для каждого ресурса в момент подключения; неверное значение открывает файлы без пароля.
samba-tip-entries = записи smb.conf, которые моделирует этот модуль, в порядке следования в файле: заголовки `[section]` и директивы.
samba-tip-section = имя раздела для заголовка `[section]`; пусто для обычной строки директивы.
samba-tip-key = имя параметра, без учёта регистра, возможно из нескольких слов (`guest ok`).
samba-tip-value = значение параметра до конца строки; макросы `%` сохраняются дословно.
samba-rec-value = лучше задать явное усиленное значение, чем полагаться на значение по умолчанию, зашитое в upstream.

## samba module — validation diagnostics
samba-empty-key = у директивы нет имени параметра.
samba-empty-section = заголовок раздела пуст.
samba-bad-key = `{$key}` был бы разобран как раздел или комментарий, а не как ключ директивы.
samba-bad-value = `{$value}` оканчивается на `\` и поглотил бы следующую строку.
samba-bad-section = `{$section}` содержит `[` или `]` либо оканчивается на `\` и не пережил бы запись и повторное чтение.
samba-guest-ok = для `guest ok` задано {$value}; неаутентифицированные клиенты могут подключаться ко всем ресурсам, которые наследуют это значение.
samba-map-to-guest = для `map to guest` задано {$value}; любое значение, кроме Never, превращает неудачные входы в гостевые сеансы.
samba-min-protocol = для `server min protocol` задано {$value}; задайте не ниже SMB3_00 и откажитесь от уровней протокола времён SMB1.
samba-smb-encrypt = для `smb encrypt` задано {$value}; задайте required, чтобы трафик SMB не мог идти незашифрованным.
samba-restrict-anonymous = для `restrict anonymous` задано {$value}; значение 2 скрывает список ресурсов от анонимных пользователей.
samba-rec-server-signing = для `server signing` задано {$value}; задайте mandatory, чтобы трафик SMB подписывался криптографически.
samba-rec-load-printers = для `load printers` задано {$value}; задайте no, если только этот хост действительно не раздаёт принтеры.
samba-rec-interfaces = директива `interfaces` не задана; привяжите samba к явным адресам вместо прослушивания на всех интерфейсах.
samba-writable-exposure = этот ресурс разрешает запись через writeable, read only или write list; убедитесь, что запись нужна всем клиентам.
samba-root-command = `{$key}` запускает команду с правами root при каждом подходящем подключении.
samba-client-command = `{$key}` позволяет клиенту заставить samba запустить команду; клиент управляет тем, что получает команда.
samba-usershare-guests = для `usershare allow guests` задано {$value}; пользователи могут публиковать ресурсы, которые любой открывает без пароля.
samba-wide-links = для `wide links` задано {$value}; символические ссылки могут вывести клиентов за пределы ресурса.

## module template — copy-me example
TEMPLATE-name = шаблон модуля
TEMPLATE-note-precedence = этот вымышленный модуль — проверяемый при компиляции пример для новых модулей конфигурации.
TEMPLATE-tip-settings = настройки, которые моделирует этот вымышленный модуль, в порядке следования в файле.
TEMPLATE-tip-key = имя директивы, одно слово, без пробельных символов.
TEMPLATE-tip-value = значение директивы до конца строки.
TEMPLATE-rec-value = лучше задать явное значение, чем полагаться на значение по умолчанию из upstream.
TEMPLATE-invalid-key = `{$key}` не является допустимым именем директивы.
TEMPLATE-duplicate-key = `{$key}` задан более одного раза; действует последнее значение.
TEMPLATE-too-many-settings = настроек в этом файле: {$count}; разделите большие конфигурации на файлы поменьше.

## detent-core — parse, model, and edit errors
## These are the failures a module's own document model can raise, so they are
## prefixed `core-` rather than with a module id.
core-parse-malformed = этот файл не соответствует формату, которого ожидает `{$module}`: {$reason}
core-model-shape = переданная конфигурация имеет не ту структуру, которая ожидалась: {$reason}
core-model-unrepresentable = этот файл содержит то, что редактор не может представить: {$reason}
core-edit-line-break = значение не может содержать перевод строки или нулевой байт; `{$value}` содержит.
core-edit-index-out-of-range = внутренняя ошибка: строка {$index} находится вне файла из {$len} строк.
core-edit-unsupported = эту правку нельзя выразить в формате файла: {$reason}

## detent-core — version-gated options
core-version-too-old = `{$option}` требует {$service} {$since} или новее; на этом хосте {$installed}.
core-version-unknown = установленная версия {$service} неизвестна, поэтому `{$option}` (требует {$service} {$since} или новее) может не работать.

## operations layer — errors surfaced by detent-ops
ops-unknown-module = в этой сборке нет модуля с именем `{$module}`.
ops-invalid-model = конфигурация для `{$module}` недопустима: {$reason}
ops-check-failed = внешний валидатор `{$program}` отклонил кандидата: {$reason}
ops-hash-conflict = `{$path}` изменился на диске после чтения; прочитайте его заново и повторите попытку.
ops-privsep-failed = привилегированный помощник отказал или не смог выполнить запрос: {$reason}
ops-service-failed = действие над службой не завершилось: {$reason}
ops-no-target = `{$module}` не управляет ни одним файлом на этом хосте.
ops-no-service = `{$module}` не управляет ни одной службой на этом хосте, поэтому её нельзя перезапустить.
ops-audit-failed = не удалось прочитать журнал аудита: {$reason}
ops-audit-unavailable = не удалось записать журнал аудита, поэтому операция отклонена: {$reason}
ops-unsupported = {$what} не поддерживается в этой сборке.
ops-commit-pending = другое окно commit-confirm уже ожидает подтверждения.
ops-update-running = обновление уже выполняется; дождитесь его завершения, затем проверьте запущенную версию.
ops-update-tag-invalid = это не версия выпуска; она должна иметь вид v1.2.3.
ops-update-not-newer = этот выпуск не новее запущенной версии; ничего не запущено.
ops-no-backup = commit-confirm требует сохранённой резервной копии; ничего не изменено.
ops-arm-failed-restored = commit-confirm не удалось взвести, поэтому изменение отменено; прежнее содержимое возвращено.
ops-arm-failed-unrestored = commit-confirm не удалось взвести, и изменение НЕ удалось отменить; новое содержимое всё ещё на диске. Немедленно восстановите предыдущую резервную копию.
ops-target-missing = управляемого файла не существует; создайте его (установите его пакет или создайте вручную) и повторите попытку.
ops-denied = у вас нет права на это действие.

## detent-web — configuration, TLS, the operations bridge, and the listener
web-config-unreadable = не удалось прочитать `{$path}`: {$reason}
web-config-malformed = `{$path}` не является допустимой конфигурацией detent: {$reason}
web-config-zero-value = `{$field}` должно быть больше нуля.
web-config-weak-argon2 = `auth.argon2.m_kib` равно {$m}, что ниже минимума {$min} kib.
web-tls-generate-failed = не удалось создать начальный сертификат: {$reason}
web-tls-key-rejected = сертификат и его закрытый ключ отклонены: {$reason}
web-tls-store-unreadable = не удалось прочитать `{$path}`: {$reason}
web-tls-store-unwritable = не удалось подготовить `{$path}` к записи: {$reason}
web-tls-store-write-failed = не удалось записать `{$path}`: {$reason}
web-tls-acme-pem-rejected = выданный сертификат или ключ не являются пригодным PEM.
web-engine-stopped = механизм операций больше не работает; повторите попытку, когда служба вернётся.
web-cert-renew-not-acme = для продления нужно `tls.bootstrap = "acme"` в detent.toml.
web-cert-renew-unavailable = клиент acme не получил запрос на продление; повторите попытку позже.
web-update-not-checked = на этом хосте проверка обновлений ещё не выполнялась; запустите `detent update --check` от имени root.
web-server-bind-failed = не удалось начать прослушивание `{$addr}`: {$reason}
web-server-address-unknown = не удалось прочитать адрес прослушивания: {$reason}

## detent-web — auth: passwords, sessions, api tokens, totp, csrf
web-auth-entropy-unavailable = системный генератор случайных чисел дал сбой, поэтому учётные данные не могли быть выданы.
web-auth-argon2-params = настроенные параметры argon2 непригодны: {$reason}
web-auth-hash-failed = не удалось вычислить хеш пароля.
web-auth-password-too-short = пароль должен содержать не менее 12 символов.
web-auth-password-too-long = пароль может содержать не более 128 символов.
web-auth-password-unchanged = новый пароль должен отличаться от текущего.
web-auth-password-change-required = смените пароль, прежде чем делать что-либо ещё.
web-auth-user-name-invalid = `{$name}` не подходит как имя пользователя; используйте от 1 до 32 символов из `a-z`, `0-9`, `.`, `_` или `-`, начиная с буквы или цифры.
web-auth-user-exists = пользователь с именем `{$name}` уже существует.
web-auth-user-unknown = пользователя с именем `{$name}` нет.
web-auth-invalid-credentials = имя пользователя, пароль или код были неверны.
web-auth-rate-limited = слишком много попыток; подождите {$seconds} с и повторите попытку.
web-auth-session-limit = открыто слишком много сеансов; дождитесь истечения одного из них и войдите снова.
web-auth-busy = выполняется слишком много входов; подождите немного и повторите попытку.
web-auth-unauthenticated = войдите, чтобы сделать это.
web-auth-ambiguous-credentials = отправьте либо cookie сеанса, либо токен bearer, но не оба сразу.
web-auth-csrf-rejected = этот запрос не прошёл межсайтовые проверки.
web-auth-token-unknown = этого api-токена не существует, он отозван или истёк.
web-auth-token-limit = на этом хосте уже выдано максимальное число api-токенов.
web-auth-totp-secret-invalid = этот секрет аутентификатора не является допустимым base32.
web-auth-store-unreadable = не удалось прочитать `{$path}`: {$reason}
web-auth-store-unwritable = не удалось подготовить `{$path}` к записи: {$reason}
web-auth-store-write-failed = не удалось записать `{$path}`: {$reason}
web-auth-store-malformed = `{$path}` не является допустимым файлом учётных данных detent: {$reason}
web-denied-scope = эти учётные данные не имеют области действия `{$scope}`.

## detent-web — the api surface
web-request-malformed = тело запроса не имеет структуры, которой ожидает эта конечная точка.
web-request-too-deep = тело запроса слишком глубоко вложено.
web-api-unexpected-outcome = операция выполнена, но её результат не удалось отобразить.
