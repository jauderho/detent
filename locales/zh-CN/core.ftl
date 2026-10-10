# needs-review: machine-drafted Simplified Chinese translation; not yet checked by a native speaker.
## detent-core — zh-CN
## Source: locales/en-US/core.ftl. Same ids, same placeables. Code-like tokens
## (directive names, paths, flags, option values) stay untranslated.

## chrony module — display name, security notes, schema tooltips
chrony-name = chrony
chrony-note-precedence = 此文件会覆盖编译时内置的默认值；错误的值会悄无声息地改变主机的计时方式。
chrony-tip-settings = 此模块所管理的 chrony.conf 指令（按文件中的顺序）；文件中的其他内容会原样保留。
chrony-tip-key = 指令名称，单个单词，不区分大小写。
chrony-tip-value = 此指令的值，直到行尾；对于 `rtcsync` 这类无值指令则为空。
chrony-rec-value = 建议明确指定值，不要依赖编译时内置的默认值。

## chrony module — validation diagnostics
chrony-privileged-directive = `{$key}` 设置的是 chronyd 以 root 身份写入的文件，或 chronyd 运行时使用的用户。应用之前请先检查该值。
chrony-invalid-key = `{$key}` 不是有效的 chrony 指令名称。
chrony-duplicate-key = `{$key}` 被设置了多次；以最后一个值为准。
chrony-too-many-settings = 此文件包含 {$count} 项设置；请将其拆分为 /etc/chrony/conf.d 下的 drop-in 文件。
chrony-allow-open = `allow {$value}` 会向整个互联网提供时间服务；请只允许确实需要的网络。
chrony-missing-makestep = 未设置 makestep；启动时时钟可能无限制地漂移，而不会被步进调整到正常范围。
chrony-missing-rtcsync = 未设置 rtcsync；硬件时钟相对于系统时钟会发生漂移。
chrony-rec-nts = 池 {$pool} 在未使用 nts 选项的情况下被使用；建议使用支持 nts 的时间源，以防时间被伪造。
chrony-cmdport-open = cmdport 为 {$port}；除非 chronyc 必须通过网络访问此主机，否则请设置 cmdport 0。
chrony-external-directive = `{$key}` 会加载外部文件或运行外部程序；此模块拒绝跨出其配置文件边界的指令。

## dhcp module — display name, security notes, schema tooltips
dhcp-name = dhcp
dhcp-note-commit-confirm = 错误的 DHCP 更改会使所有客户端以及您本人与网络断开；确认之前请仔细检查差异。
dhcp-tip-dnsmasq = /etc/dnsmasq.conf 中的 `key=value` 设置（按文件中的顺序）；注释和未知的行会原样保留。
dhcp-tip-kea-v4 = Kea DHCPv4 服务器（`Dhcp4`）中受管理的部分；未知的 Kea 选项会原样保留。
dhcp-tip-kea-v6 = Kea DHCPv6 服务器（`Dhcp6`）中受管理的部分；未知的 Kea 选项会原样保留。
dhcp-tip-key = dnsmasq 选项名称，单个单词，不含空白字符。
dhcp-tip-value = `=` 之后的值；像 `domain-needed` 这样的单独标志没有值。
dhcp-tip-interfaces = Kea 服务器监听的接口；列表为空表示服务器在所有接口上应答。
dhcp-tip-valid-lifetime = 默认租约有效期，单位为秒；对大多数网络来说 3600 是合理的默认值。
dhcp-tip-subnets = 服务器从中分配地址的子网。
dhcp-tip-id = Kea 的稳定子网标识符；编辑时请保持不变，租约是以它为键的。
dhcp-tip-subnet = CIDR 形式的子网前缀，例如 `192.168.1.0/24`。
dhcp-tip-pools = 该子网的动态地址池。
dhcp-tip-routers = 下发给客户端的路由器（默认网关）选项。
dhcp-tip-domain-servers = 下发给客户端的 DNS 服务器（`domain-name-servers`）。
dhcp-tip-pool = 地址池，写作范围 `192.168.1.100 - 192.168.1.200` 或前缀 `192.168.1.0/24`。

## dhcp module — validation diagnostics
dhcp-empty-key = 某项 dnsmasq 设置的选项名称为空。
dhcp-invalid-key = `{$key}` 不是有效的 dnsmasq 选项名称；它必须是不含空白字符、`=` 或 `#` 的单个单词。
dhcp-malformed-cidr = `{$value}` 不是有效的 CIDR 前缀，例如 `192.168.1.0/24`。
dhcp-malformed-pool = `{$value}` 不是有效的地址池；请使用 `192.168.1.100 - 192.168.1.200` 这样的范围，或 CIDR 前缀。
dhcp-external-directive = `{$key}` 会加载外部文件或运行命令；此模块不会创建或修改跨出其配置文件边界的指令。
dhcp-authoritative-set = `dhcp-authoritative` 会让 dnsmasq 成为该网段中唯一的 DHCP 服务器；仅在不存在其他 DHCP 服务器时才设置它。
dhcp-kea-interfaces-empty = {$server} 未配置任何接口，将在所有接口上监听；请明确指定接口。
dhcp-rec-rebind = domain-needed 和 bogus-priv 没有同时设置；它们用于过滤 DNS 重绑定攻击以及发往上游的私有地址 A 记录查询。
dhcp-rec-lifetime = {$server} 的 valid-lifetime 为 {$lifetime}；请将其保持在 300 到 86400 秒之间，使租约能按预期续期。

## hosts module — display name, security notes, schema tooltips
hosts-name = hosts
hosts-note-spoofing = 这里的条目会覆盖 DNS；错误或恶意的条目会悄无声息地重定向域名查询。
hosts-tip-entries = /etc/hosts 中的地址到名称的映射（按文件中的顺序）。
hosts-tip-ip = 下面的名称所解析到的地址。
hosts-tip-hostnames = 解析到此地址的名称，规范名称在前。
hosts-tip-comment = 此条目的行内注释（如有）。

## hosts module — validation diagnostics
hosts-invalid-hostname = `{$name}` 不是有效的主机名。
hosts-duplicate-canonical = `{$name}` 是多个条目的规范名称。
hosts-no-hostnames = 此条目没有主机名。
hosts-hostname-is-ip = `{$name}` 是地址字面量，不是主机名。
hosts-ipv6-zone-unsupported = `{$name}` 带有 IPv6 区域 ID，而 /etc/hosts 不支持它。
hosts-hostname-multiple-ips = `{$name}` 解析到同一地址族的多个地址。
hosts-localhost-not-loopback = `localhost` 指向 `{$ip}`，而它不是环回地址。
hosts-missing-localhost = 没有 `localhost` 条目。
hosts-missing-ipv6-localhost = 没有 IPv6 的 `localhost` 条目。
hosts-too-many-entries = 此文件包含 {$count} 个条目；请考虑改用 DNS。

## mounts module — display name, security notes, schema tooltips
mounts-name = mounts
mounts-note-boot = 错误的 /etc/fstab 可能导致主机在下次重启时无法启动；每次更改都需要二次确认。确认无法发现错误的条目，因为在下次启动之前没有任何程序会读取该文件。
mounts-tip-entries = /etc/fstab 中的挂载条目（按文件中的顺序）。
mounts-tip-spec = 挂载的对象：设备、`UUID=...`/`LABEL=...`、nfs 导出，或表示交换分区的 `none`。
mounts-tip-mountpoint = 文件系统的挂载位置；交换分区则为 `none`/`swap`。
mounts-tip-fstype = 文件系统类型，例如 ext4，或 `swap`。
mounts-tip-options = 以逗号分隔的挂载选项，例如 defaults,nosuid。
mounts-tip-dump = dump(8) 的备份频率；几乎总是 0。
mounts-tip-pass = fsck 的检查顺序号：根文件系统为 1，其他需检查的文件系统为 2，0 表示跳过。
mounts-rec-options = 对用户可写的数据使用 nosuid、nodev 和 noexec 加以保护；对网络文件系统建议使用 x-systemd.automount。

## mounts module — validation diagnostics
mounts-empty-spec = 第 {$index} 个条目的 spec（第一列）为空。
mounts-empty-mountpoint = 第 {$index} 个条目的挂载点（第二列）为空。
mounts-invalid-fstype = `{$fstype}` 不是有效的文件系统类型。
mounts-pass-too-high = 第 {$index} 个条目的 pass 为 `{$pass}`；fsck 最多运行 2 轮。
mounts-root-pass = 根文件系统的 pass 应为 1，而不是 `{$pass}`。
mounts-missing-nofail = `{$mountpoint}` 是可移动介质，但没有 `nofail`；拔出后启动会卡住。
mounts-missing-boot-escape = `{$mountpoint}` 既没有 nofail 也没有 noauto；挂载失败可能会拖住启动过程。
mounts-critical-noauto = `{$mountpoint}` 是启动所必需的，但带有 noauto，因此系统可能在没有它的情况下继续启动。
mounts-missing-guards = `{$mountpoint}` 挂载了用户可写的数据，但没有 `{$missing}`；请添加。
mounts-network-automount = `{$mountpoint}` 是网络文件系统，但没有 `x-systemd.automount`；启动时会等待网络。
mounts-noauto-without-user = 有 `noauto` 而没有 `user`：只有 root 才能挂载它，这就失去了意义。
mounts-relative-mountpoint = 第 {$index} 个条目挂载到 `{$mountpoint}`，而它不是绝对路径。
mounts-no-root-entry = 没有任何条目挂载 `/`；请确认根文件系统是通过其他方式挂载的。

## network module — display name, security notes, schema tooltips
network-name = network
network-note-precedence = 错误的网络配置可能使管理员无法连接此主机；每次更改都需要二次确认。
network-tip-interfaces = 此主机所配置的接口（按文件中的顺序）。
network-tip-iface-name = 接口名称，例如 eth0。
network-tip-iface-dhcp-v4 = 此接口是否通过 DHCP 获取其 IPv4 地址。
network-tip-iface-dhcp-v6 = 此接口是否通过 DHCP 获取其 IPv6 地址。
network-tip-iface-addresses = CIDR 表示法的静态地址，例如 192.168.1.10/24。
network-tip-iface-gateway-v4 = IPv4 的默认网关，用于静态寻址的情况。
network-tip-iface-gateway-v6 = IPv6 的默认网关，用于静态寻址的情况。
network-tip-iface-dns = 此接口使用的 DNS 服务器。
network-tip-iface-routes = 此接口的静态路由。
network-tip-iface-vlan = 此接口的 VLAN 设置（当它是 VLAN 时）。
network-tip-iface-bridge = 此接口的网桥设置（当它是网桥时）。
network-tip-route-to = 目的地 CIDR 或 default。
network-tip-route-via = 下一跳 IP。
network-tip-vlan-link = 此 VLAN 的父链路，例如 eth0。
network-tip-vlan-id = VLAN id，1–4094。
network-tip-bridge-members = 此网桥的成员接口名称。

## network module — validation diagnostics
network-invalid-cidr = `{$value}` 不是有效的 CIDR 地址。
network-invalid-ip = `{$value}` 不是有效的 IP 地址。
network-gateway-outside-subnet = 网关 `{$gateway}` 不在此接口的子网之内。
network-vlan-range = VLAN id `{$id}` 超出了 1–4094 的范围。
network-duplicate-interface = 接口 `{$name}` 出现了多次。
network-interface-order = 接口 `{$name}` 必须排在它上方的接口之前：请按名称顺序列出接口。
network-injection = `{$value}` 包含换行符或空字节。
network-static-no-gateway = 此静态寻址的接口没有网关。
network-static-no-dns = 此静态寻址的接口没有 DNS 服务器。
network-dhcp-static-mixed = 此接口同时使用了 DHCP 和静态地址。
network-rec-ipv6-privacy = 启用 DHCPv6 时，请同时启用 IPv6 隐私扩展。
network-rec-ra-accept = 仅在明确由 DHCPv6 管理时才接受路由器通告。
network-rec-no-promisc = 此接口不应运行在混杂模式下。

## nfs module — display name, security notes, schema tooltips
nfs-name = nfs
nfs-note-live-state = 导出规则由内核在每次挂载时强制执行；错误的一行会悄无声息地改变哪些主机可以读取哪些文件系统。
nfs-tip-entries = /etc/exports 中的导出项（按文件中的顺序）。
nfs-tip-path = 导出点：此主机上的绝对目录路径。
nfs-tip-clients = 允许挂载此导出的主机，按匹配顺序排列；第一个匹配的规格生效。
nfs-tip-host = 客户端规格：名称、地址、地址/子网掩码、通配符、`*`（所有客户端）或 @netgroup。
nfs-tip-options = 此客户端的导出选项，以逗号分隔；列表为空则采用文件的默认值。
nfs-rec-options = 请明确写出 rw/ro、sync/async、root_squash 以及子树处理方式；不同 nfs-utils 版本之间的默认值会发生变化。

## nfs module — validation diagnostics
nfs-empty-path = 某个导出点为空。
nfs-relative-path = `{$path}` 不是绝对路径；导出点必须以 `/` 开头。
nfs-empty-host = `{$path}` 的某个客户端没有主机规格。
nfs-bad-host = `{$host}` 不是有效的客户端规格；它以 `-` 开头，或包含会截断该行的语法。
nfs-bad-path = `{$path}` 包含会截断导出行的语法。
nfs-bad-continuation = `{$path}` 会以续行反斜杠结尾，并折叠下一行。
nfs-invalid-option = `{$option}` 不是有效的导出选项；选项是不含空白字符或括号的单个标记。
nfs-no-root-squash = `{$host}` 使用 no_root_squash 挂载，并在导出上保留 root 权限。
nfs-sec-sys-only = `{$host}` 使用默认的 sec=sys，或只协商 sec=sys；请添加 krb5p 以获得加密保护。
nfs-world-export = 每个客户端都可以对 `{$host}` 进行读写访问。
nfs-subtree-undecided = `{$host}` 既没有指定 subtree_check 也没有指定 no_subtree_check；上游已更改了默认值，请明确说明您想要哪一个。
nfs-root-squash-undecided = `{$host}` 既没有指定 root_squash 也没有指定 no_root_squash；请明确说明您想要哪一个。
nfs-sync-undecided = `{$host}` 既没有指定 sync 也没有指定 async；建议使用 sync，它会将写入提交到稳定存储。

## resolver module — display name, security notes, schema tooltips
resolver-name = resolver
resolver-note-managed-symlink = 在此主机上 /etc/resolv.conf 由某个解析器后端管理；detent 拒绝编辑受管理的符号链接目标，而是改为配置该后端。
resolver-tip-resolv = 此模块所管理的 /etc/resolv.conf 指令；文件中的其他内容会原样保留。
resolver-tip-resolved = systemd-resolved 的设置（按文件中的顺序）。更改这些设置会重启 systemd-resolved。
resolver-tip-unbound = 此模块所管理的 unbound.conf 配置项（按文件中的顺序）。更改这些设置会重启 unbound。

## resolver module — validation diagnostics
resolver-no-nameserver = 未配置任何 nameserver。
resolver-duplicate-nameserver = `{$ip}` 作为 nameserver 出现了多次。
resolver-too-many-nameservers = 此文件列出了 {$count} 个 nameserver；glibc 最多读取 {$max} 个。
resolver-invalid-domain = `{$domain}` 不是有效的域名。
resolver-unknown-option = `{$option}` 不是 glibc 的 resolv.conf 解析器所接受的选项。
resolver-search-and-domain = 同时存在 `search` 和 `domain`；设置了 `search` 时，glibc 会忽略 `domain`。
resolver-no-config = 此模型完全没有配置任何解析器后端。
resolver-backend-missing = 这些设置用于配置 {$service}，但在此主机上未检测到它。
resolver-rec-dnssec = DNSSEC 设置为 allow-downgrade；`DNSSEC=yes` 会进行严格验证，在上游数据允许的情况下建议使用。
resolver-rec-dot = DNSOverTLS 为机会性模式，会降级为明文；`DNSOverTLS=yes` 则强制要求使用 TLS。
resolver-unknown-hardening = `{$key}` 不是此模块为 unbound 所管理的指令。
resolver-unbound-misplaced = `{$key}` 应放在 unbound.conf 的 {$section} 小节中，而不是这里。
resolver-invalid-forward-addr = `{$addr}` 不是 ip[@port][#auth-name] 形式的有效 forward-addr。
resolver-invalid-forward-name = `{$name}` 不是有效的 forward-zone 名称。
resolver-forward-tls-no-auth = 此区域通过 TLS 转发，但其 forward-addr 没有 `#auth-name`，因此该 TLS 连接未经认证。
resolver-rec-hardening = `{$key}` 已被禁用；启用它可以加固 unbound，防御上游欺骗和委派滥用。
resolver-forward-zone-unnamed = 没有 name: 的 forward-zone: 不会转发任何内容，还会削弱配置；请为每个区域命名。

## samba module — display name, security notes, schema tooltips
samba-name = samba
samba-note-guest-access = 访客访问权限在连接时按共享逐个授予；错误的值会让文件在没有密码的情况下暴露。
samba-tip-entries = 此模块所管理的 smb.conf 条目（按文件中的顺序）：`[section]` 标题和指令都包括在内。
samba-tip-section = `[section]` 标题的小节名称；对于普通指令行则为空。
samba-tip-key = 参数名称，不区分大小写，可能由多个单词组成（`guest ok`）。
samba-tip-value = 参数的值，直到行尾；`%` 宏会原样保留。
samba-rec-value = 建议明确指定加固后的值，不要依赖上游编译时内置的默认值。

## samba module — validation diagnostics
samba-empty-key = 某条指令没有参数名称。
samba-empty-section = 某个小节标题为空。
samba-bad-key = `{$key}` 会被解析为小节或注释，而不是指令键。
samba-bad-value = `{$value}` 以 `\` 结尾，会吞掉下一行。
samba-bad-section = `{$section}` 包含 `[` 或 `]`，或以 `\` 结尾，无法完整往返还原。
samba-guest-ok = `guest ok` 设置为 {$value}；未经认证的客户端可以连接到所有继承该设置的共享。
samba-map-to-guest = `map to guest` 为 {$value}；除 Never 之外的任何值都会把登录失败变成访客会话。
samba-min-protocol = `server min protocol` 为 {$value}；请至少设置为 SMB3_00，并弃用 SMB1 时代的协议级别。
samba-smb-encrypt = `smb encrypt` 为 {$value}；请设置为 required，使 SMB 流量不能以未加密的方式传输。
samba-restrict-anonymous = `restrict anonymous` 为 {$value}；设置为 2 可向匿名用户隐藏共享列表。
samba-rec-server-signing = `server signing` 为 {$value}；请设置为 mandatory，使 SMB 流量经过加密签名。
samba-rec-load-printers = `load printers` 为 {$value}；除非此主机确实共享打印机，否则请设置为 no。
samba-rec-interfaces = 未设置 `interfaces` 指令；请将 samba 绑定到明确的地址，而不是监听所有接口。
samba-writable-exposure = 此共享通过 writeable、read only 或 write list 允许写入；请确认是否每个客户端都应有写入权限。
samba-root-command = `{$key}` 会在每个匹配的连接上以 root 权限运行命令。
samba-client-command = `{$key}` 允许客户端让 samba 运行命令；命令的内容由客户端控制。
samba-usershare-guests = `usershare allow guests` 为 {$value}；用户可以发布任何人无需密码即可打开的共享。
samba-wide-links = `wide links` 为 {$value}；符号链接可能把客户端引到共享之外。

## module template — copy-me example
TEMPLATE-name = 模块模板
TEMPLATE-note-precedence = 这个虚构的模块是供新配置模块参考的、经过编译检查的示例。
TEMPLATE-tip-settings = 这个虚构模块所管理的设置（按文件中的顺序）。
TEMPLATE-tip-key = 指令名称，单个单词，不含空白字符。
TEMPLATE-tip-value = 指令的值，直到行尾。
TEMPLATE-rec-value = 建议明确指定值，不要依赖上游的默认值。
TEMPLATE-invalid-key = `{$key}` 不是有效的指令名称。
TEMPLATE-duplicate-key = `{$key}` 被设置了多次；以最后一个值为准。
TEMPLATE-too-many-settings = 此文件包含 {$count} 项设置；请将大型配置拆分为较小的文件。

## detent-core — parse, model, and edit errors
## These are the failures a module's own document model can raise, so they are
## prefixed `core-` rather than with a module id.
core-parse-malformed = 此文件不符合 `{$module}` 所要求的格式：{$reason}
core-model-shape = 提供的配置不具备预期的结构：{$reason}
core-model-unrepresentable = 此文件包含编辑器无法表示的内容：{$reason}
core-edit-line-break = 值不能包含换行符或空字节；`{$value}` 包含了。
core-edit-index-out-of-range = 内部错误：第 {$index} 行超出了只有 {$len} 行的文件范围。
core-edit-unsupported = 此编辑无法用该文件的格式表达：{$reason}

## detent-core — version-gated options
core-version-too-old = `{$option}` 需要 {$service} {$since} 或更高版本；此主机上的版本是 {$installed}。
core-version-unknown = 已安装的 {$service} 版本未知，因此 `{$option}`（需要 {$service} {$since} 或更高版本）可能无法使用。

## operations layer — errors surfaced by detent-ops
ops-unknown-module = 此构建中没有名为 `{$module}` 的模块。
ops-invalid-model = `{$module}` 的配置无效：{$reason}
ops-check-failed = 外部验证程序 `{$program}` 拒绝了候选配置：{$reason}
ops-hash-conflict = `{$path}` 在被读取之后已在磁盘上发生变化；请重新读取后再试。
ops-privsep-failed = 特权辅助进程拒绝了请求，或无法完成请求：{$reason}
ops-service-failed = 服务操作未能完成：{$reason}
ops-no-target = `{$module}` 在此主机上不管理任何文件。
ops-no-service = `{$module}` 在此主机上不控制任何服务，因此无法重启。
ops-audit-failed = 无法读取审计日志：{$reason}
ops-audit-unavailable = 无法写入审计日志，因此该操作被拒绝：{$reason}
ops-unsupported = 此构建不支持{$what}。
ops-commit-pending = 已有另一个 commit-confirm 窗口处于待确认状态。
ops-update-running = 更新已在运行；请等待其完成，然后检查当前运行的版本。
ops-update-tag-invalid = 这不是发布版本号；它的格式必须类似 v1.2.3。
ops-update-not-newer = 该发布版本并不比当前运行的版本更新；未启动任何操作。
ops-no-backup = commit-confirm 需要保留一份备份；未做任何更改。
ops-arm-failed-restored = 无法启用 commit-confirm，因此更改已被撤销；先前的内容已恢复。
ops-arm-failed-unrestored = 无法启用 commit-confirm，且更改无法撤销；新内容仍在磁盘上。请立即恢复先前的备份。
ops-target-missing = 受管理的文件不存在；请创建它（安装其软件包或手动创建），然后重试。
ops-denied = 您无权执行此操作。

## detent-web — configuration, TLS, the operations bridge, and the listener
web-config-unreadable = 无法读取 `{$path}`：{$reason}
web-config-malformed = `{$path}` 不是有效的 detent 配置：{$reason}
web-config-zero-value = `{$field}` 必须大于零。
web-config-weak-argon2 = `auth.argon2.m_kib` 为 {$m}，低于最小值 {$min} kib。
web-tls-generate-failed = 无法生成引导证书：{$reason}
web-tls-key-rejected = 证书及其私钥被拒绝：{$reason}
web-tls-store-unreadable = 无法读取 `{$path}`：{$reason}
web-tls-store-unwritable = 无法为写入准备 `{$path}`：{$reason}
web-tls-store-write-failed = 无法写入 `{$path}`：{$reason}
web-tls-acme-pem-rejected = 签发的证书或密钥不是可用的 PEM。
web-engine-stopped = 操作引擎已不再运行；请在服务恢复后重试。
web-cert-renew-not-acme = 续期需要在 detent.toml 中设置 `tls.bootstrap = "acme"`。
web-cert-renew-unavailable = acme 客户端没有收到续期请求；请稍后再试。
web-update-not-checked = 此主机尚未进行过更新检查；请以 root 身份运行 `detent update --check`。
web-server-bind-failed = 无法监听 `{$addr}`：{$reason}
web-server-address-unknown = 无法回读监听地址：{$reason}

## detent-web — auth: passwords, sessions, api tokens, totp, csrf
web-auth-entropy-unavailable = 系统随机数生成器出现故障，因此无法签发任何凭据。
web-auth-argon2-params = 所配置的 argon2 参数不可用：{$reason}
web-auth-hash-failed = 无法对密码进行哈希。
web-auth-password-too-short = 密码至少须有 12 个字符。
web-auth-password-too-long = 密码最多只能有 128 个字符。
web-auth-password-unchanged = 新密码必须与当前密码不同。
web-auth-password-change-required = 请先修改密码，然后再进行其他操作。
web-auth-user-name-invalid = `{$name}` 不是可用的用户名；请使用 1 到 32 个 `a-z`、`0-9`、`.`、`_` 或 `-` 字符，并以字母或数字开头。
web-auth-user-exists = 名为 `{$name}` 的用户已存在。
web-auth-user-unknown = 没有名为 `{$name}` 的用户。
web-auth-invalid-credentials = 用户名、密码或验证码不正确。
web-auth-rate-limited = 尝试次数过多；请等待 {$seconds} 秒后再试。
web-auth-session-limit = 打开的会话过多；请等待其中一个过期后再重新登录。
web-auth-busy = 正在进行的登录过多；请稍候再试。
web-auth-unauthenticated = 请先登录再执行此操作。
web-auth-ambiguous-credentials = 请发送会话 cookie 或 bearer 令牌二者之一，不要同时发送。
web-auth-csrf-rejected = 此请求未通过跨站检查。
web-auth-token-unknown = 该 api 令牌不存在、已被吊销或已过期。
web-auth-token-limit = 此主机已持有 api 令牌数量的上限。
web-auth-totp-secret-invalid = 该验证器密钥不是有效的 base32。
web-auth-store-unreadable = 无法读取 `{$path}`：{$reason}
web-auth-store-unwritable = 无法为写入准备 `{$path}`：{$reason}
web-auth-store-write-failed = 无法写入 `{$path}`：{$reason}
web-auth-store-malformed = `{$path}` 不是有效的 detent 凭据文件：{$reason}
web-denied-scope = 此凭据不具备 `{$scope}` 作用域。

## detent-web — the api surface
web-request-malformed = 请求体的结构不是此端点所期望的。
web-request-too-deep = 请求体的嵌套层级过深。
web-api-unexpected-outcome = 操作已完成，但其结果无法呈现。
