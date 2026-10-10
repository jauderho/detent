# needs-review: machine-drafted Traditional Chinese translation; not yet checked by a native speaker.
## detent-core — zh-TW
## Source: locales/en-US/core.ftl. Same ids, same placeables. Code-like tokens
## (directive names, paths, flags, option values) stay untranslated.

## chrony module — display name, security notes, schema tooltips
chrony-name = chrony
chrony-note-precedence = 此檔案會覆寫編譯時內建的預設值；錯誤的值會在不知不覺中改變主機的校時方式。
chrony-tip-settings = 此模組所處理的 chrony.conf 指令（依檔案中的順序）；檔案中的其他內容會原封不動地保留。
chrony-tip-key = 指令名稱，單一個單字，不區分大小寫。
chrony-tip-value = 此指令的值，直到行尾；對於 `rtcsync` 這類沒有值的指令則為空。
chrony-rec-value = 建議明確指定值，不要依賴編譯時內建的預設值。

## chrony module — validation diagnostics
chrony-privileged-directive = `{$key}` 設定的是 chronyd 以 root 身分寫入的檔案，或 chronyd 執行時所用的使用者。套用之前請先檢查該值。
chrony-invalid-key = `{$key}` 不是有效的 chrony 指令名稱。
chrony-duplicate-key = `{$key}` 被設定了多次；以最後一個值為準。
chrony-too-many-settings = 此檔案包含 {$count} 項設定；請將其拆分為 /etc/chrony/conf.d 底下的 drop-in 檔案。
chrony-allow-open = `allow {$value}` 會向整個網際網路提供時間服務；請只允許確實需要的網路。
chrony-missing-makestep = 未設定 makestep；啟動時時鐘可能無限制地漂移，而不會被步進調整到正常範圍。
chrony-missing-rtcsync = 未設定 rtcsync；硬體時鐘相對於系統時鐘會發生漂移。
chrony-rec-nts = 集區 {$pool} 在未使用 nts 選項的情況下被使用；建議使用支援 nts 的時間來源，以免時間遭到偽造。
chrony-cmdport-open = cmdport 為 {$port}；除非 chronyc 必須透過網路連線到此主機，否則請設定 cmdport 0。
chrony-external-directive = `{$key}` 會載入外部檔案或執行外部程式；此模組會拒絕跨出其設定檔案邊界的指令。

## dhcp module — display name, security notes, schema tooltips
dhcp-name = dhcp
dhcp-note-commit-confirm = 錯誤的 DHCP 變更會使所有用戶端以及您本人與網路中斷連線；確認之前請仔細檢查差異。
dhcp-tip-dnsmasq = /etc/dnsmasq.conf 中的 `key=value` 設定（依檔案中的順序）；註解和未知的行會原封不動地保留。
dhcp-tip-kea-v4 = Kea DHCPv4 伺服器（`Dhcp4`）中受管理的部分；未知的 Kea 選項會原封不動地保留。
dhcp-tip-kea-v6 = Kea DHCPv6 伺服器（`Dhcp6`）中受管理的部分；未知的 Kea 選項會原封不動地保留。
dhcp-tip-key = dnsmasq 選項名稱，單一個單字，不含空白字元。
dhcp-tip-value = `=` 之後的值；像 `domain-needed` 這樣的單獨旗標沒有值。
dhcp-tip-interfaces = Kea 伺服器監聽的介面；清單為空表示伺服器在所有介面上回應。
dhcp-tip-valid-lifetime = 預設租約有效期限，單位為秒；對大多數網路來說 3600 是合理的預設值。
dhcp-tip-subnets = 伺服器從中配發位址的子網路。
dhcp-tip-id = Kea 的穩定子網路識別碼；編輯時請保持不變，租約是以它為鍵的。
dhcp-tip-subnet = CIDR 形式的子網路前置碼，例如 `192.168.1.0/24`。
dhcp-tip-pools = 該子網路的動態位址集區。
dhcp-tip-routers = 下發給用戶端的路由器（預設閘道）選項。
dhcp-tip-domain-servers = 下發給用戶端的 DNS 伺服器（`domain-name-servers`）。
dhcp-tip-pool = 位址集區，寫作範圍 `192.168.1.100 - 192.168.1.200` 或前置碼 `192.168.1.0/24`。

## dhcp module — validation diagnostics
dhcp-empty-key = 某項 dnsmasq 設定的選項名稱為空。
dhcp-invalid-key = `{$key}` 不是有效的 dnsmasq 選項名稱；它必須是不含空白字元、`=` 或 `#` 的單一個單字。
dhcp-malformed-cidr = `{$value}` 不是有效的 CIDR 前置碼，例如 `192.168.1.0/24`。
dhcp-malformed-pool = `{$value}` 不是有效的位址集區；請使用 `192.168.1.100 - 192.168.1.200` 這樣的範圍，或 CIDR 前置碼。
dhcp-external-directive = `{$key}` 會載入外部檔案或執行指令；此模組不會建立或修改跨出其設定檔案邊界的指令。
dhcp-authoritative-set = `dhcp-authoritative` 會讓 dnsmasq 成為該網段中唯一的 DHCP 伺服器；僅在不存在其他 DHCP 伺服器時才設定它。
dhcp-kea-interfaces-empty = {$server} 未設定任何介面，將在所有介面上監聽；請明確指定介面。
dhcp-rec-rebind = domain-needed 和 bogus-priv 並未同時設定；它們用於過濾 DNS 重新繫結攻擊，以及送往上游的私有位址 A 記錄查詢。
dhcp-rec-lifetime = {$server} 的 valid-lifetime 為 {$lifetime}；請將其保持在 300 到 86400 秒之間，讓租約能如預期地續期。

## hosts module — display name, security notes, schema tooltips
hosts-name = hosts
hosts-note-spoofing = 這裡的項目會覆寫 DNS；錯誤或惡意的項目會在不知不覺中重新導向名稱查詢。
hosts-tip-entries = /etc/hosts 中位址與名稱的對應（依檔案中的順序）。
hosts-tip-ip = 下方的名稱所解析到的位址。
hosts-tip-hostnames = 解析到此位址的名稱，正規名稱在前。
hosts-tip-comment = 此項目的行內註解（如有）。

## hosts module — validation diagnostics
hosts-invalid-hostname = `{$name}` 不是有效的主機名稱。
hosts-duplicate-canonical = `{$name}` 是多個項目的正規名稱。
hosts-no-hostnames = 此項目沒有主機名稱。
hosts-hostname-is-ip = `{$name}` 是位址常值，不是主機名稱。
hosts-ipv6-zone-unsupported = `{$name}` 帶有 IPv6 區域 ID，而 /etc/hosts 不支援它。
hosts-hostname-multiple-ips = `{$name}` 解析到同一位址系列的多個位址。
hosts-localhost-not-loopback = `localhost` 指向 `{$ip}`，而它不是迴路位址。
hosts-missing-localhost = 沒有 `localhost` 項目。
hosts-missing-ipv6-localhost = 沒有 IPv6 的 `localhost` 項目。
hosts-too-many-entries = 此檔案包含 {$count} 個項目；請考慮改用 DNS。

## mounts module — display name, security notes, schema tooltips
mounts-name = mounts
mounts-note-boot = 錯誤的 /etc/fstab 可能導致主機在下次重新啟動時無法開機；每次變更都需要再次確認。確認無法發現錯誤的項目，因為在下次開機之前沒有任何程式會讀取該檔案。
mounts-tip-entries = /etc/fstab 中的掛載項目（依檔案中的順序）。
mounts-tip-spec = 掛載的對象：裝置、`UUID=...`/`LABEL=...`、nfs 匯出，或代表交換空間的 `none`。
mounts-tip-mountpoint = 檔案系統的掛載位置；交換空間則為 `none`/`swap`。
mounts-tip-fstype = 檔案系統類型，例如 ext4，或 `swap`。
mounts-tip-options = 以逗號分隔的掛載選項，例如 defaults,nosuid。
mounts-tip-dump = dump(8) 的備份頻率；幾乎總是 0。
mounts-tip-pass = fsck 的檢查順序編號：根檔案系統為 1，其他需檢查的檔案系統為 2，0 表示略過。
mounts-rec-options = 對使用者可寫入的資料使用 nosuid、nodev 和 noexec 加以保護；對網路檔案系統建議使用 x-systemd.automount。

## mounts module — validation diagnostics
mounts-empty-spec = 第 {$index} 個項目的 spec（第一欄）為空。
mounts-empty-mountpoint = 第 {$index} 個項目的掛載點（第二欄）為空。
mounts-invalid-fstype = `{$fstype}` 不是有效的檔案系統類型。
mounts-pass-too-high = 第 {$index} 個項目的 pass 為 `{$pass}`；fsck 最多執行 2 輪。
mounts-root-pass = 根檔案系統的 pass 應為 1，而不是 `{$pass}`。
mounts-missing-nofail = `{$mountpoint}` 是卸除式媒體，但沒有 `nofail`；拔除後開機會卡住。
mounts-missing-boot-escape = `{$mountpoint}` 既沒有 nofail 也沒有 noauto；掛載失敗可能會拖住開機程序。
mounts-critical-noauto = `{$mountpoint}` 是開機所必需的，但帶有 noauto，因此系統可能在沒有它的情況下繼續開機。
mounts-missing-guards = `{$mountpoint}` 掛載了使用者可寫入的資料，但沒有 `{$missing}`；請加入。
mounts-network-automount = `{$mountpoint}` 是網路檔案系統，但沒有 `x-systemd.automount`；開機時會等待網路。
mounts-noauto-without-user = 有 `noauto` 而沒有 `user`：只有 root 才能掛載它，這就失去了意義。
mounts-relative-mountpoint = 第 {$index} 個項目掛載到 `{$mountpoint}`，而它不是絕對路徑。
mounts-no-root-entry = 沒有任何項目掛載 `/`；請確認根檔案系統是透過其他方式掛載的。

## network module — display name, security notes, schema tooltips
network-name = network
network-note-precedence = 錯誤的網路設定可能使管理員無法連線到此主機；每次變更都需要再次確認。
network-tip-interfaces = 此主機所設定的介面（依檔案中的順序）。
network-tip-iface-name = 介面名稱，例如 eth0。
network-tip-iface-dhcp-v4 = 此介面是否透過 DHCP 取得其 IPv4 位址。
network-tip-iface-dhcp-v6 = 此介面是否透過 DHCP 取得其 IPv6 位址。
network-tip-iface-addresses = CIDR 表示法的靜態位址，例如 192.168.1.10/24。
network-tip-iface-gateway-v4 = IPv4 的預設閘道，用於靜態定址的情況。
network-tip-iface-gateway-v6 = IPv6 的預設閘道，用於靜態定址的情況。
network-tip-iface-dns = 此介面使用的 DNS 伺服器。
network-tip-iface-routes = 此介面的靜態路由。
network-tip-iface-vlan = 此介面的 VLAN 設定（當它是 VLAN 時）。
network-tip-iface-bridge = 此介面的橋接器設定（當它是橋接器時）。
network-tip-route-to = 目的地 CIDR 或 default。
network-tip-route-via = 下一躍點 IP。
network-tip-vlan-link = 此 VLAN 的父連結，例如 eth0。
network-tip-vlan-id = VLAN id，1–4094。
network-tip-bridge-members = 此橋接器的成員介面名稱。

## network module — validation diagnostics
network-invalid-cidr = `{$value}` 不是有效的 CIDR 位址。
network-invalid-ip = `{$value}` 不是有效的 IP 位址。
network-gateway-outside-subnet = 閘道 `{$gateway}` 不在此介面的子網路之內。
network-vlan-range = VLAN id `{$id}` 超出了 1–4094 的範圍。
network-duplicate-interface = 介面 `{$name}` 出現了多次。
network-interface-order = 介面 `{$name}` 必須排在它上方的介面之前：請依名稱順序列出介面。
network-injection = `{$value}` 包含換行字元或空位元組。
network-static-no-gateway = 此靜態定址的介面沒有閘道。
network-static-no-dns = 此靜態定址的介面沒有 DNS 伺服器。
network-dhcp-static-mixed = 此介面同時使用了 DHCP 和靜態位址。
network-rec-ipv6-privacy = 啟用 DHCPv6 時，請同時啟用 IPv6 隱私擴充功能。
network-rec-ra-accept = 僅在明確由 DHCPv6 管理時才接受路由器通告。
network-rec-no-promisc = 此介面不應執行於混雜模式。

## nfs module — display name, security notes, schema tooltips
nfs-name = nfs
nfs-note-live-state = 匯出規則由核心在每次掛載時強制執行；錯誤的一行會在不知不覺中改變哪些主機可以讀取哪些檔案系統。
nfs-tip-entries = /etc/exports 中的匯出項目（依檔案中的順序）。
nfs-tip-path = 匯出點：此主機上的絕對目錄路徑。
nfs-tip-clients = 允許掛載此匯出的主機，依比對順序排列；第一個符合的規格生效。
nfs-tip-host = 用戶端規格：名稱、位址、位址/子網路遮罩、萬用字元、`*`（所有用戶端）或 @netgroup。
nfs-tip-options = 此用戶端的匯出選項，以逗號分隔；清單為空則採用檔案的預設值。
nfs-rec-options = 請明確寫出 rw/ro、sync/async、root_squash 以及子樹處理方式；不同 nfs-utils 版本之間的預設值會有變動。

## nfs module — validation diagnostics
nfs-empty-path = 某個匯出點為空。
nfs-relative-path = `{$path}` 不是絕對路徑；匯出點必須以 `/` 開頭。
nfs-empty-host = `{$path}` 的某個用戶端沒有主機規格。
nfs-bad-host = `{$host}` 不是有效的用戶端規格；它以 `-` 開頭，或包含會截斷該行的語法。
nfs-bad-path = `{$path}` 包含會截斷匯出行的語法。
nfs-bad-continuation = `{$path}` 會以續行反斜線結尾，並折疊下一行。
nfs-invalid-option = `{$option}` 不是有效的匯出選項；選項是不含空白字元或括號的單一權杖。
nfs-no-root-squash = `{$host}` 使用 no_root_squash 掛載，並在匯出上保留 root 權限。
nfs-sec-sys-only = `{$host}` 使用預設的 sec=sys，或只協商 sec=sys；請加入 krb5p 以取得加密保護。
nfs-world-export = 每個用戶端都可以對 `{$host}` 進行讀寫存取。
nfs-subtree-undecided = `{$host}` 既沒有指定 subtree_check 也沒有指定 no_subtree_check；上游已更改預設值，請明確說明您想要哪一個。
nfs-root-squash-undecided = `{$host}` 既沒有指定 root_squash 也沒有指定 no_root_squash；請明確說明您想要哪一個。
nfs-sync-undecided = `{$host}` 既沒有指定 sync 也沒有指定 async；建議使用 sync，它會將寫入提交到穩定的儲存裝置。

## resolver module — display name, security notes, schema tooltips
resolver-name = resolver
resolver-note-managed-symlink = 在此主機上 /etc/resolv.conf 由某個解析器後端管理；detent 拒絕編輯受管理的符號連結目標，而是改為設定該後端。
resolver-tip-resolv = 此模組所處理的 /etc/resolv.conf 指令；檔案中的其他內容會原封不動地保留。
resolver-tip-resolved = systemd-resolved 的設定（依檔案中的順序）。變更這些設定會重新啟動 systemd-resolved。
resolver-tip-unbound = 此模組所處理的 unbound.conf 項目（依檔案中的順序）。變更這些設定會重新啟動 unbound。

## resolver module — validation diagnostics
resolver-no-nameserver = 未設定任何 nameserver。
resolver-duplicate-nameserver = `{$ip}` 作為 nameserver 出現了多次。
resolver-too-many-nameservers = 此檔案列出了 {$count} 個 nameserver；glibc 最多讀取 {$max} 個。
resolver-invalid-domain = `{$domain}` 不是有效的網域名稱。
resolver-unknown-option = `{$option}` 不是 glibc 的 resolv.conf 剖析器所接受的選項。
resolver-search-and-domain = 同時存在 `search` 和 `domain`；設定了 `search` 時，glibc 會忽略 `domain`。
resolver-no-config = 此模型完全沒有設定任何解析器後端。
resolver-backend-missing = 這些設定用於設定 {$service}，但在此主機上未偵測到它。
resolver-rec-dnssec = DNSSEC 設定為 allow-downgrade；`DNSSEC=yes` 會進行嚴格驗證，在上游資料允許的情況下建議使用。
resolver-rec-dot = DNSOverTLS 為機會性模式，會降級為明文；`DNSOverTLS=yes` 則強制要求使用 TLS。
resolver-unknown-hardening = `{$key}` 不是此模組為 unbound 所處理的指令。
resolver-unbound-misplaced = `{$key}` 應放在 unbound.conf 的 {$section} 區段中，而不是這裡。
resolver-invalid-forward-addr = `{$addr}` 不是 ip[@port][#auth-name] 形式的有效 forward-addr。
resolver-invalid-forward-name = `{$name}` 不是有效的 forward-zone 名稱。
resolver-forward-tls-no-auth = 此區域透過 TLS 轉送，但其 forward-addr 沒有 `#auth-name`，因此該 TLS 連線未經驗證。
resolver-rec-hardening = `{$key}` 已被停用；啟用它可以強化 unbound，防禦上游偽造和委派濫用。
resolver-forward-zone-unnamed = 沒有 name: 的 forward-zone: 不會轉送任何內容，還會削弱設定；請為每個區域命名。

## samba module — display name, security notes, schema tooltips
samba-name = samba
samba-note-guest-access = 訪客存取權限在連線時依共用項目逐一授與；錯誤的值會讓檔案在沒有密碼的情況下暴露。
samba-tip-entries = 此模組所處理的 smb.conf 項目（依檔案中的順序）：`[section]` 標頭和指令都包括在內。
samba-tip-section = `[section]` 標頭的區段名稱；對於一般指令行則為空。
samba-tip-key = 參數名稱，不區分大小寫，可能由多個單字組成（`guest ok`）。
samba-tip-value = 參數的值，直到行尾；`%` 巨集會原封不動地保留。
samba-rec-value = 建議明確指定強化後的值，不要依賴上游編譯時內建的預設值。

## samba module — validation diagnostics
samba-empty-key = 某條指令沒有參數名稱。
samba-empty-section = 某個區段標頭為空。
samba-bad-key = `{$key}` 會被剖析為區段或註解，而不是指令鍵。
samba-bad-value = `{$value}` 以 `\` 結尾，會吞掉下一行。
samba-bad-section = `{$section}` 包含 `[` 或 `]`，或以 `\` 結尾，無法完整往返還原。
samba-guest-ok = `guest ok` 設定為 {$value}；未經驗證的用戶端可以連線到所有繼承該設定的共用項目。
samba-map-to-guest = `map to guest` 為 {$value}；除 Never 之外的任何值都會把登入失敗變成訪客工作階段。
samba-min-protocol = `server min protocol` 為 {$value}；請至少設定為 SMB3_00，並捨棄 SMB1 時代的通訊協定等級。
samba-smb-encrypt = `smb encrypt` 為 {$value}；請設定為 required，使 SMB 流量不能以未加密的方式傳輸。
samba-restrict-anonymous = `restrict anonymous` 為 {$value}；設定為 2 可向匿名使用者隱藏共用項目清單。
samba-rec-server-signing = `server signing` 為 {$value}；請設定為 mandatory，使 SMB 流量經過密碼學簽章。
samba-rec-load-printers = `load printers` 為 {$value}；除非此主機確實共用印表機，否則請設定為 no。
samba-rec-interfaces = 未設定 `interfaces` 指令；請將 samba 繫結到明確的位址，而不是監聽所有介面。
samba-writable-exposure = 此共用項目透過 writeable、read only 或 write list 允許寫入；請確認是否每個用戶端都應有寫入權限。
samba-root-command = `{$key}` 會在每個符合的連線上以 root 權限執行指令。
samba-client-command = `{$key}` 允許用戶端讓 samba 執行指令；指令的內容由用戶端控制。
samba-usershare-guests = `usershare allow guests` 為 {$value}；使用者可以發布任何人無需密碼即可開啟的共用項目。
samba-wide-links = `wide links` 為 {$value}；符號連結可能把用戶端引到共用項目之外。

## module template — copy-me example
TEMPLATE-name = 模組範本
TEMPLATE-note-precedence = 這個虛構的模組是供新設定模組參考、經過編譯檢查的範例。
TEMPLATE-tip-settings = 這個虛構模組所處理的設定（依檔案中的順序）。
TEMPLATE-tip-key = 指令名稱，單一個單字，不含空白字元。
TEMPLATE-tip-value = 指令的值，直到行尾。
TEMPLATE-rec-value = 建議明確指定值，不要依賴上游的預設值。
TEMPLATE-invalid-key = `{$key}` 不是有效的指令名稱。
TEMPLATE-duplicate-key = `{$key}` 被設定了多次；以最後一個值為準。
TEMPLATE-too-many-settings = 此檔案包含 {$count} 項設定；請將大型設定拆分為較小的檔案。

## detent-core — parse, model, and edit errors
## These are the failures a module's own document model can raise, so they are
## prefixed `core-` rather than with a module id.
core-parse-malformed = 此檔案不符合 `{$module}` 所要求的格式：{$reason}
core-model-shape = 提供的設定不具備預期的結構：{$reason}
core-model-unrepresentable = 此檔案包含編輯器無法表示的內容：{$reason}
core-edit-line-break = 值不能包含換行字元或空位元組；`{$value}` 包含了。
core-edit-index-out-of-range = 內部錯誤：第 {$index} 行超出了只有 {$len} 行的檔案範圍。
core-edit-unsupported = 此編輯無法用該檔案的格式表達：{$reason}

## detent-core — version-gated options
core-version-too-old = `{$option}` 需要 {$service} {$since} 或更新版本；此主機上的版本是 {$installed}。
core-version-unknown = 已安裝的 {$service} 版本未知，因此 `{$option}`（需要 {$service} {$since} 或更新版本）可能無法使用。

## operations layer — errors surfaced by detent-ops
ops-unknown-module = 此組建中沒有名為 `{$module}` 的模組。
ops-invalid-model = `{$module}` 的設定無效：{$reason}
ops-check-failed = 外部驗證程式 `{$program}` 拒絕了候選設定：{$reason}
ops-hash-conflict = `{$path}` 在被讀取之後已在磁碟上發生變更；請重新讀取後再試。
ops-privsep-failed = 特權輔助程式拒絕了要求，或無法完成要求：{$reason}
ops-service-failed = 服務操作未能完成：{$reason}
ops-no-target = `{$module}` 在此主機上不管理任何檔案。
ops-no-service = `{$module}` 在此主機上不控制任何服務，因此無法重新啟動。
ops-audit-failed = 無法讀取稽核記錄：{$reason}
ops-audit-unavailable = 無法寫入稽核記錄，因此該操作被拒絕：{$reason}
ops-unsupported = 此組建不支援{$what}。
ops-commit-pending = 已有另一個 commit-confirm 視窗處於待確認狀態。
ops-update-running = 更新已在執行；請等待其完成，然後檢查目前執行的版本。
ops-update-tag-invalid = 這不是發行版本號；它的格式必須類似 v1.2.3。
ops-update-not-newer = 該發行版本並不比目前執行的版本更新；未啟動任何操作。
ops-no-backup = commit-confirm 需要保留一份備份；未做任何變更。
ops-arm-failed-restored = 無法啟用 commit-confirm，因此變更已被復原；先前的內容已還原。
ops-arm-failed-unrestored = 無法啟用 commit-confirm，且變更無法復原；新內容仍在磁碟上。請立即還原先前的備份。
ops-target-missing = 受管理的檔案不存在；請建立它（安裝其套件或手動建立），然後重試。
ops-denied = 您沒有執行此操作的權限。

## detent-web — configuration, TLS, the operations bridge, and the listener
web-config-unreadable = 無法讀取 `{$path}`：{$reason}
web-config-malformed = `{$path}` 不是有效的 detent 設定：{$reason}
web-config-zero-value = `{$field}` 必須大於零。
web-config-weak-argon2 = `auth.argon2.m_kib` 為 {$m}，低於最小值 {$min} kib。
web-tls-generate-failed = 無法產生引導憑證：{$reason}
web-tls-key-rejected = 憑證及其私密金鑰被拒絕：{$reason}
web-tls-store-unreadable = 無法讀取 `{$path}`：{$reason}
web-tls-store-unwritable = 無法為寫入準備 `{$path}`：{$reason}
web-tls-store-write-failed = 無法寫入 `{$path}`：{$reason}
web-tls-acme-pem-rejected = 簽發的憑證或金鑰不是可用的 PEM。
web-engine-stopped = 操作引擎已不再執行；請在服務恢復後重試。
web-cert-renew-not-acme = 更新憑證需要在 detent.toml 中設定 `tls.bootstrap = "acme"`。
web-cert-renew-unavailable = acme 用戶端沒有收到更新要求；請稍後再試。
web-update-not-checked = 此主機尚未進行過更新檢查；請以 root 身分執行 `detent update --check`。
web-server-bind-failed = 無法監聽 `{$addr}`：{$reason}
web-server-address-unknown = 無法回讀監聽位址：{$reason}

## detent-web — auth: passwords, sessions, api tokens, totp, csrf
web-auth-entropy-unavailable = 系統亂數產生器發生故障，因此無法簽發任何認證資訊。
web-auth-argon2-params = 所設定的 argon2 參數無法使用：{$reason}
web-auth-hash-failed = 無法對密碼進行雜湊。
web-auth-password-too-short = 密碼至少須有 12 個字元。
web-auth-password-too-long = 密碼最多只能有 128 個字元。
web-auth-password-unchanged = 新密碼必須與目前的密碼不同。
web-auth-password-change-required = 請先變更密碼，然後再進行其他操作。
web-auth-user-name-invalid = `{$name}` 不是可用的使用者名稱；請使用 1 到 32 個 `a-z`、`0-9`、`.`、`_` 或 `-` 字元，並以字母或數字開頭。
web-auth-user-exists = 名為 `{$name}` 的使用者已存在。
web-auth-user-unknown = 沒有名為 `{$name}` 的使用者。
web-auth-invalid-credentials = 使用者名稱、密碼或驗證碼不正確。
web-auth-rate-limited = 嘗試次數過多；請等待 {$seconds} 秒後再試。
web-auth-session-limit = 開啟的工作階段過多；請等待其中一個過期後再重新登入。
web-auth-busy = 正在進行的登入過多；請稍候再試。
web-auth-unauthenticated = 請先登入再執行此操作。
web-auth-ambiguous-credentials = 請傳送工作階段 cookie 或 bearer 權杖二者之一，不要同時傳送。
web-auth-csrf-rejected = 此要求未通過跨站檢查。
web-auth-token-unknown = 該 api 權杖不存在、已被撤銷或已過期。
web-auth-token-limit = 此主機已持有 api 權杖數量的上限。
web-auth-totp-secret-invalid = 該驗證器金鑰不是有效的 base32。
web-auth-store-unreadable = 無法讀取 `{$path}`：{$reason}
web-auth-store-unwritable = 無法為寫入準備 `{$path}`：{$reason}
web-auth-store-write-failed = 無法寫入 `{$path}`：{$reason}
web-auth-store-malformed = `{$path}` 不是有效的 detent 認證資訊檔案：{$reason}
web-denied-scope = 此認證資訊不具備 `{$scope}` 範圍。

## detent-web — the api surface
web-request-malformed = 要求本文的結構不是此端點所預期的。
web-request-too-deep = 要求本文的巢狀層級過深。
web-api-unexpected-outcome = 操作已完成，但其結果無法呈現。
