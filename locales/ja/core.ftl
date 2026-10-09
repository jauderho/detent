# needs-review: machine-drafted Japanese translation; not yet checked by a native speaker.
## detent-core — ja
## Source: locales/en-US/core.ftl. Same ids, same placeables. Code-like tokens
## (directive names, paths, flags, option values) stay untranslated.

## chrony module — display name, security notes, schema tooltips
chrony-name = chrony
chrony-note-precedence = このファイルは組み込みの既定値を上書きします。誤った値は、ホストの時刻管理を黙って変えてしまいます。
chrony-tip-settings = このモジュールが扱う chrony.conf のディレクティブ (ファイル内の順)。ファイル内のそれ以外の内容はそのまま保持されます。
chrony-tip-key = ディレクティブ名。1 語で、大文字と小文字は区別されません。
chrony-tip-value = このディレクティブの値 (行末まで)。`rtcsync` のように値を持たないディレクティブでは空です。
chrony-rec-value = 組み込みの既定値に頼らず、明示的な値を指定することをお勧めします。

## chrony module — validation diagnostics
chrony-privileged-directive = `{$key}` は chronyd が root として書き込むファイル、または chronyd の実行ユーザーを設定します。適用する前に値を確認してください。
chrony-invalid-key = `{$key}` は有効な chrony ディレクティブ名ではありません。
chrony-duplicate-key = `{$key}` が複数回設定されています。最後の値が有効です。
chrony-too-many-settings = このファイルには {$count} 個の設定があります。/etc/chrony/conf.d の下のドロップインファイルに分割してください。
chrony-allow-open = `allow {$value}` はインターネット全体に時刻を提供します。必要なネットワークだけを許可してください。
chrony-missing-makestep = makestep が設定されていません。起動時にクロックが範囲内に補正されず、際限なくずれる可能性があります。
chrony-missing-rtcsync = rtcsync が設定されていません。ハードウェアクロックがシステムクロックに対してずれていきます。
chrony-rec-nts = プール {$pool} が nts オプションなしで使われています。時刻を偽装されないよう、nts 対応のソースを選んでください。
chrony-cmdport-open = cmdport は {$port} です。chronyc がネットワーク経由でこのホストに接続する必要がない限り、cmdport 0 に設定してください。
chrony-external-directive = `{$key}` は外部ファイルを読み込むか外部プログラムを実行します。このモジュールは、設定されたファイル境界を越えるディレクティブを拒否します。

## dhcp module — display name, security notes, schema tooltips
dhcp-name = dhcp
dhcp-note-commit-confirm = DHCP の誤った変更は、すべてのクライアントとあなた自身をネットワークから切り離します。確認する前に差分を慎重に確認してください。
dhcp-tip-dnsmasq = /etc/dnsmasq.conf の `key=value` 設定 (ファイル内の順)。コメントと未知の行はそのまま保持されます。
dhcp-tip-kea-v4 = Kea DHCPv4 サーバー (`Dhcp4`) の管理対象部分。未知の Kea オプションはそのまま保持されます。
dhcp-tip-kea-v6 = Kea DHCPv6 サーバー (`Dhcp6`) の管理対象部分。未知の Kea オプションはそのまま保持されます。
dhcp-tip-key = dnsmasq のオプション名。1 語で、空白を含みません。
dhcp-tip-value = `=` の後の値。`domain-needed` のような単独のフラグには値がありません。
dhcp-tip-interfaces = Kea サーバーが待ち受けるインターフェース。リストが空の場合、サーバーはすべてのインターフェースで応答します。
dhcp-tip-valid-lifetime = 既定のリース期間 (秒)。ほとんどのネットワークでは 3600 が妥当な既定値です。
dhcp-tip-subnets = サーバーがアドレスを割り当てるサブネット。
dhcp-tip-id = Kea の安定したサブネット識別子。リースはこの値で管理されるため、編集しても変えないでください。
dhcp-tip-subnet = CIDR 形式のサブネットプレフィックス。例: `192.168.1.0/24`。
dhcp-tip-pools = このサブネットの動的アドレスプール。
dhcp-tip-routers = クライアントに渡すルーター (デフォルトゲートウェイ) オプション。
dhcp-tip-domain-servers = クライアントに渡す DNS サーバー (`domain-name-servers`)。
dhcp-tip-pool = プール。範囲 `192.168.1.100 - 192.168.1.200` またはプレフィックス `192.168.1.0/24` で指定します。

## dhcp module — validation diagnostics
dhcp-empty-key = dnsmasq の設定のオプション名が空です。
dhcp-invalid-key = `{$key}` は有効な dnsmasq オプション名ではありません。空白、`=`、`#` を含まない 1 語でなければなりません。
dhcp-malformed-cidr = `{$value}` は有効な CIDR プレフィックスではありません。例: `192.168.1.0/24`。
dhcp-malformed-pool = `{$value}` は有効なプールではありません。`192.168.1.100 - 192.168.1.200` のような範囲か、CIDR プレフィックスを使用してください。
dhcp-external-directive = `{$key}` は外部ファイルを読み込むかコマンドを実行します。このモジュールは、設定されたファイル境界を越えるディレクティブを作成も変更もしません。
dhcp-authoritative-set = `dhcp-authoritative` は dnsmasq をそのセグメントで唯一の DHCP サーバーにします。ほかに DHCP サーバーがない場合にのみ設定してください。
dhcp-kea-interfaces-empty = {$server} にはインターフェースが設定されておらず、すべてのインターフェースで待ち受けます。インターフェースを明示してください。
dhcp-rec-rebind = domain-needed と bogus-priv の両方は設定されていません。これらはリバインド攻撃と、プライベートアドレスに対するアップストリームへの A クエリを防ぎます。
dhcp-rec-lifetime = {$server} の valid-lifetime は {$lifetime} です。リースが予測どおり更新されるよう、300 秒から 86400 秒の間にしてください。

## hosts module — display name, security notes, schema tooltips
hosts-name = hosts
hosts-note-spoofing = ここのエントリは DNS より優先されます。誤ったエントリや悪意のあるエントリは、名前解決を黙って別の宛先へ向けます。
hosts-tip-entries = /etc/hosts のアドレスと名前の対応 (ファイル内の順)。
hosts-tip-ip = 下の名前が解決されるアドレス。
hosts-tip-hostnames = このアドレスに解決される名前。正規名が先頭です。
hosts-tip-comment = このエントリの行内コメント (ある場合)。

## hosts module — validation diagnostics
hosts-invalid-hostname = `{$name}` は有効なホスト名ではありません。
hosts-duplicate-canonical = `{$name}` が複数のエントリの正規名になっています。
hosts-no-hostnames = このエントリにはホスト名がありません。
hosts-hostname-is-ip = `{$name}` はホスト名ではなく、アドレスリテラルです。
hosts-ipv6-zone-unsupported = `{$name}` には IPv6 ゾーン ID が含まれていますが、/etc/hosts はこれをサポートしていません。
hosts-hostname-multiple-ips = `{$name}` は同じファミリーの複数のアドレスに解決されます。
hosts-localhost-not-loopback = `localhost` が `{$ip}` を指していますが、これはループバックアドレスではありません。
hosts-missing-localhost = `localhost` のエントリがありません。
hosts-missing-ipv6-localhost = IPv6 の `localhost` エントリがありません。
hosts-too-many-entries = このファイルには {$count} 個のエントリがあります。代わりに DNS の利用を検討してください。

## mounts module — display name, security notes, schema tooltips
mounts-name = mounts
mounts-note-boot = /etc/fstab が誤っていると、次回の再起動でホストが起動不能になることがあります。すべての変更に 2 回目の確認が必要です。次回の起動までファイルを読むものがないため、確認では誤ったエントリを検出できません。
mounts-tip-entries = /etc/fstab のマウントエントリ (ファイル内の順)。
mounts-tip-spec = マウント対象。デバイス、`UUID=...`/`LABEL=...`、nfs エクスポート、またはスワップの場合は `none`。
mounts-tip-mountpoint = ファイルシステムのマウント先。スワップの場合は `none`/`swap`。
mounts-tip-fstype = ファイルシステムの種類。例: ext4、またはスワップの場合は `swap`。
mounts-tip-options = カンマ区切りのマウントオプション。例: defaults,nosuid。
mounts-tip-dump = dump(8) のバックアップ頻度。ほとんどの場合 0 です。
mounts-tip-pass = fsck のパス番号。ルートは 1、その他のチェック対象は 2、スキップは 0。
mounts-rec-options = ユーザーが書き込めるデータは nosuid、nodev、noexec で保護してください。ネットワークファイルシステムでは x-systemd.automount を推奨します。

## mounts module — validation diagnostics
mounts-empty-spec = エントリ {$index} の spec (1 列目) が空です。
mounts-empty-mountpoint = エントリ {$index} のマウントポイント (2 列目) が空です。
mounts-invalid-fstype = `{$fstype}` は有効なファイルシステムの種類ではありません。
mounts-pass-too-high = エントリ {$index} の pass は `{$pass}` です。fsck のパスは最大 2 です。
mounts-root-pass = ルートファイルシステムの pass は `{$pass}` ではなく 1 にしてください。
mounts-missing-nofail = `{$mountpoint}` はリムーバブルメディアですが `nofail` がありません。取り外すと起動が停止します。
mounts-missing-boot-escape = `{$mountpoint}` には nofail も noauto もありません。マウントに失敗すると起動が止まることがあります。
mounts-critical-noauto = `{$mountpoint}` は起動に必要ですが noauto が指定されているため、システムはこれなしで続行する可能性があります。
mounts-missing-guards = `{$mountpoint}` はユーザーが書き込めるデータを `{$missing}` なしでマウントします。追加してください。
mounts-network-automount = `{$mountpoint}` はネットワークファイルシステムですが `x-systemd.automount` がありません。起動時にネットワークを待ちます。
mounts-noauto-without-user = `noauto` が `user` なしで指定されています。root だけがマウントでき、意味がありません。
mounts-relative-mountpoint = エントリ {$index} は `{$mountpoint}` にマウントしますが、これは絶対パスではありません。
mounts-no-root-entry = `/` をマウントするエントリがありません。ルートファイルシステムが別の方法でマウントされているか確認してください。

## network module — display name, security notes, schema tooltips
network-name = network
network-note-precedence = ネットワーク設定の誤りは、管理者をこのホストから切り離すことがあります。すべての変更に 2 回目の確認が必要です。
network-tip-interfaces = このホストが設定するインターフェース (ファイル内の順)。
network-tip-iface-name = インターフェース名。例: eth0。
network-tip-iface-dhcp-v4 = このインターフェースが DHCP で IPv4 アドレスを取得するかどうか。
network-tip-iface-dhcp-v6 = このインターフェースが DHCP で IPv6 アドレスを取得するかどうか。
network-tip-iface-addresses = CIDR 表記の静的アドレス。例: 192.168.1.10/24。
network-tip-iface-gateway-v4 = 静的アドレス指定の場合の IPv4 デフォルトゲートウェイ。
network-tip-iface-gateway-v6 = 静的アドレス指定の場合の IPv6 デフォルトゲートウェイ。
network-tip-iface-dns = このインターフェースの DNS サーバー。
network-tip-iface-routes = このインターフェースの静的ルート。
network-tip-iface-vlan = このインターフェースが VLAN の場合の VLAN 設定。
network-tip-iface-bridge = このインターフェースがブリッジの場合のブリッジ設定。
network-tip-route-to = 宛先の CIDR または default。
network-tip-route-via = ネクストホップの IP。
network-tip-vlan-link = この VLAN の親リンク。例: eth0。
network-tip-vlan-id = VLAN ID。1–4094。
network-tip-bridge-members = このブリッジのメンバーインターフェース名。

## network module — validation diagnostics
network-invalid-cidr = `{$value}` は有効な CIDR アドレスではありません。
network-invalid-ip = `{$value}` は有効な IP アドレスではありません。
network-gateway-outside-subnet = ゲートウェイ `{$gateway}` がこのインターフェースのサブネットの外にあります。
network-vlan-range = VLAN ID `{$id}` が 1–4094 の範囲外です。
network-duplicate-interface = インターフェース `{$name}` が複数回出現しています。
network-interface-order = インターフェース `{$name}` は上にあるインターフェースより前に置く必要があります。インターフェースは名前順に並べてください。
network-injection = `{$value}` に改行または null バイトが含まれています。
network-static-no-gateway = この静的アドレスのインターフェースにはゲートウェイがありません。
network-static-no-dns = この静的アドレスのインターフェースには DNS サーバーがありません。
network-dhcp-static-mixed = このインターフェースには DHCP と静的アドレスの両方があります。
network-rec-ipv6-privacy = DHCPv6 を使う場合は、IPv6 プライバシー拡張を有効にしてください。
network-rec-ra-accept = ルーターアドバタイズは、DHCPv6 を明示的に管理している場合にのみ受け入れてください。
network-rec-no-promisc = このインターフェースはプロミスキャスモードで動作させないでください。

## nfs module — display name, security notes, schema tooltips
nfs-name = nfs
nfs-note-live-state = エクスポートはマウントのたびにカーネルが適用します。誤った行は、どのホストがどのファイルシステムを読めるかを黙って変えてしまいます。
nfs-tip-entries = /etc/exports のエクスポート (ファイル内の順)。
nfs-tip-path = エクスポートポイント。このホスト上の絶対ディレクトリパス。
nfs-tip-clients = このエクスポートをマウントできるホスト (照合順)。最初に一致した指定が優先されます。
nfs-tip-host = クライアント指定。名前、アドレス、アドレス/ネットマスク、ワイルドカード、`*` (すべてのクライアント)、または @netgroup。
nfs-tip-options = このクライアントのエクスポートオプション (カンマ区切り)。リストが空の場合はファイルの既定値が使われます。
nfs-rec-options = rw/ro、sync/async、root_squash、サブツリーの扱いを明示してください。既定値は nfs-utils のリリース間で変わります。

## nfs module — validation diagnostics
nfs-empty-path = エクスポートポイントが空です。
nfs-relative-path = `{$path}` は絶対パスではありません。エクスポートポイントは `/` で始まる必要があります。
nfs-empty-host = `{$path}` のクライアントにホスト指定がありません。
nfs-bad-host = `{$host}` は有効なクライアント指定ではありません。`-` で始まっているか、行が途中で切れる構文を含んでいます。
nfs-bad-path = `{$path}` に、エクスポート行を途中で切る構文が含まれています。
nfs-bad-continuation = `{$path}` は継続のバックスラッシュで終わり、次の行を連結してしまいます。
nfs-invalid-option = `{$option}` は有効なエクスポートオプションではありません。オプションは空白や括弧を含まない単純なトークンです。
nfs-no-root-squash = `{$host}` は no_root_squash でマウントされ、エクスポート上で root 権限を保持します。
nfs-sec-sys-only = `{$host}` は既定の sec=sys を使うか、sec=sys のみをネゴシエートします。暗号による保護のため krb5p を追加してください。
nfs-world-export = `{$host}` はすべてのクライアントから読み書き可能です。
nfs-subtree-undecided = `{$host}` は subtree_check も no_subtree_check も指定していません。アップストリームが既定値を変更したため、どちらにするか明示してください。
nfs-root-squash-undecided = `{$host}` は root_squash も no_root_squash も指定していません。どちらにするか明示してください。
nfs-sync-undecided = `{$host}` は sync も async も指定していません。書き込みを安定したストレージにコミットする sync を推奨します。

## resolver module — display name, security notes, schema tooltips
resolver-name = resolver
resolver-note-managed-symlink = このホストでは /etc/resolv.conf はリゾルバーバックエンドによって管理されています。detent は管理対象のシンボリックリンクの参照先を編集せず、代わりにバックエンドを設定します。
resolver-tip-resolv = このモジュールが扱う /etc/resolv.conf のディレクティブ。ファイル内のそれ以外の内容はそのまま保持されます。
resolver-tip-resolved = systemd-resolved の設定 (ファイル内の順)。変更すると systemd-resolved が再起動されます。
resolver-tip-unbound = このモジュールが扱う unbound.conf の項目 (ファイル内の順)。変更すると unbound が再起動されます。

## resolver module — validation diagnostics
resolver-no-nameserver = ネームサーバーが設定されていません。
resolver-duplicate-nameserver = `{$ip}` が複数のネームサーバーとして出現しています。
resolver-too-many-nameservers = このファイルには {$count} 個のネームサーバーがあります。glibc が読むのは最大 {$max} 個です。
resolver-invalid-domain = `{$domain}` は有効なドメイン名ではありません。
resolver-unknown-option = `{$option}` は glibc の resolv.conf パーサーが受け付けるオプションではありません。
resolver-search-and-domain = `search` と `domain` の両方があります。`search` が設定されている場合、glibc は `domain` を無視します。
resolver-no-config = このモデルはリゾルバーバックエンドを一切設定しません。
resolver-backend-missing = これらの設定は {$service} を設定しますが、このホストでは検出されませんでした。
resolver-rec-dnssec = DNSSEC は allow-downgrade に設定されています。`DNSSEC=yes` は厳密に検証するため、アップストリームのデータが許す場合に推奨されます。
resolver-rec-dot = DNSOverTLS は opportunistic で、平文にダウングレードされます。`DNSOverTLS=yes` なら TLS が必須になります。
resolver-unknown-hardening = `{$key}` は、このモジュールが unbound 向けに扱うディレクティブではありません。
resolver-unbound-misplaced = `{$key}` は、ここではなく unbound.conf の {$section} セクションに置く必要があります。
resolver-invalid-forward-addr = `{$addr}` は ip[@port][#auth-name] 形式の有効な forward-addr ではありません。
resolver-invalid-forward-name = `{$name}` は有効な forward-zone 名ではありません。
resolver-forward-tls-no-auth = このゾーンは forward-addr に `#auth-name` を付けずに TLS で転送するため、TLS 接続は認証されません。
resolver-rec-hardening = `{$key}` は無効です。有効にすると、unbound をアップストリームのなりすましや委任の悪用から強化できます。
resolver-forward-zone-unnamed = 名前のない forward-zone: は何も転送せず、設定を弱めます。すべてのゾーンに名前を付けてください。

## samba module — display name, security notes, schema tooltips
samba-name = samba
samba-note-guest-access = ゲストアクセスは接続時に共有ごとに許可されます。誤った値は、パスワードなしでファイルを公開してしまいます。
samba-tip-entries = このモジュールが扱う smb.conf のエントリ (ファイル内の順)。`[section]` ヘッダーとディレクティブの両方。
samba-tip-section = `[section]` ヘッダーのセクション名。通常のディレクティブ行では空です。
samba-tip-key = パラメーター名。大文字と小文字は区別されず、複数語の場合があります (`guest ok`)。
samba-tip-value = パラメーターの値 (行末まで)。`%` マクロはそのまま保持されます。
samba-rec-value = アップストリームの組み込みの既定値に頼らず、明示的に強化した値を指定することをお勧めします。

## samba module — validation diagnostics
samba-empty-key = ディレクティブにパラメーター名がありません。
samba-empty-section = セクションヘッダーが空です。
samba-bad-key = `{$key}` は、ディレクティブのキーではなくセクションまたはコメントとして解析されます。
samba-bad-value = `{$value}` は `\` で終わっており、次の行を飲み込んでしまいます。
samba-bad-section = `{$section}` には `[` または `]` が含まれているか `\` で終わっており、往復で元に戻りません。
samba-guest-ok = `guest ok` は {$value} に設定されています。認証されていないクライアントは、これを継承するすべての共有に接続できます。
samba-map-to-guest = `map to guest` は {$value} です。Never 以外の値では、ログインの失敗がゲストセッションになります。
samba-min-protocol = `server min protocol` は {$value} です。少なくとも SMB3_00 に設定し、SMB1 時代のプロトコルレベルを外してください。
samba-smb-encrypt = `smb encrypt` は {$value} です。SMB 通信が暗号化されずに流れないよう required に設定してください。
samba-restrict-anonymous = `restrict anonymous` は {$value} です。2 にすると、匿名ユーザーから共有一覧が見えなくなります。
samba-rec-server-signing = `server signing` は {$value} です。SMB 通信に暗号署名を付けるため mandatory に設定してください。
samba-rec-load-printers = `load printers` は {$value} です。このホストが実際にプリンターを共有する場合を除き、no に設定してください。
samba-rec-interfaces = `interfaces` ディレクティブが設定されていません。すべてのインターフェースで待ち受けるのではなく、samba を明示的なアドレスにバインドしてください。
samba-writable-exposure = この共有は writeable、read only、write list のいずれかで書き込みを許可しています。すべてのクライアントに書き込みを許可してよいか確認してください。
samba-root-command = `{$key}` は、一致するすべての接続で root 権限でコマンドを実行します。
samba-client-command = `{$key}` はクライアントが samba にコマンドを実行させることを可能にします。コマンドに渡される内容はクライアントが制御します。
samba-usershare-guests = `usershare allow guests` は {$value} です。ユーザーは、誰でもパスワードなしで開ける共有を公開できます。
samba-wide-links = `wide links` は {$value} です。シンボリックリンクにより、クライアントが共有の外へ出られる可能性があります。

## module template — copy-me example
TEMPLATE-name = モジュールテンプレート
TEMPLATE-note-precedence = この架空のモジュールは、新しい設定モジュール向けのコンパイル検証済みの例です。
TEMPLATE-tip-settings = この架空のモジュールが扱う設定 (ファイル内の順)。
TEMPLATE-tip-key = ディレクティブ名。1 語で、空白を含みません。
TEMPLATE-tip-value = ディレクティブの値 (行末まで)。
TEMPLATE-rec-value = アップストリームの既定値に頼らず、明示的な値を指定することをお勧めします。
TEMPLATE-invalid-key = `{$key}` は有効なディレクティブ名ではありません。
TEMPLATE-duplicate-key = `{$key}` が複数回設定されています。最後の値が有効です。
TEMPLATE-too-many-settings = このファイルには {$count} 個の設定があります。大きな設定は小さなファイルに分割してください。

## detent-core — parse, model, and edit errors
## These are the failures a module's own document model can raise, so they are
## prefixed `core-` rather than with a module id.
core-parse-malformed = このファイルは `{$module}` が想定する形式と一致しません: {$reason}
core-model-shape = 指定された設定は想定された形ではありません: {$reason}
core-model-unrepresentable = このファイルには、エディターが表現できない内容が含まれています: {$reason}
core-edit-line-break = 値に改行や null バイトを含めることはできません。`{$value}` には含まれています。
core-edit-index-out-of-range = 内部エラー: 行 {$index} は {$len} 行のファイルの範囲外です。
core-edit-unsupported = この編集は、ファイルの形式では表現できません: {$reason}

## detent-core — version-gated options
core-version-too-old = `{$option}` には {$service} {$since} 以降が必要です。このホストは {$installed} です。
core-version-unknown = インストールされている {$service} のバージョンが不明なため、`{$option}` ({$service} {$since} 以降が必要) は動作しない可能性があります。

## operations layer — errors surfaced by detent-ops
ops-unknown-module = このビルドには `{$module}` という名前のモジュールがありません。
ops-invalid-model = `{$module}` の設定は有効ではありません: {$reason}
ops-check-failed = 外部の検証ツール `{$program}` が候補を拒否しました: {$reason}
ops-hash-conflict = `{$path}` は読み取り後にディスク上で変更されました。読み直してからやり直してください。
ops-privsep-failed = 特権ヘルパーがリクエストを拒否したか、完了できませんでした: {$reason}
ops-service-failed = サービス操作が完了しませんでした: {$reason}
ops-no-target = `{$module}` はこのホスト上のファイルを管理していません。
ops-no-service = `{$module}` はこのホスト上のサービスを制御しないため、再起動できません。
ops-audit-failed = 監査ログを読み取れませんでした: {$reason}
ops-audit-unavailable = 監査ログに書き込めなかったため、操作は拒否されました: {$reason}
ops-unsupported = {$what} はこのビルドではサポートされていません。
ops-commit-pending = 別の commit-confirm ウィンドウがすでに保留中です。
ops-update-running = 更新はすでに実行中です。完了するまで待ってから、実行中のバージョンを確認してください。
ops-update-tag-invalid = これはリリースバージョンではありません。v1.2.3 の形式でなければなりません。
ops-update-not-newer = そのリリースは実行中のバージョンより新しくありません。何も開始されませんでした。
ops-no-backup = commit-confirm には保持されたバックアップが必要です。何も変更されていません。
ops-arm-failed-restored = commit-confirm を有効にできなかったため、変更は取り消されました。以前の内容に戻っています。
ops-arm-failed-unrestored = commit-confirm を有効にできず、変更を取り消すことも「できませんでした」。新しい内容がまだディスク上にあります。今すぐ以前のバックアップを復元してください。
ops-target-missing = 管理対象のファイルが存在しません。作成してください (パッケージをインストールするか、手動で作成)。その後やり直してください。
ops-denied = その操作を行う権限がありません。

## detent-web — configuration, TLS, the operations bridge, and the listener
web-config-unreadable = `{$path}` を読み取れませんでした: {$reason}
web-config-malformed = `{$path}` は有効な detent 設定ではありません: {$reason}
web-config-zero-value = `{$field}` は 0 より大きくなければなりません。
web-config-weak-argon2 = `auth.argon2.m_kib` は {$m} で、最小値 {$min} kib を下回っています。
web-tls-generate-failed = ブートストラップ証明書を生成できませんでした: {$reason}
web-tls-key-rejected = 証明書とその秘密鍵が拒否されました: {$reason}
web-tls-store-unreadable = `{$path}` を読み取れませんでした: {$reason}
web-tls-store-unwritable = `{$path}` を書き込み用に準備できませんでした: {$reason}
web-tls-store-write-failed = `{$path}` に書き込めませんでした: {$reason}
web-tls-acme-pem-rejected = 発行された証明書または鍵は、使用可能な PEM ではありませんでした。
web-engine-stopped = 操作エンジンはもう動作していません。サービスが復旧したらやり直してください。
web-cert-renew-not-acme = 更新には detent.toml の `tls.bootstrap = "acme"` が必要です。
web-cert-renew-unavailable = ACME クライアントが更新リクエストを受け取りませんでした。しばらくしてからやり直してください。
web-update-not-checked = このホストではまだ更新の確認が実行されていません。root で `detent update --check` を実行してください。
web-server-bind-failed = `{$addr}` で待ち受けできませんでした: {$reason}
web-server-address-unknown = 待ち受けアドレスを読み戻せませんでした: {$reason}

## detent-web — auth: passwords, sessions, api tokens, totp, csrf
web-auth-entropy-unavailable = システムの乱数生成器が失敗したため、資格情報を発行できませんでした。
web-auth-argon2-params = 設定された argon2 パラメーターは使用できません: {$reason}
web-auth-hash-failed = パスワードをハッシュ化できませんでした。
web-auth-user-name-invalid = `{$name}` は使用できないユーザー名です。`a-z`、`0-9`、`.`、`_`、`-` を 1 〜 32 文字使い、先頭は英字または数字にしてください。
web-auth-user-exists = `{$name}` という名前のユーザーはすでに存在します。
web-auth-user-unknown = `{$name}` という名前のユーザーはいません。
web-auth-invalid-credentials = ユーザー名、パスワード、またはコードが正しくありません。
web-auth-rate-limited = 試行回数が多すぎます。{$seconds} 秒待ってからやり直してください。
web-auth-session-limit = 開いているセッションが多すぎます。どれかが期限切れになるまで待ってから、再度サインインしてください。
web-auth-busy = 進行中のサインインが多すぎます。しばらく待ってからやり直してください。
web-auth-unauthenticated = この操作を行うにはサインインしてください。
web-auth-ambiguous-credentials = セッションクッキーかベアラートークンのどちらか一方だけを送信してください。両方は送信できません。
web-auth-csrf-rejected = このリクエストはクロスサイトチェックに合格しませんでした。
web-auth-token-unknown = その API トークンは存在しないか、失効しているか、期限が切れています。
web-auth-token-limit = このホストはすでに API トークンの最大数を保持しています。
web-auth-totp-secret-invalid = その認証アプリのシークレットは有効な base32 ではありません。
web-auth-store-unreadable = `{$path}` を読み取れませんでした: {$reason}
web-auth-store-unwritable = `{$path}` を書き込み用に準備できませんでした: {$reason}
web-auth-store-write-failed = `{$path}` に書き込めませんでした: {$reason}
web-auth-store-malformed = `{$path}` は有効な detent 資格情報ファイルではありません: {$reason}
web-denied-scope = この資格情報には `{$scope}` スコープがありません。

## detent-web — the api surface
web-request-malformed = リクエスト本文の形が、このエンドポイントの想定と異なります。
web-request-too-deep = リクエスト本文のネストが深すぎます。
web-api-unexpected-outcome = 操作は完了しましたが、その結果を表示できませんでした。
