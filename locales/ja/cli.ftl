# needs-review: machine-drafted Japanese translation; not yet checked by a native speaker.
## detent CLI — ja
## Source: locales/en-US/cli.ftl. Same ids, same placeables. Identifiers — module ids,
## paths, unit names, digests, enum wire names such as `restart` or `active` — are
## interpolated verbatim and must not be translated.

## severity words, prefixed to every rendered diagnostic
cli-severity-error = エラー
cli-severity-warning = 警告
cli-severity-recommendation = 注記

## yes/no, used wherever a flag is rendered
cli-yes = はい
cli-no = いいえ

## progress notes, printed on stderr under --verbose
cli-note-settings = ロケール {$locale}、状態ルート {$state}、設定 {$config}
cli-note-operation = {$module} に対して {$operation} を実行中

## failures that stop a command before the operations layer sees it
cli-bad-stdin = stdin からモデルを読み取れませんでした: {$reason}
cli-bad-json = stdin のモデルは有効な JSON ではありません: {$reason}
cli-bad-hash = `{$value}` は 16 進 64 文字の SHA-256 ダイジェストではありません。
cli-start-failed = 特権ヘルパーを起動できませんでした: {$reason}
cli-monitor-stop = 特権ヘルパーが正常に停止しませんでした: {$reason}
cli-monitor-busy = 別の detent モニターがすでにこの状態ルートを所有しています。Web UI から再試行するか、`detent serve` を実行してください。
cli-monitor-lock-unavailable = {$path} の状態ロックを取得できないため、このコマンドは何も変更できません。そのディレクトリに書き込めるユーザーで実行するか、--state-root を指定してください。
cli-commit-recovered = 未確認のコミット {$commit} を復旧しました。{$restored} 件のターゲットを復元し、失敗は {$failures} 件でした。
cli-commit-confirm-needs-serve = このモジュールには commit-confirm が必要です。確認ウィンドウを確実に適用するため、Web UI か `detent serve` を使用してください。
cli-config-load-failed = {$path} の設定を読み込めませんでした: {$reason}
cli-no-command = コマンドが指定されていません。

## self-test probe and self-update (PLAN §2.9)
cli-self-test = バージョン {$version}、機能 {$features}
cli-update-available = 更新があります: {$tag}、公開日 {$published}
cli-update-security-available = セキュリティ更新があります: {$tag}、公開日 {$published}
cli-update-none = 利用可能な更新はありません (現在 {$current})
cli-update-held-young = {$tag} は {$current} より新しいですが、公開から {$days} 日未満のため、経過日数の制限で保留されています
cli-update-held-rejected = {$tag} は {$current} より新しいですが、このホストでロールバックされたためスキップされます
cli-verify-bundle-ok = {$file} は {$tag} 用として証明されています
cli-update-failed = 更新に失敗しました: {$reason}
cli-update-installed = {$tag} をインストールしました。置き換えられたバイナリは {$previous} に残してあります
cli-update-not-restarted = サービスは再起動されなかったため、新しいバイナリはまだ実行されていません: {$reason}
cli-update-rolled-back = ロールバックしました: {$reason}
cli-update-rollback-failed = 更新に失敗し ({$reason})、ロールバックにも失敗しました ({$error})。このホストは対応が必要です

## config
cli-module-line = {$id}  {$name}
cli-no-model = このモジュールはこのホスト上のファイルをまだ管理していないため、表示するモデルがありません。
cli-valid = この設定は有効です。
cli-plan-no-change = {$module} はすでに {$path} の内容と同じです。変更はありません。
cli-plan-service = これを適用すると {$unit} に影響します。
cli-plan-hash = ファイルのハッシュは現在 {$hash} です。競合する編集を拒否するには --expect-hash として指定してください。
cli-check-ran = アップストリームの検証ツール {$program} を実行しました。合格: {$passed}。{$detail}
cli-check-skipped = アップストリームの検証ツール {$program} は実行されませんでした。{$detail}
cli-applied = {$module} を {$path} に書き込みました。
cli-applied-hash = ハッシュは {$prev} から {$new} になりました。バックアップを保持: {$backup}
cli-mounts-off = mounts: 有効化はオフです ([mounts] activate_new_entries)。新しい fstab エントリは次回の起動またはマウント時に有効になります。
cli-mounts-error = mounts: マウントユニットは起動されませんでした: {$reason}
cli-mounts-none = mounts: マウントする新しい fstab エントリはありません。
cli-mounts-unit = mount {$mountpoint} ({$unit}): {$state}
cli-mounts-unit-detail = mount {$mountpoint} ({$unit}): {$state}: {$detail}
cli-commit-armed = コミット {$id} は {$seconds} 秒以内 ({$deadline} まで) に確認する必要があります。確認しないとロールバックされます。
cli-commit-confirmed = コミット {$id} は確認されました。ロールバックされません。
cli-commit-rolled-back = コミット {$id} をロールバックしました。{$targets} 件のターゲットを元に戻しました。

## backups
cli-no-backups = このモジュールのバックアップはまだ保持されていません。
cli-backup-line = {$id}  {$name}  {$bytes} バイト  {$digest}
cli-restored = ターゲット {$target} を元に戻しました。ハッシュは現在 {$hash} です。

## services
cli-service-status = {$unit} は {$state} です。起動時に開始: {$enabled}
cli-serviced = {$unit} に {$action} を依頼しました。現在実行中: {$active}

## host
cli-host-profile = {$hostname}: {$os}、init {$init}、RAM {$ram} MiB
cli-host-service-version = インストール済みの {$service} のバージョンは {$version} です
cli-host-backends = ネットワークバックエンド {$network}、リゾルバーバックエンド {$resolver}、ディストリビューション {$distro} {$version}
cli-host-note = 検出メモ: {$note}

## audit
cli-no-audit = 一致する監査ログ記録はありません。
cli-audit-line = {$ts}  {$who}  {$op}  {$module}  {$result}  {$error}

## --dryrun
cli-dryrun-apply = ドライラン: {$module} について {$path} に書き込まれる内容です。
cli-dryrun-operation = ドライラン: {$module} に対して {$operation} が実行されます。
cli-dryrun-nothing = ドライラン: 何も変更されていません。
cli-dryrun-serve = ドライラン: モニターとワーカーは {$modules} 個のモジュールと {$targets} 個のターゲットで、{$state} をルートとして起動します。
cli-dryrun-serve-mounts = ドライラン: mounts の適用後、ランナーは新しい fstab エントリのマウントユニットを起動します (mounts.activate_new_entries = true)。
cli-dryrun-cert-renew = ドライラン: {$address} のサーバーに ({$name} として) 証明書を今すぐ更新するよう依頼します。何も送信していません。

## serve
cli-serve-monitor = ワーカーを pid {$pid} として起動しました。特権の放棄: {$dropped}
cli-serve-worker = ワーカーは実行中です。HTTP サーバーはフェーズ 4 で追加されます。ハンドシェイク: {$greeted}
cli-serve-failed = モニターとワーカーを起動できませんでした: {$reason}
cli-serve-stopped = ペアが予期せず停止しました: {$reason} {$status}
cli-serve-privileged-port = ポート {$port} には cap_net_bind_service またはモニターから渡されたソケットが必要ですが、このビルドはどちらもサポートしていません。1024 以上のポートを使うか、前段にリバースプロキシを置いてください。
cli-serve-acme-unsupported = このビルドには dns-01 プロバイダー (機能 acme-dns-providers) がないため、ACME 証明書を取得できません。{$path} の tls.bootstrap を "self-signed" に設定してください。
cli-serve-acme-setting-missing = tls.bootstrap は "acme" ですが、{$path} に {$setting} が設定されていません。
cli-serve-acme-path-outside = {$setting} ({$value}) は状態ルート {$root} の下にありません。隔離されたプロセスはそこにしか書き込めません。
cli-serve-acme-credentials-dir = ACME 資格情報ディレクトリ {$path} を準備できませんでした: {$reason}
cli-serve-secrets-failed = シークレットファイル {$path} は拒否されました: {$reason}
cli-serve-acme-secret-missing = acme.provider が設定されていますが、{$path} の [acme] テーブルに dns_provider シークレットがありません。
cli-serve-acme-provider-invalid = acme.provider の dns-01 プロバイダーは使用できません: {$reason}
cli-serve-acme-providers-not-built = このビルドには dns-01 プロバイダー (機能 acme-dns-providers) がありません。{$path} から [acme.provider] を削除してください。
cli-serve-handshake-failed = ワーカーはモニターとのハンドシェイクを完了できませんでした。
cli-serve-auth-failed = アカウント、トークン、セッションのストアを開けませんでした: {$reason}
cli-serve-tls-failed = TLS 証明書を準備できませんでした: {$reason}
cli-serve-cert-fingerprint = TLS ブートストラップ証明書のフィンガープリント (sha-256): {$fingerprint}
cli-serve-web-failed = Web サーバーを起動できませんでした: {$reason}
cli-serve-web-stopped = Web サーバーが正常に停止しませんでした: {$reason}
cli-serve-listening = {$addr} で待ち受け中
cli-serve-confinement-degraded = 隔離が縮退しています: {$detail}
cli-mcp-missing-token = {$var} が設定されていません。`detent token create` で発行し、mcp サーバーを起動する前にエクスポートしてください。
cli-mcp-serve-failed = mcp サーバーを起動できませんでした: {$reason}
cli-mcp-listening = mcp が {$transport} で待ち受け中
cli-mcp-http-needs-privsep = mcp の http トランスポートは root またはケーパビリティ付きでは実行できません。ネットワークパーサーが root 相当の権限で動くことになります。ケーパビリティなしの非 root ユーザーで実行するか、stdio トランスポートを使用してください。
cli-mcp-bind-not-loopback = mcp の http バインドはループバック (127.0.0.1 または ::1) でなければなりません。ベアラーは通信路上で平文です。
cli-dryrun-mcp = ドライラン: mcp はスコープ {$scope} で {$addr} 上の {$transport} を提供します。

## setup, user, token
cli-setup-exists = `{$name}` という名前のユーザーはこのホストにすでに存在します。上書きするには --force を指定してください。
cli-setup-created = 管理者アカウント `{$name}` を作成しました。
cli-user-created = アカウント `{$name}` を作成しました。
cli-user-passwd = `{$name}` のパスワードを変更しました。
cli-user-removed = アカウント `{$name}` を削除しました。
cli-token-created = トークン {$id} ({$label}) を作成しました。二度と表示されません: {$token}
cli-token-revoked = トークン {$id} を失効させました。
cli-token-no-tokens = 発行されたトークンはありません。
cli-token-line = {$id}  {$label}  {$scopes}  {$created}  {$expires}
cli-credential-failed = リクエストを完了できませんでした: {$reason}
cli-state-command-as-root = detent {$command} を root で実行してはいけません。書き込まれるファイルが root の所有になり、サービスが読めなくなります。代わりにサービスアカウントで実行してください: sudo -u {$account} detent {$command}

## cert status
cli-cert-source = ソース: {$source}
cli-cert-fingerprint = フィンガープリント (sha-256): {$fingerprint}
cli-cert-not-after = 有効期限: {$not_after}
cli-cert-not-after-unknown = 有効期限: 不明 (証明書を解析できませんでした)。
cli-cert-lifetime = 使用済みの有効期間: {$percent} (警告: {$warning})。
cli-cert-lifetime-no-warning = 使用済みの有効期間: {$percent} (警告なし)。
cli-cert-lifetime-unknown = 使用済みの有効期間: 不明 (証明書を解析できませんでした)。
cli-cert-missing = {$path} に証明書が保存されていません。サーバーを一度起動すると証明書が書き込まれます。
cli-cert-unreadable = {$path} の証明書を読み取れませんでした: {$reason}

## cert renew
cli-cert-renew-requested = 更新を要求しました。サーバーが ACME クライアントに今すぐ更新するよう依頼しました。結果は `detent cert status` で確認してください。
cli-cert-renew-token-refused = トークンが拒否されました (HTTP {$status})。書き込みスコープが必要です: `detent token create <name> --write`。
cli-cert-renew-not-acme = サーバーは ACME プロセスを実行していません (`tls.bootstrap` が `acme` ではありません)。更新するものはありません。
cli-cert-renew-server-error = サーバーが HTTP {$status} を返しました: {$message_id}
cli-cert-renew-server-error-bare = サーバーが HTTP {$status} を返しました。
cli-cert-renew-unreachable = {$address} のサーバーと通信できませんでした: {$reason}
cli-cert-renew-no-token = API トークンがありません。--token-file <path> を指定するか、{$var} を設定してください。書き込みトークンは `detent token create <name> --write` で発行します。
cli-cert-renew-bad-token = {$source} のトークンが拒否されました: {$reason}
cli-cert-renew-ca-unreadable = CA ファイル {$path} を読み取れませんでした: {$reason}

## password entry (setup, user add, user passwd)
cli-password-prompt = パスワード:
cli-password-confirm = パスワードの確認:
cli-password-mismatch = パスワードが一致しませんでした。
cli-password-empty = パスワードを空にすることはできません。

## doctor
cli-status-ok = ok
cli-status-warn = 警告
cli-status-fail = 失敗
cli-doctor-modules = このビルドに組み込まれているモジュール: {$detail}
cli-doctor-state-root = 状態ディレクトリ {$detail}
cli-doctor-config = 設定ファイル {$detail}
cli-doctor-privsep = 権限分離で正常に動作するペアをフォークできます: {$detail}
cli-doctor-landlock = landlock: {$detail}
cli-doctor-seccomp = seccomp: {$detail}
cli-doctor-confinement = サンドボックスによる隔離: {$detail}
cli-doctor-serve-confinement = 前回の serve 起動時の隔離: {$detail}
cli-doctor-mounts = fstab 適用後のマウント有効化: {$detail}
