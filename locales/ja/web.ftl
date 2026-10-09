# needs-review: machine-drafted Japanese translation; not yet checked by a native speaker.
## detent web admin UI — ja
## Source: locales/en-US/web.ftl. Same ids, same placeables.

## Status bar
status-brand = detent
status-online = システム稼働中
status-clock-label = utc
status-mode-label = モード
theme-toggle-aria = ライトモードとダークモードを切り替える
theme-toggle-title = ライト / ダークを切り替え

## catfu component layer
## Chrome the shared components render themselves. Content strings (field
## captions, table headers, banner copy) are supplied by the calling page.
component-countdown-remaining = 残り時間
component-field-info = 詳細情報
component-modal-close = 閉じる
component-switch-off = オフ
component-switch-on = オン
component-table-empty = レコードなし

## API failures
## docs/API.md: every failure is `{ code, message_id }`, and `message_id` is a
## Fluent id. src/api/messages.ts resolves it here; an id this build does not
## know falls back to `api-error-unknown`, so an id is never rendered raw.
##
## The first three are the console's own — a failure that never reached a
## server has no `message_id` to resolve. The rest mirror the ids the server
## sends, argument-free: locales/en-US/core.ftl interpolates `{$path}`,
## `{$reason}` and friends, and the API deliberately sends none of them.
api-error-network = コンソールはこのホストに接続できませんでした。
api-error-malformed = このホストから、コンソールが読み取れない応答が返されました。
api-error-unknown = このホストが報告した障害について、コンソールには説明がありません。
core-edit-index-out-of-range = 内部エラー: 編集がファイルの範囲外の行を指定しました。
core-edit-line-break = 値に改行や null バイトを含めることはできません。
core-edit-unsupported = この編集は、ファイルの形式では表現できません。
core-model-shape = 指定された設定は想定された形ではありません。
core-model-unrepresentable = このファイルには、エディターが表現できない内容が含まれています。
core-parse-malformed = このファイルは、モジュールが想定する形式と一致しません。
ops-audit-failed = 監査ログを読み取れませんでした。
ops-audit-unavailable = 監査ログに書き込めなかったため、操作は拒否されました。
ops-denied = その操作を行う権限がありません。
ops-hash-conflict = ファイルは読み取り後にディスク上で変更されました。読み直してからやり直してください。
ops-check-failed = 外部の検証ツールが候補を拒否しました。
ops-invalid-model = その設定は有効ではありません。
ops-no-service = このモジュールはこのホスト上のサービスを制御しないため、再起動できません。
ops-no-target = このモジュールはこのホスト上のファイルを管理していません。
ops-privsep-failed = 特権ヘルパーがリクエストを拒否したか、完了できませんでした。
ops-service-failed = サービス操作が完了しませんでした。
ops-unknown-module = このビルドにはその名前のモジュールがありません。
ops-unsupported = それはこのビルドではサポートされていません。
ops-commit-pending = 別の commit-confirm ウィンドウがすでに保留中です。
ops-update-running = 更新はすでに実行中です。完了するまで待ってから、実行中のバージョンを確認してください。
ops-update-tag-invalid = これはリリースバージョンではありません。v1.2.3 の形式でなければなりません。
ops-update-not-newer = そのリリースは実行中のバージョンより新しくありません。何も開始されませんでした。
ops-no-backup = commit-confirm には保持されたバックアップが必要です。何も変更されていません。
ops-arm-failed-restored = commit-confirm を有効にできなかったため、変更は取り消されました。以前の内容に戻っています。
ops-arm-failed-unrestored = commit-confirm を有効にできず、変更を取り消すことも「できませんでした」。新しい内容がまだディスク上にあります。今すぐ以前のバックアップを復元してください。
ops-target-missing = 管理対象のファイルが存在しません。作成してください (パッケージをインストールするか、手動で作成)。その後やり直してください。
web-api-unexpected-outcome = 操作は完了しましたが、その結果を表示できませんでした。
web-auth-ambiguous-credentials = セッションクッキーかベアラートークンのどちらか一方だけを送信してください。両方は送信できません。
web-auth-argon2-params = 設定された argon2 パラメーターは使用できません。
web-auth-busy = 進行中のサインインが多すぎます。しばらく待ってからやり直してください。
web-auth-csrf-rejected = このリクエストはクロスサイトチェックに合格しませんでした。ページを再読み込みしてからやり直してください。
web-auth-entropy-unavailable = システムの乱数生成器が失敗したため、資格情報を発行できませんでした。
web-auth-hash-failed = パスワードをハッシュ化できませんでした。
web-auth-invalid-credentials = ユーザー名、パスワード、またはコードが正しくありません。
web-auth-rate-limited = 試行回数が多すぎます。しばらく待ってからやり直してください。
web-auth-session-limit = 開いているセッションが多すぎます。どれかが期限切れになるまで待ってから、再度サインインしてください。
web-auth-store-malformed = このホスト上の資格情報ファイルが有効ではありません。
web-auth-store-unreadable = このホスト上の資格情報ファイルを読み取れませんでした。
web-auth-store-unwritable = このホスト上の資格情報ファイルを書き込み用に準備できませんでした。
web-auth-store-write-failed = このホスト上の資格情報ファイルに書き込めませんでした。
web-auth-token-limit = このホストはすでに API トークンの最大数を保持しています。
web-auth-token-unknown = その API トークンは存在しないか、失効しているか、期限が切れています。
web-auth-totp-secret-invalid = その認証アプリのシークレットは有効な base32 ではありません。
web-auth-unauthenticated = この操作を行うにはサインインしてください。
web-auth-user-exists = その名前のユーザーはすでに存在します。
web-auth-user-name-invalid = そのユーザー名は使用できません。`a-z`、`0-9`、`.`、`_`、`-` を 1 〜 32 文字使い、先頭は英字または数字にしてください。
web-auth-user-unknown = その名前のユーザーはいません。
web-cert-renew-not-acme = 更新には detent.toml の `tls.bootstrap = "acme"` が必要です。
web-cert-renew-unavailable = ACME クライアントが更新リクエストを受け取りませんでした。しばらくしてからやり直してください。
web-denied-scope = この資格情報には、その操作に必要なスコープがありません。
web-engine-stopped = 操作エンジンはもう動作していません。サービスが復旧したらやり直してください。
web-update-not-checked = このホストではまだ更新の確認が実行されていません。root で `detent update --check` を実行してください。
web-request-malformed = リクエスト本文の形が、このエンドポイントの想定と異なります。
web-request-too-deep = リクエスト本文のネストが深すぎます。

## Sign in
login-title = サインイン
login-panel-label = セッション
login-username-label = ユーザー名
login-password-label = パスワード
login-totp-label = 認証コード
login-totp-description = このアカウントに登録した認証アプリの 6 桁のコード。
login-totp-reveal = 認証コードを使う
login-submit = サインイン
login-submitting = サインイン中
login-retry-after = 試行回数が多すぎます。{$seconds} 秒待ってからやり直してください。

## Session and scope
auth-checking = このセッションを確認中
auth-sign-out = サインアウト
scope-gate-read-only = このセッションには読み取り権限しかないため、このホストの何も変更できません。
scope-gate-signed-out = このホストを変更するにはサインインしてください。

## Navigation
nav-label = セクション
nav-dashboard = ダッシュボード
nav-modules = モジュール
nav-services = サービス
nav-backups = バックアップ
nav-audit = 監査
nav-certificates = 証明書
nav-settings = 設定

## Routed pages
## Certificates and settings are still named placeholders: neither has an API
## to drive. Certificates waits on Phase 6 (ACME); settings waits on the user
## and token endpoints.
page-placeholder-body = このセクションはまだ作られていません。
page-dashboard-title = ダッシュボード
page-modules-title = モジュール
page-module-detail-title = モジュール {$module}
page-services-title = サービス
page-backups-title = バックアップ
page-audit-title = 監査ログ
page-certificates-title = 証明書
page-settings-title = 設定
page-not-found-title = ページが見つかりません
page-not-found-body = そのアドレスは、このコンソール内のどこも指していません。
page-not-found-home = ダッシュボードへ移動

## Pending commit
pending-commit-message = 設定の変更が確認待ちです。このウィンドウが閉じると、自動的にロールバックされます。
pending-commit-countdown-label = 確認までの残り時間
pending-commit-confirm = 変更を確認
pending-commit-confirming = 確認中…

## Shared page states
## Every section is a query away from its data, so loading, failure and "this
## host has none of these" are shared rather than re-worded per page.
state-loading = 読み込み中
state-unknown = 不明
value-no = いいえ
value-yes = はい

## Dashboard
dashboard-host-panel = ホスト
dashboard-host-hostname = ホスト名
dashboard-host-os = オペレーティングシステム
dashboard-host-init = init システム
dashboard-host-distro = ディストリビューション
dashboard-host-ram = メモリ
dashboard-host-network-backend = ネットワークバックエンド
dashboard-host-resolver-backend = リゾルバーバックエンド
dashboard-host-notes = 検出メモ
dashboard-cert-panel = 証明書
dashboard-cert-fingerprint = フィンガープリント
dashboard-cert-expires = 有効期限
dashboard-cert-lifetime-used = 使用済みの有効期間
dashboard-cert-expired = 期限切れです。この証明書を交換してください。
dashboard-cert-expiring-soon = 30 日以内に期限が切れます。更新を計画してください。
dashboard-cert-half = 証明書の有効期間の半分を使用しました。更新が予定されています。
dashboard-cert-quarter = 証明書の有効期間の 4 分の 3 を使用しました。まもなく更新してください。
cert-renew-panel = 更新
cert-renew-now = 今すぐ更新
cert-renew-requested = 更新を要求しました。新しい証明書は、CA が発行した時点でインストールされます。
dashboard-modules-panel = モジュール
dashboard-modules-count = {$count ->
   *[other] {$count} 個のモジュールがこのビルドに組み込まれています。
}
dashboard-audit-panel = 最近のアクティビティ
dashboard-view-all = すべて表示
dashboard-update-panel = 更新
dashboard-update-current = 実行中のバージョン
dashboard-update-published = 公開日
dashboard-update-up-to-date = このビルドに提供される新しいリリースはありません。
dashboard-update-available = このビルド向けにリリース {$tag} が利用可能です。
dashboard-update-security = このリリースはセキュリティ更新としてマークされています。経過日数の制限を回避します。
dashboard-update-install = {$tag} をインストール
dashboard-update-confirm-title = この更新をインストールしますか？
dashboard-update-confirm-body = {$tag} のインストールをバックグラウンドで開始します。インストールされると detent サービスが再起動し、ページが切断されて再接続されることがあります。再起動後のサービスが正常でない場合、更新はロールバックされます。
dashboard-update-confirm-action = インストール
dashboard-update-confirm-cancel = キャンセル
dashboard-update-started = {$version} への更新をバックグラウンドで開始しました。インストールされるとサービスが再起動し、正常でなければロールバックされます。結果は実行中のバージョンで確認できます。

## Modules
modules-panel-label = インストール済みモジュール
modules-col-module = モジュール
modules-col-targets = ファイル
modules-col-services = サービス
modules-col-commit-confirm = commit-confirm
modules-commit-confirm-required = 必須
modules-commit-confirm-not-required = 不要
modules-empty = このビルドにはモジュールが組み込まれていません。
modules-none = なし

## One module
module-about-panel = モジュール
module-configuration-panel = 設定
module-upstream-label = 追従するアップストリーム
module-targets-label = ファイル
module-services-label = サービス
module-current-hash-label = ディスク上のダイジェスト
module-security-notes-label = セキュリティに関する注記
module-model-missing = このモジュールのファイルは、このホストにまだ存在しません。以下のフォームはモジュール自身の既定値から始まり、適用するとファイルが作成されます。
module-action-validate = 検証
module-action-plan = 計画
module-action-apply = 適用
module-action-discard = 編集を破棄
module-busy = 処理中
module-validate-clean = この設定は、このホストが実行するすべてのチェックに合格しました。
module-plan-title = 計画された変更
module-plan-no-change = この設定はディスク上の内容とすでに同じです。適用するものはありません。
module-plan-diff-label = 差分
module-plan-checks-label = アップストリームのチェック
module-plan-check-passed = 合格
module-plan-check-failed = 失敗
module-plan-check-exit = 終了コード {$code}
module-plan-services-label = 影響を受けるサービス
module-plan-apply = この変更を適用
module-apply-title = この変更を適用しますか？
module-apply-body = このホストの {$path} に書き込みます。現在の内容は先にバックアップされます。
module-apply-commit-confirm = このモジュールは管理者を締め出す可能性があるため、この変更は commit-confirm ウィンドウを有効にします。期限までに確認しない限り、自動的にロールバックされます。
module-apply-service-label = 適用後
module-apply-service-none = サービスには何もしない
module-apply-cancel = キャンセル
module-applied = 変更を {$path} に書き込みました。
module-applied-created = {$path} は存在しなかったため、作成されました。
module-mounts-off = 新しい fstab エントリはマウントされませんでした ([mounts] activate_new_entries がオフ)。次回の起動またはマウント時に有効になります。
module-mounts-error = マウントユニットは起動されませんでした: {$reason}
module-mounts-none = マウントする新しい fstab エントリはありません。
module-mounts-units = 新しい fstab エントリのマウントユニット:
module-mount-state-mounted = マウント済み
module-mount-state-already-mounted = すでにマウント済み
module-mount-state-pending = マウント中
module-mount-state-failed = 失敗
module-mount-state-protected = 拒否: 保護されたパス
module-mount-state-stopped = アンマウント済み
module-cancel = キャンセル

## Services
services-panel-label = サービス
services-col-module = モジュール
services-col-unit = ユニット
services-col-state = 状態
services-col-enabled = 起動時
services-col-since = 開始時刻
services-col-actions = 操作
services-state-active = アクティブ
services-state-inactive = 非アクティブ
services-state-failed = 失敗
services-state-activating = 起動中
services-state-deactivating = 停止中
services-state-unknown = 不明
services-action-restart = 再起動
services-action-reload = リロード
services-action-start = 開始
services-action-stop = 停止
services-acted = {$unit}: {$detail}
services-empty = このビルドのどのモジュールも、このホスト上のサービスを制御していません。
services-confirm-title = {$unit} を{$action}しますか？
services-confirm-body = 実行中のサービスに即座に作用します。
services-confirm-cancel = キャンセル

## Backups
backups-col-name = バックアップ
backups-col-created = 取得日時
backups-col-size = サイズ
backups-col-digest = ダイジェスト
backups-col-actions = 操作
backups-action-restore = 復元
backups-confirm-title = このバックアップを復元しますか？
backups-confirm-body = {$target} を保持されているコピーで置き換えます。現在の内容は先にバックアップされます。
backups-confirm-cancel = キャンセル
backups-restored = バックアップを復元しました。
backups-empty = このモジュールのバックアップはまだありません。
backups-module-panel = {$module} のバックアップ

## Audit log
audit-panel-label = 監査ログ
audit-col-when = 日時
audit-col-who = 呼び出し元
audit-col-how = 資格情報
audit-col-op = 操作
audit-col-module = モジュール
audit-col-result = 結果
audit-filter-module-label = モジュール
audit-filter-who-label = 呼び出し元
audit-filter-limit-label = 行数
audit-filter-apply = 絞り込み
audit-filter-clear = クリア
audit-empty = このホストにはまだ何も記録されていません。
audit-result-ok = ok
audit-result-denied = 拒否
audit-result-error = 失敗
audit-identity-local-user = ローカルユーザー
audit-identity-session = セッション
audit-identity-token = API トークン
audit-op-list-modules = モジュール一覧
audit-op-get-module = モジュール読み取り
audit-op-validate = 検証
audit-op-plan = 計画
audit-op-apply = 適用
audit-op-confirm-commit = コミット確認
audit-op-rollback-commit = コミットのロールバック
audit-op-list-backups = バックアップ一覧
audit-op-restore = バックアップ復元
audit-op-service-status = サービス状態の読み取り
audit-op-service-action = サービス操作
audit-op-host-profile = ホストプロファイルの読み取り
audit-op-audit-query = 監査ログの読み取り
audit-op-cert-status = 証明書状態の読み取り
audit-op-update-status = 更新状態の読み取り
audit-op-cert-renew = 証明書の更新
audit-op-update-apply = 更新のインストール
## Schema-driven module forms
## Chrome the form engine (web/src/forms) renders around a module's schema.
## Field captions come from the schema's own property names, and a field's
## tooltip and recommendation are Fluent ids in the *module's* locale file, not
## here — a missing one degrades to no tooltip and is never rendered raw.
forms-advanced-toggle = 詳細
forms-badge-security-high = セキュリティへの影響大
forms-badge-deprecated = {$version} で非推奨
forms-diagnostic-at-field = {$field}: {$message}
forms-diagnostic-unknown = このホストが、このビルドに説明のないチェック結果を報告しました ({$id})。
forms-item-add-caption = 追加
forms-item-move-down-caption = 下
forms-item-move-up-caption = 上
forms-item-remove-caption = 削除
forms-list-empty = まだ何もありません。
forms-option-none = なし
forms-row-add = {$field} に行を追加
forms-row-label = 行 {$index}
forms-row-move-down = {$field} の行 {$index} を下へ移動
forms-row-move-up = {$field} の行 {$index} を上へ移動
forms-row-remove = {$field} の行 {$index} を削除
forms-tag-add = {$field} に項目を追加
forms-tag-item = {$field} の項目 {$index}
forms-tag-move-down = {$field} の項目 {$index} を下へ移動
forms-tag-move-up = {$field} の項目 {$index} を上へ移動
forms-tag-remove = {$field} の項目 {$index} を削除
forms-unsupported-note = このビルドではこの値を編集できません。保存されている状態のまま表示され、変更されません。
forms-version-unsupported = {$service} {$since} が必要です (インストール済み: {$installed})

## Form validation
## Mirrors the schema constraints for immediate feedback. The server is the
## authority: a clean pass here is not a promise that apply will succeed.
forms-error-enum = 一覧の値から選んでください。
forms-error-format-ip = 有効な IP アドレスではありません。
forms-error-integer = 整数を使用してください。
forms-error-max-length = {$max} 文字以内にしてください。
forms-error-maximum = {$max} 以下にしてください。
forms-error-min-length = {$min} 文字以上にしてください。
forms-error-minimum = {$min} 以上にしてください。
forms-error-pattern = この値は、このフィールドが受け付ける形式と一致しません。
forms-error-required = このフィールドは必須です。
forms-error-type = この値は、このフィールドが保持する種類の値ではありません。
