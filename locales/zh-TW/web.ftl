# needs-review: machine-drafted Traditional Chinese translation; not yet checked by a native speaker.
## detent web admin UI — zh-TW
## Source: locales/en-US/web.ftl. Same ids, same placeables, same selectors.

## Status bar
status-brand = detent
status-online = 系統上線中
status-clock-label = utc
status-mode-label = 模式
theme-toggle-aria = 切換淺色與深色模式
theme-toggle-title = 切換淺色 / 深色

## catfu component layer
## Chrome the shared components render themselves. Content strings (field
## captions, table headers, banner copy) are supplied by the calling page.
component-countdown-remaining = 剩餘時間
component-field-info = 更多資訊
component-modal-close = 關閉
component-switch-off = 關
component-switch-on = 開
component-table-empty = 沒有紀錄

## API failures
## docs/API.md: every failure is `{ code, message_id }`, and `message_id` is a
## Fluent id. src/api/messages.ts resolves it here; an id this build does not
## know falls back to `api-error-unknown`, so an id is never rendered raw.
##
## The first three are the console's own — a failure that never reached a
## server has no `message_id` to resolve. The rest mirror the ids the server
## sends, argument-free: locales/en-US/core.ftl interpolates `{$path}`,
## `{$reason}` and friends, and the API deliberately sends none of them.
api-error-network = 主控台無法連線到此主機。
api-error-malformed = 此主機傳回了主控台無法讀取的回應。
api-error-unknown = 此主機回報了一個主控台沒有對應說明的錯誤。
core-edit-index-out-of-range = 內部錯誤：某次編輯指向了檔案之外的行。
core-edit-line-break = 值不能包含換行字元或空位元組。
core-edit-unsupported = 此編輯無法用該檔案的格式表達。
core-model-shape = 提供的設定不具備預期的結構。
core-model-unrepresentable = 此檔案包含編輯器無法表示的內容。
core-parse-malformed = 此檔案不符合其模組所要求的格式。
ops-audit-failed = 無法讀取稽核記錄。
ops-audit-unavailable = 無法寫入稽核記錄，因此該操作被拒絕。
ops-denied = 您沒有執行此操作的權限。
ops-hash-conflict = 該檔案在被讀取之後已在磁碟上發生變更；請重新讀取後再試。
ops-check-failed = 外部驗證程式拒絕了候選設定。
ops-invalid-model = 該設定無效。
ops-no-service = 此模組在此主機上不控制任何服務，因此無法重新啟動。
ops-no-target = 此模組在此主機上不管理任何檔案。
ops-privsep-failed = 特權輔助程式拒絕了要求，或無法完成要求。
ops-service-failed = 服務操作未能完成。
ops-unknown-module = 此組建中沒有該名稱的模組。
ops-unsupported = 此組建不支援該操作。
ops-commit-pending = 已有另一個 commit-confirm 視窗處於待確認狀態。
ops-update-running = 更新已在執行；請等待其完成，然後檢查目前執行的版本。
ops-update-tag-invalid = 這不是發行版本號；它的格式必須類似 v1.2.3。
ops-update-not-newer = 該發行版本並不比目前執行的版本更新；未啟動任何操作。
ops-no-backup = commit-confirm 需要保留一份備份；未做任何變更。
ops-arm-failed-restored = 無法啟用 commit-confirm，因此變更已被復原；先前的內容已還原。
ops-arm-failed-unrestored = 無法啟用 commit-confirm，且變更無法復原；新內容仍在磁碟上。請立即還原先前的備份。
ops-target-missing = 受管理的檔案不存在；請建立它（安裝其套件或手動建立），然後重試。
web-api-unexpected-outcome = 操作已完成，但其結果無法呈現。
web-auth-ambiguous-credentials = 請傳送工作階段 cookie 或 bearer 權杖二者之一，不要同時傳送。
web-auth-argon2-params = 所設定的 argon2 參數無法使用。
web-auth-busy = 正在進行的登入過多；請稍候再試。
web-auth-csrf-rejected = 此要求未通過跨站檢查；請重新載入頁面後再試。
web-auth-entropy-unavailable = 系統亂數產生器發生故障，因此無法簽發任何認證資訊。
web-auth-hash-failed = 無法對密碼進行雜湊。
web-auth-invalid-credentials = 使用者名稱、密碼或驗證碼不正確。
web-auth-password-change-required = 請先變更密碼，然後再進行其他操作。
web-auth-password-too-long = 密碼最多只能有 128 個字元。
web-auth-password-too-short = 密碼至少須有 12 個字元。
web-auth-password-unchanged = 新密碼必須與目前的密碼不同。
web-auth-rate-limited = 嘗試次數過多；請稍候再試。
web-auth-session-limit = 開啟的工作階段過多；請等待其中一個過期後再重新登入。
web-auth-store-malformed = 此主機上的某個認證資訊檔案無效。
web-auth-store-unreadable = 無法讀取此主機上的某個認證資訊檔案。
web-auth-store-unwritable = 無法為寫入準備此主機上的某個認證資訊檔案。
web-auth-store-write-failed = 無法寫入此主機上的某個認證資訊檔案。
web-auth-token-limit = 此主機已持有 api 權杖數量的上限。
web-auth-token-unknown = 該 api 權杖不存在、已被撤銷或已過期。
web-auth-totp-secret-invalid = 該驗證器金鑰不是有效的 base32。
web-auth-unauthenticated = 請先登入再執行此操作。
web-auth-user-exists = 已存在同名使用者。
web-auth-user-name-invalid = 該使用者名稱無法使用；請使用 1 到 32 個 `a-z`、`0-9`、`.`、`_` 或 `-` 字元，並以字母或數字開頭。
web-auth-user-unknown = 沒有該名稱的使用者。
web-cert-renew-not-acme = 更新憑證需要在 detent.toml 中設定 `tls.bootstrap = "acme"`。
web-cert-renew-unavailable = acme 用戶端沒有收到更新要求；請稍後再試。
web-denied-scope = 此認證資訊不具備該操作所需的範圍。
web-engine-stopped = 操作引擎已不再執行；請在服務恢復後重試。
web-update-not-checked = 此主機尚未進行過更新檢查；請以 root 身分執行 `detent update --check`。
web-request-malformed = 要求本文的結構不是此端點所預期的。
web-request-too-deep = 要求本文的巢狀層級過深。

## Sign in
login-title = 登入
login-panel-label = 工作階段
login-username-label = 使用者名稱
login-password-label = 密碼
login-totp-label = 驗證器驗證碼
login-totp-description = 為此帳號綁定的驗證器所顯示的六位數字。
login-totp-reveal = 使用驗證器驗證碼
login-submit = 登入
login-submitting = 登入中
login-retry-after = 嘗試次數過多；請等待 {$seconds} 秒後再試。

## Change password
password-change-title = 變更密碼
password-change-panel-label = 密碼
password-change-intro = 此帳號必須先設定新密碼，才能進行其他操作。
password-change-current-label = 目前的密碼
password-change-new-label = 新密碼
password-change-new-description = 12 到 128 個字元；可使用任意字元。
password-change-confirm-label = 確認新密碼
password-change-mismatch = 兩次輸入的新密碼不一致。
password-change-submit = 變更密碼
password-change-submitting = 正在變更密碼

## Session and scope
auth-checking = 正在檢查此工作階段
auth-sign-out = 登出
scope-gate-read-only = 此工作階段僅具有讀取權限，無法變更此主機上的任何內容。
scope-gate-signed-out = 請登入後再變更此主機上的內容。

## Navigation
nav-label = 區段
nav-dashboard = 儀表板
nav-modules = 模組
nav-services = 服務
nav-backups = 備份
nav-audit = 稽核
nav-certificates = 憑證
nav-settings = 設定

## Routed pages
## Certificates and settings are still named placeholders: neither has an API
## to drive. Certificates waits on Phase 6 (ACME); settings waits on the user
## and token endpoints.
page-placeholder-body = 此區段尚未建置。
page-dashboard-title = 儀表板
page-modules-title = 模組
page-module-detail-title = 模組 {$module}
page-services-title = 服務
page-backups-title = 備份
page-audit-title = 稽核記錄
page-certificates-title = 憑證
page-settings-title = 設定
page-not-found-title = 找不到頁面
page-not-found-body = 該位址在此主控台中不對應任何內容。
page-not-found-home = 前往儀表板

## Pending commit
pending-commit-message = 有一項設定變更正在等待確認；此視窗關閉時，它會自動回復。
pending-commit-countdown-label = 確認剩餘時間
pending-commit-confirm = 確認變更
pending-commit-confirming = 正在確認…

## Shared page states
## Every section is a query away from its data, so loading, failure and "this
## host has none of these" are shared rather than re-worded per page.
state-loading = 載入中
state-unknown = 未知
value-no = 否
value-yes = 是

## Dashboard
dashboard-host-panel = 主機
dashboard-host-hostname = 主機名稱
dashboard-host-os = 作業系統
dashboard-host-init = init 系統
dashboard-host-distro = 發行版
dashboard-host-ram = 記憶體
dashboard-host-network-backend = 網路後端
dashboard-host-resolver-backend = 解析器後端
dashboard-host-notes = 偵測說明
dashboard-cert-panel = 憑證
dashboard-cert-fingerprint = 指紋
dashboard-cert-expires = 到期時間
dashboard-cert-lifetime-used = 已用有效期限
dashboard-cert-expired = 已過期；請更換此憑證。
dashboard-cert-expiring-soon = 將在 30 天內到期；請規劃更新。
dashboard-cert-half = 已用去憑證有效期限的一半；更新已排程。
dashboard-cert-quarter = 已用去憑證有效期限的四分之三；請盡快更新。
cert-renew-panel = 更新
cert-renew-now = 立即更新
cert-renew-requested = 已要求更新。CA 簽發新憑證後將自動安裝。
dashboard-modules-panel = 模組
dashboard-modules-count = {$count ->
   *[other] 此組建中編譯進了 {$count} 個模組。
}
dashboard-audit-panel = 最近活動
dashboard-view-all = 檢視全部
dashboard-update-panel = 更新
dashboard-update-current = 目前執行的版本
dashboard-update-published = 發布時間
dashboard-update-up-to-date = 沒有適用於此組建的更新版本。
dashboard-update-available = 此組建有可用的版本 {$tag}。
dashboard-update-security = 此版本被標示為安全性更新；它不受時間門檻限制。
dashboard-update-install = 安裝 {$tag}
dashboard-update-confirm-title = 安裝此更新？
dashboard-update-confirm-body = 這將在背景開始安裝 {$tag}。如果安裝成功，detent 服務會重新啟動，頁面可能會中斷後重新連線；如果重新啟動後的服務狀態不正常，更新會回復。
dashboard-update-confirm-action = 安裝
dashboard-update-confirm-cancel = 取消
dashboard-update-started = 已在背景開始更新到 {$version}。如果安裝成功，服務會重新啟動；如果狀態不正常，則會回復；目前執行的版本會顯示結果。

## Modules
modules-panel-label = 已安裝的模組
modules-col-module = 模組
modules-col-targets = 檔案
modules-col-services = 服務
modules-col-commit-confirm = commit-confirm
modules-commit-confirm-required = 需要
modules-commit-confirm-not-required = 不需要
modules-empty = 此組建中沒有編譯進任何模組。
modules-none = 無

## One module
module-about-panel = 模組
module-configuration-panel = 設定
module-upstream-label = 追蹤上游
module-targets-label = 檔案
module-services-label = 服務
module-current-hash-label = 磁碟上的摘要
module-security-notes-label = 安全性說明
module-model-missing = 此模組的檔案在此主機上尚不存在。下方的表單以該模組自身的預設值為起點，套用後會建立該檔案。
module-action-validate = 驗證
module-action-plan = 預覽
module-action-apply = 套用
module-action-discard = 捨棄編輯
module-busy = 處理中
module-validate-clean = 此設定通過了此主機執行的所有檢查。
module-plan-title = 預定的變更
module-plan-no-change = 此設定與磁碟上現有的內容一致；沒有需要套用的變更。
module-plan-diff-label = 差異
module-plan-checks-label = 上游檢查
module-plan-check-passed = 通過
module-plan-check-failed = 失敗
module-plan-check-exit = 結束碼 {$code}
module-plan-services-label = 將受影響的服務
module-plan-apply = 套用此變更
module-apply-title = 套用此變更？
module-apply-body = 這將在此主機上寫入 {$path}。目前的內容會先被備份。
module-apply-commit-confirm = 此模組可能導致管理員被鎖在外面，因此該變更會啟用 commit-confirm 視窗：除非您在截止時間之前確認，否則它會自動回復。
module-apply-service-label = 之後
module-apply-service-none = 不處理該服務
module-apply-cancel = 取消
module-applied = 變更已寫入 {$path}。
module-applied-created = {$path} 原本不存在，現已建立。
module-mounts-off = 新的 fstab 項目未被掛載（[mounts] activate_new_entries 已關閉）；它們將在下次開機或掛載時生效。
module-mounts-error = 未啟動任何掛載單元：{$reason}
module-mounts-none = 沒有需要掛載的新 fstab 項目。
module-mounts-units = 新 fstab 項目的掛載單元：
module-mount-state-mounted = 已掛載
module-mount-state-already-mounted = 先前已掛載
module-mount-state-pending = 仍在掛載
module-mount-state-failed = 失敗
module-mount-state-protected = 已拒絕：受保護的路徑
module-mount-state-stopped = 已卸載
module-cancel = 取消

## Services
services-panel-label = 服務
services-col-module = 模組
services-col-unit = 單元
services-col-state = 狀態
services-col-enabled = 開機時啟動
services-col-since = 起始時間
services-col-actions = 操作
services-state-active = 執行中
services-state-inactive = 未執行
services-state-failed = 失敗
services-state-activating = 啟動中
services-state-deactivating = 停止中
services-state-unknown = 未知
services-action-restart = 重新啟動
services-action-reload = 重新載入
services-action-start = 啟動
services-action-stop = 停止
services-acted = {$unit}：{$detail}
services-empty = 此組建中沒有模組在此主機上控制服務。
services-confirm-title = {$action} {$unit}？
services-confirm-body = 這會立即作用於執行中的服務。
services-confirm-cancel = 取消

## Backups
backups-col-name = 備份
backups-col-created = 建立時間
backups-col-size = 大小
backups-col-digest = 摘要
backups-col-actions = 操作
backups-action-restore = 還原
backups-confirm-title = 還原此備份？
backups-confirm-body = 這將用保留的副本取代 {$target}。目前的內容會先被備份。
backups-confirm-cancel = 取消
backups-restored = 備份已還原。
backups-empty = 此模組尚未備份任何內容。
backups-module-panel = {$module} 備份

## Audit log
audit-panel-label = 稽核記錄
audit-col-when = 時間
audit-col-who = 呼叫者
audit-col-how = 認證資訊
audit-col-op = 操作
audit-col-module = 模組
audit-col-result = 結果
audit-filter-module-label = 模組
audit-filter-who-label = 呼叫者
audit-filter-limit-label = 列數
audit-filter-apply = 篩選
audit-filter-clear = 清除
audit-empty = 此主機上尚未記錄任何內容。
audit-result-ok = 成功
audit-result-denied = 已拒絕
audit-result-error = 失敗
audit-identity-local-user = 本機使用者
audit-identity-session = 工作階段
audit-identity-token = api 權杖
audit-op-list-modules = 列出模組
audit-op-get-module = 讀取模組
audit-op-validate = 驗證
audit-op-plan = 預覽
audit-op-apply = 套用
audit-op-confirm-commit = 確認提交
audit-op-rollback-commit = 回復提交
audit-op-list-backups = 列出備份
audit-op-restore = 還原備份
audit-op-service-status = 讀取服務狀態
audit-op-service-action = 操作服務
audit-op-host-profile = 讀取主機概況
audit-op-audit-query = 讀取稽核記錄
audit-op-cert-status = 讀取憑證狀態
audit-op-update-status = 讀取更新狀態
audit-op-cert-renew = 更新憑證
audit-op-update-apply = 安裝更新
## Schema-driven module forms
## Chrome the form engine (web/src/forms) renders around a module's schema.
## Field captions come from the schema's own property names, and a field's
## tooltip and recommendation are Fluent ids in the *module's* locale file, not
## here — a missing one degrades to no tooltip and is never rendered raw.
forms-advanced-toggle = 進階
forms-badge-security-high = 對安全性影響大
forms-badge-deprecated = 自 {$version} 起已棄用
forms-diagnostic-at-field = {$field}：{$message}
forms-diagnostic-unknown = 此主機回報了一個此組建沒有對應說明的檢查結果（{$id}）。
forms-item-add-caption = 新增
forms-item-move-down-caption = 下移
forms-item-move-up-caption = 上移
forms-item-remove-caption = 刪除
forms-list-empty = 這裡還沒有內容。
forms-option-none = 無
forms-row-add = 在 {$field} 新增一列
forms-row-label = 第 {$index} 列
forms-row-move-down = 將 {$field} 的第 {$index} 列下移
forms-row-move-up = 將 {$field} 的第 {$index} 列上移
forms-row-remove = 刪除 {$field} 的第 {$index} 列
forms-tag-add = 在 {$field} 新增一個項目
forms-tag-item = {$field} 的第 {$index} 個項目
forms-tag-move-down = 將 {$field} 的第 {$index} 個項目下移
forms-tag-move-up = 將 {$field} 的第 {$index} 個項目上移
forms-tag-remove = 刪除 {$field} 的第 {$index} 個項目
forms-unsupported-note = 此組建無法編輯該值。它會依儲存的原樣顯示，並維持不變。
forms-version-unsupported = 需要 {$service} {$since}，已安裝 {$installed}

## Form validation
## Mirrors the schema constraints for immediate feedback. The server is the
## authority: a clean pass here is not a promise that apply will succeed.
forms-error-enum = 請選擇列出的值之一。
forms-error-format-ip = 這不是有效的 ip 位址。
forms-error-integer = 請使用整數。
forms-error-max-length = 最多使用 {$max} 個字元。
forms-error-maximum = 請使用不超過 {$max} 的值。
forms-error-min-length = 至少使用 {$min} 個字元。
forms-error-minimum = 請使用不小於 {$min} 的值。
forms-error-pattern = 此值與該欄位接受的格式不符。
forms-error-required = 此欄位為必填。
forms-error-type = 此值不是該欄位所接受的類型。
