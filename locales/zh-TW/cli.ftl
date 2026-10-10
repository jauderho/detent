# needs-review: machine-drafted Traditional Chinese translation; not yet checked by a native speaker.
## detent CLI — zh-TW
## Source: locales/en-US/cli.ftl. Same ids, same placeables. Identifiers — module ids,
## paths, unit names, digests, enum wire names such as `restart` or `active` — are
## interpolated verbatim and must not be translated.

## severity words, prefixed to every rendered diagnostic
cli-severity-error = 錯誤
cli-severity-warning = 警告
cli-severity-recommendation = 注意

## yes/no, used wherever a flag is rendered
cli-yes = 是
cli-no = 否

## progress notes, printed on stderr under --verbose
cli-note-settings = 地區設定 {$locale}，狀態根目錄 {$state}，設定 {$config}
cli-note-operation = 正在對 {$module} 執行 {$operation}

## failures that stop a command before the operations layer sees it
cli-bad-stdin = 無法從 stdin 讀取模型：{$reason}
cli-bad-json = stdin 上的模型不是有效的 JSON：{$reason}
cli-bad-hash = `{$value}` 不是由 64 個十六進位字元組成的 SHA-256 摘要。
cli-start-failed = 無法啟動特權輔助程式：{$reason}
cli-monitor-stop = 特權輔助程式未能正常停止：{$reason}
cli-monitor-busy = 另一個 detent 監控程式已佔用此狀態根目錄；請透過網頁介面重試，或執行 `detent serve`。
cli-monitor-lock-unavailable = 無法取得 {$path} 中的狀態鎖，因此此指令無法變更任何內容；請以對該目錄有寫入權限的使用者身分執行，或傳入 --state-root。
cli-commit-recovered = 已復原未確認的提交 {$commit}；已還原 {$restored} 個目標，其中 {$failures} 個失敗。
cli-commit-confirm-needs-serve = 此模組需要 commit-confirm；請使用網頁介面或 `detent serve`，以便確認視窗得到強制執行。
cli-config-load-failed = 無法載入位於 {$path} 的設定：{$reason}
cli-no-command = 未指定任何指令。

## self-test probe and self-update (PLAN §2.9)
cli-self-test = 版本 {$version}，功能 {$features}
cli-update-available = 有可用的更新：{$tag}，發布於 {$published}
cli-update-security-available = 有可用的安全性更新：{$tag}，發布於 {$published}
cli-update-none = 沒有可用的更新（目前 {$current}）
cli-update-held-young = {$tag} 比 {$current} 新，但發布未滿 {$days} 天；時間門檻將其暫緩
cli-update-held-rejected = {$tag} 比 {$current} 新，但已在此主機上回復；將略過它
cli-verify-bundle-ok = {$file} 已證實屬於 {$tag}
cli-update-failed = 更新失敗：{$reason}
cli-update-installed = 已安裝 {$tag}；被取代的執行檔保存在 {$previous}
cli-update-not-restarted = 服務未重新啟動，因此新的執行檔尚未執行：{$reason}
cli-update-rolled-back = 已回復：{$reason}
cli-update-rollback-failed = 更新失敗（{$reason}），回復也失敗了（{$error}）；此主機需要處理

## config
cli-module-line = {$id}  {$name}
cli-no-model = 此模組在此主機上尚未管理任何檔案，因此沒有可顯示的模型。
cli-valid = 此設定有效。
cli-plan-no-change = {$module} 與 {$path} 的內容已經一致；不會有任何變更。
cli-plan-service = 套用此變更會影響 {$unit}。
cli-plan-hash = 該檔案目前的雜湊為 {$hash}；將其作為 --expect-hash 傳入，可拒絕同時發生的編輯。
cli-check-ran = 已執行上游驗證程式 {$program}；是否通過：{$passed}。{$detail}
cli-check-skipped = 未執行上游驗證程式 {$program}。{$detail}
cli-applied = 已將 {$module} 寫入 {$path}。
cli-applied-hash = 其雜湊由 {$prev} 變為 {$new}；備份已保留：{$backup}
cli-mounts-off = mounts：啟用功能已關閉（[mounts] activate_new_entries）；新的 fstab 項目將在下次開機或掛載時生效。
cli-mounts-error = mounts：未啟動任何掛載單元：{$reason}
cli-mounts-none = mounts：沒有需要掛載的新 fstab 項目。
cli-mounts-unit = 掛載 {$mountpoint}（{$unit}）：{$state}
cli-mounts-unit-detail = 掛載 {$mountpoint}（{$unit}）：{$state}：{$detail}
cli-commit-armed = 提交 {$id} 必須在 {$seconds} 秒內（即 {$deadline} 之前）確認，否則將回復。
cli-commit-confirmed = 提交 {$id} 已確認，不會被回復。
cli-commit-rolled-back = 提交 {$id} 已回復；{$targets} 個目標已還原。

## backups
cli-no-backups = 此模組尚未保留任何備份。
cli-backup-line = {$id}  {$name}  {$bytes} 位元組  {$digest}
cli-restored = 目標 {$target} 已還原，其雜湊目前為 {$hash}。

## services
cli-service-status = {$unit} 處於 {$state} 狀態；開機時啟動：{$enabled}
cli-serviced = 已要求 {$unit} 執行 {$action}；目前是否執行中：{$active}

## host
cli-host-profile = {$hostname}：{$os}，init {$init}，{$ram} MiB 記憶體
cli-host-service-version = 已安裝的 {$service} 版本為 {$version}
cli-host-backends = 網路後端 {$network}，解析器後端 {$resolver}，發行版 {$distro} {$version}
cli-host-note = 偵測說明：{$note}

## audit
cli-no-audit = 稽核記錄中沒有符合的紀錄。
cli-audit-line = {$ts}  {$who}  {$op}  {$module}  {$result}  {$error}
cli-audit-verified = 稽核鏈在紀錄 {$sequence} 之前完好；標頭摘要 {$hash}
cli-audit-broken = 無法驗證稽核鏈：{$reason}

## --dryrun
cli-dryrun-apply = 試執行：這是將為 {$module} 寫入 {$path} 的內容。
cli-dryrun-operation = 試執行：將對 {$module} 執行 {$operation}。
cli-dryrun-nothing = 試執行：未做任何變更。
cli-dryrun-serve = 試執行：監控程式和工作程式將啟動，帶有 {$modules} 個模組和 {$targets} 個目標，根目錄為 {$state}。
cli-dryrun-serve-mounts = 試執行：mounts 套用之後，執行器將啟動新 fstab 項目的掛載單元（mounts.activate_new_entries = true）。
cli-dryrun-cert-renew = 試執行：將要求位於 {$address} 的伺服器（以 {$name} 身分）立即更新其憑證；未傳送任何內容。

## serve
cli-serve-monitor = 工作程式已啟動，pid 為 {$pid}；是否已放棄特權：{$dropped}
cli-serve-worker = 工作程式正在執行；其 http 伺服器將在第 4 階段提供。握手：{$greeted}
cli-serve-failed = 無法啟動監控程式和工作程式：{$reason}
cli-serve-stopped = 這對程序意外停止：{$reason} {$status}
cli-serve-privileged-port = 通訊埠 {$port} 需要 cap_net_bind_service 或由監控程式傳遞的 socket，此組建均不支援；請使用 1024 或更高的通訊埠，或在前面放置反向代理。
cli-serve-privilege-mode = 所設定的特權模式與此程序不符，因此服務未啟動：{$reason}
cli-serve-acme-unsupported = 此組建沒有 dns-01 提供者（功能 acme-dns-providers），因此無法取得 acme 憑證；請在 {$path} 中將 tls.bootstrap 設為 "self-signed"。
cli-serve-acme-setting-missing = tls.bootstrap 為 "acme"，但 {$path} 中未設定 {$setting}。
cli-serve-acme-path-outside = {$setting}（{$value}）不在狀態根目錄 {$root} 之下：受限的程序只能寫入該目錄。
cli-serve-acme-credentials-dir = 無法準備 acme 認證資訊目錄 {$path}：{$reason}
cli-serve-secrets-failed = 機密檔案 {$path} 被拒絕：{$reason}
cli-serve-acme-secret-missing = 已設定 acme.provider，但 {$path} 的 [acme] 表中沒有 dns_provider 機密。
cli-serve-acme-provider-invalid = acme.provider 中的 dns-01 提供者無法使用：{$reason}
cli-serve-acme-providers-not-built = 此組建沒有 dns-01 提供者（功能 acme-dns-providers）；請從 {$path} 中移除 [acme.provider]。
cli-serve-handshake-failed = 工作程式未能完成與監控程式的握手。
cli-serve-auth-failed = 無法開啟帳號、權杖和工作階段儲存區：{$reason}
cli-serve-tls-failed = 無法準備 tls 憑證：{$reason}
cli-serve-cert-fingerprint = tls 引導憑證指紋（sha-256）：{$fingerprint}
cli-serve-web-failed = 網頁伺服器無法啟動：{$reason}
cli-serve-web-stopped = 網頁伺服器未能正常停止：{$reason}
cli-serve-listening = 正在監聽 {$addr}
cli-serve-confinement-degraded = 隔離已降級：{$detail}
cli-mcp-missing-token = 未設定 {$var}；請先用 `detent token create` 建立一個並匯出，然後再啟動 mcp 伺服器。
cli-mcp-serve-failed = mcp 伺服器無法啟動：{$reason}
cli-mcp-listening = mcp 正在提供 {$transport} 服務
cli-mcp-http-needs-privsep = mcp http 傳輸不能以 root 身分或帶有 capabilities 執行：網路剖析器將以近似 root 的權限執行；請以不帶 capabilities 的非 root 使用者身分執行，或改用 stdio 傳輸。
cli-mcp-bind-not-loopback = mcp http 繫結位址必須是迴路位址（127.0.0.1 或 ::1）；bearer 權杖在網路上是以明文傳送的。
cli-dryrun-mcp = 試執行：mcp 將在 {$addr} 上提供 {$transport} 服務，範圍為 {$scope}。

## setup, user, token
cli-setup-exists = 此主機上已存在名為 `{$name}` 的使用者；傳入 --force 可覆寫它。
cli-setup-created = 已建立管理員帳號 `{$name}`。
cli-user-created = 已建立帳號 `{$name}`。
cli-user-passwd = 已變更 `{$name}` 的密碼。
cli-user-removed = 已移除帳號 `{$name}`。
cli-totp-uri = 請將此內容加入您的驗證器應用程式：{$uri}
cli-totp-secret = 或將此金鑰輸入其中：{$secret}
cli-totp-code-prompt = 驗證器中的驗證碼：
cli-totp-code-empty = 驗證碼不能為空。
cli-totp-code-wrong = 該驗證碼無效，因此未啟用第二重驗證。
cli-user-totp-enabled = 已啟用 `{$name}` 的第二重驗證。
cli-totp-disable-prompt = 要停用 `{$name}` 的第二重驗證嗎？[y/N]
cli-totp-disable-cancelled = `{$name}` 的第二重驗證維持啟用。
cli-user-totp-disabled = 已停用 `{$name}` 的第二重驗證。
cli-token-created = 已建立權杖 {$id}（{$label}）；它不會再次顯示：{$token}
cli-token-revoked = 已撤銷權杖 {$id}。
cli-token-no-tokens = 尚未簽發任何權杖。
cli-token-line = {$id}  {$label}  {$scopes}  {$created}  {$expires}
cli-credential-failed = 無法完成該要求：{$reason}
cli-audit-failed = 變更已完成，但無法寫入其稽核紀錄：{$reason}
cli-state-command-as-root = detent {$command} 不得以 root 身分執行：它寫入的檔案將歸 root 所有，服務將無法讀取。請改用服務帳號執行：sudo -u {$account} detent {$command}

## cert status
cli-cert-source = 來源：{$source}
cli-cert-fingerprint = 指紋（sha-256）：{$fingerprint}
cli-cert-not-after = 到期時間：{$not_after}
cli-cert-not-after-unknown = 到期時間：未知（憑證無法剖析）。
cli-cert-lifetime = 已用有效期限：{$percent}（警告：{$warning}）。
cli-cert-lifetime-no-warning = 已用有效期限：{$percent}（無警告）。
cli-cert-lifetime-unknown = 已用有效期限：未知（憑證無法剖析）。
cli-cert-missing = {$path} 中沒有儲存憑證；請啟動一次伺服器，讓它寫入憑證。
cli-cert-unreadable = 無法讀取 {$path} 中的憑證：{$reason}

## cert renew
cli-cert-renew-requested = 已要求更新：伺服器已請其 ACME 用戶端立即更新。請用 `detent cert status` 查看結果。
cli-cert-renew-token-refused = 權杖被拒絕（HTTP {$status}）；它需要寫入範圍：`detent token create <name> --write`。
cli-cert-renew-not-acme = 伺服器沒有執行 ACME 程序（`tls.bootstrap` 不是 `acme`），因此無需更新。
cli-cert-renew-server-error = 伺服器回應了 HTTP {$status}：{$message_id}
cli-cert-renew-server-error-bare = 伺服器回應了 HTTP {$status}。
cli-cert-renew-unreachable = 無法與位於 {$address} 的伺服器通訊：{$reason}
cli-cert-renew-no-token = 沒有 API 權杖：請傳入 --token-file <path> 或設定 {$var}。可用 `detent token create <name> --write` 建立寫入權杖。
cli-cert-renew-bad-token = 來自 {$source} 的權杖被拒絕：{$reason}
cli-cert-renew-ca-unreadable = 無法讀取 CA 檔案 {$path}：{$reason}

## password entry (setup, user add, user passwd)
cli-password-prompt = 密碼：
cli-password-confirm = 確認密碼：
cli-password-mismatch = 兩次輸入的密碼不一致。
cli-password-empty = 密碼不能為空。

## doctor
cli-status-ok = ok
cli-status-warn = 警告
cli-status-fail = 失敗
cli-doctor-modules = 此組建中編譯進來的模組：{$detail}
cli-doctor-state-root = 狀態目錄 {$detail}
cli-doctor-config = 設定檔 {$detail}
cli-doctor-privsep = 特權分離能否產生出可用的程序對：{$detail}
cli-doctor-landlock = landlock: {$detail}
cli-doctor-seccomp = seccomp: {$detail}
cli-doctor-confinement = 沙箱隔離：{$detail}
cli-doctor-serve-confinement = 上次 serve 啟動時的隔離：{$detail}
cli-doctor-mounts = fstab 套用後的掛載啟用：{$detail}
cli-doctor-privilege-mode = 特權模式：{$detail}
cli-doctor-service-account = 服務帳號：{$detail}
cli-doctor-state-owner = 狀態目錄擁有者：{$detail}
cli-doctor-backups-dir = 備份目錄：{$detail}
cli-doctor-polkit-rule = polkit 規則：{$detail}
cli-doctor-polkit-daemon = polkit 常駐程式：{$detail}
cli-doctor-unit-capabilities = 服務單元身分和 capabilities：{$detail}
