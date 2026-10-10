# needs-review: machine-drafted Simplified Chinese translation; not yet checked by a native speaker.
## detent CLI — zh-CN
## Source: locales/en-US/cli.ftl. Same ids, same placeables. Identifiers — module ids,
## paths, unit names, digests, enum wire names such as `restart` or `active` — are
## interpolated verbatim and must not be translated.

## severity words, prefixed to every rendered diagnostic
cli-severity-error = 错误
cli-severity-warning = 警告
cli-severity-recommendation = 注意

## yes/no, used wherever a flag is rendered
cli-yes = 是
cli-no = 否

## progress notes, printed on stderr under --verbose
cli-note-settings = 语言区域 {$locale}，状态根目录 {$state}，配置 {$config}
cli-note-operation = 正在对 {$module} 执行 {$operation}

## failures that stop a command before the operations layer sees it
cli-bad-stdin = 无法从 stdin 读取模型：{$reason}
cli-bad-json = stdin 上的模型不是有效的 JSON：{$reason}
cli-bad-hash = `{$value}` 不是由 64 个十六进制字符组成的 SHA-256 摘要。
cli-start-failed = 无法启动特权辅助进程：{$reason}
cli-monitor-stop = 特权辅助进程未能正常停止：{$reason}
cli-monitor-busy = 另一个 detent 监控进程已占用此状态根目录；请通过 Web 界面重试，或运行 `detent serve`。
cli-monitor-lock-unavailable = 无法获取 {$path} 中的状态锁，因此此命令无法更改任何内容；请以对该目录有写权限的用户身份运行，或传入 --state-root。
cli-commit-recovered = 已恢复未确认的提交 {$commit}；已还原 {$restored} 个目标，其中 {$failures} 个失败。
cli-commit-confirm-needs-serve = 此模块需要 commit-confirm；请使用 Web 界面或 `detent serve`，以便确认窗口得到强制执行。
cli-config-load-failed = 无法加载位于 {$path} 的配置：{$reason}
cli-no-command = 未给出任何命令。

## self-test probe and self-update (PLAN §2.9)
cli-self-test = 版本 {$version}，功能 {$features}
cli-update-available = 有可用更新：{$tag}，发布于 {$published}
cli-update-security-available = 有可用的安全更新：{$tag}，发布于 {$published}
cli-update-none = 没有可用更新（当前 {$current}）
cli-update-held-young = {$tag} 比 {$current} 新，但发布未满 {$days} 天；时间门槛将其暂缓
cli-update-held-rejected = {$tag} 比 {$current} 新，但已在此主机上回滚；将跳过它
cli-verify-bundle-ok = {$file} 已被证明属于 {$tag}
cli-update-failed = 更新失败：{$reason}
cli-update-installed = 已安装 {$tag}；被替换的二进制文件保存在 {$previous}
cli-update-not-restarted = 服务未重启，因此新的二进制文件尚未运行：{$reason}
cli-update-rolled-back = 已回滚：{$reason}
cli-update-rollback-failed = 更新失败（{$reason}），回滚也失败了（{$error}）；此主机需要处理

## config
cli-module-line = {$id}  {$name}
cli-no-model = 此模块在此主机上尚未管理任何文件，因此没有可显示的模型。
cli-valid = 此配置有效。
cli-plan-no-change = {$module} 与 {$path} 的内容已经一致；不会有任何更改。
cli-plan-service = 应用此更改会影响 {$unit}。
cli-plan-hash = 该文件现在的哈希为 {$hash}；将其作为 --expect-hash 传入，可拒绝并发的编辑。
cli-check-ran = 已运行上游验证程序 {$program}；是否通过：{$passed}。{$detail}
cli-check-skipped = 未运行上游验证程序 {$program}。{$detail}
cli-applied = 已将 {$module} 写入 {$path}。
cli-applied-hash = 其哈希由 {$prev} 变为 {$new}；备份已保留：{$backup}
cli-mounts-off = mounts：激活已关闭（[mounts] activate_new_entries）；新的 fstab 条目将在下次启动或挂载时生效。
cli-mounts-error = mounts：未启动任何挂载单元：{$reason}
cli-mounts-none = mounts：没有需要挂载的新 fstab 条目。
cli-mounts-unit = 挂载 {$mountpoint}（{$unit}）：{$state}
cli-mounts-unit-detail = 挂载 {$mountpoint}（{$unit}）：{$state}：{$detail}
cli-commit-armed = 提交 {$id} 必须在 {$seconds} 秒内（即 {$deadline} 之前）确认，否则将回滚。
cli-commit-confirmed = 提交 {$id} 已确认，不会被回滚。
cli-commit-rolled-back = 提交 {$id} 已回滚；{$targets} 个目标已还原。

## backups
cli-no-backups = 此模块尚未保留任何备份。
cli-backup-line = {$id}  {$name}  {$bytes} 字节  {$digest}
cli-restored = 目标 {$target} 已还原，其哈希现为 {$hash}。

## services
cli-service-status = {$unit} 处于 {$state} 状态；开机启动：{$enabled}
cli-serviced = 已要求 {$unit} 执行 {$action}；当前是否运行：{$active}

## host
cli-host-profile = {$hostname}：{$os}，init {$init}，{$ram} MiB 内存
cli-host-service-version = 已安装的 {$service} 版本为 {$version}
cli-host-backends = 网络后端 {$network}，解析器后端 {$resolver}，发行版 {$distro} {$version}
cli-host-note = 检测说明：{$note}

## audit
cli-no-audit = 审计日志中没有匹配的记录。
cli-audit-line = {$ts}  {$who}  {$op}  {$module}  {$result}  {$error}
cli-audit-verified = 审计链在记录 {$sequence} 之前完好；头部摘要 {$hash}
cli-audit-broken = 无法验证审计链：{$reason}

## --dryrun
cli-dryrun-apply = 试运行：这是将为 {$module} 写入 {$path} 的内容。
cli-dryrun-operation = 试运行：将对 {$module} 执行 {$operation}。
cli-dryrun-nothing = 试运行：未做任何更改。
cli-dryrun-serve = 试运行：监控进程和工作进程将启动，带有 {$modules} 个模块和 {$targets} 个目标，根目录为 {$state}。
cli-dryrun-serve-mounts = 试运行：mounts 应用之后，运行器将启动新 fstab 条目的挂载单元（mounts.activate_new_entries = true）。
cli-dryrun-cert-renew = 试运行：将请求位于 {$address} 的服务器（以 {$name} 身份）立即续期其证书；未发送任何内容。

## serve
cli-serve-monitor = 工作进程已启动，pid 为 {$pid}；是否已放弃特权：{$dropped}
cli-serve-worker = 工作进程正在运行；其 http 服务器将在第 4 阶段提供。握手：{$greeted}
cli-serve-failed = 无法启动监控进程和工作进程：{$reason}
cli-serve-stopped = 这对进程意外停止：{$reason} {$status}
cli-serve-privileged-port = 端口 {$port} 需要 cap_net_bind_service 或由监控进程传递的套接字，此构建均不支持；请使用 1024 或更高的端口，或在前面放置反向代理。
cli-serve-privilege-mode = 所配置的特权模式与此进程不符，因此服务未启动：{$reason}
cli-serve-acme-unsupported = 此构建没有 dns-01 提供商（功能 acme-dns-providers），因此无法获取 acme 证书；请在 {$path} 中将 tls.bootstrap 设为 "self-signed"。
cli-serve-acme-setting-missing = tls.bootstrap 为 "acme"，但 {$path} 中未设置 {$setting}。
cli-serve-acme-path-outside = {$setting}（{$value}）不在状态根目录 {$root} 之下：受限进程只能写入该目录。
cli-serve-acme-credentials-dir = 无法准备 acme 凭据目录 {$path}：{$reason}
cli-serve-secrets-failed = 密钥文件 {$path} 被拒绝：{$reason}
cli-serve-acme-secret-missing = 已设置 acme.provider，但 {$path} 的 [acme] 表中没有 dns_provider 密钥。
cli-serve-acme-provider-invalid = acme.provider 中的 dns-01 提供商无法使用：{$reason}
cli-serve-acme-providers-not-built = 此构建没有 dns-01 提供商（功能 acme-dns-providers）；请从 {$path} 中移除 [acme.provider]。
cli-serve-handshake-failed = 工作进程未能完成与监控进程的握手。
cli-serve-auth-failed = 无法打开账户、令牌和会话存储：{$reason}
cli-serve-tls-failed = 无法准备 tls 证书：{$reason}
cli-serve-cert-fingerprint = tls 引导证书指纹（sha-256）：{$fingerprint}
cli-serve-web-failed = Web 服务器无法启动：{$reason}
cli-serve-web-stopped = Web 服务器未能正常停止：{$reason}
cli-serve-listening = 正在监听 {$addr}
cli-serve-confinement-degraded = 隔离已降级：{$detail}
cli-mcp-missing-token = 未设置 {$var}；请先用 `detent token create` 创建一个并导出，然后再启动 mcp 服务器。
cli-mcp-serve-failed = mcp 服务器无法启动：{$reason}
cli-mcp-listening = mcp 正在提供 {$transport} 服务
cli-mcp-http-needs-privsep = mcp http 传输不能以 root 身份或带有 capabilities 运行：网络解析器将以近似 root 的权限运行；请以不带 capabilities 的非 root 用户身份运行，或改用 stdio 传输。
cli-mcp-bind-not-loopback = mcp http 绑定地址必须是环回地址（127.0.0.1 或 ::1）；bearer 令牌在网络上是明文传输的。
cli-dryrun-mcp = 试运行：mcp 将在 {$addr} 上提供 {$transport} 服务，作用域为 {$scope}。

## setup, user, token
cli-setup-exists = 此主机上已存在名为 `{$name}` 的用户；传入 --force 可覆盖它。
cli-setup-created = 已创建管理员账户 `{$name}`。
cli-user-created = 已创建账户 `{$name}`。
cli-user-passwd = 已修改 `{$name}` 的密码。
cli-user-removed = 已删除账户 `{$name}`。
cli-totp-uri = 请将此内容添加到您的验证器应用：{$uri}
cli-totp-secret = 或将此密钥输入其中：{$secret}
cli-totp-code-prompt = 验证器中的验证码：
cli-totp-code-empty = 验证码不能为空。
cli-totp-code-wrong = 该验证码无效，因此未开启第二重验证。
cli-user-totp-enabled = 已开启 `{$name}` 的第二重验证。
cli-totp-disable-prompt = 要关闭 `{$name}` 的第二重验证吗？[y/N]
cli-totp-disable-cancelled = `{$name}` 的第二重验证保持开启。
cli-user-totp-disabled = 已关闭 `{$name}` 的第二重验证。
cli-token-created = 已创建令牌 {$id}（{$label}）；它不会再次显示：{$token}
cli-token-revoked = 已吊销令牌 {$id}。
cli-token-no-tokens = 尚未签发任何令牌。
cli-token-line = {$id}  {$label}  {$scopes}  {$created}  {$expires}
cli-credential-failed = 无法完成该请求：{$reason}
cli-audit-failed = 更改已完成，但无法写入其审计记录：{$reason}
cli-state-command-as-root = detent {$command} 不得以 root 身份运行：它写入的文件将归 root 所有，服务将无法读取。请改用服务账户运行：sudo -u {$account} detent {$command}

## cert status
cli-cert-source = 来源：{$source}
cli-cert-fingerprint = 指纹（sha-256）：{$fingerprint}
cli-cert-not-after = 到期时间：{$not_after}
cli-cert-not-after-unknown = 到期时间：未知（证书无法解析）。
cli-cert-lifetime = 已用有效期：{$percent}（警告：{$warning}）。
cli-cert-lifetime-no-warning = 已用有效期：{$percent}（无警告）。
cli-cert-lifetime-unknown = 已用有效期：未知（证书无法解析）。
cli-cert-missing = {$path} 中没有存储证书；请启动一次服务器，让它写入证书。
cli-cert-unreadable = 无法读取 {$path} 中的证书：{$reason}

## cert renew
cli-cert-renew-requested = 已请求续期：服务器已要求其 ACME 客户端立即续期。请用 `detent cert status` 查看结果。
cli-cert-renew-token-refused = 令牌被拒绝（HTTP {$status}）；它需要写入作用域：`detent token create <name> --write`。
cli-cert-renew-not-acme = 服务器没有运行 ACME 进程（`tls.bootstrap` 不是 `acme`），因此无需续期。
cli-cert-renew-server-error = 服务器返回了 HTTP {$status}：{$message_id}
cli-cert-renew-server-error-bare = 服务器返回了 HTTP {$status}。
cli-cert-renew-unreachable = 无法与位于 {$address} 的服务器通信：{$reason}
cli-cert-renew-no-token = 没有 API 令牌：请传入 --token-file <path> 或设置 {$var}。可用 `detent token create <name> --write` 创建写入令牌。
cli-cert-renew-bad-token = 来自 {$source} 的令牌被拒绝：{$reason}
cli-cert-renew-ca-unreadable = 无法读取 CA 文件 {$path}：{$reason}

## password entry (setup, user add, user passwd)
cli-password-prompt = 密码：
cli-password-confirm = 确认密码：
cli-password-mismatch = 两次输入的密码不一致。
cli-password-empty = 密码不能为空。

## doctor
cli-status-ok = ok
cli-status-warn = 警告
cli-status-fail = 失败
cli-doctor-modules = 此构建中编译进来的模块：{$detail}
cli-doctor-state-root = 状态目录 {$detail}
cli-doctor-config = 配置文件 {$detail}
cli-doctor-privsep = 特权分离能否派生出可用的进程对：{$detail}
cli-doctor-landlock = landlock: {$detail}
cli-doctor-seccomp = seccomp: {$detail}
cli-doctor-confinement = 沙箱隔离：{$detail}
cli-doctor-serve-confinement = 上次 serve 启动时的隔离：{$detail}
cli-doctor-mounts = fstab 应用后的挂载激活：{$detail}
cli-doctor-privilege-mode = 特权模式：{$detail}
cli-doctor-service-account = 服务账户：{$detail}
cli-doctor-state-owner = 状态目录所有者：{$detail}
cli-doctor-backups-dir = 备份目录：{$detail}
cli-doctor-polkit-rule = polkit 规则：{$detail}
cli-doctor-polkit-daemon = polkit 守护进程：{$detail}
cli-doctor-unit-capabilities = 服务单元身份和 capabilities：{$detail}
