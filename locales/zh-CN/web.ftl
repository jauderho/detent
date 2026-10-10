# needs-review: machine-drafted Simplified Chinese translation; not yet checked by a native speaker.
## detent web admin UI — zh-CN
## Source: locales/en-US/web.ftl. Same ids, same placeables, same selectors.

## Status bar
status-brand = detent
status-online = 系统在线
status-clock-label = utc
status-mode-label = 模式
theme-toggle-aria = 切换浅色和深色模式
theme-toggle-title = 切换浅色 / 深色

## catfu component layer
## Chrome the shared components render themselves. Content strings (field
## captions, table headers, banner copy) are supplied by the calling page.
component-countdown-remaining = 剩余时间
component-field-info = 更多信息
component-modal-close = 关闭
component-switch-off = 关
component-switch-on = 开
component-table-empty = 暂无记录

## API failures
## docs/API.md: every failure is `{ code, message_id }`, and `message_id` is a
## Fluent id. src/api/messages.ts resolves it here; an id this build does not
## know falls back to `api-error-unknown`, so an id is never rendered raw.
##
## The first three are the console's own — a failure that never reached a
## server has no `message_id` to resolve. The rest mirror the ids the server
## sends, argument-free: locales/en-US/core.ftl interpolates `{$path}`,
## `{$reason}` and friends, and the API deliberately sends none of them.
api-error-network = 控制台无法连接到此主机。
api-error-malformed = 此主机发送了控制台无法读取的应答。
api-error-unknown = 此主机报告了一个控制台没有对应说明的故障。
core-edit-index-out-of-range = 内部错误：某次编辑指向了文件之外的行。
core-edit-line-break = 值不能包含换行符或空字节。
core-edit-unsupported = 此编辑无法用该文件的格式表达。
core-model-shape = 提供的配置不具备预期的结构。
core-model-unrepresentable = 此文件包含编辑器无法表示的内容。
core-parse-malformed = 此文件不符合其模块所要求的格式。
ops-audit-failed = 无法读取审计日志。
ops-audit-unavailable = 无法写入审计日志，因此该操作被拒绝。
ops-denied = 您无权执行此操作。
ops-hash-conflict = 该文件在被读取之后已在磁盘上发生变化；请重新读取后再试。
ops-check-failed = 外部验证程序拒绝了候选配置。
ops-invalid-model = 该配置无效。
ops-no-service = 此模块在此主机上不控制任何服务，因此无法重启。
ops-no-target = 此模块在此主机上不管理任何文件。
ops-privsep-failed = 特权辅助进程拒绝了请求，或无法完成请求。
ops-service-failed = 服务操作未能完成。
ops-unknown-module = 此构建中没有该名称的模块。
ops-unsupported = 此构建不支持该操作。
ops-commit-pending = 已有另一个 commit-confirm 窗口处于待确认状态。
ops-update-running = 更新已在运行；请等待其完成，然后检查当前运行的版本。
ops-update-tag-invalid = 这不是发布版本号；它的格式必须类似 v1.2.3。
ops-update-not-newer = 该发布版本并不比当前运行的版本更新；未启动任何操作。
ops-no-backup = commit-confirm 需要保留一份备份；未做任何更改。
ops-arm-failed-restored = 无法启用 commit-confirm，因此更改已被撤销；先前的内容已恢复。
ops-arm-failed-unrestored = 无法启用 commit-confirm，且更改无法撤销；新内容仍在磁盘上。请立即恢复先前的备份。
ops-target-missing = 受管理的文件不存在；请创建它（安装其软件包或手动创建），然后重试。
web-api-unexpected-outcome = 操作已完成，但其结果无法呈现。
web-auth-ambiguous-credentials = 请发送会话 cookie 或 bearer 令牌二者之一，不要同时发送。
web-auth-argon2-params = 所配置的 argon2 参数不可用。
web-auth-busy = 正在进行的登录过多；请稍候再试。
web-auth-csrf-rejected = 此请求未通过跨站检查；请刷新页面后重试。
web-auth-entropy-unavailable = 系统随机数生成器出现故障，因此无法签发任何凭据。
web-auth-hash-failed = 无法对密码进行哈希。
web-auth-invalid-credentials = 用户名、密码或验证码不正确。
web-auth-password-change-required = 请先修改密码，然后再进行其他操作。
web-auth-password-too-long = 密码最多只能有 128 个字符。
web-auth-password-too-short = 密码至少须有 12 个字符。
web-auth-password-unchanged = 新密码必须与当前密码不同。
web-auth-rate-limited = 尝试次数过多；请稍候再试。
web-auth-session-limit = 打开的会话过多；请等待其中一个过期后再重新登录。
web-auth-store-malformed = 此主机上的某个凭据文件无效。
web-auth-store-unreadable = 无法读取此主机上的某个凭据文件。
web-auth-store-unwritable = 无法为写入准备此主机上的某个凭据文件。
web-auth-store-write-failed = 无法写入此主机上的某个凭据文件。
web-auth-token-limit = 此主机已持有 api 令牌数量的上限。
web-auth-token-unknown = 该 api 令牌不存在、已被吊销或已过期。
web-auth-totp-secret-invalid = 该验证器密钥不是有效的 base32。
web-auth-unauthenticated = 请先登录再执行此操作。
web-auth-user-exists = 已存在同名用户。
web-auth-user-name-invalid = 该用户名不可用；请使用 1 到 32 个 `a-z`、`0-9`、`.`、`_` 或 `-` 字符，并以字母或数字开头。
web-auth-user-unknown = 没有该名称的用户。
web-cert-renew-not-acme = 续期需要在 detent.toml 中设置 `tls.bootstrap = "acme"`。
web-cert-renew-unavailable = acme 客户端没有收到续期请求；请稍后再试。
web-denied-scope = 此凭据不具备该操作所需的作用域。
web-engine-stopped = 操作引擎已不再运行；请在服务恢复后重试。
web-update-not-checked = 此主机尚未进行过更新检查；请以 root 身份运行 `detent update --check`。
web-request-malformed = 请求体的结构不是此端点所期望的。
web-request-too-deep = 请求体的嵌套层级过深。

## Sign in
login-title = 登录
login-panel-label = 会话
login-username-label = 用户名
login-password-label = 密码
login-totp-label = 验证器验证码
login-totp-description = 为此账户绑定的验证器所显示的六位数字。
login-totp-reveal = 使用验证器验证码
login-submit = 登录
login-submitting = 正在登录
login-retry-after = 尝试次数过多；请等待 {$seconds} 秒后再试。

## Change password
password-change-title = 修改密码
password-change-panel-label = 密码
password-change-intro = 此账户必须先设置新密码，才能进行其他操作。
password-change-current-label = 当前密码
password-change-new-label = 新密码
password-change-new-description = 12 到 128 个字符；可使用任意字符。
password-change-confirm-label = 确认新密码
password-change-mismatch = 两次输入的新密码不一致。
password-change-submit = 修改密码
password-change-submitting = 正在修改密码

## Session and scope
auth-checking = 正在检查此会话
auth-sign-out = 退出登录
scope-gate-read-only = 此会话仅具有读取权限，无法更改此主机上的任何内容。
scope-gate-signed-out = 请登录后再更改此主机上的内容。

## Navigation
nav-label = 栏目
nav-dashboard = 仪表盘
nav-modules = 模块
nav-services = 服务
nav-backups = 备份
nav-audit = 审计
nav-certificates = 证书
nav-settings = 设置

## Routed pages
## Certificates and settings are still named placeholders: neither has an API
## to drive. Certificates waits on Phase 6 (ACME); settings waits on the user
## and token endpoints.
page-placeholder-body = 此栏目尚未构建。
page-dashboard-title = 仪表盘
page-modules-title = 模块
page-module-detail-title = 模块 {$module}
page-services-title = 服务
page-backups-title = 备份
page-audit-title = 审计日志
page-certificates-title = 证书
page-settings-title = 设置
page-not-found-title = 页面不存在
page-not-found-body = 该地址在此控制台中不对应任何内容。
page-not-found-home = 前往仪表盘

## Pending commit
pending-commit-message = 有一项配置更改正在等待确认；此窗口关闭时，它会自动回滚。
pending-commit-countdown-label = 确认剩余时间
pending-commit-confirm = 确认更改
pending-commit-confirming = 正在确认…

## Shared page states
## Every section is a query away from its data, so loading, failure and "this
## host has none of these" are shared rather than re-worded per page.
state-loading = 正在加载
state-unknown = 未知
value-no = 否
value-yes = 是

## Dashboard
dashboard-host-panel = 主机
dashboard-host-hostname = 主机名
dashboard-host-os = 操作系统
dashboard-host-init = init 系统
dashboard-host-distro = 发行版
dashboard-host-ram = 内存
dashboard-host-network-backend = 网络后端
dashboard-host-resolver-backend = 解析器后端
dashboard-host-notes = 检测说明
dashboard-cert-panel = 证书
dashboard-cert-fingerprint = 指纹
dashboard-cert-expires = 到期时间
dashboard-cert-lifetime-used = 已用有效期
dashboard-cert-expired = 已过期；请更换此证书。
dashboard-cert-expiring-soon = 将在 30 天内到期；请计划续期。
dashboard-cert-half = 已用去证书有效期的一半；续期已排入计划。
dashboard-cert-quarter = 已用去证书有效期的四分之三；请尽快续期。
cert-renew-panel = 续期
cert-renew-now = 立即续期
cert-renew-requested = 已请求续期。CA 签发新证书后将自动安装。
dashboard-modules-panel = 模块
dashboard-modules-count = {$count ->
   *[other] 此构建中编译进了 {$count} 个模块。
}
dashboard-audit-panel = 最近活动
dashboard-view-all = 查看全部
dashboard-update-panel = 更新
dashboard-update-current = 当前运行的版本
dashboard-update-published = 发布时间
dashboard-update-up-to-date = 没有适用于此构建的更新版本。
dashboard-update-available = 此构建有可用的版本 {$tag}。
dashboard-update-security = 此版本被标记为安全更新；它不受时间门槛限制。
dashboard-update-install = 安装 {$tag}
dashboard-update-confirm-title = 安装此更新？
dashboard-update-confirm-body = 这将在后台开始安装 {$tag}。如果安装成功，detent 服务会重启，页面可能会断开后重新连接；如果重启后的服务状态不正常，更新会回滚。
dashboard-update-confirm-action = 安装
dashboard-update-confirm-cancel = 取消
dashboard-update-started = 已在后台开始更新到 {$version}。如果安装成功，服务会重启；如果状态不正常，则会回滚；当前运行的版本会显示结果。

## Modules
modules-panel-label = 已安装的模块
modules-col-module = 模块
modules-col-targets = 文件
modules-col-services = 服务
modules-col-commit-confirm = commit-confirm
modules-commit-confirm-required = 需要
modules-commit-confirm-not-required = 不需要
modules-empty = 此构建中没有编译进任何模块。
modules-none = 无

## One module
module-about-panel = 模块
module-configuration-panel = 配置
module-upstream-label = 跟随上游
module-targets-label = 文件
module-services-label = 服务
module-current-hash-label = 磁盘上的摘要
module-security-notes-label = 安全说明
module-model-missing = 此模块的文件在此主机上尚不存在。下面的表单以该模块自身的默认值为起点，应用后会创建该文件。
module-action-validate = 验证
module-action-plan = 预览
module-action-apply = 应用
module-action-discard = 放弃编辑
module-busy = 处理中
module-validate-clean = 此配置通过了此主机运行的所有检查。
module-plan-title = 计划的更改
module-plan-no-change = 此配置与磁盘上已有的内容一致；没有需要应用的更改。
module-plan-diff-label = 差异
module-plan-checks-label = 上游检查
module-plan-check-passed = 通过
module-plan-check-failed = 失败
module-plan-check-exit = 退出码 {$code}
module-plan-services-label = 将受影响的服务
module-plan-apply = 应用此更改
module-apply-title = 应用此更改？
module-apply-body = 这将在此主机上写入 {$path}。当前内容会先被备份。
module-apply-commit-confirm = 此模块可能导致管理员被锁定在外，因此该更改会启用 commit-confirm 窗口：除非您在截止时间之前确认，否则它会自动回滚。
module-apply-service-label = 之后
module-apply-service-none = 不处理该服务
module-apply-cancel = 取消
module-applied = 更改已写入 {$path}。
module-applied-created = {$path} 原本不存在，现已创建。
module-mounts-off = 新的 fstab 条目未被挂载（[mounts] activate_new_entries 已关闭）；它们将在下次启动或挂载时生效。
module-mounts-error = 未启动任何挂载单元：{$reason}
module-mounts-none = 没有需要挂载的新 fstab 条目。
module-mounts-units = 新 fstab 条目的挂载单元：
module-mount-state-mounted = 已挂载
module-mount-state-already-mounted = 此前已挂载
module-mount-state-pending = 仍在挂载
module-mount-state-failed = 失败
module-mount-state-protected = 已拒绝：受保护的路径
module-mount-state-stopped = 已卸载
module-cancel = 取消

## Services
services-panel-label = 服务
services-col-module = 模块
services-col-unit = 单元
services-col-state = 状态
services-col-enabled = 开机启动
services-col-since = 起始时间
services-col-actions = 操作
services-state-active = 运行中
services-state-inactive = 未运行
services-state-failed = 失败
services-state-activating = 正在启动
services-state-deactivating = 正在停止
services-state-unknown = 未知
services-action-restart = 重启
services-action-reload = 重新加载
services-action-start = 启动
services-action-stop = 停止
services-acted = {$unit}：{$detail}
services-empty = 此构建中没有模块在此主机上控制服务。
services-confirm-title = {$action} {$unit}？
services-confirm-body = 这会立即作用于正在运行的服务。
services-confirm-cancel = 取消

## Backups
backups-col-name = 备份
backups-col-created = 创建时间
backups-col-size = 大小
backups-col-digest = 摘要
backups-col-actions = 操作
backups-action-restore = 还原
backups-confirm-title = 还原此备份？
backups-confirm-body = 这将用保留的副本替换 {$target}。当前内容会先被备份。
backups-confirm-cancel = 取消
backups-restored = 备份已还原。
backups-empty = 此模块尚未备份任何内容。
backups-module-panel = {$module} 备份

## Audit log
audit-panel-label = 审计日志
audit-col-when = 时间
audit-col-who = 调用者
audit-col-how = 凭据
audit-col-op = 操作
audit-col-module = 模块
audit-col-result = 结果
audit-filter-module-label = 模块
audit-filter-who-label = 调用者
audit-filter-limit-label = 行数
audit-filter-apply = 筛选
audit-filter-clear = 清除
audit-empty = 此主机上尚未记录任何内容。
audit-result-ok = 成功
audit-result-denied = 已拒绝
audit-result-error = 失败
audit-identity-local-user = 本地用户
audit-identity-session = 会话
audit-identity-token = api 令牌
audit-op-list-modules = 列出模块
audit-op-get-module = 读取模块
audit-op-validate = 验证
audit-op-plan = 预览
audit-op-apply = 应用
audit-op-confirm-commit = 确认提交
audit-op-rollback-commit = 回滚提交
audit-op-list-backups = 列出备份
audit-op-restore = 还原备份
audit-op-service-status = 读取服务状态
audit-op-service-action = 操作服务
audit-op-host-profile = 读取主机概况
audit-op-audit-query = 读取审计日志
audit-op-cert-status = 读取证书状态
audit-op-update-status = 读取更新状态
audit-op-cert-renew = 续期证书
audit-op-update-apply = 安装更新
## Schema-driven module forms
## Chrome the form engine (web/src/forms) renders around a module's schema.
## Field captions come from the schema's own property names, and a field's
## tooltip and recommendation are Fluent ids in the *module's* locale file, not
## here — a missing one degrades to no tooltip and is never rendered raw.
forms-advanced-toggle = 高级
forms-badge-security-high = 对安全影响大
forms-badge-deprecated = 自 {$version} 起已弃用
forms-diagnostic-at-field = {$field}：{$message}
forms-diagnostic-unknown = 此主机报告了一个此构建没有对应说明的检查结果（{$id}）。
forms-item-add-caption = 添加
forms-item-move-down-caption = 下移
forms-item-move-up-caption = 上移
forms-item-remove-caption = 删除
forms-list-empty = 这里还没有内容。
forms-option-none = 无
forms-row-add = 向 {$field} 添加一行
forms-row-label = 第 {$index} 行
forms-row-move-down = 将 {$field} 的第 {$index} 行下移
forms-row-move-up = 将 {$field} 的第 {$index} 行上移
forms-row-remove = 删除 {$field} 的第 {$index} 行
forms-tag-add = 向 {$field} 添加一项
forms-tag-item = {$field} 的第 {$index} 项
forms-tag-move-down = 将 {$field} 的第 {$index} 项下移
forms-tag-move-up = 将 {$field} 的第 {$index} 项上移
forms-tag-remove = 删除 {$field} 的第 {$index} 项
forms-unsupported-note = 此构建无法编辑该值。它按存储的原样显示，保持不变。
forms-version-unsupported = 需要 {$service} {$since}，已安装 {$installed}

## Form validation
## Mirrors the schema constraints for immediate feedback. The server is the
## authority: a clean pass here is not a promise that apply will succeed.
forms-error-enum = 请选择列出的值之一。
forms-error-format-ip = 这不是有效的 ip 地址。
forms-error-integer = 请使用整数。
forms-error-max-length = 最多使用 {$max} 个字符。
forms-error-maximum = 请使用不超过 {$max} 的值。
forms-error-min-length = 至少使用 {$min} 个字符。
forms-error-minimum = 请使用不小于 {$min} 的值。
forms-error-pattern = 此值与该字段接受的格式不符。
forms-error-required = 此字段为必填项。
forms-error-type = 此值不是该字段所接受的类型。
