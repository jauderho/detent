# needs-review: machine-drafted Brazilian Portuguese translation; not yet checked by a native speaker.
## detent web admin UI — pt-BR
## Source: locales/en-US/web.ftl. Same ids, same placeables.

## Status bar
status-brand = detent
status-online = sistema online
status-clock-label = utc
status-mode-label = modo
theme-toggle-aria = alternar entre os modos claro e escuro
theme-toggle-title = alternar claro / escuro

## catfu component layer
## Chrome the shared components render themselves. Content strings (field
## captions, table headers, banner copy) are supplied by the calling page.
component-countdown-remaining = tempo restante
component-field-info = mais informações
component-modal-close = fechar
component-switch-off = desligado
component-switch-on = ligado
component-table-empty = nenhum registro

## API failures
## docs/API.md: every failure is `{ code, message_id }`, and `message_id` is a
## Fluent id. src/api/messages.ts resolves it here; an id this build does not
## know falls back to `api-error-unknown`, so an id is never rendered raw.
##
## The first three are the console's own — a failure that never reached a
## server has no `message_id` to resolve. The rest mirror the ids the server
## sends, argument-free: locales/en-US/core.ftl interpolates `{$path}`,
## `{$reason}` and friends, and the API deliberately sends none of them.
api-error-network = o console não conseguiu alcançar este host.
api-error-malformed = este host enviou uma resposta que o console não conseguiu ler.
api-error-unknown = este host relatou uma falha para a qual o console não tem descrição.
core-edit-index-out-of-range = erro interno: uma edição apontou para uma linha fora do arquivo.
core-edit-line-break = um valor não pode conter quebra de linha nem byte nulo.
core-edit-unsupported = esta edição não pode ser expressa no formato do arquivo.
core-model-shape = a configuração fornecida não tem a forma esperada.
core-model-unrepresentable = este arquivo contém algo que o editor não consegue representar.
core-parse-malformed = este arquivo não corresponde ao formato que seu módulo espera.
ops-audit-failed = não foi possível ler o log de auditoria.
ops-audit-unavailable = não foi possível gravar o log de auditoria, então a operação foi recusada.
ops-denied = você não tem permissão para fazer isso.
ops-hash-conflict = o arquivo mudou no disco desde que foi lido; leia-o novamente e tente de novo.
ops-check-failed = o validador externo recusou o candidato.
ops-invalid-model = essa configuração não é válida.
ops-no-service = este módulo não controla nenhum serviço neste host, então não pode ser reiniciado.
ops-no-target = este módulo não gerencia nenhum arquivo neste host.
ops-privsep-failed = o auxiliar privilegiado recusou ou não conseguiu concluir a solicitação.
ops-service-failed = a ação do serviço não foi concluída.
ops-unknown-module = não há módulo com esse nome nesta compilação.
ops-unsupported = isso não é suportado nesta compilação.
ops-commit-pending = outra janela de commit-confirm já está pendente.
ops-update-running = uma atualização já está em execução; aguarde o término e verifique a versão em execução.
ops-update-tag-invalid = isso não é uma versão de lançamento; deve ter a forma v1.2.3.
ops-update-not-newer = esse lançamento não é mais novo que a versão em execução; nada foi iniciado.
ops-no-backup = commit-confirm exige um backup retido; nada foi alterado.
ops-arm-failed-restored = não foi possível armar o commit-confirm, então a alteração foi desfeita; o conteúdo anterior foi restaurado.
ops-arm-failed-unrestored = não foi possível armar o commit-confirm e a alteração NÃO pôde ser desfeita; o novo conteúdo ainda está no disco. Restaure o backup anterior agora.
ops-target-missing = o arquivo gerenciado não existe; crie-o (instalando seu pacote ou manualmente) e tente de novo.
web-api-unexpected-outcome = a operação foi concluída, mas seu resultado não pôde ser exibido.
web-auth-ambiguous-credentials = envie um cookie de sessão ou um token bearer, não os dois.
web-auth-argon2-params = os parâmetros argon2 configurados não são utilizáveis.
web-auth-busy = há logins demais em andamento; aguarde um momento e tente novamente.
web-auth-csrf-rejected = esta solicitação não passou nas verificações entre sites; recarregue a página e tente novamente.
web-auth-entropy-unavailable = o gerador de números aleatórios do sistema falhou, então nenhuma credencial pôde ser emitida.
web-auth-hash-failed = não foi possível gerar o hash da senha.
web-auth-invalid-credentials = o nome de usuário, a senha ou o código não estava correto.
web-auth-password-change-required = altere sua senha antes de fazer qualquer outra coisa.
web-auth-password-too-long = uma senha pode ter no máximo 128 caracteres.
web-auth-password-too-short = uma senha deve ter pelo menos 12 caracteres.
web-auth-password-unchanged = a nova senha deve ser diferente da atual.
web-auth-rate-limited = tentativas demais; aguarde um momento e tente novamente.
web-auth-session-limit = há sessões demais abertas; aguarde uma expirar e entre novamente.
web-auth-store-malformed = um arquivo de credenciais neste host não é válido.
web-auth-store-unreadable = não foi possível ler um arquivo de credenciais neste host.
web-auth-store-unwritable = não foi possível preparar um arquivo de credenciais neste host para gravação.
web-auth-store-write-failed = não foi possível gravar um arquivo de credenciais neste host.
web-auth-token-limit = este host já tem o número máximo de tokens de api.
web-auth-token-unknown = esse token de api não existe, foi revogado ou expirou.
web-auth-totp-secret-invalid = esse segredo do autenticador não é um base32 válido.
web-auth-unauthenticated = entre para fazer isso.
web-auth-user-exists = já existe um usuário com esse nome.
web-auth-user-name-invalid = esse nome de usuário não é utilizável; use de 1 a 32 caracteres entre `a-z`, `0-9`, `.`, `_` ou `-`, começando com uma letra ou um dígito.
web-auth-user-unknown = não há usuário com esse nome.
web-cert-renew-not-acme = a renovação exige `tls.bootstrap = "acme"` em detent.toml.
web-cert-renew-unavailable = o cliente acme não recebeu a solicitação de renovação; tente novamente mais tarde.
web-denied-scope = esta credencial não possui o escopo que essa ação exige.
web-engine-stopped = o mecanismo de operações não está mais em execução; tente novamente quando o serviço voltar.
web-update-not-checked = nenhuma verificação de atualização foi executada neste host ainda; execute `detent update --check` como root.
web-request-malformed = o corpo da solicitação não tem a forma que este endpoint espera.
web-request-too-deep = o corpo da solicitação tem aninhamento profundo demais.

## Sign in
login-title = entrar
login-panel-label = sessão
login-username-label = nome de usuário
login-password-label = senha
login-totp-label = código do autenticador
login-totp-description = seis dígitos do autenticador cadastrado para esta conta.
login-totp-reveal = usar um código do autenticador
login-submit = entrar
login-submitting = entrando
login-retry-after = tentativas demais; aguarde {$seconds} segundos e tente novamente.

## Change password
password-change-title = altere sua senha
password-change-panel-label = senha
password-change-intro = esta conta precisa definir uma nova senha antes de fazer qualquer outra coisa.
password-change-current-label = senha atual
password-change-new-label = nova senha
password-change-new-description = de 12 a 128 caracteres; qualquer caractere é permitido.
password-change-confirm-label = confirme a nova senha
password-change-mismatch = as duas novas senhas não são iguais.
password-change-submit = alterar senha
password-change-submitting = alterando a senha

## Session and scope
auth-checking = verificando esta sessão
auth-sign-out = sair
scope-gate-read-only = esta sessão tem apenas acesso de leitura; ela não pode alterar nada neste host.
scope-gate-signed-out = entre para alterar qualquer coisa neste host.

## Navigation
nav-label = seções
nav-dashboard = painel
nav-modules = módulos
nav-services = serviços
nav-backups = backups
nav-audit = auditoria
nav-certificates = certificados
nav-settings = configurações

## Routed pages
## Certificates and settings are still named placeholders: neither has an API
## to drive. Certificates waits on Phase 6 (ACME); settings waits on the user
## and token endpoints.
page-placeholder-body = esta seção ainda não foi construída.
page-dashboard-title = painel
page-modules-title = módulos
page-module-detail-title = módulo {$module}
page-services-title = serviços
page-backups-title = backups
page-audit-title = log de auditoria
page-certificates-title = certificados
page-settings-title = configurações
page-not-found-title = página inexistente
page-not-found-body = esse endereço não corresponde a nada neste console.
page-not-found-home = ir para o painel

## Pending commit
pending-commit-message = uma alteração de configuração está aguardando confirmação; ela sofre rollback sozinha quando esta janela se fecha.
pending-commit-countdown-label = tempo restante para confirmar
pending-commit-confirm = confirmar alteração
pending-commit-confirming = confirmando…

## Shared page states
## Every section is a query away from its data, so loading, failure and "this
## host has none of these" are shared rather than re-worded per page.
state-loading = carregando
state-unknown = desconhecido
value-no = não
value-yes = sim

## Dashboard
dashboard-host-panel = host
dashboard-host-hostname = nome do host
dashboard-host-os = sistema operacional
dashboard-host-init = sistema init
dashboard-host-distro = distribuição
dashboard-host-ram = memória
dashboard-host-network-backend = backend de rede
dashboard-host-resolver-backend = backend de resolvedor
dashboard-host-notes = notas de detecção
dashboard-cert-panel = certificado
dashboard-cert-fingerprint = impressão digital
dashboard-cert-expires = expira em
dashboard-cert-lifetime-used = vida útil usada
dashboard-cert-expired = expirado; substitua este certificado.
dashboard-cert-expiring-soon = expira em até 30 dias; planeje a renovação.
dashboard-cert-half = metade da vida útil do certificado foi usada; a renovação está agendada.
dashboard-cert-quarter = três quartos da vida útil do certificado foram usados; renove em breve.
cert-renew-panel = renovação
cert-renew-now = renovar agora
cert-renew-requested = renovação solicitada. O novo certificado é instalado quando a CA o emitir.
dashboard-modules-panel = módulos
dashboard-modules-count = {$count ->
    [one] um módulo está compilado nesta versão.
   *[other] {$count} módulos estão compilados nesta versão.
}
dashboard-audit-panel = atividade recente
dashboard-view-all = ver tudo
dashboard-update-panel = atualização
dashboard-update-current = versão em execução
dashboard-update-published = publicada em
dashboard-update-up-to-date = nenhum lançamento mais novo é oferecido para esta compilação.
dashboard-update-available = o lançamento {$tag} está disponível para esta compilação.
dashboard-update-security = este lançamento está marcado como atualização de segurança; ele ignora o filtro de idade.
dashboard-update-install = instalar {$tag}
dashboard-update-confirm-title = instalar esta atualização?
dashboard-update-confirm-body = isto inicia a instalação de {$tag} em segundo plano. se a instalação for concluída, o serviço detent reinicia e a página pode desconectar e reconectar; se o serviço reiniciado não estiver saudável, a atualização sofre rollback.
dashboard-update-confirm-action = instalar
dashboard-update-confirm-cancel = cancelar
dashboard-update-started = a atualização para {$version} foi iniciada em segundo plano. o serviço reinicia se ela for instalada e sofre rollback se não estiver saudável; a versão em execução mostra o resultado.

## Modules
modules-panel-label = módulos instalados
modules-col-module = módulo
modules-col-targets = arquivos
modules-col-services = serviços
modules-col-commit-confirm = commit-confirm
modules-commit-confirm-required = obrigatório
modules-commit-confirm-not-required = não obrigatório
modules-empty = esta compilação não tem módulos compilados.
modules-none = nenhum

## One module
module-about-panel = módulo
module-configuration-panel = configuração
module-upstream-label = acompanha o upstream
module-targets-label = arquivos
module-services-label = serviços
module-current-hash-label = digest no disco
module-security-notes-label = notas de segurança
module-model-missing = o arquivo deste módulo ainda não existe neste host. o formulário abaixo parte dos padrões do próprio módulo, e aplicá-lo cria o arquivo.
module-action-validate = validar
module-action-plan = planejar
module-action-apply = aplicar
module-action-discard = descartar edições
module-busy = processando
module-validate-clean = esta configuração passou em todas as verificações que este host executa.
module-plan-title = alteração planejada
module-plan-no-change = esta configuração corresponde ao que já está no disco; não há nada a aplicar.
module-plan-diff-label = diff
module-plan-checks-label = verificações upstream
module-plan-check-passed = aprovada
module-plan-check-failed = reprovada
module-plan-check-exit = saída {$code}
module-plan-services-label = serviços que isto afetaria
module-plan-apply = aplicar esta alteração
module-apply-title = aplicar esta alteração?
module-apply-body = isto grava {$path} neste host. o conteúdo atual é copiado para backup antes.
module-apply-commit-confirm = este módulo pode bloquear o acesso de um administrador, então a alteração arma uma janela de commit-confirm: ela sofre rollback sozinha, a menos que você a confirme antes do prazo.
module-apply-service-label = depois
module-apply-service-none = deixar o serviço como está
module-apply-cancel = cancelar
module-applied = a alteração foi gravada em {$path}.
module-applied-created = {$path} não existia e foi criado.
module-mounts-off = as novas entradas do fstab não foram montadas ([mounts] activate_new_entries está desligado); elas entram em vigor na próxima inicialização ou montagem.
module-mounts-error = nenhuma unidade de montagem foi iniciada: {$reason}
module-mounts-none = não há nova entrada do fstab para montar.
module-mounts-units = unidades de montagem das novas entradas do fstab:
module-mount-state-mounted = montado
module-mount-state-already-mounted = já montado
module-mount-state-pending = ainda montando
module-mount-state-failed = falhou
module-mount-state-protected = recusado: caminho protegido
module-mount-state-stopped = desmontado
module-cancel = cancelar

## Services
services-panel-label = serviços
services-col-module = módulo
services-col-unit = unidade
services-col-state = estado
services-col-enabled = na inicialização
services-col-since = desde
services-col-actions = ações
services-state-active = ativo
services-state-inactive = inativo
services-state-failed = falhou
services-state-activating = iniciando
services-state-deactivating = parando
services-state-unknown = desconhecido
services-action-restart = reiniciar
services-action-reload = recarregar
services-action-start = iniciar
services-action-stop = parar
services-acted = {$unit}: {$detail}
services-empty = nenhum módulo desta compilação controla um serviço neste host.
services-confirm-title = {$action} {$unit}?
services-confirm-body = isto age imediatamente sobre o serviço em execução.
services-confirm-cancel = cancelar

## Backups
backups-col-name = backup
backups-col-created = criado em
backups-col-size = tamanho
backups-col-digest = digest
backups-col-actions = ações
backups-action-restore = restaurar
backups-confirm-title = restaurar este backup?
backups-confirm-body = isto substitui {$target} pela cópia retida. o conteúdo atual é copiado para backup antes.
backups-confirm-cancel = cancelar
backups-restored = o backup foi restaurado.
backups-empty = nada foi copiado para backup deste módulo ainda.
backups-module-panel = backups de {$module}

## Audit log
audit-panel-label = log de auditoria
audit-col-when = quando
audit-col-who = solicitante
audit-col-how = credencial
audit-col-op = operação
audit-col-module = módulo
audit-col-result = resultado
audit-filter-module-label = módulo
audit-filter-who-label = solicitante
audit-filter-limit-label = linhas
audit-filter-apply = filtrar
audit-filter-clear = limpar
audit-empty = nada foi registrado neste host ainda.
audit-result-ok = ok
audit-result-denied = negado
audit-result-error = falhou
audit-identity-local-user = usuário local
audit-identity-session = sessão
audit-identity-token = token de api
audit-op-list-modules = listar módulos
audit-op-get-module = ler módulo
audit-op-validate = validar
audit-op-plan = planejar
audit-op-apply = aplicar
audit-op-confirm-commit = confirmar commit
audit-op-rollback-commit = fazer rollback do commit
audit-op-list-backups = listar backups
audit-op-restore = restaurar backup
audit-op-service-status = ler estado do serviço
audit-op-service-action = agir sobre o serviço
audit-op-host-profile = ler perfil do host
audit-op-audit-query = ler log de auditoria
audit-op-cert-status = ler estado do certificado
audit-op-update-status = ler estado da atualização
audit-op-cert-renew = renovar certificado
audit-op-update-apply = instalar atualização
## Schema-driven module forms
## Chrome the form engine (web/src/forms) renders around a module's schema.
## Field captions come from the schema's own property names, and a field's
## tooltip and recommendation are Fluent ids in the *module's* locale file, not
## here — a missing one degrades to no tooltip and is never rendered raw.
forms-advanced-toggle = avançado
forms-badge-security-high = alto impacto na segurança
forms-badge-deprecated = obsoleto desde {$version}
forms-diagnostic-at-field = {$field}: {$message}
forms-diagnostic-unknown = este host relatou um resultado de verificação para o qual esta compilação não tem descrição ({$id}).
forms-item-add-caption = adicionar
forms-item-move-down-caption = bx
forms-item-move-up-caption = sob
forms-item-remove-caption = exc
forms-list-empty = nada aqui ainda.
forms-option-none = nenhum
forms-row-add = adicionar uma linha a {$field}
forms-row-label = linha {$index}
forms-row-move-down = mover a linha {$index} de {$field} para baixo
forms-row-move-up = mover a linha {$index} de {$field} para cima
forms-row-remove = remover a linha {$index} de {$field}
forms-tag-add = adicionar um item a {$field}
forms-tag-item = item {$index} de {$field}
forms-tag-move-down = mover o item {$index} de {$field} para baixo
forms-tag-move-up = mover o item {$index} de {$field} para cima
forms-tag-remove = remover o item {$index} de {$field}
forms-unsupported-note = esta compilação não consegue editar este valor. ele é exibido como armazenado e permanece inalterado.
forms-version-unsupported = exige {$service} {$since}, instalado {$installed}

## Form validation
## Mirrors the schema constraints for immediate feedback. The server is the
## authority: a clean pass here is not a promise that apply will succeed.
forms-error-enum = escolha um dos valores listados.
forms-error-format-ip = este não é um endereço ip válido.
forms-error-integer = use um número inteiro.
forms-error-max-length = use no máximo {$max} caracteres.
forms-error-maximum = use {$max} ou menos.
forms-error-min-length = use pelo menos {$min} caracteres.
forms-error-minimum = use {$min} ou mais.
forms-error-pattern = este valor não corresponde ao formato que este campo aceita.
forms-error-required = este campo é obrigatório.
forms-error-type = este valor não é do tipo de valor que este campo contém.
