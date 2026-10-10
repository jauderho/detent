# needs-review: machine-drafted Brazilian Portuguese translation; not yet checked by a native speaker.
## detent CLI — pt-BR
## Source: locales/en-US/cli.ftl. Same ids, same placeables. Identifiers — module ids,
## paths, unit names, digests, enum wire names such as `restart` or `active` — are
## interpolated verbatim and must not be translated.

## severity words, prefixed to every rendered diagnostic
cli-severity-error = erro
cli-severity-warning = aviso
cli-severity-recommendation = nota

## yes/no, used wherever a flag is rendered
cli-yes = sim
cli-no = não

## progress notes, printed on stderr under --verbose
cli-note-settings = idioma {$locale}, diretório de estado {$state}, configuração {$config}
cli-note-operation = executando {$operation} para {$module}

## failures that stop a command before the operations layer sees it
cli-bad-stdin = não foi possível ler o modelo da entrada padrão: {$reason}
cli-bad-json = o modelo na entrada padrão não é um json válido: {$reason}
cli-bad-hash = `{$value}` não é um digest sha-256 de 64 caracteres hexadecimais.
cli-start-failed = não foi possível iniciar o auxiliar privilegiado: {$reason}
cli-monitor-stop = o auxiliar privilegiado não parou corretamente: {$reason}
cli-monitor-busy = outro monitor do detent já é dono deste diretório de estado; tente novamente pela interface web ou execute `detent serve`.
cli-monitor-lock-unavailable = não foi possível obter o bloqueio de estado em {$path}, então este comando não pode alterar nada; execute-o com um usuário que possa gravar nesse diretório ou passe --state-root.
cli-commit-recovered = commit não confirmado {$commit} recuperado; {$restored} destinos restaurados com {$failures} falhas.
cli-commit-confirm-needs-serve = este módulo exige commit-confirm; use a interface web ou `detent serve` para que a janela de confirmação continue sendo aplicada.
cli-config-load-failed = não foi possível carregar a configuração em {$path}: {$reason}
cli-no-command = nenhum comando foi informado.

## self-test probe and self-update (PLAN §2.9)
cli-self-test = versão {$version}, recursos {$features}
cli-update-available = atualização disponível: {$tag}, publicada em {$published}
cli-update-security-available = atualização de segurança disponível: {$tag}, publicada em {$published}
cli-update-none = nenhuma atualização disponível (atual {$current})
cli-update-held-young = {$tag} é mais novo que {$current}, mas tem menos de {$days} dia(s); o filtro de idade o retém
cli-update-held-rejected = {$tag} é mais novo que {$current}, mas sofreu rollback neste host; ele será ignorado
cli-verify-bundle-ok = {$file} está atestado para {$tag}
cli-update-failed = a atualização falhou: {$reason}
cli-update-installed = {$tag} instalado; o binário substituído foi mantido em {$previous}
cli-update-not-restarted = o serviço não foi reiniciado, então o novo binário ainda não está em execução: {$reason}
cli-update-rolled-back = rollback feito: {$reason}
cli-update-rollback-failed = a atualização falhou ({$reason}) e o rollback também falhou ({$error}); este host precisa de atenção

## config
cli-module-line = {$id}  {$name}
cli-no-model = este módulo ainda não gerencia nenhum arquivo neste host, então não há modelo para mostrar.
cli-valid = esta configuração é válida.
cli-plan-no-change = {$module} já é o que {$path} contém; nada mudaria.
cli-plan-service = aplicar isto afetaria {$unit}.
cli-plan-hash = o arquivo agora tem o hash {$hash}; passe-o como --expect-hash para recusar uma edição concorrente.
cli-check-ran = o validador upstream {$program} foi executado; aprovado: {$passed}. {$detail}
cli-check-skipped = o validador upstream {$program} não foi executado. {$detail}
cli-applied = {$module} foi gravado em {$path}.
cli-applied-hash = o hash era {$prev} e agora é {$new}; backup mantido: {$backup}
cli-mounts-off = mounts: a ativação está desligada ([mounts] activate_new_entries); novas entradas do fstab entram em vigor na próxima inicialização ou montagem.
cli-mounts-error = mounts: nenhuma unidade de montagem foi iniciada: {$reason}
cli-mounts-none = mounts: nenhuma nova entrada do fstab para montar.
cli-mounts-unit = montagem {$mountpoint} ({$unit}): {$state}
cli-mounts-unit-detail = montagem {$mountpoint} ({$unit}): {$state}: {$detail}
cli-commit-armed = o commit {$id} deve ser confirmado em até {$seconds} segundos, até {$deadline}, ou sofrerá rollback.
cli-commit-confirmed = o commit {$id} foi confirmado e não sofrerá rollback.
cli-commit-rolled-back = o commit {$id} sofreu rollback; {$targets} destinos foram restaurados.

## backups
cli-no-backups = nenhum backup foi mantido para este módulo ainda.
cli-backup-line = {$id}  {$name}  {$bytes} bytes  {$digest}
cli-restored = o destino {$target} foi restaurado e agora tem o hash {$hash}.

## services
cli-service-status = {$unit} está {$state}; inicia na inicialização do sistema: {$enabled}
cli-serviced = {$unit} foi solicitado a executar {$action}; em execução agora: {$active}

## host
cli-host-profile = {$hostname}: {$os}, init {$init}, {$ram} mib de ram
cli-host-service-version = o {$service} instalado está na versão {$version}
cli-host-backends = backend de rede {$network}, backend de resolvedor {$resolver}, distribuição {$distro} {$version}
cli-host-note = nota de detecção: {$note}

## audit
cli-no-audit = o log de auditoria não tem registros correspondentes.
cli-audit-line = {$ts}  {$who}  {$op}  {$module}  {$result}  {$error}
cli-audit-verified = a cadeia de auditoria está íntegra até o registro {$sequence}; digest do topo {$hash}
cli-audit-broken = não foi possível verificar a cadeia de auditoria: {$reason}

## --dryrun
cli-dryrun-apply = simulação: isto é o que seria gravado em {$path} para {$module}.
cli-dryrun-operation = simulação: {$operation} seria executado para {$module}.
cli-dryrun-nothing = simulação: nada foi alterado.
cli-dryrun-serve = simulação: o monitor e o worker iniciariam com {$modules} módulos e {$targets} destinos, com raiz em {$state}.
cli-dryrun-serve-mounts = simulação: após um apply de mounts, o runner iniciaria as unidades de montagem das novas entradas do fstab (mounts.activate_new_entries = true).
cli-dryrun-cert-renew = simulação: pediria ao servidor em {$address} (como {$name}) que renovasse seu certificado agora; nada foi enviado.

## serve
cli-serve-monitor = o worker iniciou como pid {$pid}; privilégios descartados: {$dropped}
cli-serve-worker = o worker está em execução; seu servidor http chega na fase 4. handshake: {$greeted}
cli-serve-failed = não foi possível iniciar o monitor e o worker: {$reason}
cli-serve-stopped = o par parou inesperadamente: {$reason} {$status}
cli-serve-privileged-port = a porta {$port} exige cap_net_bind_service ou um socket passado pelo monitor, e esta compilação não suporta nenhum dos dois; use uma porta 1024 ou superior, ou coloque um proxy reverso na frente.
cli-serve-privilege-mode = o modo de privilégio configurado não corresponde a este processo, então o serviço não iniciou: {$reason}
cli-serve-acme-unsupported = esta compilação não tem provedores dns-01 (recurso acme-dns-providers), então não pode obter certificados acme; defina tls.bootstrap como "self-signed" em {$path}.
cli-serve-acme-setting-missing = tls.bootstrap é "acme", mas {$setting} não está definido em {$path}.
cli-serve-acme-path-outside = {$setting} ({$value}) não está sob a raiz de estado {$root}: os processos confinados gravam somente lá.
cli-serve-acme-credentials-dir = não foi possível preparar o diretório de credenciais acme {$path}: {$reason}
cli-serve-secrets-failed = o arquivo de segredos {$path} foi recusado: {$reason}
cli-serve-acme-secret-missing = acme.provider está definido, mas {$path} não tem segredo dns_provider em sua tabela [acme].
cli-serve-acme-provider-invalid = o provedor dns-01 em acme.provider não pode ser usado: {$reason}
cli-serve-acme-providers-not-built = esta compilação não tem provedores dns-01 (recurso acme-dns-providers); remova [acme.provider] de {$path}.
cli-serve-handshake-failed = o worker não conseguiu concluir o handshake com o monitor.
cli-serve-auth-failed = não foi possível abrir o armazenamento de contas, tokens e sessões: {$reason}
cli-serve-tls-failed = não foi possível preparar o certificado tls: {$reason}
cli-serve-cert-fingerprint = impressão digital do certificado de bootstrap tls (sha-256): {$fingerprint}
cli-serve-web-failed = o servidor web não conseguiu iniciar: {$reason}
cli-serve-web-stopped = o servidor web não parou corretamente: {$reason}
cli-serve-listening = escutando em {$addr}
cli-serve-confinement-degraded = confinamento degradado: {$detail}
cli-mcp-missing-token = {$var} não está definido; gere um com `detent token create` e exporte-o antes de iniciar o servidor mcp.
cli-mcp-serve-failed = não foi possível iniciar o servidor mcp: {$reason}
cli-mcp-listening = mcp servindo {$transport}
cli-mcp-http-needs-privsep = o transporte http do mcp não pode ser executado como root nem com capabilities: o parser de rede teria poder equivalente ao de root; execute como usuário não root sem capabilities ou use o transporte stdio.
cli-mcp-bind-not-loopback = o bind http do mcp deve ser loopback (127.0.0.1 ou ::1); o bearer trafega em texto simples.
cli-dryrun-mcp = simulação: o mcp serviria {$transport} em {$addr} com o escopo {$scope}.

## setup, user, token
cli-setup-exists = um usuário chamado `{$name}` já existe neste host; passe --force para sobrescrevê-lo.
cli-setup-created = a conta de administrador `{$name}` foi criada.
cli-user-created = a conta `{$name}` foi criada.
cli-user-passwd = a senha de `{$name}` foi alterada.
cli-user-removed = a conta `{$name}` foi removida.
cli-totp-uri = adicione isto ao seu aplicativo autenticador: {$uri}
cli-totp-secret = ou digite esta chave nele: {$secret}
cli-totp-code-prompt = código do seu autenticador:
cli-totp-code-empty = um código não pode ser vazio.
cli-totp-code-wrong = esse código não é válido, então o segundo fator não foi ativado.
cli-user-totp-enabled = o segundo fator de `{$name}` foi ativado.
cli-totp-disable-prompt = desativar o segundo fator de `{$name}`? [y/N]
cli-totp-disable-cancelled = o segundo fator de `{$name}` foi mantido ativado.
cli-user-totp-disabled = o segundo fator de `{$name}` foi desativado.
cli-token-created = o token {$id} ({$label}) foi criado; ele não será mostrado novamente: {$token}
cli-token-revoked = o token {$id} foi revogado.
cli-token-no-tokens = nenhum token foi emitido.
cli-token-line = {$id}  {$label}  {$scopes}  {$created}  {$expires}
cli-credential-failed = não foi possível concluir a solicitação: {$reason}
cli-audit-failed = a alteração foi feita, mas seu registro de auditoria não pôde ser gravado: {$reason}
cli-state-command-as-root = detent {$command} não deve ser executado como root: os arquivos que ele grava pertenceriam ao root, e o serviço não conseguiria lê-los. Execute-o como a conta de serviço: sudo -u {$account} detent {$command}

## cert status
cli-cert-source = origem: {$source}
cli-cert-fingerprint = impressão digital (sha-256): {$fingerprint}
cli-cert-not-after = expira em: {$not_after}
cli-cert-not-after-unknown = expiração: desconhecida (o certificado não pôde ser interpretado).
cli-cert-lifetime = vida útil usada: {$percent} (aviso: {$warning}).
cli-cert-lifetime-no-warning = vida útil usada: {$percent} (sem aviso).
cli-cert-lifetime-unknown = vida útil usada: desconhecida (o certificado não pôde ser interpretado).
cli-cert-missing = nenhum certificado está armazenado em {$path}; inicie o servidor uma vez para que ele grave um.
cli-cert-unreadable = não foi possível ler o certificado em {$path}: {$reason}

## cert renew
cli-cert-renew-requested = renovação solicitada: o servidor pediu ao seu cliente ACME que renove agora. Confira o resultado com `detent cert status`.
cli-cert-renew-token-refused = o token foi recusado (HTTP {$status}); ele precisa de escopo de gravação: `detent token create <name> --write`.
cli-cert-renew-not-acme = o servidor não executa nenhum processo ACME (`tls.bootstrap` não é `acme`), então não há o que renovar.
cli-cert-renew-server-error = o servidor respondeu HTTP {$status}: {$message_id}
cli-cert-renew-server-error-bare = o servidor respondeu HTTP {$status}.
cli-cert-renew-unreachable = não foi possível se comunicar com o servidor em {$address}: {$reason}
cli-cert-renew-no-token = nenhum token de API: passe --token-file <path> ou defina {$var}. Gere um token de gravação com `detent token create <name> --write`.
cli-cert-renew-bad-token = o token de {$source} foi recusado: {$reason}
cli-cert-renew-ca-unreadable = não foi possível ler o arquivo da CA {$path}: {$reason}

## password entry (setup, user add, user passwd)
cli-password-prompt = senha:
cli-password-confirm = confirme a senha:
cli-password-mismatch = as senhas não coincidem.
cli-password-empty = uma senha não pode ser vazia.

## doctor
cli-status-ok = ok
cli-status-warn = aviso
cli-status-fail = falha
cli-doctor-modules = módulos compilados nesta versão: {$detail}
cli-doctor-state-root = diretório de estado {$detail}
cli-doctor-config = arquivo de configuração {$detail}
cli-doctor-privsep = a separação de privilégios consegue criar um par funcional: {$detail}
cli-doctor-landlock = landlock: {$detail}
cli-doctor-seccomp = seccomp: {$detail}
cli-doctor-confinement = confinamento do sandbox: {$detail}
cli-doctor-serve-confinement = confinamento na última inicialização do serve: {$detail}
cli-doctor-mounts = ativação de montagem após um apply do fstab: {$detail}
cli-doctor-privilege-mode = modo de privilégio: {$detail}
cli-doctor-service-account = conta de serviço: {$detail}
cli-doctor-state-owner = dono do diretório de estado: {$detail}
cli-doctor-backups-dir = diretório de backups: {$detail}
cli-doctor-polkit-rule = regra do polkit: {$detail}
cli-doctor-polkit-daemon = daemon do polkit: {$detail}
cli-doctor-unit-capabilities = identidade e capabilities da unidade de serviço: {$detail}
