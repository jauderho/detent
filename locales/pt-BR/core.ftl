# needs-review: machine-drafted Brazilian Portuguese translation; not yet checked by a native speaker.
## detent-core — pt-BR
## Source: locales/en-US/core.ftl. Same ids, same placeables.

## chrony module — display name, security notes, schema tooltips
chrony-name = chrony
chrony-note-precedence = este arquivo substitui os padrões compilados; um valor incorreto altera silenciosamente a forma como o host mantém a hora.
chrony-tip-settings = as diretivas de chrony.conf que este módulo modela, na ordem do arquivo; todo o resto do arquivo é preservado sem alterações.
chrony-tip-key = o nome da diretiva, uma palavra, sem distinção entre maiúsculas e minúsculas.
chrony-tip-value = o valor desta diretiva, até o fim da linha; vazio para diretivas sem valor, como `rtcsync`.
chrony-rec-value = prefira um valor explícito a depender do padrão compilado.

## chrony module — validation diagnostics
chrony-privileged-directive = `{$key}` define um arquivo que o chronyd grava como root, ou o usuário com o qual ele é executado. Confira o valor antes de aplicar.
chrony-invalid-key = `{$key}` não é um nome de diretiva do chrony válido.
chrony-duplicate-key = `{$key}` está definido mais de uma vez; vale o último valor.
chrony-too-many-settings = este arquivo tem {$count} configurações; divida-o em arquivos drop-in em /etc/chrony/conf.d.
chrony-allow-open = `allow {$value}` serve a hora para toda a internet; permita apenas as redes que precisam dela.
chrony-missing-makestep = makestep não está definido; na inicialização, o relógio pode se desviar sem limite em vez de ser ajustado de uma vez para a faixa correta.
chrony-missing-rtcsync = rtcsync não está definido; o relógio de hardware vai se desviar em relação ao relógio do sistema.
chrony-rec-nts = o pool {$pool} é usado sem a opção nts; prefira fontes compatíveis com nts para que a hora não possa ser falsificada.
chrony-cmdport-open = cmdport é {$port}; defina cmdport 0, a menos que o chronyc precise acessar este host pela rede.
chrony-external-directive = `{$key}` carrega arquivos externos ou executa um programa externo; este módulo recusa diretivas que ultrapassam o limite de arquivos configurado.

## dhcp module — display name, security notes, schema tooltips
dhcp-name = dhcp
dhcp-note-commit-confirm = uma alteração incorreta no DHCP desconecta todos os clientes, e você também, da rede; confira o diff com cuidado antes de confirmar.
dhcp-tip-dnsmasq = as configurações `chave=valor` de /etc/dnsmasq.conf, na ordem do arquivo; comentários e linhas desconhecidas são preservados sem alterações.
dhcp-tip-kea-v4 = o subconjunto gerenciado do servidor Kea DHCPv4 (`Dhcp4`); opções desconhecidas do Kea são preservadas sem alterações.
dhcp-tip-kea-v6 = o subconjunto gerenciado do servidor Kea DHCPv6 (`Dhcp6`); opções desconhecidas do Kea são preservadas sem alterações.
dhcp-tip-key = o nome da opção do dnsmasq, uma palavra, sem espaços em branco.
dhcp-tip-value = o valor após `=`; um sinalizador simples como `domain-needed` não tem valor.
dhcp-tip-interfaces = as interfaces nas quais o servidor Kea escuta; uma lista vazia significa que o servidor responde em todas as interfaces.
dhcp-tip-valid-lifetime = o tempo de vida padrão da concessão em segundos; 3600 é um bom padrão para a maioria das redes.
dhcp-tip-subnets = as sub-redes das quais o servidor atribui endereços.
dhcp-tip-id = o identificador estável de sub-rede do Kea; mantenha-o estável entre edições, pois as concessões são indexadas por ele.
dhcp-tip-subnet = o prefixo da sub-rede em formato CIDR, por exemplo `192.168.1.0/24`.
dhcp-tip-pools = os pools de endereços dinâmicos da sub-rede.
dhcp-tip-routers = a opção de roteadores (gateway padrão) entregue aos clientes.
dhcp-tip-domain-servers = os servidores DNS (`domain-name-servers`) entregues aos clientes.
dhcp-tip-pool = um pool como intervalo `192.168.1.100 - 192.168.1.200` ou como prefixo `192.168.1.0/24`.

## dhcp module — validation diagnostics
dhcp-empty-key = uma configuração do dnsmasq tem um nome de opção vazio.
dhcp-invalid-key = `{$key}` não é um nome de opção do dnsmasq válido; deve ser uma palavra sem espaços em branco, `=` ou `#`.
dhcp-malformed-cidr = `{$value}` não é um prefixo CIDR válido, por exemplo `192.168.1.0/24`.
dhcp-malformed-pool = `{$value}` não é um pool válido; use um intervalo como `192.168.1.100 - 192.168.1.200` ou um prefixo CIDR.
dhcp-external-directive = `{$key}` carrega arquivos externos ou executa comandos; este módulo não cria nem modifica diretivas que ultrapassam o limite de arquivos configurado.
dhcp-authoritative-set = `dhcp-authoritative` torna o dnsmasq o único servidor DHCP do segmento; defina-o apenas quando não houver outro servidor DHCP.
dhcp-kea-interfaces-empty = {$server} não tem interfaces configuradas e vai escutar em todas as interfaces; nomeie as interfaces explicitamente.
dhcp-rec-rebind = domain-needed e bogus-priv não estão ambos definidos; eles filtram ataques de rebind e consultas A upstream para endereços privados.
dhcp-rec-lifetime = {$server} tem valid-lifetime {$lifetime}; mantenha-o entre 300 e 86400 segundos para que as concessões sejam renovadas de forma previsível.

## hosts module — display name, security notes, schema tooltips
hosts-name = hosts
hosts-note-spoofing = as entradas aqui substituem o dns; uma entrada incorreta ou maliciosa redireciona consultas silenciosamente.
hosts-tip-entries = os mapeamentos de endereço para nome em /etc/hosts, na ordem do arquivo.
hosts-tip-ip = o endereço para o qual os nomes abaixo são resolvidos.
hosts-tip-hostnames = os nomes que resolvem para este endereço, com o nome canônico primeiro.
hosts-tip-comment = o comentário em linha desta entrada, se houver.

## hosts module — validation diagnostics
hosts-invalid-hostname = `{$name}` não é um nome de host válido.
hosts-duplicate-canonical = `{$name}` é o nome canônico de mais de uma entrada.
hosts-no-hostnames = esta entrada não tem nomes de host.
hosts-hostname-is-ip = `{$name}` é um endereço literal, não um nome de host.
hosts-ipv6-zone-unsupported = `{$name}` contém um id de zona ipv6, que /etc/hosts não suporta.
hosts-hostname-multiple-ips = `{$name}` resolve para mais de um endereço da mesma família.
hosts-localhost-not-loopback = `localhost` aponta para `{$ip}`, que não é um endereço de loopback.
hosts-missing-localhost = não há entrada `localhost`.
hosts-missing-ipv6-localhost = não há entrada `localhost` ipv6.
hosts-too-many-entries = este arquivo tem {$count} entradas; considere usar dns.

## mounts module — display name, security notes, schema tooltips
mounts-name = mounts
mounts-note-boot = um /etc/fstab incorreto pode deixar o host sem conseguir inicializar na próxima reinicialização; toda alteração exige uma segunda confirmação. A confirmação não consegue detectar uma entrada incorreta, porque nada lê o arquivo antes da próxima inicialização.
mounts-tip-entries = as entradas de montagem em /etc/fstab, na ordem do arquivo.
mounts-tip-spec = o que é montado: um dispositivo, `UUID=...`/`LABEL=...`, uma exportação nfs ou `none` para swap.
mounts-tip-mountpoint = onde o sistema de arquivos é montado, ou `none`/`swap` para swap.
mounts-tip-fstype = o tipo do sistema de arquivos, por exemplo ext4, ou `swap`.
mounts-tip-options = as opções de montagem separadas por vírgula, por exemplo defaults,nosuid.
mounts-tip-dump = a frequência de backup do dump(8); quase sempre 0.
mounts-tip-pass = o número da passagem do fsck: 1 para a raiz, 2 para os demais sistemas de arquivos verificados, 0 para ignorar.
mounts-rec-options = proteja dados graváveis por usuários com nosuid, nodev e noexec; prefira x-systemd.automount em sistemas de arquivos de rede.

## mounts module — validation diagnostics
mounts-empty-spec = a entrada {$index} tem uma spec vazia (primeira coluna).
mounts-empty-mountpoint = a entrada {$index} tem um ponto de montagem vazio (segunda coluna).
mounts-invalid-fstype = `{$fstype}` não é um tipo de sistema de arquivos válido.
mounts-pass-too-high = a entrada {$index} tem pass `{$pass}`; o fsck executa no máximo 2 passagens.
mounts-root-pass = o sistema de arquivos raiz deve ter pass 1, não `{$pass}`.
mounts-missing-nofail = `{$mountpoint}` é uma mídia removível sem `nofail`; a inicialização trava quando ela é desconectada.
mounts-missing-boot-escape = `{$mountpoint}` não tem nofail nem noauto; uma montagem com falha pode atrasar a inicialização.
mounts-critical-noauto = `{$mountpoint}` é necessário para a inicialização, mas tem noauto, então o sistema pode continuar sem ele.
mounts-missing-guards = `{$mountpoint}` monta dados graváveis por usuários sem `{$missing}`; adicione-os.
mounts-network-automount = `{$mountpoint}` é um sistema de arquivos de rede sem `x-systemd.automount`; a inicialização espera pela rede.
mounts-noauto-without-user = `noauto` sem `user`: somente o root pode montá-lo, o que anula o propósito.
mounts-relative-mountpoint = a entrada {$index} monta em `{$mountpoint}`, que não é um caminho absoluto.
mounts-no-root-entry = nenhuma entrada monta `/`; verifique se o sistema de arquivos raiz é montado de outra forma.

## network module — display name, security notes, schema tooltips
network-name = network
network-note-precedence = uma configuração de rede incorreta pode isolar o administrador deste host; toda alteração exige uma segunda confirmação.
network-tip-interfaces = as interfaces que este host configura, na ordem do arquivo.
network-tip-iface-name = o nome da interface, por exemplo eth0.
network-tip-iface-dhcp-v4 = se esta interface obtém o endereço IPv4 por DHCP.
network-tip-iface-dhcp-v6 = se esta interface obtém o endereço IPv6 por DHCP.
network-tip-iface-addresses = endereços estáticos em notação CIDR, por exemplo 192.168.1.10/24.
network-tip-iface-gateway-v4 = o gateway padrão para IPv4, quando o endereçamento é estático.
network-tip-iface-gateway-v6 = o gateway padrão para IPv6, quando o endereçamento é estático.
network-tip-iface-dns = servidores DNS desta interface.
network-tip-iface-routes = rotas estáticas desta interface.
network-tip-iface-vlan = configurações de VLAN desta interface, quando ela é uma VLAN.
network-tip-iface-bridge = configurações de bridge desta interface, quando ela é uma bridge.
network-tip-route-to = o CIDR de destino ou default.
network-tip-route-via = o IP do próximo salto.
network-tip-vlan-link = o link pai desta VLAN, por exemplo eth0.
network-tip-vlan-id = o id da VLAN, 1–4094.
network-tip-bridge-members = nomes das interfaces membros desta bridge.

## network module — validation diagnostics
network-invalid-cidr = `{$value}` não é um endereço CIDR válido.
network-invalid-ip = `{$value}` não é um endereço IP válido.
network-gateway-outside-subnet = o gateway `{$gateway}` está fora das sub-redes desta interface.
network-vlan-range = o id de VLAN `{$id}` está fora de 1–4094.
network-duplicate-interface = a interface `{$name}` aparece mais de uma vez.
network-interface-order = a interface `{$name}` deve vir antes das interfaces acima dela: liste as interfaces em ordem de nome.
network-injection = `{$value}` contém uma quebra de linha ou um byte nulo.
network-static-no-gateway = esta interface com endereçamento estático não tem gateway.
network-static-no-dns = esta interface com endereçamento estático não tem servidores DNS.
network-dhcp-static-mixed = esta interface tem endereços DHCP e estáticos ao mesmo tempo.
network-rec-ipv6-privacy = ative as extensões de privacidade do IPv6 quando o DHCPv6 estiver ativado.
network-rec-ra-accept = aceite anúncios de roteador somente quando o DHCPv6 for gerenciado explicitamente.
network-rec-no-promisc = esta interface não deve operar em modo promíscuo.

## nfs module — display name, security notes, schema tooltips
nfs-name = nfs
nfs-note-live-state = as exportações são aplicadas pelo kernel a cada montagem; uma linha incorreta altera silenciosamente quais hosts podem ler quais sistemas de arquivos.
nfs-tip-entries = as exportações em /etc/exports, na ordem do arquivo.
nfs-tip-path = o ponto de exportação: um caminho de diretório absoluto neste host.
nfs-tip-clients = os hosts autorizados a montar esta exportação, na ordem de correspondência; vale a primeira especificação que corresponder.
nfs-tip-host = a especificação do cliente: um nome, endereço, endereço/máscara de rede, curinga, `*` (todos os clientes) ou @netgroup.
nfs-tip-options = as opções de exportação deste cliente, separadas por vírgula; uma lista vazia usa os padrões do arquivo.
nfs-rec-options = declare explicitamente rw/ro, sync/async, root_squash e o tratamento de subárvores; os padrões mudam entre versões do nfs-utils.

## nfs module — validation diagnostics
nfs-empty-path = um ponto de exportação está vazio.
nfs-relative-path = `{$path}` não é absoluto; um ponto de exportação deve começar com `/`.
nfs-empty-host = um cliente de `{$path}` não tem especificação de host.
nfs-bad-host = `{$host}` não é uma especificação de cliente válida; ela começa com `-` ou contém uma sintaxe que truncaria a linha.
nfs-bad-path = `{$path}` contém uma sintaxe que truncaria a linha de exportação.
nfs-bad-continuation = `{$path}` terminaria com uma barra invertida de continuação e dobraria a próxima linha.
nfs-invalid-option = `{$option}` não é uma opção de exportação válida; as opções são tokens simples sem espaços em branco ou parênteses.
nfs-no-root-squash = `{$host}` monta com no_root_squash e mantém privilégios de root na exportação.
nfs-sec-sys-only = `{$host}` usa o padrão sec=sys ou negocia somente sec=sys; adicione krb5p para proteção criptográfica.
nfs-world-export = `{$host}` é acessível para leitura e gravação por todos os clientes.
nfs-subtree-undecided = `{$host}` não declara subtree_check nem no_subtree_check; o upstream mudou o padrão, então diga qual você quer.
nfs-root-squash-undecided = `{$host}` não declara root_squash nem no_root_squash; diga qual você quer.
nfs-sync-undecided = `{$host}` não declara sync nem async; prefira sync, que confirma as gravações em armazenamento estável.

## resolver module — display name, security notes, schema tooltips
resolver-name = resolver
resolver-note-managed-symlink = neste host /etc/resolv.conf é gerenciado por um backend de resolvedor; o detent se recusa a editar o destino de um link simbólico gerenciado e configura o backend.
resolver-tip-resolv = as diretivas de /etc/resolv.conf que este módulo modela; todo o resto do arquivo é preservado sem alterações.
resolver-tip-resolved = as configurações do systemd-resolved, na ordem do arquivo. Alterá-las reinicia o systemd-resolved.
resolver-tip-unbound = os itens de unbound.conf que este módulo modela, na ordem do arquivo. Alterá-los reinicia o unbound.

## resolver module — validation diagnostics
resolver-no-nameserver = nenhum nameserver está configurado.
resolver-duplicate-nameserver = `{$ip}` aparece como mais de um nameserver.
resolver-too-many-nameservers = este arquivo lista {$count} nameservers; a glibc lê no máximo {$max}.
resolver-invalid-domain = `{$domain}` não é um nome de domínio válido.
resolver-unknown-option = `{$option}` não é uma opção que o parser de resolv.conf da glibc aceita.
resolver-search-and-domain = `search` e `domain` estão presentes; a glibc ignora `domain` quando `search` está definido.
resolver-no-config = este modelo não configura nenhum backend de resolvedor.
resolver-backend-missing = estas configurações configuram {$service}, que não foi detectado neste host.
resolver-rec-dnssec = DNSSEC está definido como allow-downgrade; `DNSSEC=yes` valida de forma estrita e é recomendado quando os dados upstream permitem.
resolver-rec-dot = DNSOverTLS é oportunista, o que faz downgrade para texto simples; `DNSOverTLS=yes` exige TLS.
resolver-unknown-hardening = `{$key}` não é uma diretiva que este módulo modela para o unbound.
resolver-unbound-misplaced = `{$key}` pertence à seção {$section} de unbound.conf, não aqui.
resolver-invalid-forward-addr = `{$addr}` não é um forward-addr válido no formato ip[@porta][#auth-name].
resolver-invalid-forward-name = `{$name}` não é um nome de forward-zone válido.
resolver-forward-tls-no-auth = esta zona encaminha por TLS sem um `#auth-name` no forward-addr, então a conexão TLS não é autenticada.
resolver-rec-hardening = `{$key}` está desativado; ativá-lo reforça o unbound contra falsificação upstream e abuso de delegação.
resolver-forward-zone-unnamed = um forward-zone: sem name: não encaminha nada e enfraquece a configuração; dê um nome a cada zona.

## samba module — display name, security notes, schema tooltips
samba-name = samba
samba-note-guest-access = o acesso de convidado é concedido por compartilhamento no momento da conexão; um valor incorreto expõe arquivos sem senha.
samba-tip-entries = as entradas de smb.conf que este módulo modela, na ordem do arquivo: cabeçalhos `[section]` e diretivas.
samba-tip-section = o nome da seção de um cabeçalho `[section]`; vazio para uma linha de diretiva simples.
samba-tip-key = o nome do parâmetro, sem distinção entre maiúsculas e minúsculas e possivelmente com várias palavras (`guest ok`).
samba-tip-value = o valor do parâmetro, até o fim da linha; macros `%` são preservadas literalmente.
samba-rec-value = prefira um valor explícito e reforçado a depender do padrão compilado do upstream.

## samba module — validation diagnostics
samba-empty-key = uma diretiva não tem nome de parâmetro.
samba-empty-section = um cabeçalho de seção está vazio.
samba-bad-key = `{$key}` seria interpretado como uma seção ou um comentário, não como uma chave de diretiva.
samba-bad-value = `{$value}` termina com `\` e engoliria a próxima linha.
samba-bad-section = `{$section}` contém `[` ou `]` ou termina com `\` e não sobreviveria a uma ida e volta.
samba-guest-ok = `guest ok` está definido como {$value}; clientes não autenticados podem se conectar a todos os compartilhamentos que o herdam.
samba-map-to-guest = `map to guest` é {$value}; qualquer valor diferente de Never transforma logins com falha em sessões de convidado.
samba-min-protocol = `server min protocol` é {$value}; defina pelo menos SMB3_00 e descarte os níveis de protocolo da era SMB1.
samba-smb-encrypt = `smb encrypt` é {$value}; defina required para que o tráfego SMB não possa circular sem criptografia.
samba-restrict-anonymous = `restrict anonymous` é {$value}; 2 oculta a lista de compartilhamentos dos usuários anônimos.
samba-rec-server-signing = `server signing` é {$value}; defina mandatory para que o tráfego SMB seja assinado criptograficamente.
samba-rec-load-printers = `load printers` é {$value}; defina no, a menos que este host realmente compartilhe impressoras.
samba-rec-interfaces = nenhuma diretiva `interfaces` está definida; vincule o samba a endereços explícitos em vez de escutar em todas as interfaces.
samba-writable-exposure = este compartilhamento permite gravações por writeable, read only ou write list; confirme se todos os clientes devem ter acesso de gravação.
samba-root-command = `{$key}` executa um comando com privilégios de root em cada conexão correspondente.
samba-client-command = `{$key}` permite que um cliente faça o samba executar um comando; o cliente controla o que o comando recebe.
samba-usershare-guests = `usershare allow guests` é {$value}; usuários podem publicar compartilhamentos que qualquer pessoa abre sem senha.
samba-wide-links = `wide links` é {$value}; links simbólicos podem levar os clientes para fora do compartilhamento.

## module template — copy-me example
TEMPLATE-name = modelo de módulo
TEMPLATE-note-precedence = este módulo fictício é um exemplo verificado na compilação para novos módulos de configuração.
TEMPLATE-tip-settings = as configurações que este módulo fictício modela, na ordem do arquivo.
TEMPLATE-tip-key = o nome da diretiva, uma palavra, sem espaços em branco.
TEMPLATE-tip-value = o valor da diretiva, até o fim da linha.
TEMPLATE-rec-value = prefira um valor explícito a depender de um padrão do upstream.
TEMPLATE-invalid-key = `{$key}` não é um nome de diretiva válido.
TEMPLATE-duplicate-key = `{$key}` está definido mais de uma vez; vale o último valor.
TEMPLATE-too-many-settings = este arquivo tem {$count} configurações; divida configurações grandes em arquivos menores.

## detent-core — parse, model, and edit errors
## These are the failures a module's own document model can raise, so they are
## prefixed `core-` rather than with a module id.
core-parse-malformed = este arquivo não corresponde ao formato que `{$module}` espera: {$reason}
core-model-shape = a configuração fornecida não tem a forma esperada: {$reason}
core-model-unrepresentable = este arquivo contém algo que o editor não consegue representar: {$reason}
core-edit-line-break = um valor não pode conter quebra de linha nem byte nulo; `{$value}` contém.
core-edit-index-out-of-range = erro interno: a linha {$index} está fora de um arquivo de {$len} linhas.
core-edit-unsupported = esta edição não pode ser expressa no formato do arquivo: {$reason}

## detent-core — version-gated options
core-version-too-old = `{$option}` exige {$service} {$since} ou posterior; este host tem {$installed}.
core-version-unknown = a versão instalada de {$service} é desconhecida, então `{$option}` (exige {$service} {$since} ou posterior) pode não funcionar.

## operations layer — errors surfaced by detent-ops
ops-unknown-module = não há módulo chamado `{$module}` nesta compilação.
ops-invalid-model = a configuração de `{$module}` não é válida: {$reason}
ops-check-failed = o validador externo `{$program}` recusou o candidato: {$reason}
ops-hash-conflict = `{$path}` mudou no disco desde que foi lido; leia-o novamente e tente de novo.
ops-privsep-failed = o auxiliar privilegiado recusou ou não conseguiu concluir a solicitação: {$reason}
ops-service-failed = a ação do serviço não foi concluída: {$reason}
ops-no-target = `{$module}` não gerencia nenhum arquivo neste host.
ops-no-service = `{$module}` não controla nenhum serviço neste host, então não pode ser reiniciado.
ops-audit-failed = não foi possível ler o log de auditoria: {$reason}
ops-audit-unavailable = não foi possível gravar o log de auditoria, então a operação foi recusada: {$reason}
ops-unsupported = {$what} não é suportado nesta compilação.
ops-commit-pending = outra janela de commit-confirm já está pendente.
ops-update-running = uma atualização já está em execução; aguarde o término e verifique a versão em execução.
ops-update-tag-invalid = isso não é uma versão de lançamento; deve ter a forma v1.2.3.
ops-update-not-newer = esse lançamento não é mais novo que a versão em execução; nada foi iniciado.
ops-no-backup = commit-confirm exige um backup retido; nada foi alterado.
ops-arm-failed-restored = não foi possível armar o commit-confirm, então a alteração foi desfeita; o conteúdo anterior foi restaurado.
ops-arm-failed-unrestored = não foi possível armar o commit-confirm e a alteração NÃO pôde ser desfeita; o novo conteúdo ainda está no disco. Restaure o backup anterior agora.
ops-target-missing = o arquivo gerenciado não existe; crie-o (instalando seu pacote ou manualmente) e tente de novo.
ops-denied = você não tem permissão para fazer isso.

## detent-web — configuration, TLS, the operations bridge, and the listener
web-config-unreadable = não foi possível ler `{$path}`: {$reason}
web-config-malformed = `{$path}` não é uma configuração válida do detent: {$reason}
web-config-zero-value = `{$field}` deve ser maior que zero.
web-config-weak-argon2 = `auth.argon2.m_kib` é {$m}, abaixo do mínimo de {$min} kib.
web-tls-generate-failed = não foi possível gerar o certificado de bootstrap: {$reason}
web-tls-key-rejected = o certificado e sua chave privada foram rejeitados: {$reason}
web-tls-store-unreadable = não foi possível ler `{$path}`: {$reason}
web-tls-store-unwritable = não foi possível preparar `{$path}` para gravação: {$reason}
web-tls-store-write-failed = não foi possível gravar `{$path}`: {$reason}
web-tls-acme-pem-rejected = o certificado ou a chave emitida não era um PEM utilizável.
web-engine-stopped = o mecanismo de operações não está mais em execução; tente novamente quando o serviço voltar.
web-cert-renew-not-acme = a renovação exige `tls.bootstrap = "acme"` em detent.toml.
web-cert-renew-unavailable = o cliente acme não recebeu a solicitação de renovação; tente novamente mais tarde.
web-update-not-checked = nenhuma verificação de atualização foi executada neste host ainda; execute `detent update --check` como root.
web-server-bind-failed = não foi possível escutar em `{$addr}`: {$reason}
web-server-address-unknown = não foi possível ler de volta o endereço de escuta: {$reason}

## detent-web — auth: passwords, sessions, api tokens, totp, csrf
web-auth-entropy-unavailable = o gerador de números aleatórios do sistema falhou, então nenhuma credencial pôde ser emitida.
web-auth-argon2-params = os parâmetros argon2 configurados não são utilizáveis: {$reason}
web-auth-hash-failed = não foi possível gerar o hash da senha.
web-auth-password-too-short = uma senha deve ter pelo menos 12 caracteres.
web-auth-password-too-long = uma senha pode ter no máximo 128 caracteres.
web-auth-password-unchanged = a nova senha deve ser diferente da atual.
web-auth-password-change-required = altere sua senha antes de fazer qualquer outra coisa.
web-auth-user-name-invalid = `{$name}` não é um nome de usuário utilizável; use de 1 a 32 caracteres entre `a-z`, `0-9`, `.`, `_` ou `-`, começando com uma letra ou um dígito.
web-auth-user-exists = já existe um usuário chamado `{$name}`.
web-auth-user-unknown = não há usuário chamado `{$name}`.
web-auth-invalid-credentials = o nome de usuário, a senha ou o código não estava correto.
web-auth-rate-limited = tentativas demais; aguarde {$seconds} segundos e tente novamente.
web-auth-session-limit = há sessões demais abertas; aguarde uma expirar e entre novamente.
web-auth-busy = há logins demais em andamento; aguarde um momento e tente novamente.
web-auth-unauthenticated = entre para fazer isso.
web-auth-ambiguous-credentials = envie um cookie de sessão ou um token bearer, não os dois.
web-auth-csrf-rejected = esta solicitação não passou nas verificações entre sites.
web-auth-token-unknown = esse token de api não existe, foi revogado ou expirou.
web-auth-token-limit = este host já tem o número máximo de tokens de api.
web-auth-totp-secret-invalid = esse segredo do autenticador não é um base32 válido.
web-auth-store-unreadable = não foi possível ler `{$path}`: {$reason}
web-auth-store-unwritable = não foi possível preparar `{$path}` para gravação: {$reason}
web-auth-store-write-failed = não foi possível gravar `{$path}`: {$reason}
web-auth-store-malformed = `{$path}` não é um arquivo de credenciais válido do detent: {$reason}
web-denied-scope = esta credencial não possui o escopo `{$scope}`.

## detent-web — the api surface
web-request-malformed = o corpo da solicitação não tem a forma que este endpoint espera.
web-request-too-deep = o corpo da solicitação tem aninhamento profundo demais.
web-api-unexpected-outcome = a operação foi concluída, mas seu resultado não pôde ser exibido.
