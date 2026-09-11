# O que o Scanner Filadelfia le, e o que ele nao faz

Este documento existe porque a pergunta e justa: voce vai rodar como administrador um
programa que alguem te mandou. Voce merece saber exatamente o que ele toca.

Tudo aqui pode ser conferido no codigo deste repositorio. Onde o texto cita um arquivo,
e la que a checagem mora.

## O basico

- Roda so quando voce abre. Nao instala nada, nao cria servico, nao entra na inicializacao
  do Windows e nao fica rodando depois que voce fecha a janela.
- Precisa de administrador porque le registro, servicos, logs do Windows e memoria de
  processo. Sem isso metade das checagens falha.
- Abre uma tela no seu navegador em `127.0.0.1`, so na sua maquina, protegida por um token
  aleatorio gerado a cada execucao. Ninguem de fora acessa essa tela.
- Voce ve na tela exatamente o mesmo relatorio que a equipe recebe. Nao existe parte
  escondida do jogador.

## O que ele le

**Sistema e configuracao** (`checks_sistema.go`, `checks_servicos.go`, `checks_registro.go`)
Versao e build do Windows, integridade de codigo, modo de teste de assinatura, servicos do
Windows e se foram parados, politicas do Defender, chaves de inicializacao automatica,
tarefas agendadas. Le tambem a data da ultima alteracao da chave de cada servico, para
distinguir varios servicos desligados de uma vez por um programa de ajustes feitos a mao ao
longo do tempo.

**Rastros de execucao** (`checks_logs.go`, `checks_etw.go`, `checks_artefatos.go`, `checks_arquivos.go`)
Logs de eventos do Windows, sessoes de rastreamento do kernel, Prefetch, ShimCache, relatorios
de falha, atalhos e listas de arquivos recentes, nomes de arquivos nos discos fixos. Le tambem
os arquivos de texto do Assistente de Compatibilidade em `C:\Windows\appcompat\pca`, que
guardam o caminho e a hora de cada programa com janela que foi aberto.

Nos executaveis recentes das pastas do usuario le o fluxo alternativo `Zone.Identifier`, que o
proprio Windows grava dentro do arquivo baixado e que contem o endereco de origem do download.
Le so esse fluxo, so em executavel, e so o endereco.

**Processos e memoria** (`checks_processos.go`, `checks_memoria.go`)
Lista de processos com caminho, processo pai e assinatura digital, modulos carregados,
janelas abertas, handles abertos no FiveM, e regioes de memoria executaveis do proprio FiveM.
A varredura de arquivos passa tambem por pendrive conectado, alem dos discos fixos.

De cada janela le tamanho, posicao, estilo e se ela pediu ao Windows para nao aparecer em
captura de tela. Serve para achar mira e ESP desenhados por cima do jogo. Nao le o conteudo
de nenhuma janela.

No processo do jogo a leitura e mais funda: alem das regioes de codigo, le tambem a memoria de
dados, porque executor de Lua manda o script para dentro do jogo e o texto fica ali; confere se
alguma thread do jogo comeca fora de qualquer dll registrada, que e o rastro de codigo carregado
na marra; e compara o codigo de dez dll do Windows carregadas no jogo com o arquivo delas no
disco, para achar funcao desviada. Nada disso e gravado: so entra no relatorio o endereco e o
trecho de texto em volta de um nome de cheat, quando existe.

Tambem le a memoria dos programas que nao sao do Windows e nao tem assinatura de antivirus,
anticheat ou de fabricante conhecido, procurando nome de cheat. Navegador, Discord e
programas de conversa ficam de fora de proposito: eles carregam na memoria o texto de
qualquer pagina ou conversa aberta, e isso nao diz nada sobre cheat. A leitura e feita na
memoria e descartada: nenhum trecho e gravado alem do pedaco de texto em volta de um nome
de cheat, quando existe.

**Integridade do jogo** (`checks_jogo.go`, `analise_meta.go`)
Assinatura digital dos arquivos do FiveM e do GTA V, e a pasta `citizen` do FiveM: a data dos
arquivos-chave dela (o atualizador grava todos na mesma leva) e, se existir uma copia solta da
`citizen` em Downloads, Desktop, Documentos ou Temp, o hash de dez arquivos dela comparado com
os instalados. Nao le o conteudo dos arquivos alem de calcular o hash.

Le tambem os arquivos `.meta` que estejam em `citizen\common\data` dentro da instalacao do
FiveM, e compara os valores de recuo e dispersao com o padrao do jogo. Uma instalacao limpa nao
tem nenhum arquivo `.meta` nessa pasta. Le so numero de configuracao de arma, nada mais.

**Historico de execucao com hash** (`checks_amcache.go`)
Le o Amcache.hve, o registro que o Windows mantem de todo programa que ja executou, com o
hash SHA1 de cada um. Serve para achar loader que rodou e foi apagado, e para bater hash de
cheat conhecido mesmo com o arquivo renomeado. Tambem calcula o SHA256 dos executaveis das
pastas de download, area de trabalho e temporarios.

**Conteudo de arquivo** (`checks_conteudo.go`, `checks_pacotes.go`)
Le o conteudo de arquivos procurando nomes de cheat conhecidos, e lista o que existe dentro
de .zip e .rar. Procura padrao, nao le documento pessoal para guardar.

**Navegador e Discord** (`checks_navegadores.go`, `checks_discord.go`)
Historico, downloads, cookies, favoritos, sites mais visitados, o que foi digitado na barra
de endereco, icones de site, nomes de formulario salvos, e o cache do Discord.

Do banco de senhas do navegador ele le **apenas o endereco do site e o nome de usuario**.
A senha em si fica criptografada pelo Windows e nao e lida em lugar nenhum: procure por
`password_value` no codigo e voce nao vai encontrar.

**Rede** (`checks_rede.go`)
Cache de DNS da maquina e o journal do NTFS, que e o registro de mudancas de arquivo do
proprio Windows.

## O que entra no relatorio

Esta e a parte que importa mais.

Historico, cookies, contas salvas, cache do Discord e conteudo de arquivo sao lidos **na
memoria** e comparados com a lista de assinaturas. **So vira achado no relatorio o que bate
com um nome de cheat conhecido.** O resto e descartado ali mesmo e nunca e gravado nem
enviado. Seu historico de navegacao normal nao aparece em lugar nenhum.

Entram no relatorio, sempre:

- Nome do PC, nome de usuario do Windows e informacoes do sistema.
- A lista de processos que estavam rodando durante a checagem.
- Os achados, com o detalhe de cada um.

## O que sai da sua maquina

Quando o scanner e usado com autorizacao da equipe, ao terminar ele envia **o relatorio**
para o servidor da cidade, comprimido, junto com um identificador do computador.

Esse identificador e um hash, um numero embaralhado, calculado a partir do MachineGuid do
Windows, do serial do disco C e do nome do PC (`licenca.go`). Ele serve para o codigo de
autorizacao valer em um unico computador. Nao da para voltar dele para os seus dados.

Nada alem disso sai. Nenhum arquivo seu e enviado. Nenhuma senha, nenhum cookie, nenhum
conteudo de conversa.

## O que ele escreve na sua maquina

- O relatorio, em `.txt` e `.json`, na pasta do executavel.
- Copias temporarias dos bancos do navegador, porque o Chrome trava o arquivo original
  enquanto esta aberto. Sao apagadas logo depois.
- Uma sessao temporaria de rastreamento do kernel, criada com o `logman` do proprio Windows
  para ver se o rastreamento do sistema foi adulterado, e encerrada em seguida
  (`checks_etw.go`).

Ele nao altera configuracao do Windows, nao mexe no Defender, nao apaga nada seu e nao
instala driver.

Existe um modo opcional, desligado por padrao, ligado so com `-autodestruir`: ao fechar,
o scanner apaga o proprio `.exe` e o `assinaturas.json` que estiver ao lado dele, usando
um `.bat` temporario. O relatorio e mantido, e nenhum outro arquivo seu e tocado. Sem esse
argumento, o scanner nunca se apaga.

## O que ele nao faz, e da para conferir

Procure no codigo e voce nao vai achar nenhuma dessas coisas:

- Captura de teclas.
- Captura de tela.
- Camera ou microfone.
- Leitura da area de transferencia.
- Acesso remoto ao seu PC.
- Leitura de senha salva.

## Uma ressalva honesta

O scanner e invasivo por natureza. Ele foi feito para achar quem esconde cheat, e para isso
precisa olhar bastante coisa. O que este documento promete nao e que ele olha pouco: e que
ele olha para procurar cheat, entrega so o que bate com cheat, e mostra para voce o mesmo
que mostra para a equipe.

Se algo aqui nao bater com o codigo, abra uma issue. E para isso que ele esta aberto.
