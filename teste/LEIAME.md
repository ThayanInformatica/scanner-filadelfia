# Teste em Windows de verdade

Este roteiro planta evidencias falsas numa maquina, roda o scanner e confere se cada uma
apareceu no relatorio. E o teste de regressao do projeto: nada aqui roda no Mac ou no Linux,
so num Windows real ou numa maquina virtual.

Nada do que ele planta e perigoso. Os "cheats" sao copias do `cmd.exe` renomeadas, os
arquivos sao texto, e tudo e removido pelo `desplantar.ps1`.

## Roteiro

1. Numa maquina virtual Windows 10 ou 11, copie o `scanner.exe`, o `assinaturas.json`
   da cidade e a pasta `teste/`.
2. Compile o verificador uma vez, em qualquer sistema: `go build -o verificar.exe ./teste/verificar`
   (ou `GOOS=windows GOARCH=amd64 go build -o verificar.exe ./teste/verificar` fora do Windows).
3. Abra o PowerShell como administrador e rode `.\teste\plantar.ps1`. Ele le o primeiro
   nome da lista `marcas` e o primeiro dominio do `assinaturas.json`, planta 17 evidencias e
   grava `plantio.json`.
4. Rode o `scanner.exe` como administrador e faca a checagem completa.
5. Rode `.\verificar.exe .\teste\plantio.json .\scanner-<PC>-<data>.json`.
   Ele imprime PASS ou FAIL por evidencia e sai com codigo 1 se alguma falhou.
6. Rode `.\teste\desplantar.ps1` para limpar.

## O que cada evidencia prova

| # | evidencia | etapa que deve pegar |
| --- | --- | --- |
| 1 | exe com nome de cheat em Downloads | varredura de arquivos |
| 2 | zip com programa dentro | conteudo dos pacotes |
| 3 | .txt com cabecalho MZ | varredura de arquivos (disfarce) |
| 4 | fluxo alternativo com nome de cheat | varredura manual (ADS) |
| 5 | atalho para pasta de cheat | artefatos (lnk) |
| 6 | tarefa agendada | varredura manual (tarefas) |
| 7 | chave Run | historico de execucao no registro |
| 8 | processo rodando com nome de cheat | processos |
| 9 | exe com nome aleatorio no Temp | varredura de arquivos |
| 10 | string de cheat num .lua | strings de conteudo |
| 11 | convite no cache do Discord | Discord |
| 12 | cheat chamado `scanner_*` | varredura de arquivos (evasao por nome) |
| 13 | dominio de cheat resolvido | cache DNS |
| 14 | Prefetch do loader executado | Prefetch |
| 15 | arquivo com nome de cheat na lixeira | recentes e lixeira |
| 16 | loader no Amcache | Amcache |
| 17 | string de cheat na memoria de processo sem assinatura | memoria dos outros processos |

A 16 depende do Windows gravar o Amcache, o que ele faz num agendamento proprio. O script
dispara a tarefa na hora, mas em alguns PCs leva minutos. Se so ela falhar, espere e rode o
scanner de novo.

## O que este roteiro NAO testa

Nada que seja destrutivo no Windows de teste: limpar log de eventos, apagar o journal do
NTFS, desligar o Defender, ligar testsigning. Essas checagens existem no scanner, mas
plantar a evidencia delas estraga a maquina. Teste na mao, numa VM descartavel, se quiser.
