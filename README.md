# Scanner Filadelfia

Ferramenta de checagem de PC para cidades de FiveM. Procura cheat, sinal de cheat que ja
rodou, e rastro apagado na marra. Roda no Windows, mostra o resultado numa tela no navegador
e entrega o relatorio para a equipe da cidade.

O codigo esta aberto por um motivo simples: quem roda isso esta dando acesso de administrador
ao proprio PC. **Leia o [TRANSPARENCIA.md](TRANSPARENCIA.md)** para saber exatamente o que o
programa le, o que sai da sua maquina e o que ele nao faz.

## Como funciona

O jogador abre o executavel, digita o codigo que a equipe passou, e roda a checagem. No fim,
o relatorio inteiro sobe para o servidor da cidade e a equipe abre pelo painel, sem precisar
receber arquivo pela mao de quem esta sendo checado.

O codigo de autorizacao vale uma vez, em um unico computador, e queima quando o relatorio
chega.

## O que ele procura

- Cheat rodando, cheat que ja rodou e cheat apagado depois.
- Injecao em memoria no FiveM, incluindo modulo carregado na mao que nao aparece na lista.
- Driver vulneravel usado para carregar codigo em kernel.
- Windows modificado, ISO pirata e ativador.
- Servico de protecao parado, log apagado, Prefetch desligado, journal do NTFS zerado.
- Hardware de trapaca, como placa DMA e adaptador de mouse e teclado.
- Rastro em navegador, Discord e pacote compactado.

Um resultado critico e indicio forte, nao prova. A ferramenta foi feita para embasar
conversa com o jogador, nao para banir sozinha.

## Compilar

Precisa de Go 1.27 ou mais novo. Nao usa cgo.

```
./build.sh                                  # exe solto, sem exigir autorizacao
./build.sh https://scanner.suacidade.com    # exe que so roda com codigo da equipe
```

Sai em `dist/scanner.exe`. O endereco do servidor fica gravado no binario.

Para conferir que o executavel que voce recebeu foi feito deste codigo, compile com a mesma
versao do Go e compare o SHA256. O build usa `-trimpath`, entao o resultado nao depende do
caminho da sua pasta.

## A lista de assinaturas

Os nomes de cheat conhecidos **nao estao neste repositorio**, de proposito. Publicar a lista
seria entregar de graga o mapa de evasao para quem escreve cheat.

O que esta aqui e o `assinaturas.exemplo.json`, com tres nomes de mentira, para o projeto
compilar e rodar. O scanner baixa a lista real do servidor da cidade depois de autenticar,
e a mantem so na memoria.

Se voce for usar em outra cidade, monte a sua propria lista no mesmo formato e publique pelo
painel, ou passe com `-assinaturas caminho.json`.

## O servidor

O servico de autorizacao esta em [`servidor/`](servidor/). E um binario Go com Postgres, com
painel web para a equipe gerar codigo, acompanhar quem usou e abrir os relatorios recebidos.
As instrucoes de instalacao estao no [servidor/LEIAME.md](servidor/LEIAME.md).

## Rodar os testes

```
go test ./...
```

Os testes que dependem da lista real ficam marcados como pulados se voce nao tiver um
`assinaturas.json` na raiz. Os demais rodam em qualquer sistema, inclusive fora do Windows.

## Aviso

Nao existe garantia. Ferramenta de checagem erra, tanto para mais quanto para menos.
Confirme com o jogador antes de tomar qualquer decisao.
