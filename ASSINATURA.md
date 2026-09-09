# Assinatura digital do scanner.exe

O Defender marcou o `scanner.exe` como `Trojan:Win32/Ulthar.A!ml`. O sufixo `!ml` quer dizer
"machine learning": nenhuma regra de virus bateu, o modelo do Defender apenas achou o arquivo
estranho. Isso acontece porque o programa e escrito em Go, nao tem assinatura digital, e faz
exatamente o que malware faz (le processos, memoria, registro e journal do disco).

Existem tres caminhos, do mais barato para o mais completo.

## 1. Ja feito: dar identidade ao executavel (custo zero)

A partir da versao 2.1.0 o exe carrega:

- Nome do produto, empresa, descricao, copyright e versao (aba Detalhes das propriedades)
- Icone proprio
- Manifesto pedindo administrador de forma declarada
- Tabela de simbolos preservada (binario "pelado" pontua mais na heuristica)

Isso nao elimina o alerta sozinho, mas tira o exe da categoria "arquivo anonimo sem procedencia",
que e o que mais pesa no modelo.

## 2. Reportar o falso positivo para a Microsoft (custo zero, alguns dias)

Envie o arquivo em:

https://www.microsoft.com/en-us/wdsi/filesubmission

Preencha assim:

- Tipo de envio: **Software developer**
- Deteccao: `Trojan:Win32/Ulthar.A!ml`
- Marque **Incorrectly detected as malware** (falso positivo)
- Descricao sugerida: ferramenta interna de checagem de PC de um servidor de FiveM, roda apenas
  local, gera relatorio em arquivo e nao envia dados para lugar nenhum

A resposta costuma vir em 1 a 3 dias uteis. Quando a Microsoft libera, o alerta some para todo
mundo, sem precisar de certificado. **Refaca o envio a cada versao nova do exe.**

## 3. Certificado de assinatura de codigo

### Azure Trusted Signing (recomendado hoje)

E o caminho mais barato e sem token fisico. A Microsoft guarda a chave.

- Custo: cerca de **US$ 10 por mes** no plano basico
- Nao precisa de token USB nem HSM proprio
- Exige uma empresa (CNPJ) com pelo menos 3 anos de registro, ou verificacao de identidade
  individual quando disponivel na regiao
- Portal: https://learn.microsoft.com/azure/trusted-signing/

### Certificado OV tradicional

- Custo: por volta de **R$ 1.000 a 1.500 por ano** (Certisign, DigiCert, Sectigo)
- Precisa de CNPJ e validacao da empresa
- Desde 2023 a chave privada precisa ficar em token fisico ou HSM
- A reputacao no SmartScreen e construida com o tempo, nao e imediata

### Certificado EV

- Custo: **R$ 2.500 a 4.000 por ano**
- Reputacao no SmartScreen imediata
- Token fisico obrigatorio, o que complica automatizar a assinatura

**Nao adianta** gerar certificado proprio (self-signed): o Windows nao confia e o Defender ignora.

## Como assinar depois de ter o certificado

No Windows, com o SDK instalado (`signtool.exe`), rode o `assinar.ps1` que esta neste projeto:

```powershell
.\assinar.ps1 -Certificado "C:\caminho\certificado.pfx" -Senha "senha do pfx"
```

Ou direto:

```powershell
signtool sign /f certificado.pfx /p SENHA /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 scanner.exe
signtool verify /pa /v scanner.exe
```

O `/tr` (carimbo de tempo) e importante: sem ele a assinatura vence junto com o certificado e os
executaveis antigos passam a dar erro.

## Enquanto nao assinar

Avise o jogador antes da telagem: o Windows pode alertar, e ele deve escolher "Executar assim
mesmo" ou "Manter arquivo" no navegador. Se voce mandar o exe pelo Discord, o download tambem
pode ser bloqueado. Um zip com senha resolve o bloqueio do navegador, mas nao o do Defender.
