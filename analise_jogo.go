package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

type ArquivoDoJogo struct {
	Caminho    string
	Nome       string
	Assinatura string
	Assinante  string
	Tamanho    int64
	Modificado time.Time
	NaRaiz     bool
}

var assinantesEsperadosDoJogo = []string{
	"citizenfx", "cfx.re", "rockstar", "take-two", "microsoft", "nvidia", "amd", "intel", "google",
	"the chromium authors", "valve", "epic games", "steam", "khronos", "openssl", "curl", "libcef", "spectre",
}

var dependenciasSemAssinaturaNoFiveM = []string{
	"libuv", "v8-", "v8_", "libcef", "chrome_elf", "botan", "mono-", "libmono", "msgpack", "steam_api",
	"d3dcompiler", "vulkan", "openal", "libeay", "ssleay", "zlib", "icu", "swiftshader", "vk_", "dxil",
	"discord_game_sdk", "sentry", "crashpad", "ffmpeg", "avcodec", "avformat", "avutil", "sqlite",
}

func dependenciaConhecidaSemAssinatura(nome string) bool {
	n := strings.ToLower(nome)
	for _, marca := range dependenciasSemAssinaturaNoFiveM {
		if strings.Contains(n, marca) {
			return true
		}
	}
	return false
}

func assinanteConhecidoDoJogo(assinante string) bool {
	a := strings.ToLower(assinante)
	for _, e := range assinantesEsperadosDoJogo {
		if strings.Contains(a, e) {
			return true
		}
	}
	return false
}

func avaliarIntegridadeDoJogo(pasta string, arquivos []ArquivoDoJogo, a *Assinaturas) []Sinal {
	var sinais []Sinal
	if len(arquivos) == 0 {
		return nil
	}
	assinados, adulterados, considerados := 0, 0, 0
	var suspeitos []ArquivoDoJogo
	for _, arq := range arquivos {
		if !dependenciaConhecidaSemAssinatura(arq.Nome) {
			considerados++
		}
		switch strings.ToLower(arq.Assinatura) {
		case "valid":
			assinados++
			if !assinanteConhecidoDoJogo(arq.Assinante) {
				suspeitos = append(suspeitos, arq)
			}
		case "hashmismatch":
			adulterados++
			sinais = append(sinais, Sinal{Critico, "Arquivo do jogo ASSINADO MAS ALTERADO: " + arq.Nome, arq.Caminho + "\n" + formataHora(arq.Modificado) + "\nO arquivo foi modificado depois de assinado pelo fabricante. E exatamente o que acontece quando alguem troca uma dll do jogo por uma versao com cheat embutido", "cheat"})
		default:
			suspeitos = append(suspeitos, arq)
		}
	}

	proporcao := 1.0
	if considerados > 0 {
		proporcao = float64(assinados) / float64(considerados)
	}
	for _, arq := range suspeitos {
		if termo := a.Marca(arq.Nome); termo != "" {
			sinais = append(sinais, Sinal{Critico, "Arquivo com nome de cheat dentro da pasta do jogo ('" + termo + "'): " + arq.Nome, arq.Caminho + "\n" + formataHora(arq.Modificado), "cheat"})
			continue
		}
		if !arq.NaRaiz || dependenciaConhecidaSemAssinatura(arq.Nome) {
			continue
		}
		if proporcao < 0.5 {
			continue
		}
		sev := Alerta
		motivo := "sem assinatura digital"
		if strings.EqualFold(arq.Assinatura, "Valid") {
			motivo = "assinado por " + resumeTexto(arq.Assinante, 60) + ", que nao e fabricante do jogo"
			sev = Critico
		}
		sinais = append(sinais, Sinal{sev, "Arquivo do jogo " + motivo + ": " + arq.Nome, fmt.Sprintf("%s\n%s  %d KB\nA maioria dos arquivos desta pasta e assinada pelo fabricante e este nao e. Arquivo trocado por versao modificada aparece assim", arq.Caminho, formataHora(arq.Modificado), arq.Tamanho/1024), "suspeito"})
	}

	if adulterados == 0 && len(sinais) == 0 && assinados > 0 {
		return nil
	}
	return ordenaSinais(sinais)
}

var dllsDeInjecaoNoJogo = map[string]string{
	"dinput8.dll":   "carregador de mods ASI (padrao do ScriptHookV e de menus)",
	"dsound.dll":    "carregador de mods por substituicao de dll do Windows",
	"d3d9.dll":      "carregador grafico substituido",
	"d3d11.dll":     "carregador grafico substituido",
	"d3d12.dll":     "carregador grafico substituido",
	"dxgi.dll":      "carregador grafico substituido (ReShade tambem usa)",
	"version.dll":   "carregador por substituicao de dll do Windows",
	"winmm.dll":     "carregador por substituicao de dll do Windows",
	"xinput1_3.dll": "carregador por substituicao de dll do Windows",
	"opengl32.dll":  "carregador por substituicao de dll do Windows",
}

func avaliarPastaDoGTA(pasta string, arquivos []ArquivoDoJogo, a *Assinaturas) []Sinal {
	var sinais []Sinal
	var asi []string
	for _, arq := range arquivos {
		nome := strings.ToLower(arq.Nome)
		linha := fmt.Sprintf("%s  (%d KB, %s)", arq.Caminho, arq.Tamanho/1024, formataHora(arq.Modificado))
		if termo := a.Marca(arq.Nome); termo != "" {
			sinais = append(sinais, Sinal{Critico, "Arquivo com nome de cheat na pasta do GTA ('" + termo + "'): " + arq.Nome, linha, "cheat"})
			continue
		}
		if classe, termo := a.Classificar(arq.Nome); classe != SemMatch {
			sinais = append(sinais, Sinal{classe.Severidade(), "Arquivo na pasta do GTA bate com '" + termo + "': " + arq.Nome, linha, "suspeito"})
			continue
		}
		if descricao, ok := dllsDeInjecaoNoJogo[nome]; ok {
			sev := Alerta
			if strings.EqualFold(arq.Assinatura, "Valid") && assinanteConhecidoDoJogo(arq.Assinante) {
				continue
			}
			sinais = append(sinais, Sinal{sev, "DLL de carregamento de mod na pasta do GTA: " + arq.Nome, linha + "\n" + descricao + "\nO GTA original nao traz essa dll. Ela existe para carregar codigo de fora junto com o jogo. Mod visual usa o mesmo caminho, entao confirme o que ela carrega", "suspeito"})
			continue
		}
		if strings.HasSuffix(nome, ".asi") {
			asi = append(asi, linha)
		}
	}
	sort.Strings(asi)
	if len(asi) > 0 {
		sinais = append(sinais, Sinal{Alerta, fmt.Sprintf("%d plugin(s) .asi instalado(s) na pasta do GTA", len(asi)), strings.Join(limitaLinhas(asi, 80), "\n") + "\nTodo .asi e codigo carregado dentro do jogo. Menu de cheat se instala assim, mas mod visual tambem. Cada um precisa ser conferido", "suspeito"})
	}
	return ordenaSinais(sinais)
}

func avaliarLocalDaInstalacao(caminho string) []Sinal {
	c := strings.ToLower(caminho)
	for _, marca := range []string{`\downloads\`, `\desktop\`, `\temp\`, `\users\public\`, `\$recycle.bin\`} {
		if strings.Contains(c, marca) {
			return []Sinal{{Alerta, "FiveM instalado em pasta fora do padrao", caminho + "\nO instalador oficial coloca o FiveM em AppData\\Local\\FiveM. Instalacao em Downloads, Desktop ou Temp costuma indicar copia baixada pronta de outro lugar, e nao instalacao pelo site oficial", "suspeito"}}
		}
	}
	return nil
}

type SinalDeVirtualizacao struct {
	Fonte string
	Valor string
	Marca string
}

var marcasDeVM = []string{
	"vmware", "virtualbox", "vbox", "qemu", "kvm", "xen", "parallels", "hyper-v", "virtual machine",
	"innotek", "bochs", "sandbox", "cuckoo", "utm", "bhyve", "proxmox",
}

func avaliarVirtualizacao(sinaisVM []SinalDeVirtualizacao) []Sinal {
	if len(sinaisVM) == 0 {
		return nil
	}
	var linhas []string
	vistos := map[string]bool{}
	for _, s := range sinaisVM {
		chave := s.Fonte + s.Marca
		if vistos[chave] {
			continue
		}
		vistos[chave] = true
		linhas = append(linhas, fmt.Sprintf("%s: %s  (bate com '%s')", s.Fonte, resumeTexto(s.Valor, 90), s.Marca))
	}
	sort.Strings(linhas)
	return []Sinal{{Critico, "Este Windows esta rodando dentro de uma MAQUINA VIRTUAL", strings.Join(linhas, "\n") + "\nTelagem feita dentro de maquina virtual nao vale: o jogador pode estar mostrando um sistema limpo enquanto joga no Windows real da maquina. Peca para rodar o scanner no Windows onde o FiveM abre", "cheat"}}
}

type ArquivoDaCitizen struct {
	Relativo   string
	Hash       string
	Modificado time.Time
	Existe     bool
}

type CitizenSolta struct {
	Raiz      string
	Arquivos  []ArquivoDaCitizen
	Instalada []ArquivoDaCitizen
}

var arquivosChaveDaCitizen = []string{
	`clr2\lib\mono\4.5\CitizenFX.Core.dll`,
	`clr2\lib\mono\4.5\CitizenFX.Core.Client.dll`,
	`clr2\lib\mono\4.5\v2\CitizenFX.Core.dll`,
	`clr2\lib\mono\4.5\v2\CitizenFX.FiveM.dll`,
	`clr2\lib\mono\4.5\v2\CitizenFX.FiveM.NativeImpl.dll`,
	`clr2\lib\mono\4.5\v2\Native\CitizenFX.FiveM.Native.dll`,
	`clr2\lib\mono\4.5\mscorlib.dll`,
	`scripting\lua\scheduler.lua`,
	`scripting\lua\natives_loader.lua`,
	`scripting\v8\main.js`,
}

func avaliarCitizenSolta(c CitizenSolta, instalacao string) []Sinal {
	instalada := map[string]ArquivoDaCitizen{}
	for _, a := range c.Instalada {
		instalada[strings.ToLower(a.Relativo)] = a
	}
	var iguais, diferentes, soNaCopia []string
	iguaisComMesmaData := 0
	for _, a := range c.Arquivos {
		if !a.Existe {
			continue
		}
		i, ok := instalada[strings.ToLower(a.Relativo)]
		linha := fmt.Sprintf("%s  copia: %s  instalado: %s", a.Relativo, formataHora(a.Modificado), formataHora(i.Modificado))
		switch {
		case !ok || !i.Existe:
			soNaCopia = append(soNaCopia, a.Relativo)
		case a.Hash != "" && a.Hash == i.Hash:
			iguais = append(iguais, linha)
			if !a.Modificado.IsZero() && a.Modificado.Equal(i.Modificado) {
				iguaisComMesmaData++
			}
		default:
			diferentes = append(diferentes, linha)
		}
	}
	if len(iguais)+len(diferentes)+len(soNaCopia) == 0 {
		return nil
	}
	cabecalho := c.Raiz + "\nComparacao com a citizen instalada em " + instalacao
	if len(diferentes) == 0 && len(iguais) > 0 {
		sev := Alerta
		nota := "\nTodos os arquivos-chave da copia solta sao identicos aos instalados. Ou a copia veio da propria instalacao (backup), ou a instalacao foi trocada por esta copia. "
		if iguaisComMesmaData > 0 {
			sev = Critico
			nota += fmt.Sprintf("%d arquivo(s) instalado(s) tem exatamente a mesma data da copia solta, e o instalador do FiveM grava os arquivos dele com a data da atualizacao, nao com a data de um pacote de terceiro: a citizen instalada FOI TROCADA por esta copia. ", iguaisComMesmaData)
		}
		nota += "Pergunte de onde veio a pasta e confira a origem no historico do navegador"
		return []Sinal{{sev, fmt.Sprintf("Pasta 'citizen' do FiveM solta em %s, identica a instalada", nomeBase(c.Raiz)), cabecalho + "\n" + strings.Join(limitaLinhas(iguais, 12), "\n") + nota, "suspeito"}}
	}
	detalhe := cabecalho
	if len(diferentes) > 0 {
		detalhe += "\nDIFERENTES do instalado:\n  " + strings.Join(limitaLinhas(diferentes, 12), "\n  ")
	}
	if len(iguais) > 0 {
		detalhe += "\nIguais ao instalado:\n  " + strings.Join(limitaLinhas(iguais, 12), "\n  ")
	}
	if len(soNaCopia) > 0 {
		detalhe += "\nSo existem na copia:\n  " + strings.Join(limitaLinhas(soNaCopia, 12), "\n  ")
	}
	sev := Alerta
	if len(diferentes) > 0 {
		sev = Critico
	}
	return []Sinal{{sev, fmt.Sprintf("Pasta 'citizen' do FiveM solta em %s, com %d arquivo(s) diferente(s) da instalada", nomeBase(c.Raiz), len(diferentes)), detalhe + "\nUma citizen modificada e o jeito de embutir executor de script no proprio FiveM. Se a instalada esta integra hoje, o FiveM pode ter restaurado os arquivos na ultima atualizacao; a copia solta continua sendo o pacote que o jogador baixou. Abra a CitizenFX.Core.dll da copia e compare com a oficial", "cheat"}}
}

func avaliarDatasDaCitizenInstalada(arquivos []ArquivoDaCitizen, instalacao string) []Sinal {
	var datas []time.Time
	for _, a := range arquivos {
		if a.Existe && !a.Modificado.IsZero() {
			datas = append(datas, a.Modificado)
		}
	}
	if len(datas) < 4 {
		return nil
	}
	sort.Slice(datas, func(i, j int) bool { return datas[i].Before(datas[j]) })
	mediana := datas[len(datas)/2]
	var fora []string
	for _, a := range arquivos {
		if !a.Existe || a.Modificado.IsZero() {
			continue
		}
		diferenca := a.Modificado.Sub(mediana)
		if diferenca < 0 {
			diferenca = -diferenca
		}
		if diferenca > 36*time.Hour {
			fora = append(fora, fmt.Sprintf("%s  %s (os demais: %s)", a.Relativo, formataHora(a.Modificado), formataHora(mediana)))
		}
	}
	if len(fora) == 0 || len(fora)*2 > len(datas) {
		return nil
	}
	return []Sinal{{Critico, fmt.Sprintf("%d arquivo(s) da citizen instalada com data diferente dos vizinhos", len(fora)), instalacao + "\n" + strings.Join(fora, "\n") + "\nO atualizador do FiveM grava todos os arquivos da citizen na mesma leva, entao eles tem a mesma data. Um arquivo com data solta foi copiado por cima na mao, que e como se troca a CitizenFX.Core.dll por versao com executor", "cheat"}}
}
