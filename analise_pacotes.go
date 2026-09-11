package main

import (
	"archive/zip"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type ItemDePacote struct {
	Nome    string
	Tamanho int64
}

type PacoteAnalisado struct {
	Caminho           string
	Formato           string
	Itens             []ItemDePacote
	Truncado          bool
	Erro              string
	Modificado        time.Time
	Tamanho           int64
	ProtegidoPorSenha bool
	ListagemIlegivel  bool
}

var extensoesDePacote = map[string]string{
	".zip": "zip", ".rar": "rar", ".7z": "7z", ".tar": "tar", ".gz": "gz", ".jar": "zip", ".apk": "zip",
}

func ehPacote(nome string) string {
	return extensoesDePacote[strings.ToLower(path.Ext(strings.ReplaceAll(nome, `\`, "/")))]
}

func lerZip(r io.ReaderAt, tamanho int64, maxItens int) ([]ItemDePacote, bool, error) {
	arquivo, err := zip.NewReader(r, tamanho)
	if err != nil {
		return nil, false, err
	}
	var itens []ItemDePacote
	for _, f := range arquivo.File {
		if f.FileInfo().IsDir() {
			continue
		}
		itens = append(itens, ItemDePacote{Nome: f.Name, Tamanho: int64(f.UncompressedSize64)})
		if len(itens) >= maxItens {
			return itens, true, nil
		}
	}
	return itens, false, nil
}

var extensoesPerigosasEmPacote = map[string]string{
	".exe": "programa", ".dll": "biblioteca", ".sys": "driver de kernel", ".asi": "plugin de GTA",
	".bat": "script de comando", ".cmd": "script de comando", ".ps1": "script PowerShell",
	".vbs": "script", ".js": "script", ".scr": "programa", ".msi": "instalador", ".lua": "script Lua",
	".ahk": "macro AutoHotkey", ".jar": "programa Java", ".reg": "alteracao de registro",
}

func avaliarPacote(p PacoteAnalisado, a *Assinaturas) []Sinal {
	if p.ProtegidoPorSenha || p.ListagemIlegivel {
		sev := Alerta
		nota := "\nPacote com senha esconde de qualquer checagem o que tem dentro, inclusive do antivirus. Programa e jogo de verdade nao sao distribuidos assim. E o formato padrao de entrega de cheat, justamente para passar batido. Peca a senha ao jogador e abra na frente dele"
		if pastaQuente(p.Caminho) || arquivoDoUniversoDoJogo(nomeBase(p.Caminho)) != "" {
			sev = Critico
		}
		return []Sinal{{sev, "Pacote PROTEGIDO POR SENHA, nao deu para ver o conteudo: " + nomeBase(p.Caminho),
			p.Caminho + "\n" + formataHora(p.Modificado) + "  " + formataTamanho(p.Tamanho) + "\n" + p.Erro + nota, "suspeito"}}
	}
	if p.Erro != "" {
		return []Sinal{{Info, "Nao consegui abrir o pacote " + nomeBase(p.Caminho), p.Caminho + "\n" + p.Erro + "\nAbra manualmente para conferir o conteudo", ""}}
	}
	if len(p.Itens) == 0 {
		return nil
	}
	var sinais []Sinal
	var perigosos []string
	var todos []string
	vistos := map[string]bool{}

	for _, item := range p.Itens {
		base := nomeBase(item.Nome)
		linha := fmt.Sprintf("%s  (%s)", item.Nome, formataTamanho(item.Tamanho))
		todos = append(todos, linha)

		if termo := a.Marca(item.Nome); termo != "" && !vistos["m"+termo] {
			vistos["m"+termo] = true
			sinais = append(sinais, Sinal{Critico, fmt.Sprintf("Dentro de %s tem arquivo com nome de cheat ('%s'): %s", nomeBase(p.Caminho), termo, base), p.Caminho + "\n" + linha + "\nO scanner abriu o pacote e leu a lista de arquivos de dentro dele", "cheat"})
			continue
		}
		if classe, termo := a.Classificar(item.Nome); classe != SemMatch && !a.TextoInocente(item.Nome) && !vistos["c"+termo] {
			vistos["c"+termo] = true
			sinais = append(sinais, Sinal{classe.Severidade(), fmt.Sprintf("Dentro de %s tem arquivo que bate com '%s': %s", nomeBase(p.Caminho), termo, base), p.Caminho + "\n" + linha, "suspeito"})
			continue
		}
		ext := strings.ToLower(path.Ext(strings.ReplaceAll(item.Nome, `\`, "/")))
		if extensaoDeTexto(item.Nome) {
			continue
		}
		if tipo, ok := extensoesPerigosasEmPacote[ext]; ok {
			perigosos = append(perigosos, fmt.Sprintf("%s  [%s]  %s", item.Nome, tipo, formataTamanho(item.Tamanho)))
		}
	}

	sort.Strings(perigosos)
	if len(perigosos) > 0 && pacoteDoProprioScanner(p.Itens) {
		return []Sinal{{Info, fmt.Sprintf("%s e o pacote do proprio Scanner Filadelfia", nomeBase(p.Caminho)), p.Caminho + "\n" + strings.Join(limitaLinhas(perigosos, 10), "\n") + "\nscanner.exe, verificar.exe e os scripts de teste sao deste kit, nao do jogador", ""}}
	}
	if len(perigosos) > 0 {
		if temCitizen, estranhos := pastaCitizenNoPacote(p.Itens); temCitizen {
			sinais = append(sinais, sinalDePacoteComCitizen(p, perigosos, estranhos))
			perigosos = nil
		}
	}
	doJogo := arquivoDoUniversoDoJogo(nomeBase(p.Caminho)) != ""
	if len(perigosos) > 0 && soManifestoDeRecurso(p.Itens) {
		sinais = append(sinais, Sinal{Info, fmt.Sprintf("%s e um recurso de servidor FiveM (so tem fxmanifest.lua de script)", nomeBase(p.Caminho)), p.Caminho + "\n" + strings.Join(limitaLinhas(perigosos, 20), "\n") + "\nfxmanifest.lua e o arquivo de descricao de recurso de servidor, nao e programa. Pacote de mod de carro, mapa ou roupa vem assim", ""})
		perigosos = nil
	}
	if len(perigosos) > 0 && modGraficoConhecido(p.Caminho, p.Itens) {
		sinais = append(sinais, Sinal{Alerta, fmt.Sprintf("%s e um mod grafico conhecido com %d programa(s) dentro", nomeBase(p.Caminho), len(perigosos)), p.Caminho + "\n" + strings.Join(limitaLinhas(perigosos, 40), "\n") + "\nQuantV, NaturalVision, ReShade e ENB funcionam com dxgi.dll, d3d11.dll ou plugin .asi: e o mecanismo normal deles, nao e cheat. Mas qualquer uma dessas dll pode ter sido trocada, entao vale conferir a assinatura ou o hash contra o pacote original", "suspeito"})
		perigosos = nil
	}
	if len(perigosos) > 0 && !(len(perigosos) == 1 && !doJogo && len(p.Itens) <= 12) {
		sev := Alerta
		nota := "\nPacote de mod visual normalmente so tem .rpf, .ytd, .ydr, imagem e texto. Programa, dll, driver ou script dentro de um pacote de mod e o jeito mais comum de entregar cheat"
		if doJogo {
			sev = Critico
			if oficial, estranhos := conteudoBateComFiveMOficial(p.Itens); oficial {
				if len(estranhos) == 0 {
					sev = Alerta
					nota = "\nOs arquivos de dentro sao os mesmos da pasta 'citizen' oficial do FiveM (CitizenFX.Core, Mono, System.*). Tem cara de pacote de otimizacao de FPS, que e comum, mas qualquer uma dessas dll pode ter sido trocada. Conferir a assinatura digital antes de descartar"
				} else {
					nota = "\nO pacote imita a pasta 'citizen' oficial do FiveM, mas tem arquivo que nao pertence a ela:\n  " + strings.Join(limitaLinhas(estranhos, 60), "\n  ")
				}
			}
		}
		sinais = append(sinais, Sinal{sev, fmt.Sprintf("%s tem %d programa(s)/script(s) dentro", nomeBase(p.Caminho), len(perigosos)), p.Caminho + "\n" + strings.Join(limitaLinhas(perigosos, 80), "\n") + nota, "suspeito"})
	}

	if len(sinais) == 0 {
		sort.Strings(todos)
		sinais = append(sinais, Sinal{Info, fmt.Sprintf("Conteudo de %s: %d arquivo(s), nada suspeito", nomeBase(p.Caminho), len(p.Itens)), p.Caminho + "\n" + strings.Join(limitaLinhas(todos, 100), "\n"), ""})
	}
	return ordenaSinais(sinais)
}

var nomesDeModGrafico = []string{"quantv", "naturalvision", "nve", "reshade", "enb", "visualv", "redux", "fivem enhanced", "graphics"}

var dllsDeModGrafico = map[string]bool{
	"dxgi.dll": true, "d3d11.dll": true, "d3d12.dll": true, "d3d9.dll": true, "d3d10.dll": true, "opengl32.dll": true,
	"dinput8.dll": true, "reshade64.dll": true, "reshade32.dll": true, "enbseries.dll": true, "enblocal.dll": true,
}

func modGraficoConhecido(caminhoDoPacote string, itens []ItemDePacote) bool {
	nomePacote := strings.ToLower(nomeBase(caminhoDoPacote))
	temMarca := false
	for _, m := range nomesDeModGrafico {
		if strings.Contains(nomePacote, m) {
			temMarca = true
			break
		}
	}
	if !temMarca {
		return false
	}
	for _, item := range itens {
		base := strings.ToLower(nomeBase(item.Nome))
		ext := path.Ext(base)
		if extensoesPerigosasEmPacote[ext] == "" || extensaoDeTexto(base) {
			continue
		}
		if dllsDeModGrafico[base] {
			continue
		}
		if ext == ".asi" {
			ok := false
			for _, m := range nomesDeModGrafico {
				if strings.Contains(base, m) {
					ok = true
					break
				}
			}
			if ok {
				continue
			}
		}
		return false
	}
	return true
}

func soManifestoDeRecurso(itens []ItemDePacote) bool {
	perigosos := 0
	for _, item := range itens {
		base := strings.ToLower(nomeBase(item.Nome))
		if extensoesPerigosasEmPacote[path.Ext(base)] == "" || extensaoDeTexto(base) {
			continue
		}
		if base != "fxmanifest.lua" && base != "__resource.lua" {
			return false
		}
		perigosos++
	}
	return perigosos > 0
}

func nomesDentroDoRarPorTexto(dados []byte, maxItens int) []ItemDePacote {
	var itens []ItemDePacote
	vistos := map[string]bool{}
	atual := make([]byte, 0, 260)
	guarda := func() {
		if len(atual) < 5 {
			atual = atual[:0]
			return
		}
		nome := string(atual)
		atual = atual[:0]
		if !strings.Contains(nome, ".") || vistos[nome] {
			return
		}
		ext := strings.ToLower(path.Ext(nome))
		if len(ext) < 2 || len(ext) > 6 {
			return
		}
		for _, c := range nome {
			if c < 0x20 {
				return
			}
		}
		vistos[nome] = true
		itens = append(itens, ItemDePacote{Nome: nome})
	}
	for i := 0; i < len(dados) && len(itens) < maxItens; i++ {
		c := dados[i]
		legivel := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '.' || c == '_' || c == '-' || c == ' ' || c == '\\' || c == '/' || c == '(' || c == ')' || c == '\''
		if legivel {
			if len(atual) < 260 {
				atual = append(atual, c)
			}
			continue
		}
		guarda()
	}
	guarda()
	return itens
}

var prefixosDoCitizenOficial = []string{
	"citizen/", "citizen\\", "clr2/", "clr2\\", "resources/", "resources\\",
}

var pastasDoCitizenOficial = []string{
	"citizen/scripting/", "citizen/shaderz/", "citizen/clr2/", "citizen/dui/", "citizen/ui/", "citizen/common/", "citizen/platform/",
}

var arquivosDoCitizenOficial = []string{
	"citizenfx.", "mono.", "microsoft.csharp", "msgpack", "system.", "mscorlib", "netstandard",
	"citizen-", "cfx-", "ros.dll", "botan", "cef", "libcef", "v8", "libuv", "steam_api", "discord",
	"gta5_settings", "shaders", "scripting", "natives", "manifest", "fxmanifest", "__resource",
}

func conteudoBateComFiveMOficial(itens []ItemDePacote) (bool, []string) {
	if len(itens) == 0 {
		return false, nil
	}
	comPrefixo := 0
	var estranhos []string
	for _, item := range itens {
		nome := strings.ToLower(strings.ReplaceAll(item.Nome, `\`, "/"))
		daPasta := false
		for _, p := range prefixosDoCitizenOficial {
			if strings.HasPrefix(nome, strings.ToLower(strings.ReplaceAll(p, `\`, "/"))) {
				daPasta = true
				break
			}
		}
		if daPasta {
			comPrefixo++
		}
		base := nomeBase(item.Nome)
		conhecido := false
		for _, pasta := range pastasDoCitizenOficial {
			if strings.Contains(nome, pasta) {
				conhecido = true
				break
			}
		}
		for _, marca := range arquivosDoCitizenOficial {
			if strings.Contains(strings.ToLower(base), marca) {
				conhecido = true
				break
			}
		}
		if !conhecido && extensoesPerigosasEmPacote[strings.ToLower(path.Ext(base))] != "" {
			estranhos = append(estranhos, item.Nome)
		}
	}
	return comPrefixo*2 >= len(itens), estranhos
}

var reLinhaUnrar = regexp.MustCompile(`^\s*[\.A-Za-z]{5,}\s+(\d+)\s+\S+\s+\S+\s+(.+?)\s*$`)

func lerListagemDePacote(saida string, ehUnrar bool, maxItens int) []ItemDePacote {
	var itens []ItemDePacote
	var atual *ItemDePacote
	for _, linha := range strings.Split(saida, "\n") {
		linha = strings.TrimRight(linha, "\r")
		if len(itens) >= maxItens {
			break
		}
		if ehUnrar {
			m := reLinhaUnrar.FindStringSubmatch(linha)
			if m == nil {
				continue
			}
			tamanho, _ := strconv.ParseInt(m[1], 10, 64)
			nome := strings.TrimSpace(m[2])
			if nome == "" || strings.HasPrefix(nome, "-") {
				continue
			}
			itens = append(itens, ItemDePacote{Nome: nome, Tamanho: tamanho})
			continue
		}
		limpa := strings.TrimSpace(linha)
		switch {
		case strings.HasPrefix(limpa, "Path = "):
			if atual != nil {
				itens = append(itens, *atual)
			}
			atual = &ItemDePacote{Nome: strings.TrimPrefix(limpa, "Path = ")}
		case strings.HasPrefix(limpa, "Size = ") && atual != nil:
			atual.Tamanho, _ = strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(limpa, "Size = ")), 10, 64)
		case strings.HasPrefix(limpa, "Folder = ") && atual != nil:
			if strings.Contains(limpa, "+") {
				atual = nil
			}
		}
	}
	if atual != nil && len(itens) < maxItens {
		itens = append(itens, *atual)
	}
	return itens
}

func formataTamanho(bytes int64) string {
	if bytes <= 0 {
		return "tamanho nao informado"
	}
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	}
	if bytes < 1024*1024 {
		return fmt.Sprintf("%d KB", bytes/1024)
	}
	return fmt.Sprintf("%.1f MB", float64(bytes)/1024/1024)
}

func pacoteDoProprioScanner(itens []ItemDePacote) bool {
	temScanner, temKit := false, false
	for _, item := range itens {
		base := strings.ToLower(nomeBase(item.Nome))
		switch base {
		case "scanner.exe":
			temScanner = true
		case "transparencia.md", "plantar.ps1", "verificar.exe", "so-para-a-equipe.txt", "assinaturas.exemplo.json":
			temKit = true
		}
	}
	return temScanner && temKit
}

var pastasDaEstruturaCitizen = []string{"clr2/", "scripting/", "shaderz/", "dui/", "ui/", "common/", "platform/", "ros/", "plugins/"}

func pastaCitizenNoPacote(itens []ItemDePacote) (bool, []string) {
	temCitizen := false
	for _, item := range itens {
		nome := strings.ToLower(strings.ReplaceAll(item.Nome, `\`, "/"))
		if strings.Contains(nome, "clr2/lib/mono") || strings.HasSuffix(nome, "/citizenfx.core.dll") || nome == "citizenfx.core.dll" {
			temCitizen = true
			break
		}
	}
	if !temCitizen {
		return false, nil
	}
	var estranhos []string
	for _, item := range itens {
		nome := strings.ToLower(strings.ReplaceAll(item.Nome, `\`, "/"))
		base := nomeBase(item.Nome)
		if extensoesPerigosasEmPacote[strings.ToLower(path.Ext(base))] == "" {
			continue
		}
		if dentroDaEstruturaCitizen(nome) {
			continue
		}
		estranhos = append(estranhos, item.Nome)
	}
	sort.Strings(estranhos)
	return true, estranhos
}

func dentroDaEstruturaCitizen(nome string) bool {
	for _, pasta := range pastasDaEstruturaCitizen {
		if strings.HasPrefix(nome, pasta) || strings.Contains(nome, "/"+pasta) {
			return true
		}
	}
	return false
}

func extensaoComCaixaTrocada(nome string) bool {
	ext := path.Ext(strings.ReplaceAll(nome, `\`, "/"))
	if len(ext) < 3 {
		return false
	}
	letras := ext[1:]
	return letras != strings.ToLower(letras) && letras != strings.ToUpper(letras)
}

func sinalDePacoteComCitizen(p PacoteAnalisado, perigosos, estranhos []string) Sinal {
	base := nomeBase(p.Caminho)
	if len(estranhos) == 0 {
		return Sinal{Alerta, fmt.Sprintf("%s e uma copia da pasta 'citizen' do FiveM (troca de citizen)", base),
			p.Caminho + "\n" + strings.Join(limitaLinhas(perigosos, 30), "\n") +
				"\nA pasta 'citizen' e o coracao do FiveM (CitizenFX.Core.dll, Mono, scripting). Ela nao se baixa avulsa: vem pelo instalador oficial. Pacote de 'citizen' passado por Drive, MediaFire ou Discord e o jeito mais comum de trocar a CitizenFX.Core.dll por versao com executor de script, e tambem o jeito comum de pacote de otimizacao de FPS. A etapa Integridade do jogo compara a citizen instalada com esta copia", "suspeito"}
	}
	var linhas []string
	for _, e := range estranhos {
		linha := e
		if extensaoComCaixaTrocada(e) {
			linha += "  (extensao com letras trocadas, jeito de passar por filtro)"
		}
		linhas = append(linhas, linha)
	}
	return Sinal{Critico, fmt.Sprintf("%s traz a pasta 'citizen' do FiveM junto com %d arquivo(s) que nao pertencem a ela", base, len(estranhos)),
		p.Caminho + "\nFora da estrutura da citizen:\n  " + strings.Join(limitaLinhas(linhas, 20), "\n  ") + "\nDa citizen:\n  " + strings.Join(limitaLinhas(perigosos, 20), "\n  ") +
			"\nPacote com a pasta 'citizen' do FiveM mais script ou dll solto ao lado e a entrega classica de executor: a citizen trocada carrega o script. Abra o pacote e leia o que e cada arquivo solto", "cheat"}
}

func nomeDeArquivoPlausivel(nome string) bool {
	base := nomeBase(nome)
	ponto := strings.LastIndex(base, ".")
	if ponto <= 0 || ponto == len(base)-1 {
		return false
	}
	if ponto < 3 {
		return false
	}
	ext := base[ponto+1:]
	if len(ext) > 5 {
		return false
	}
	for _, c := range ext {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	comuns := 0
	for _, c := range base[:ponto] {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == ' ' {
			comuns++
		}
	}
	return comuns*10 >= ponto*9
}

func listagemPareceLixo(itens []ItemDePacote) bool {
	if len(itens) < 5 {
		return false
	}
	plausiveis := 0
	for _, i := range itens {
		if nomeDeArquivoPlausivel(i.Nome) {
			plausiveis++
		}
	}
	return plausiveis*100 < len(itens)*45
}

func rarComSenha(dados []byte) bool {
	if len(dados) < 12 {
		return false
	}
	if string(dados[:8]) == "Rar!\x1a\x07\x01\x00" {
		return primeiroBlocoRar5EhCripto(dados[8:])
	}
	if string(dados[:7]) == "Rar!\x1a\x07\x00" {
		if len(dados) < 13 {
			return false
		}
		flags := uint16(dados[10]) | uint16(dados[11])<<8
		return flags&0x0080 != 0
	}
	return false
}

func primeiroBlocoRar5EhCripto(bloco []byte) bool {
	if len(bloco) < 6 {
		return false
	}
	pos := 4
	if _, n, ok := lerVIntRar(bloco[pos:]); ok {
		pos += n
	} else {
		return false
	}
	tipo, _, ok := lerVIntRar(bloco[pos:])
	return ok && tipo == 4
}

func lerVIntRar(dados []byte) (uint64, int, bool) {
	var valor uint64
	for i := 0; i < len(dados) && i < 10; i++ {
		valor |= uint64(dados[i]&0x7f) << (7 * i)
		if dados[i]&0x80 == 0 {
			return valor, i + 1, true
		}
	}
	return 0, 0, false
}
