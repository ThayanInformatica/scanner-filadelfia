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
	Caminho    string
	Formato    string
	Itens      []ItemDePacote
	Truncado   bool
	Erro       string
	Modificado time.Time
	Tamanho    int64
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
