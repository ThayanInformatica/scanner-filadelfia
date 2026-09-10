package main

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type InfoProcesso struct {
	PID              int
	Nome             string
	Caminho          string
	PaiPID           int
	PaiNome          string
	PaiCaminho       string
	OriginalFilename string
	ProductName      string
	CompanyName      string
	FileDescription  string
	Assinatura       string
	Assinante        string
	ExisteNoDisco    bool
	CaminhoLido      bool
	CriadoEm         time.Time
}

type HandleNoFiveM struct {
	DonoPID     int
	DonoNome    string
	DonoCaminho string
	Acesso      uint32
}

type JanelaVista struct {
	PID           int
	DonoNome      string
	DonoCaminho   string
	Titulo        string
	Classe        string
	X             int
	Y             int
	Largura       int
	Altura        int
	Layered       bool
	Transparente  bool
	Topmost       bool
	Visivel       bool
	ForaDaCaptura bool
}

type Sinal struct {
	Severidade Severidade
	Titulo     string
	Detalhe    string
	Situacao   string
}

const (
	acessoVMOperation  = 0x0008
	acessoVMRead       = 0x0010
	acessoVMWrite      = 0x0020
	acessoAllAccess    = 0x1FFFFF
	acessoCreateThread = 0x0002
)

var processosProtegidosConhecidos = map[string]bool{
	"system": true, "registry": true, "memory compression": true, "secure system": true, "smss.exe": true, "csrss.exe": true,
	"wininit.exe": true, "services.exe": true, "lsass.exe": true, "msmpeng.exe": true, "nissrv.exe": true, "mpdefendercoreservice.exe": true,
	"securityhealthservice.exe": true, "vmmem": true, "vmmemwsl": true, "audiodg.exe": true, "fontdrvhost.exe": true, "winlogon.exe": true,
	"idle": true, "lsaiso.exe": true, "sppsvc.exe": true, "sgrmbroker.exe": true, "vgc.exe": true, "vgtray.exe": true, "faceitservice.exe": true,
	"easyanticheat.exe": true, "easyanticheat_eos.exe": true, "beservice.exe": true, "gcac.exe": true, "wmiprvse.exe": true,
}

var paisEsperados = map[string][]string{
	"svchost.exe":       {"services.exe"},
	"csrss.exe":         {"smss.exe", ""},
	"lsass.exe":         {"wininit.exe"},
	"winlogon.exe":      {"smss.exe", ""},
	"services.exe":      {"wininit.exe"},
	"wininit.exe":       {"smss.exe", ""},
	"dwm.exe":           {"winlogon.exe"},
	"fontdrvhost.exe":   {"winlogon.exe", "wininit.exe"},
	"taskhostw.exe":     {"svchost.exe"},
	"runtimebroker.exe": {"svchost.exe"},
	"sihost.exe":        {"svchost.exe"},
	"spoolsv.exe":       {"services.exe"},
	"searchindexer.exe": {"services.exe"},
}

var nomesOriginaisAceitos = map[string]bool{
	"electron.exe": true, "app.exe": true, "main.exe": true, "launcher.exe": true, "java.exe": true, "javaw.exe": true,
	"python.exe": true, "pythonw.exe": true, "node.exe": true, "nw.exe": true, "cefsharp.browsersubprocess.exe": true,
	"msedgewebview2.exe": true, "chrome.exe": true, "unity.exe": true, "unityplayer.dll": true, "flutter_windows.dll": true,
	"tauri.exe": true, "dotnet.exe": true, "apphost.exe": true, "wails.exe": true, "love.exe": true, "godot.exe": true,
}

var donosDeHandleAceitos = []string{
	"csrss.exe", "lsass.exe", "svchost.exe", "msmpeng.exe", "nissrv.exe", "obs64.exe", "obs32.exe", "discord.exe", "steam.exe",
	"steamwebhelper.exe", "nvcontainer.exe", "nvdisplay.container.exe", "nvidia share.exe", "nvidia overlay.exe", "rtss.exe",
	"rtsshooks", "msiafterburner.exe", "medal.exe", "gamebar.exe", "gamebarpresencewriter.exe", "xboxgamebar", "epicgameslauncher.exe",
	"fivem", "citizenfx", "explorer.exe", "taskmgr.exe", "procexp", "systeminformer.exe", "processhacker.exe", "vgc.exe", "faceitservice.exe",
	"easyanticheat", "gcac", "wallpaper64.exe", "wallpaper32.exe", "overwolf", "ow-overlay", "streamlabs", "xsplit", "nahimic",
	"amdow.exe", "radeonsoftware.exe", "logioverlay", "lghub", "razer", "corsair", "icue", "crashpad_handler.exe", "audiodg.exe",
	"searchindexer.exe", "wmiprvse.exe", "mmc.exe", "perfmon.exe", "vmmem", "shellexperiencehost.exe", "textinputhost.exe",
}

var donosDeOverlayAceitos = []string{
	"discord.exe", "steam.exe", "steamwebhelper.exe", "nvcontainer.exe", "nvidia share.exe", "nvidia overlay.exe", "rtss.exe",
	"msiafterburner.exe", "medal.exe", "gamebar.exe", "xboxgamebar", "overwolf", "ow-overlay", "wallpaper64.exe", "wallpaper32.exe",
	"explorer.exe", "shellexperiencehost.exe", "textinputhost.exe", "searchhost.exe", "startmenuexperiencehost.exe", "lockapp.exe",
	"applicationframehost.exe", "amdow.exe", "radeonsoftware.exe", "logioverlay", "lghub", "razer", "icue", "streamlabs", "obs64.exe",
	"epicgameslauncher.exe", "ea", "ubisoftconnect", "geforce", "nvspcaps64.exe", "dwm.exe", "fivem", "citizenfx", "chrome.exe", "msedge.exe",
	"crosshair", "snipping", "screenclip", "shareX", "lightshot", "flameshot", "greenshot", "powertoys", "displayfusion", "autohotkey",
}

func lowerContains(texto string, lista []string) bool {
	t := strings.ToLower(texto)
	for _, item := range lista {
		item = strings.ToLower(item)
		if strings.Contains(t, item) {
			return true
		}
		if base := strings.TrimSuffix(item, ".exe"); base != item && strings.HasPrefix(t, base) {
			return true
		}
	}
	return false
}

func caminhoDoSistema(caminho string) bool {
	c := strings.ToLower(caminho)
	return strings.Contains(c, `\windows\`) || strings.HasPrefix(c, `\systemroot`) || strings.Contains(c, `\program files`)
}

func pastaDeUsuario(caminho string) bool {
	c := strings.ToLower(caminho)
	return strings.Contains(c, `\users\`) && !strings.Contains(c, `\program files`)
}

func pastaQuente(caminho string) bool {
	c := strings.ToLower(caminho)
	for _, p := range []string{`\temp\`, `\downloads\`, `\desktop\`, `\users\public\`, `\$recycle.bin\`, `\programdata\`, `\appdata\roaming\`, `\appdata\locallow\`, `\documents\`, `\videos\`, `\pictures\`, `\music\`} {
		if strings.Contains(c, p) {
			return true
		}
	}
	return false
}

func descreveAcesso(acesso uint32) string {
	if acesso&acessoAllAccess == acessoAllAccess {
		return "ALL_ACCESS"
	}
	var partes []string
	if acesso&acessoVMRead != 0 {
		partes = append(partes, "VM_READ")
	}
	if acesso&acessoVMWrite != 0 {
		partes = append(partes, "VM_WRITE")
	}
	if acesso&acessoVMOperation != 0 {
		partes = append(partes, "VM_OPERATION")
	}
	if acesso&acessoCreateThread != 0 {
		partes = append(partes, "CREATE_THREAD")
	}
	if len(partes) == 0 {
		return fmt.Sprintf("0x%X", acesso)
	}
	return strings.Join(partes, "|") + fmt.Sprintf(" (0x%X)", acesso)
}

func avaliarProcesso(info InfoProcesso, a *Assinaturas, agora time.Time) []Sinal {
	var sinais []Sinal
	nome := strings.ToLower(info.Nome)
	if strings.HasPrefix(nome, "scanner") {
		return nil
	}
	base := strings.ToLower(nomeBase(info.Caminho))
	textoCompleto := strings.Join([]string{info.Nome, info.Caminho, info.OriginalFilename, info.ProductName, info.CompanyName, info.FileDescription}, " ")
	rotulo := fmt.Sprintf("%s (PID %d)", info.Nome, info.PID)
	local := info.Caminho
	if local == "" {
		local = "(caminho nao acessivel)"
	}

	if classe, t := a.Classificar(textoCompleto); classe != SemMatch {
		sev := classe.Severidade()
		sinais = append(sinais, Sinal{sev, fmt.Sprintf("Processo RODANDO bate com assinatura '%s': %s", t, rotulo), local + "\nDescricao: " + info.FileDescription + "  Produto: " + info.ProductName + "  Empresa: " + info.CompanyName, "cheat"})
	}

	if pastaEsperada, ok := a.ProcessosSistema[nome]; ok && info.CaminhoLido {
		c := strings.ToLower(info.Caminho)
		if pastaEsperada == "" {
			sinais = append(sinais, Sinal{Critico, "Processo com nome IMITANDO processo do Windows: " + rotulo, local + "\nEsse nome nao existe no Windows, e uma imitacao (typosquat) usada por loader de cheat", "cheat"})
		} else if !strings.Contains(c, `\`+pastaEsperada+`\`) && !strings.HasSuffix(c, `\`+pastaEsperada) {
			sinais = append(sinais, Sinal{Critico, "Processo se passando por processo do Windows: " + rotulo, local + "\nO " + info.Nome + " legitimo fica em C:\\" + strings.ReplaceAll(pastaEsperada, "\\", "\\") + ". Rodar de outra pasta e ocultacao classica", "cheat"})
		}
	}

	if info.CaminhoLido && info.Caminho != "" && !info.ExisteNoDisco {
		sinais = append(sinais, Sinal{Critico, "Executavel APAGADO enquanto ainda roda: " + rotulo, local + "\nO arquivo nao existe mais no disco mas o processo continua. Loader de cheat se apaga depois de injetar para nao deixar rastro", "cheat"})
	}

	if info.CaminhoLido && info.OriginalFilename != "" && nomeOriginalDiverge(base, info.OriginalFilename) {
		if classe, t := a.Classificar(info.OriginalFilename + " " + info.ProductName + " " + info.FileDescription); classe != SemMatch {
			sinais = append(sinais, Sinal{Critico, fmt.Sprintf("Ferramenta '%s' RENOMEADA para %s", t, rotulo), local + "\nNome original no executavel: " + info.OriginalFilename + "  Produto: " + info.ProductName + "\nRenomear o exe e a forma mais comum de esconder cheat/injetor de quem olha a lista de processos", "cheat"})
		} else if pastaQuente(info.Caminho) && !strings.EqualFold(info.Assinatura, "Valid") {
			sinais = append(sinais, Sinal{Alerta, "Executavel renomeado rodando de pasta de usuario sem assinatura: " + rotulo, local + "\nNome original gravado no arquivo: " + info.OriginalFilename + "  Produto: " + info.ProductName + "  Empresa: " + info.CompanyName, "suspeito"})
		}
	}

	if motivo := caminhoSuspeito(info.Caminho); motivo != "" {
		sinais = append(sinais, Sinal{Alerta, "Processo " + motivo + ": " + rotulo, local, "suspeito"})
	}

	switch strings.ToLower(info.Assinatura) {
	case "hashmismatch":
		sinais = append(sinais, Sinal{Critico, "Executavel ASSINADO MAS ALTERADO (hash nao confere): " + rotulo, local + "\nO arquivo foi modificado depois de assinado. Padrao de exe legitimo com cheat embutido (patch)", "cheat"})
	case "notsigned":
		if pastaQuente(info.Caminho) {
			sinais = append(sinais, Sinal{Alerta, "Executavel SEM assinatura digital rodando de pasta de usuario: " + rotulo, local + "\nPrograma serio costuma ser assinado. Sem assinatura em Temp/Downloads/Desktop/Roaming e tipico de loader", "suspeito"})
		}
	}

	pai := strings.ToLower(info.PaiNome)
	if esperados, ok := paisEsperados[nome]; ok && info.PaiNome != "" && caminhoDoSistema(info.Caminho) {
		aceito := false
		for _, e := range esperados {
			if e == pai {
				aceito = true
			}
		}
		if !aceito {
			sinais = append(sinais, Sinal{Critico, fmt.Sprintf("%s foi iniciado por %s, e nao por %s", rotulo, info.PaiNome, strings.Join(esperados, "/")), local + "\nProcesso de sistema com pai errado = alguem lancou uma copia dele. Truque de injetor para parecer legitimo", "cheat"})
		}
	}
	if strings.Contains(pai, "gtaprocess") && !strings.Contains(nome, "fivem") && !strings.Contains(nome, "citizenfx") {
		sev := Alerta
		if nome == "cmd.exe" || nome == "powershell.exe" || nome == "wscript.exe" || nome == "cscript.exe" || nome == "rundll32.exe" || nome == "regsvr32.exe" || nome == "mshta.exe" {
			sev = Critico
		}
		sinais = append(sinais, Sinal{sev, "Processo iniciado DE DENTRO do FiveM: " + rotulo, local + "\nO FiveM nao abre programas externos. Um processo filho do jogo nasce de codigo injetado", "cheat"})
	}

	if t := a.ControleRemotoAtivo(nome + " " + info.Caminho + " " + info.FileDescription); t != "" {
		sinais = append(sinais, Sinal{Alerta, "Controle remoto ATIVO durante a checagem: " + rotulo, local + "\nFerramenta '" + t + "' rodando. Outra pessoa pode estar operando o PC ou o jogador pode estar mostrando um PC que nao e o dele", "suspeito"})
	}

	if !info.CriadoEm.IsZero() && agora.Sub(info.CriadoEm) < 15*time.Minute && agora.Sub(info.CriadoEm) > 0 {
		if classe, t := a.Classificar(textoCompleto); classe == ClasseLimpeza {
			sinais = append(sinais, Sinal{Critico, fmt.Sprintf("Limpador '%s' aberto %s antes da checagem: %s", t, agora.Sub(info.CriadoEm).Round(time.Second), rotulo), local, "cheat"})
		}
	}
	return sinais
}

func avaliarHandlesNoFiveM(handles []HandleNoFiveM, a *Assinaturas) []Sinal {
	var sinais []Sinal
	vistos := map[int]bool{}
	for _, h := range handles {
		if vistos[h.DonoPID] {
			continue
		}
		vistos[h.DonoPID] = true
		nome := strings.ToLower(h.DonoNome)
		if strings.HasPrefix(nome, "scanner") || h.DonoPID <= 4 {
			continue
		}
		rotulo := fmt.Sprintf("%s (PID %d)", h.DonoNome, h.DonoPID)
		acesso := descreveAcesso(h.Acesso)
		if classe, t := a.Classificar(h.DonoNome + " " + h.DonoCaminho); classe != SemMatch {
			sinais = append(sinais, Sinal{Critico, fmt.Sprintf("'%s' tem handle aberto na memoria do FiveM: %s", t, rotulo), h.DonoCaminho + "\nAcesso: " + acesso, "cheat"})
			continue
		}
		if lowerContains(nome, donosDeHandleAceitos) || caminhoDoSistema(h.DonoCaminho) {
			continue
		}
		escreve := h.Acesso&(acessoVMWrite|acessoVMOperation|acessoCreateThread) != 0 || h.Acesso&acessoAllAccess == acessoAllAccess
		le := h.Acesso&acessoVMRead != 0
		switch {
		case escreve:
			sinais = append(sinais, Sinal{Critico, "Processo com acesso de ESCRITA na memoria do FiveM: " + rotulo, h.DonoCaminho + "\nAcesso: " + acesso + "\nE assim que cheat externo injeta e altera o jogo. Overlay e gravador so precisam de leitura, e mesmo assim sao de fabricante conhecido", "cheat"})
		case le:
			sinais = append(sinais, Sinal{Alerta, "Processo desconhecido LENDO a memoria do FiveM: " + rotulo, h.DonoCaminho + "\nAcesso: " + acesso + "\nESP externo funciona so lendo memoria. Conferir o que e esse programa", "suspeito"})
		}
	}
	return sinais
}

func avaliarJanelas(janelas []JanelaVista, larguraTela, alturaTela int, a *Assinaturas) []Sinal {
	var sinais []Sinal
	vistos := map[string]bool{}
	for _, j := range janelas {
		nome := strings.ToLower(j.DonoNome)
		if strings.HasPrefix(nome, "scanner") {
			continue
		}
		texto := j.Titulo + " " + j.Classe
		chave := fmt.Sprintf("%d|%s|%s", j.PID, j.Titulo, j.Classe)
		if vistos[chave] {
			continue
		}
		vistos[chave] = true
		rotulo := fmt.Sprintf("%s (PID %d)", j.DonoNome, j.PID)
		if classe, t := a.Classificar(texto); classe != SemMatch && strings.TrimSpace(j.Titulo) != "" {
			sinais = append(sinais, Sinal{Critico, fmt.Sprintf("Janela com nome de cheat ('%s') aberta por %s", t, rotulo), "Titulo: " + j.Titulo + "  Classe: " + j.Classe + "\n" + j.DonoCaminho, "cheat"})
			continue
		}
		if !j.Visivel {
			continue
		}
		conhecido := lowerContains(nome, donosDeOverlayAceitos) || caminhoDoSistema(j.DonoCaminho)
		if conhecido {
			continue
		}
		local := fmt.Sprintf("Titulo: %q  Classe: %s  %dx%d em (%d,%d)\n%s", j.Titulo, j.Classe, j.Largura, j.Altura, j.X, j.Y, j.DonoCaminho)
		grande := larguraTela > 0 && alturaTela > 0 && j.Largura >= larguraTela*8/10 && j.Altura >= alturaTela*8/10
		sobreposta := j.Layered && j.Transparente
		switch {
		case sobreposta && j.Topmost && grande:
			sinais = append(sinais, Sinal{Critico, "Janela OVERLAY transparente cobrindo a tela inteira: " + rotulo, local + "\nJanela invisivel ao clique, sempre no topo e do tamanho da tela e exatamente como ESP externo desenha por cima do jogo", "cheat"})
		case sobreposta && miraSobrepostaNaTela(j, larguraTela, alturaTela):
			sev := Alerta
			if j.Topmost || j.ForaDaCaptura {
				sev = Critico
			}
			sinais = append(sinais, Sinal{sev, "Janela pequena e transparente parada no centro da tela: " + rotulo, local + "\n" + notaDeMiraSobreposta(j), "cheat"})
		case j.ForaDaCaptura:
			sinais = append(sinais, Sinal{Critico, "Janela que se esconde de gravacao e print: " + rotulo, local + "\nEssa janela pediu ao Windows para nao aparecer em captura de tela (WDA_EXCLUDEFROMCAPTURE). Programa serio quase nunca faz isso; overlay de mira faz, e anuncia como recurso, justamente para nao aparecer na telagem", "cheat"})
		}
	}
	return sinais
}

type DispositivoVisto struct {
	Classe     string
	Descricao  string
	HardwareID string
	Presente   bool
}

func avaliarDispositivos(dispositivos []DispositivoVisto, a *Assinaturas) []Sinal {
	var sinais []Sinal
	vistos := map[string]bool{}
	for _, d := range dispositivos {
		texto := d.Descricao + " " + d.HardwareID
		chave := strings.ToLower(texto)
		if vistos[chave] {
			continue
		}
		vistos[chave] = true
		estado := "conectado agora"
		if !d.Presente {
			estado = "ja foi conectado (nao esta agora)"
		}
		if t := a.HardwareDMASuspeito(texto); t != "" {
			sev := Critico
			if !d.Presente {
				sev = Alerta
			}
			sinais = append(sinais, Sinal{sev, fmt.Sprintf("Placa DMA/FPGA detectada ('%s'): %s", t, d.Descricao), d.HardwareID + "\n" + estado + "\nPlaca DMA le a memoria do jogo de um segundo PC. Nao existe uso comum disso em PC gamer", "cheat"})
			continue
		}
		if t := a.HardwareEntradaSuspeito(texto); t != "" {
			sev := Alerta
			if d.Presente {
				sev = Critico
			}
			sinais = append(sinais, Sinal{sev, fmt.Sprintf("Dispositivo de aim assist/macro ('%s'): %s", t, d.Descricao), d.HardwareID + "\n" + estado + "\nKMBox, MAKCU, Xim, Cronus e Arduino Leonardo emulam mouse para aimbot por hardware", "cheat"})
		}
	}
	return sinais
}

func ordenaSinais(sinais []Sinal) []Sinal {
	sort.SliceStable(sinais, func(i, j int) bool { return sinais[i].Severidade > sinais[j].Severidade })
	return sinais
}

func piorSituacao(sinais []Sinal) string {
	situacao := ""
	for _, s := range sinais {
		if s.Situacao == "cheat" {
			return "cheat"
		}
		if s.Situacao == "suspeito" {
			situacao = "suspeito"
		}
	}
	return situacao
}

func normalizaNomeDeExe(nome string) string {
	nome = strings.ToLower(strings.TrimSuffix(nome, filepath.Ext(nome)))
	var b strings.Builder
	for _, c := range nome {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			b.WriteRune(c)
		}
	}
	return b.String()
}

func nomeOriginalDiverge(base, original string) bool {
	orig := strings.ToLower(strings.TrimSpace(original))
	ext := filepath.Ext(orig)
	if ext != ".exe" && ext != ".dll" && ext != ".com" && ext != ".scr" {
		return false
	}
	if nomesOriginaisAceitos[orig] {
		return false
	}
	a := normalizaNomeDeExe(base)
	b := normalizaNomeDeExe(orig)
	if a == "" || b == "" || a == b {
		return false
	}
	return !strings.Contains(a, b) && !strings.Contains(b, a)
}

func miraSobrepostaNaTela(j JanelaVista, larguraTela, alturaTela int) bool {
	if larguraTela <= 0 || alturaTela <= 0 || j.Largura <= 0 || j.Altura <= 0 {
		return false
	}
	if j.Largura > 260 || j.Altura > 260 {
		return false
	}
	distancia := func(a, b int) int {
		if a > b {
			return a - b
		}
		return b - a
	}
	return distancia(j.X+j.Largura/2, larguraTela/2) <= larguraTela/20 &&
		distancia(j.Y+j.Altura/2, alturaTela/2) <= alturaTela/20
}

func notaDeMiraSobreposta(j JanelaVista) string {
	nota := "Janela pequena, invisivel ao clique e parada exatamente no centro da tela e o formato de uma mira desenhada por fora do jogo. Miras externas usam janela de 32 a 40 pixels no centro. Isso devolve ao jogador a mira que a cidade esconde quando ele nao esta mirando, e nao aparece em Game Capture do OBS nem no print do servidor"
	if j.ForaDaCaptura {
		nota += "\nEsta janela ainda pediu para nao aparecer em captura de tela"
	}
	if !j.Topmost {
		nota += "\nEla nao usa a marca de sempre-no-topo, que e a forma conhecida de escapar de checagem de overlay"
	}
	return nota
}
