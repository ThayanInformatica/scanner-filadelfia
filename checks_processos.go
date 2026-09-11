//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var pastasConhecidasDeModulos = []string{
	`\windows\`, `fivem.app`, `\program files`, `\discord`, `\nvidia`, `\steam`, `\obs`, `\rivatuner`, `\medal`,
	`\overwolf`, `\amd\`, `\intel\`, `\logitech`, `\razer`, `\corsair`, `\msi\`, `\asus`, `\realtek`, `\citrix`,
	`\appdata\local\programs\`, `\appdata\local\microsoft\`, `\programdata\microsoft\`, `\wallpaper engine`,
	`\citizenfx`, `\cfx`, `\epic games`, `\rockstar games`, `\nahimic`, `\sonic`, `\xsplit`, `\streamlabs`,
}

func checarProcessos(c *Contexto) {
	r := c.R
	r.Secao("PROCESSOS EM EXECUCAO (analise ponto a ponto)")

	processos, err := listarProcessos()
	if err != nil {
		r.Erro("listar processos: %v", err)
		return
	}
	r.Linha("%d processos em execucao", len(processos))
	c.AoVivo.ProcessosListados = len(processos)
	agora := time.Now()

	porPID := map[uint32]Processo{}
	for _, p := range processos {
		porPID[p.PID] = p
	}

	r.Progresso("Lendo versao, assinatura e hora de criacao de %d processos", len(processos))
	infos := make([]InfoProcesso, 0, len(processos))
	var candidatosAssinatura []string
	vistoCaminho := map[string]bool{}
	for _, p := range processos {
		info := InfoProcesso{PID: int(p.PID), Nome: p.Nome, Caminho: p.Caminho, PaiPID: int(p.PaiPID), CaminhoLido: p.Caminho != "", CriadoEm: horaDeCriacao(p.PID)}
		if pai, ok := porPID[p.PaiPID]; ok && p.PaiPID != 0 {
			info.PaiNome = pai.Nome
			info.PaiCaminho = pai.Caminho
		}
		if p.Caminho != "" {
			_, errStat := os.Stat(p.Caminho)
			info.ExisteNoDisco = errStat == nil
			if info.ExisteNoDisco {
				info.OriginalFilename, info.ProductName, info.CompanyName, info.FileDescription = infoDeVersao(p.Caminho)
				lower := strings.ToLower(p.Caminho)
				if !caminhoDoSistema(p.Caminho) && !vistoCaminho[lower] && len(candidatosAssinatura) < 400 {
					vistoCaminho[lower] = true
					candidatosAssinatura = append(candidatosAssinatura, p.Caminho)
				}
			}
		}
		infos = append(infos, info)
	}

	r.Progresso("Conferindo assinatura digital de %d executaveis fora do Windows", len(candidatosAssinatura))
	assinaturas := assinaturasAuthenticode(candidatosAssinatura)
	c.AssinaturasDeProcessos = assinaturas
	for i := range infos {
		if v, ok := assinaturas[strings.ToLower(infos[i].Caminho)]; ok {
			infos[i].Assinatura = v[0]
			infos[i].Assinante = v[1]
		}
	}

	var fivem []Processo
	var recentes []string
	var semAssinatura []string
	var protegidos []string
	var renomeados []string
	repetidos := map[string]int{}
	totalSinais := 0
	for _, info := range infos {
		nome := strings.ToLower(info.Nome)
		if ehOProprioScanner(info.Caminho, info.PID) {
			continue
		}
		sinais := avaliarProcesso(info, c.A, agora)
		for _, s := range sinais {
			chave := s.Severidade.String() + "|" + strings.ToLower(info.Nome) + "|" + primeiraParte(s.Titulo)
			if repetidos[chave] > 0 {
				repetidos[chave]++
				continue
			}
			repetidos[chave] = 1
			r.Add(s.Severidade, s.Titulo, s.Detalhe)
		}
		totalSinais += len(sinais)
		situacao := piorSituacao(sinais)
		if situacao == "" && strings.Contains(nome, "fivem") {
			situacao = "fivem"
		}
		r.Processo(info.PID, info.Nome, info.Caminho, situacao, info.PaiNome)
		if strings.HasPrefix(nome, "fivem") && strings.Contains(nome, "gtaprocess") && !info.CriadoEm.IsZero() {
			c.JogoAbriuEm = info.CriadoEm
		}
		if nome == "taskmgr.exe" && info.CriadoEm.After(c.TaskmgrAbertoEm) {
			c.TaskmgrAbertoEm = info.CriadoEm
		}
		if strings.HasPrefix(nome, "fivem") && strings.Contains(nome, "gtaprocess") {
			fivem = append(fivem, porPID[uint32(info.PID)])
		}
		if !info.CriadoEm.IsZero() && agora.Sub(info.CriadoEm) < 15*time.Minute && agora.Sub(info.CriadoEm) > 0 && situacao == "" {
			recentes = append(recentes, fmt.Sprintf("%s  %s  %s", formataHora(info.CriadoEm), info.Nome, info.Caminho))
		}
		if !info.CaminhoLido && info.PID > 4 && !processosProtegidosConhecidos[nome] {
			protegidos = append(protegidos, fmt.Sprintf("%s (PID %d)", info.Nome, info.PID))
		}
		if info.OriginalFilename != "" && nomeOriginalDiverge(strings.ToLower(filepath.Base(info.Caminho)), info.OriginalFilename) && situacao == "" {
			renomeados = append(renomeados, fmt.Sprintf("%s  <- %s  (%s)", info.Nome, info.OriginalFilename, info.ProductName))
		}
		if strings.EqualFold(info.Assinatura, "NotSigned") && info.CaminhoLido && !pastaQuente(info.Caminho) && situacao == "" {
			semAssinatura = append(semAssinatura, info.Nome+"  "+info.Caminho)
		}
	}
	if totalSinais == 0 {
		r.Ok("Nenhum processo com nome de cheat, imitando o Windows, apagado, renomeado, adulterado ou fora de lugar")
	}
	sort.Strings(recentes)
	if len(recentes) > 0 {
		r.Add(Info, fmt.Sprintf("Processos iniciados nos 15 minutos antes da checagem: %d", len(recentes)), strings.Join(limitaLinhas(recentes, 100), "\n"))
	}
	sort.Strings(protegidos)
	if len(protegidos) > 0 {
		r.Add(Info, fmt.Sprintf("Processos que negaram a leitura do caminho: %d", len(protegidos)), strings.Join(limitaLinhas(protegidos, 120), "\n")+"\nNormal em antivirus, anticheat, servicos de banco e processos de outro usuario. So interessa cruzado com outro indicio")
	}
	sort.Strings(renomeados)
	if len(renomeados) > 0 {
		r.Add(Info, fmt.Sprintf("Executaveis com nome diferente do original: %d", len(renomeados)), strings.Join(limitaLinhas(renomeados, 120), "\n")+"\nComum em fabricantes que reaproveitam o mesmo binario (NVIDIA, Razer, Realtek). Vira alerta quando roda de pasta de usuario sem assinatura")
	}
	if len(semAssinatura) > 0 {
		r.Add(Info, fmt.Sprintf("Executaveis sem assinatura digital rodando (fora de pastas quentes): %d", len(semAssinatura)), strings.Join(limitaLinhas(semAssinatura, 100), "\n"))
	}

	checarProcessosOcultos(c, porPID)

	if len(fivem) == 0 {
		c.JogoFechado = true
		r.Add(Alerta, "O FiveM NAO estava aberto durante a checagem", "Cinco checagens dependem do jogo rodando e ficaram de fora deste relatorio:\n  1. dll injetada na lista de modulos do jogo\n  2. cheat externo com a memoria do jogo aberta (handles)\n  3. codigo carregado na marra dentro do jogo (manual map)\n  4. string de cheat na memoria do jogo\n  5. janela de overlay desenhada por cima do jogo\nRefaca a telagem com o jogador dentro da cidade. Sem isso, um cheat ativo agora passaria despercebido")
	}
	for _, p := range fivem {
		checarModulosDoFiveM(c, p)
		checarHandlesNoFiveM(c, p, porPID)
	}
	checarJanelas(c, porPID)
	checarDrivers(c)
}

func checarProcessosOcultos(c *Contexto, toolhelp map[uint32]Processo) {
	r := c.R
	viaEnum := pidsViaEnumProcesses()
	viaNt := pidsViaNtQuery()
	var suspeitos []uint32
	for pid := range viaNt {
		if pid == 0 {
			continue
		}
		if _, ok := toolhelp[pid]; !ok {
			suspeitos = append(suspeitos, pid)
		}
	}
	for pid := range viaEnum {
		if pid == 0 {
			continue
		}
		if _, ok := toolhelp[pid]; !ok {
			suspeitos = append(suspeitos, pid)
		}
	}
	if len(suspeitos) == 0 {
		r.Ok("Lista de processos consistente entre Toolhelp, EnumProcesses e NtQuerySystemInformation (nada escondido)")
		return
	}
	segunda, err := listarProcessos()
	if err != nil {
		return
	}
	ainda := map[uint32]bool{}
	for _, p := range segunda {
		ainda[p.PID] = true
	}
	vistos := map[uint32]bool{}
	for _, pid := range suspeitos {
		if vistos[pid] || ainda[pid] {
			continue
		}
		vistos[pid] = true
		if viaNt[pid] && viaEnum[pid] {
			r.Add(Critico, fmt.Sprintf("Processo OCULTO da lista normal (PID %d)", pid), "O PID aparece pelo kernel (NtQuerySystemInformation e EnumProcesses) mas nao pelo Toolhelp usado pelo Gerenciador de Tarefas. Rootkit ou cheat escondendo o proprio processo. Caminho: "+caminhoDoProcesso(pid))
		}
	}
}

func checarModulosDoFiveM(c *Contexto, p Processo) {
	r := c.R
	modulos, err := listarModulos(p.PID)
	if err != nil {
		r.Erro("modulos do FiveM (PID %d): %v", p.PID, err)
		return
	}
	r.Linha("FiveM %s (PID %d) com %d modulos carregados", p.Nome, p.PID, len(modulos))
	c.AoVivo.JogoAberto = true
	c.AoVivo.NomeDoJogo = p.Nome
	c.AoVivo.PIDDoJogo = int(p.PID)
	c.AoVivo.ModulosDoJogo = len(modulos)
	estranhos := 0
	for _, m := range modulos {
		if classe, t := c.A.Classificar(m.Nome + " " + m.Caminho); classe != SemMatch {
			r.Add(Critico, "Modulo INJETADO no FiveM bate com assinatura '"+t+"': "+m.Nome, m.Caminho)
			r.Modulo(int(p.PID), m.Nome, m.Caminho, "cheat")
			continue
		}
		lower := strings.ToLower(m.Caminho)
		conhecido := false
		for _, pasta := range pastasConhecidasDeModulos {
			if strings.Contains(lower, pasta) {
				conhecido = true
				break
			}
		}
		if _, err := os.Stat(m.Caminho); err != nil && m.Caminho != "" {
			estranhos++
			r.Add(Critico, "Modulo no FiveM cujo arquivo foi APAGADO do disco: "+m.Nome, m.Caminho+"\nA dll continua na memoria do jogo mas o arquivo sumiu. Injetor apaga a dll depois de carregar")
			r.Modulo(int(p.PID), m.Nome, m.Caminho, "cheat")
			continue
		}
		if !conhecido {
			estranhos++
			r.Add(Alerta, "Modulo carregado no FiveM de pasta fora do padrao: "+m.Nome, m.Caminho)
			r.Modulo(int(p.PID), m.Nome, m.Caminho, "suspeito")
		} else if pareceNomeAleatorio(m.Nome) {
			estranhos++
			r.Add(Alerta, "Modulo com nome aleatorio carregado no FiveM: "+m.Nome, m.Caminho)
			r.Modulo(int(p.PID), m.Nome, m.Caminho, "suspeito")
		} else {
			r.Modulo(int(p.PID), m.Nome, m.Caminho, "")
		}
	}
	c.AoVivo.ModulosDesconhecidos = estranhos
	if estranhos == 0 {
		r.Ok("Nenhum modulo de pasta desconhecida no FiveM (PID %d). Cheats com manual map nao aparecem aqui", p.PID)
	}
}

func checarHandlesNoFiveM(c *Contexto, p Processo, porPID map[uint32]Processo) {
	r := c.R
	r.Progresso("Procurando processos com handle aberto no FiveM (PID %d)", p.PID)
	handles, err := handlesAbertosNoProcesso(p.PID)
	if err != nil {
		r.Erro("handles no FiveM: %v", err)
		return
	}
	for i := range handles {
		dono := porPID[uint32(handles[i].DonoPID)]
		handles[i].DonoNome = dono.Nome
		handles[i].DonoCaminho = dono.Caminho
		if handles[i].DonoNome == "" {
			handles[i].DonoNome = fmt.Sprintf("PID %d", handles[i].DonoPID)
		}
	}
	r.Linha("%d handle(s) de outros processos apontando para o FiveM", len(handles))
	c.AoVivo.HandlesNoJogo = len(handles)
	sinais := avaliarHandlesNoFiveM(handles, c.A)
	c.AoVivo.HandlesComEscrita = len(sinais)
	for _, s := range sinais {
		r.Add(s.Severidade, s.Titulo, s.Detalhe)
	}
	if len(sinais) == 0 {
		r.Ok("Nenhum processo desconhecido com a memoria do FiveM aberta (cheat externo nao detectado)")
	}
	var lista []string
	vistos := map[int]bool{}
	for _, h := range handles {
		if vistos[h.DonoPID] {
			continue
		}
		vistos[h.DonoPID] = true
		lista = append(lista, fmt.Sprintf("%s (PID %d)  %s  %s", h.DonoNome, h.DonoPID, descreveAcesso(h.Acesso), h.DonoCaminho))
	}
	if len(lista) > 0 {
		r.Add(Info, fmt.Sprintf("Processos com handle no FiveM: %d", len(lista)), strings.Join(limitaLinhas(lista, 120), "\n"))
	}
}

func checarJanelas(c *Contexto, porPID map[uint32]Processo) {
	r := c.R
	janelas := janelasAbertas()
	for i := range janelas {
		dono := porPID[uint32(janelas[i].PID)]
		janelas[i].DonoNome = dono.Nome
		janelas[i].DonoCaminho = dono.Caminho
	}
	w, h := tamanhoDaTela()
	sinais := avaliarJanelas(janelas, w, h, c.A)
	c.AoVivo.JanelasAnalisadas = len(janelas)
	c.AoVivo.OverlaysAcusados = len(sinais)
	for _, s := range sinais {
		r.Add(s.Severidade, s.Titulo, s.Detalhe)
	}
	if len(sinais) == 0 {
		r.Ok("Nenhuma janela overlay desconhecida nem janela com nome de cheat (%d janelas, tela %dx%d)", len(janelas), w, h)
	}
}

func checarDrivers(c *Contexto) {
	r := c.R
	r.Secao("DRIVERS DE KERNEL CARREGADOS")
	drivers, err := listarDrivers()
	if err != nil {
		r.Erro("listar drivers: %v", err)
		return
	}
	r.Linha("%d drivers carregados", len(drivers))
	c.AoVivo.DriversCarregados = len(drivers)
	problemas := 0
	defer func() { c.AoVivo.DriversAcusados = problemas }()
	for _, d := range drivers {
		base := strings.ToLower(filepath.Base(d))
		lower := strings.ToLower(d)
		foraDoSistema := !strings.Contains(lower, `\systemroot\`) && !strings.Contains(lower, `\windows\`) && !strings.Contains(lower, `\program files`)
		classe, termo := c.A.Classificar(base)
		hashRotulo := ""
		if arquivo := caminhoRealDoDriver(d); arquivo != "" {
			if h := sha256DoArquivo(arquivo, 32*1024*1024); h != "" {
				hashRotulo = c.A.HashConhecido(h)
			}
		}
		switch {
		case hashRotulo != "":
			problemas++
			sevHash, notaHash, _ := severidadeDeHashDeDriver(hashRotulo, d)
			r.Add(sevHash, "Driver carregado com HASH conhecido: "+base, d+"\nBate com: "+hashRotulo+"\nHash de driver vulneravel ou malicioso da base publica. O nome pode ter sido trocado, o hash nao"+notaHash)
		case c.A.DriverVulneravel(base) && foraDoSistema:
			problemas++
			r.Add(Critico, "Driver VULNERAVEL carregado de fora do sistema: "+base, d+"\nDriver da lista BYOVD carregado de pasta fora do Windows/Program Files. Padrao de mapeador de cheat")
		case c.A.DriverVulneravel(base):
			problemas++
			r.Add(Alerta, "Driver VULNERAVEL carregado: "+base, d+"\nDrivers dessa lista sao abusados por kdmapper e afins para injetar cheat no kernel, mas tambem vem de utilitarios de hardware (MSI Afterburner, CPU-Z, HWiNFO). Conferir se o programa dono esta instalado")
		case classe != SemMatch:
			problemas++
			r.Add(Critico, "Driver carregado bate com assinatura '"+termo+"': "+base, d)
		case foraDoSistema && (strings.Contains(lower, `\cpuid software\`) || strings.Contains(lower, `\cpuid\`)):
			r.Add(Info, "Driver do CPU-Z/HWMonitor com nome aleatorio: "+base, d+"\nA CPUID gera um nome novo a cada instalacao. Comportamento normal do CPU-Z e do HWMonitor")
		case foraDoSistema:
			problemas++
			r.Add(Alerta, "Driver carregado de pasta fora do sistema: "+base, d)
		case pareceNomeAleatorio(base):
			problemas++
			r.Add(Alerta, "Driver com nome aleatorio carregado: "+base, d)
		}
	}
	if problemas == 0 {
		r.Ok("Nenhum driver vulneravel ou fora de lugar carregado. Drivers mapeados manualmente (kdmapper) nao aparecem nesta lista")
	}
}

func caminhoRealDoDriver(caminho string) string {
	lower := strings.ToLower(caminho)
	raiz := os.Getenv("SystemRoot")
	switch {
	case strings.HasPrefix(lower, `\systemroot\`):
		return filepath.Join(raiz, caminho[len(`\systemroot\`):])
	case strings.HasPrefix(lower, `\??\`):
		return caminho[4:]
	case strings.HasPrefix(lower, `system32\`):
		return filepath.Join(raiz, caminho)
	case len(caminho) > 2 && caminho[1] == ':':
		return caminho
	}
	return ""
}
