package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

type RegiaoDeMemoria struct {
	Base       uint64
	Tamanho    uint64
	Protecao   string
	Tipo       string
	Privada    bool
	Executavel bool
}

type AchadoDeMemoria struct {
	Regiao     RegiaoDeMemoria
	TemPE      bool
	Termos     []string
	Contexto   string
	Assinatura string
}

func temCabecalhoPE(dados []byte) bool {
	for i := 0; i+0x40 < len(dados) && i < 0x2000; i++ {
		if dados[i] != 'M' || dados[i+1] != 'Z' {
			continue
		}
		off := int(uint32(dados[i+0x3c]) | uint32(dados[i+0x3d])<<8 | uint32(dados[i+0x3e])<<16 | uint32(dados[i+0x3f])<<24)
		p := i + off
		if off > 0 && off < 0x1000 && p+4 < len(dados) && dados[p] == 'P' && dados[p+1] == 'E' && dados[p+2] == 0 && dados[p+3] == 0 {
			return true
		}
	}
	return false
}

func analisarRegiao(regiao RegiaoDeMemoria, dados []byte, buscador *Buscador) *AchadoDeMemoria {
	achado := AchadoDeMemoria{Regiao: regiao}
	achado.TemPE = temCabecalhoPE(dados)
	vistos := map[string]bool{}
	buscador.Procurar(dados, func(o Ocorrencia) bool {
		if vistos[o.Termo] {
			return true
		}
		vistos[o.Termo] = true
		achado.Termos = append(achado.Termos, o.Termo)
		if achado.Contexto == "" {
			achado.Contexto = trechoEmVolta(dados, o.Inicio, o.Fim, o.UTF16)
		}
		return len(vistos) < 5
	})
	sort.Strings(achado.Termos)
	if !achado.TemPE && len(achado.Termos) == 0 && regiao.Protecao != "RWX" {
		return nil
	}
	return &achado
}

func avaliarMemoriaDoJogo(achados []AchadoDeMemoria, totalRegioes int, processo string) []Sinal {
	var sinais []Sinal
	var comPE, rwx int
	for _, a := range achados {
		rotulo := fmt.Sprintf("0x%X (%d KB, %s, %s)", a.Regiao.Base, a.Regiao.Tamanho/1024, a.Regiao.Protecao, a.Regiao.Tipo)
		switch {
		case len(a.Termos) > 0:
			detalhe := "Regiao " + rotulo + " dentro de " + processo
			if a.Contexto != "" {
				detalhe += "\n..." + a.Contexto + "..."
			}
			detalhe += "\nA string esta na memoria do jogo agora. Isso vale mesmo que o programa do cheat ja tenha sido fechado, porque a dll injetada continua carregada"
			sinais = append(sinais, Sinal{Critico, fmt.Sprintf("String de cheat '%s' NA MEMORIA do jogo", a.Termos[0]), detalhe, "cheat"})
		case a.TemPE:
			comPE++
		case a.Regiao.Protecao == "RWX" && a.Regiao.Tamanho >= 64*1024:
			rwx++
		}
	}
	if comPE > 0 {
		sinais = append(sinais, Sinal{Critico, fmt.Sprintf("%d modulo(s) carregado(s) na marra dentro de %s (manual map)", comPE, processo), "Foram encontradas regioes de memoria privadas, executaveis e com cabecalho de programa (PE) que nao correspondem a nenhuma dll registrada.\nE assim que kdmapper e injetores modernos carregam cheat: a dll roda dentro do jogo sem aparecer na lista de modulos e sem precisar de arquivo no disco.\nFechar o programa do cheat pelo Gerenciador de Tarefas nao remove isso", "cheat"})
	}
	if rwx > 0 {
		sinais = append(sinais, Sinal{Alerta, fmt.Sprintf("%d regiao(oes) de memoria gravavel e executavel (RWX) em %s", rwx, processo), "Memoria que pode ser escrita e executada ao mesmo tempo e rara em programa normal e comum em codigo injetado. Motores de script (V8, Lua JIT) tambem usam, entao sozinho nao prova nada", "suspeito"})
	}
	if len(sinais) == 0 {
		return nil
	}
	return ordenaSinais(sinais)
}

type EventoDeExecucao struct {
	Caminho string
	Quando  time.Time
	Fonte   string
}

func avaliarLinhaDoTempo(jogoAbriuEm time.Time, agora time.Time, eventos []EventoDeExecucao, a *Assinaturas) []Sinal {
	if jogoAbriuEm.IsZero() {
		return nil
	}
	var durante []string
	var cheatDurante []string
	vistos := map[string]bool{}
	for _, e := range eventos {
		if e.Quando.IsZero() || e.Quando.Before(jogoAbriuEm) || e.Quando.After(agora) {
			continue
		}
		base := strings.ToLower(nomeBase(e.Caminho))
		if strings.HasPrefix(base, "scanner") || vistos[base] {
			continue
		}
		vistos[base] = true
		linha := fmt.Sprintf("%s  %s  (%s)", formataHora(e.Quando), e.Caminho, e.Fonte)
		if classe, t := a.Classificar(e.Caminho); classe != SemMatch {
			cheatDurante = append(cheatDurante, "["+t+"] "+linha)
			continue
		}
		if caminhoDoSistema(e.Caminho) {
			continue
		}
		durante = append(durante, linha)
	}
	sort.Strings(cheatDurante)
	sort.Strings(durante)

	var sinais []Sinal
	if len(cheatDurante) > 0 {
		sinais = append(sinais, Sinal{Critico, fmt.Sprintf("%d programa(s) com nome de cheat rodaram DEPOIS que o jogo abriu", len(cheatDurante)), "O jogo abriu em " + formataHora(jogoAbriuEm) + " e continua aberto agora.\n" + strings.Join(limitaLinhas(cheatDurante, 80), "\n") + "\nEsses programas rodaram com o jogo ja aberto. Fechar o programa antes da checagem nao apaga esse registro", "cheat"})
	}
	if len(durante) > 0 {
		sinais = append(sinais, Sinal{Info, fmt.Sprintf("Programas fora do Windows que rodaram durante esta sessao de jogo: %d", len(durante)), "Jogo aberto desde " + formataHora(jogoAbriuEm) + "\n" + strings.Join(limitaLinhas(durante, 120), "\n"), ""})
	}
	return sinais
}

func avaliarFechamentoRecente(taskmgrAbertoEm time.Time, agora time.Time, cheatRodouEm time.Time) []Sinal {
	if taskmgrAbertoEm.IsZero() {
		return nil
	}
	desde := agora.Sub(taskmgrAbertoEm)
	if desde > 20*time.Minute || desde < 0 {
		return nil
	}
	detalhe := "Aberto em " + formataHora(taskmgrAbertoEm) + ", " + desde.Round(time.Second).String() + " antes desta checagem.\nAbrir o Gerenciador de Tarefas antes de uma telagem e normal em alguns casos, mas tambem e como se fecha o cheat na pressa"
	sev := Info
	if !cheatRodouEm.IsZero() && cheatRodouEm.Before(taskmgrAbertoEm) && taskmgrAbertoEm.Sub(cheatRodouEm) < 6*time.Hour {
		sev = Critico
		detalhe = "Gerenciador de Tarefas aberto em " + formataHora(taskmgrAbertoEm) + ".\nUm programa com nome de cheat rodou em " + formataHora(cheatRodouEm) + ", ou seja, ANTES de o Gerenciador ser aberto e antes desta checagem.\nEsse e o padrao de quem foi chamado para telagem e fechou o cheat pelo Gerenciador na hora"
	}
	return []Sinal{{sev, "Gerenciador de Tarefas foi aberto pouco antes da checagem", detalhe, ""}}
}

var processosQueMostramConteudoAlheio = []string{
	"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "opera_gx.exe", "vivaldi.exe", "chromium.exe",
	"discord.exe", "discordptb.exe", "discordcanary.exe", "telegram.exe", "whatsapp.exe", "spotify.exe",
	"searchhost.exe", "searchapp.exe", "windowsterminal.exe", "conhost.exe", "openconsole.exe",
}

var assinantesDeProtecao = []string{
	"easyanticheat", "epic games", "battleye", "faceit", "riot games", "vanguard", "valve", "malwarebytes",
	"kaspersky", "avast", "avg technologies", "bitdefender", "eset", "norton", "nortonlifelock", "gen digital",
	"mcafee", "sophos", "trend micro", "webroot", "panda security", "f-secure", "crowdstrike", "sentinelone",
	"cylance", "blackberry", "microsoft", "cfx.re", "citizenfx",
}

func processoForaDaVarreduraDeMemoria(nome, caminho, assinante string) bool {
	lowerNome := strings.ToLower(nome)
	for _, p := range processosQueMostramConteudoAlheio {
		if lowerNome == p {
			return true
		}
	}
	if strings.HasPrefix(lowerNome, "fivem") {
		return true
	}
	if caminho == "" {
		return true
	}
	lower := strings.ToLower(strings.ReplaceAll(caminho, "/", `\`))
	for _, pasta := range []string{`\windows\`, `\windowsapps\`, `\program files\common files\`, `\program files (x86)\common files\`} {
		if strings.Contains(lower, pasta) {
			return true
		}
	}
	ass := strings.ToLower(assinante)
	for _, a := range assinantesDeProtecao {
		if strings.Contains(ass, a) {
			return true
		}
	}
	return false
}

func avaliarMemoriaDeProcesso(nome, caminho, statusAssinatura, assinante string, termos []string, contexto string) []Sinal {
	if len(termos) == 0 {
		return nil
	}
	sort.Strings(termos)
	lista := strings.Join(termos, ", ")
	detalhe := caminho + "\nTermos na memoria: " + lista
	if contexto != "" {
		detalhe += "\n..." + contexto + "..."
	}
	if strings.EqualFold(statusAssinatura, "Valid") && assinante != "" {
		detalhe += "\nO programa tem assinatura digital valida de '" + assinante + "'. Pode ser um documento ou texto sobre cheat aberto dentro dele, e nao o cheat em si. Confira o que esta aberto nesse programa"
		return []Sinal{{Alerta, fmt.Sprintf("Texto de cheat ('%s') na memoria de %s, programa assinado", termos[0], nome), detalhe, "suspeito"}}
	}
	detalhe += "\nO programa nao tem assinatura digital valida e carrega nome de cheat na memoria. E o padrao de cheat externo (overlay, aimbot por processo separado) e de loader renomeado"
	return []Sinal{{Critico, fmt.Sprintf("String de cheat ('%s') NA MEMORIA de %s", termos[0], nome), detalhe, "cheat"}}
}

type AchadoDeDados struct {
	Endereco uint64
	Termos   []string
	Contexto string
}

func avaliarMemoriaDeDadosDoJogo(achados []AchadoDeDados, bytesLidos int64, processo string) []Sinal {
	if len(achados) == 0 {
		return nil
	}
	porTermo := map[string]AchadoDeDados{}
	var ordem []string
	for _, a := range achados {
		for _, t := range a.Termos {
			if _, existe := porTermo[t]; !existe {
				ordem = append(ordem, t)
				porTermo[t] = a
			}
		}
	}
	sort.Strings(ordem)
	var sinais []Sinal
	for _, termo := range ordem {
		a := porTermo[termo]
		detalhe := fmt.Sprintf("Endereco 0x%X na memoria de dados de %s", a.Endereco, processo)
		if a.Contexto != "" {
			detalhe += "\n..." + a.Contexto + "..."
		}
		detalhe += "\nExecutor de Lua funciona achando o lua_State do jogo e mandando o script para dentro do processo. O texto do script fica na memoria de dados, que e onde isso foi encontrado. Vale mesmo com o programa do cheat ja fechado, porque o texto continua no processo do jogo"
		sinais = append(sinais, Sinal{Critico, fmt.Sprintf("String de cheat '%s' na MEMORIA DE DADOS de %s", termo, processo), detalhe, "cheat"})
	}
	return ordenaSinais(sinais)
}

type ThreadAnalisada struct {
	TID          uint32
	Inicial      uint64
	Modulo       string
	TipoDaRegiao string
	Protecao     string
	TemPE        bool
}

func avaliarThreadsDoJogo(threads []ThreadAnalisada, processo string) []Sinal {
	var privadas []string
	var mapeadas []string
	for _, t := range threads {
		if t.Modulo != "" || t.Inicial == 0 {
			continue
		}
		linha := fmt.Sprintf("thread %d comeca em 0x%X  (%s, %s)", t.TID, t.Inicial, t.TipoDaRegiao, t.Protecao)
		if t.TemPE {
			linha += "  com cabecalho de programa (PE) na regiao"
		}
		switch t.TipoDaRegiao {
		case "privada (sem arquivo)":
			privadas = append(privadas, linha)
		case "livre", "":
		default:
			mapeadas = append(mapeadas, linha)
		}
	}
	var sinais []Sinal
	if len(privadas) > 0 {
		sort.Strings(privadas)
		sinais = append(sinais, Sinal{Critico, fmt.Sprintf("%d thread(s) de %s executando de memoria privada, fora de qualquer dll", len(privadas), processo), strings.Join(limitaLinhas(privadas, 40), "\n") + "\nToda thread normal comeca dentro de uma dll ou do exe. Thread que comeca em memoria privada e codigo carregado na marra (manual map) rodando dentro do jogo. Nao aparece na lista de modulos e sobrevive ao jogador fechar o programa do cheat", "cheat"})
	}
	if len(mapeadas) > 0 {
		sort.Strings(mapeadas)
		sinais = append(sinais, Sinal{Alerta, fmt.Sprintf("%d thread(s) de %s comecam fora dos modulos carregados", len(mapeadas), processo), strings.Join(limitaLinhas(mapeadas, 40), "\n") + "\nA regiao nao e privada, entao pode ser codigo gerado na hora por V8 ou Mono, que o FiveM usa. Vale olhar junto com o resto", "suspeito"})
	}
	return sinais
}

type HookDetectado struct {
	Modulo          string
	Deslocamento    uint64
	Endereco        uint64
	Destino         uint64
	ModuloDoDestino string
	TipoDoDestino   string
	BytesEmMemoria  string
	BytesNoDisco    string
}

var modulosQueRecebemHookLegitimo = []string{"d3d11.dll", "dxgi.dll", "d3d12.dll", "d3d9.dll", "opengl32.dll", "gdi32.dll", "gdi32full.dll"}

func hookLegitimoConhecido(modulo string) bool {
	lower := strings.ToLower(modulo)
	for _, m := range modulosQueRecebemHookLegitimo {
		if lower == m {
			return true
		}
	}
	return false
}

func avaliarHooks(hooks []HookDetectado, processo string) []Sinal {
	if len(hooks) == 0 {
		return nil
	}
	var paraPrivada []string
	porModulo := map[string][]string{}
	var ordem []string
	for _, h := range hooks {
		linha := fmt.Sprintf("%s+0x%X (0x%X) desvia para 0x%X", h.Modulo, h.Deslocamento, h.Endereco, h.Destino)
		if h.ModuloDoDestino != "" {
			linha += " dentro de " + h.ModuloDoDestino
		} else {
			linha += " em memoria " + h.TipoDoDestino
		}
		linha += fmt.Sprintf("  [memoria: %s | disco: %s]", h.BytesEmMemoria, h.BytesNoDisco)
		if h.ModuloDoDestino == "" && h.TipoDoDestino == "privada (sem arquivo)" {
			paraPrivada = append(paraPrivada, linha)
			continue
		}
		if _, existe := porModulo[h.Modulo]; !existe {
			ordem = append(ordem, h.Modulo)
		}
		porModulo[h.Modulo] = append(porModulo[h.Modulo], linha)
	}

	var sinais []Sinal
	if len(paraPrivada) > 0 {
		sort.Strings(paraPrivada)
		sinais = append(sinais, Sinal{Critico, fmt.Sprintf("%d funcao(oes) do Windows dentro de %s desviada(s) para codigo sem arquivo", len(paraPrivada), processo), strings.Join(limitaLinhas(paraPrivada, 40), "\n") + "\nO codigo da dll na memoria esta diferente do arquivo no disco, e o desvio cai em memoria privada, que nao pertence a nenhum programa instalado. Antivirus e overlay tambem desviam funcoes, mas o desvio deles cai dentro da propria dll deles. Cair em memoria sem arquivo e codigo injetado", "cheat"})
	}
	sort.Strings(ordem)
	for _, modulo := range ordem {
		linhas := porModulo[modulo]
		sev := Alerta
		nota := "\nO codigo dessa dll na memoria esta diferente do arquivo no disco. O desvio cai dentro de outro programa instalado, o que e normal em antivirus, overlay do Discord, Steam, RivaTuner e ReShade. Confira de quem e a dll de destino"
		if hookLegitimoConhecido(modulo) {
			sev = Info
			nota = "\nDesvio em dll grafica e o mecanismo normal de ReShade, ENB, overlay do Discord e RivaTuner. So vale como indicio se o destino nao tiver dono conhecido"
		}
		sinais = append(sinais, Sinal{sev, fmt.Sprintf("%d desvio(s) de funcao em %s dentro de %s", len(linhas), modulo, processo), strings.Join(limitaLinhas(linhas, 40), "\n") + nota, "suspeito"})
	}
	return ordenaSinais(sinais)
}

func destinoDoDesvio(codigo []byte, endereco uint64) (uint64, bool) {
	if len(codigo) >= 5 && codigo[0] == 0xE9 {
		rel := int32(uint32(codigo[1]) | uint32(codigo[2])<<8 | uint32(codigo[3])<<16 | uint32(codigo[4])<<24)
		return uint64(int64(endereco) + 5 + int64(rel)), true
	}
	if len(codigo) >= 12 && codigo[0] == 0x48 && codigo[1] == 0xB8 && codigo[10] == 0xFF && codigo[11] == 0xE0 {
		var destino uint64
		for i := 0; i < 8; i++ {
			destino |= uint64(codigo[2+i]) << (8 * i)
		}
		return destino, true
	}
	if len(codigo) >= 6 && codigo[0] == 0x68 && codigo[5] == 0xC3 {
		return uint64(uint32(codigo[1]) | uint32(codigo[2])<<8 | uint32(codigo[3])<<16 | uint32(codigo[4])<<24), true
	}
	if len(codigo) >= 2 && codigo[0] == 0xFF && codigo[1] == 0x25 {
		return 0, true
	}
	return 0, false
}

func emHexa(dados []byte, n int) string {
	if len(dados) > n {
		dados = dados[:n]
	}
	var partes []string
	for _, b := range dados {
		partes = append(partes, fmt.Sprintf("%02X", b))
	}
	return strings.Join(partes, " ")
}
