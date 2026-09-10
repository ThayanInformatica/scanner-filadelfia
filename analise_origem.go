package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

type EstadoDoWindows struct {
	ServicosAusentes     []string
	ArquivosAusentes     []string
	MarcasDeISO          []string
	Ativacao             string
	CanalDeAtualizacao   string
	ComponentesRemovidos []string
	DefenderResponde     bool
	Edicao               string
	Build                string
}

var servicosDeFabrica = map[string]string{
	"WinDefend":             "Microsoft Defender Antivirus",
	"SecurityHealthService": "Central de Seguranca do Windows",
	"Sense":                 "Defender Advanced Threat Protection",
	"WdNisSvc":              "inspecao de rede do Defender",
	"wscsvc":                "Central de Seguranca",
	"SysMain":               "Superfetch (registra programas executados)",
	"DPS":                   "Diagnostic Policy Service",
	"PcaSvc":                "Assistente de compatibilidade (registra exe executado)",
	"DiagTrack":             "telemetria",
	"WSearch":               "Windows Search",
	"wuauserv":              "Windows Update",
	"BITS":                  "transferencia do Windows Update",
	"WerSvc":                "relatorio de erros",
	"CDPSvc":                "plataforma de dispositivos conectados",
	"EventLog":              "log de eventos",
}

var arquivosDeFabrica = map[string]string{
	`Program Files\Windows Defender\MsMpEng.exe`: "motor do Defender",
	`Windows\System32\SecurityHealthService.exe`: "Central de Seguranca",
	`Windows\System32\smartscreen.exe`:           "SmartScreen",
	`Windows\System32\MRT.exe`:                   "ferramenta de remocao de malware",
	`Windows\System32\SearchIndexer.exe`:         "indexador de busca",
	`Windows\System32\wuauclt.exe`:               "cliente do Windows Update",
	`Windows\System32\WerFault.exe`:              "relatorio de erros",
}

var marcasDeISOModificada = map[string]string{
	`ghost`:                "Ghost Spectre",
	`ghostspectre`:         "Ghost Spectre",
	`atlas`:                "AtlasOS",
	`revios`:               "ReviOS",
	`tiny11`:               "tiny11",
	`tiny10`:               "tiny10",
	`ntlite`:               "NTLite (ISO remontada)",
	`msmg`:                 "MSMG Toolkit",
	`wintoolkit`:           "Win Toolkit",
	`optimum`:              "Optimum / OptiWin",
	`xtremeos`:             "XtremeOS",
	`gamer os`:             "ISO 'Gamer OS'",
	`lite os`:              "ISO 'Lite OS'",
	`super lite`:           "ISO 'Super Lite'",
	`compact os`:           "ISO 'Compact'",
	`spectre`:              "Ghost Spectre",
	`kms`:                  "ativador KMS",
	`kmspico`:              "KMSPico",
	`massgrave`:            "Microsoft Activation Scripts (MAS)",
	`mas_`:                 "Microsoft Activation Scripts (MAS)",
	`autopico`:             "AutoPico (KMSPico)",
	`sppextcomobjpatcher`:  "patch de ativacao",
	`re-loader`:            "Re-Loader Activator",
	`w10digitalactivation`: "W10 Digital Activation",
	`hwidgen`:              "HWIDGEN (ativacao)",
}

func avaliarWindowsModificado(e EstadoDoWindows) []Sinal {
	var sinais []Sinal
	var motivos []string

	if len(e.ServicosAusentes) > 0 {
		sort.Strings(e.ServicosAusentes)
		motivos = append(motivos, fmt.Sprintf("%d servico(s) de fabrica nao existem: %s", len(e.ServicosAusentes), strings.Join(limitaLinhas(e.ServicosAusentes, 8), ", ")))
	}
	if len(e.ArquivosAusentes) > 0 {
		sort.Strings(e.ArquivosAusentes)
		motivos = append(motivos, fmt.Sprintf("%d arquivo(s) do proprio Windows foram removidos: %s", len(e.ArquivosAusentes), strings.Join(limitaLinhas(e.ArquivosAusentes, 8), ", ")))
	}
	if len(e.MarcasDeISO) > 0 {
		sort.Strings(e.MarcasDeISO)
		motivos = append(motivos, "marcas encontradas no sistema: "+strings.Join(e.MarcasDeISO, ", "))
	}
	if len(e.ComponentesRemovidos) > 0 {
		motivos = append(motivos, "componentes de fabrica ausentes: "+strings.Join(limitaLinhas(e.ComponentesRemovidos, 6), ", "))
	}

	defenderRemovido := false
	for _, s := range e.ServicosAusentes {
		if strings.HasPrefix(strings.ToLower(s), "windefend") {
			defenderRemovido = true
		}
	}
	if defenderRemovido {
		sinais = append(sinais, Sinal{Critico, "O Windows Defender foi REMOVIDO deste Windows", "O servico WinDefend nao existe no sistema. Desligar o Defender e uma coisa, arrancar ele da instalacao e outra: isso so acontece em Windows modificado (ISO 'lite', 'gamer', Ghost Spectre e parecidas) ou em quem usou ferramenta de remocao.\nSem Defender nao existe historico de ameaca, nao existe quarentena e nao existe deteccao. Metade das provas que uma telagem procura simplesmente nao foi gravada neste PC", "cheat"})
	}

	if len(motivos) >= 2 || len(e.MarcasDeISO) > 0 || len(e.ArquivosAusentes) >= 3 {
		detalhe := strings.Join(motivos, "\n")
		if e.Edicao != "" {
			detalhe = "Edicao informada: " + e.Edicao + "  build " + e.Build + "\n" + detalhe
		}
		detalhe += "\nUm Windows modificado remove servicos, logs e protecoes de fabrica. Isso nao prova cheat, mas destroi boa parte do que a telagem mede, e e escolha do dono do PC. Trate o relatorio inteiro com essa ressalva"
		sinais = append(sinais, Sinal{Critico, "Este Windows NAO E ORIGINAL: foi modificado antes de ser instalado", detalhe, "suspeito"})
	} else if len(motivos) == 1 {
		sinais = append(sinais, Sinal{Alerta, "Sinais de Windows alterado", strings.Join(motivos, "\n"), "suspeito"})
	}

	if e.Ativacao != "" {
		sinais = append(sinais, Sinal{Alerta, "Ativacao do Windows fora do padrao: " + e.Ativacao, "Ativador pirata costuma vir junto de ISO modificada e de ferramenta que desliga o Defender. Nao prova cheat, mas explica por que as protecoes estao desligadas", "suspeito"})
	}
	return ordenaSinais(sinais)
}

func avaliarVirtualizacaoForte(sinaisVM []SinalDeVirtualizacao) []Sinal {
	fortes := 0
	for _, s := range sinaisVM {
		if s.Fonte != "servico do Windows" {
			fortes++
		}
	}
	if fortes == 0 {
		return nil
	}
	return avaliarVirtualizacao(sinaisVM)
}

type ServicoConferido struct {
	Nome       string
	Descricao  string
	Alterado   time.Time
	Desativado bool
	Parado     bool
}

func avaliarAlteracaoEmLoteDeServicos(servicos []ServicoConferido) []Sinal {
	var comHora []ServicoConferido
	for _, s := range servicos {
		if !s.Alterado.IsZero() {
			comHora = append(comHora, s)
		}
	}
	if len(comHora) < 3 {
		return nil
	}
	sort.Slice(comHora, func(i, j int) bool { return comHora[i].Alterado.Before(comHora[j].Alterado) })

	melhorInicio, melhorFim := 0, 0
	for i := range comHora {
		j := i
		for j+1 < len(comHora) && comHora[j+1].Alterado.Sub(comHora[i].Alterado) <= 10*time.Minute {
			j++
		}
		if j-i > melhorFim-melhorInicio {
			melhorInicio, melhorFim = i, j
		}
	}
	lote := comHora[melhorInicio : melhorFim+1]
	if len(lote) < 3 {
		return nil
	}
	mexidos := 0
	var linhas []string
	for _, s := range lote {
		estado := "ligado"
		if s.Desativado {
			estado = "DESATIVADO"
			mexidos++
		} else if s.Parado {
			estado = "parado"
			mexidos++
		}
		linhas = append(linhas, fmt.Sprintf("%-24s %-11s alterado em %s   (%s)", s.Nome, estado, formataHora(s.Alterado), s.Descricao))
	}
	if mexidos == 0 {
		return nil
	}
	janela := lote[len(lote)-1].Alterado.Sub(lote[0].Alterado).Round(time.Second)
	return []Sinal{{Alerta,
		fmt.Sprintf("%d servicos de rastreio configurados de uma vez so, em %s", len(lote), janela),
		strings.Join(linhas, "\n") + "\nPessoa seguindo tutorial mexe em um servico de cada vez, ao longo de dias. Varios alterados dentro da mesma janela de minutos e programa fazendo em lote, tipo painel de otimizacao ou limpador de rastro. Isso nao prova ma intencao sozinho, porque otimizador popular desliga esses mesmos servicos: serve para saber que uma ferramenta rodou, e quando",
		"suspeito"}}
}
