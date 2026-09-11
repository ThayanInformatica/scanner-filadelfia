package main

import (
	"fmt"
	"strings"
)

type ConferidoAoVivo struct {
	JogoAberto           bool
	NomeDoJogo           string
	PIDDoJogo            int
	ProcessosListados    int
	ModulosDoJogo        int
	ModulosDesconhecidos int
	HandlesNoJogo        int
	HandlesComEscrita    int
	JanelasAnalisadas    int
	OverlaysAcusados     int
	DriversCarregados    int
	DriversAcusados      int
	RegioesExecutaveis   int
	MBExecutavelLidos    int
	MBDadosLidos         int
	AchadosNaMemoria     int
	ThreadsAnalisadas    int
	ThreadsForaDeModulo  int
	DLLsConferidas       int
	HooksEncontrados     int
	ProcessosVarridos    int
	MBOutrosLidos        int
}

type conferenciaAoVivo struct {
	nome    string
	rodou   bool
	medida  string
	achados int
}

func (v ConferidoAoVivo) lista() []conferenciaAoVivo {
	return []conferenciaAoVivo{
		{"Modulo carregado no jogo vindo de pasta desconhecida", v.ModulosDoJogo > 0,
			fmt.Sprintf("%d modulos conferidos", v.ModulosDoJogo), v.ModulosDesconhecidos},
		{"Outro processo com a memoria do jogo aberta", v.HandlesNoJogo > 0 || v.JogoAberto,
			fmt.Sprintf("%d handles apontando para o jogo", v.HandlesNoJogo), v.HandlesComEscrita},
		{"Codigo injetado sem arquivo dentro do jogo", v.MBExecutavelLidos > 0 || v.RegioesExecutaveis > 0,
			fmt.Sprintf("%d regioes executaveis fora de dll, %d MB lidos", v.RegioesExecutaveis, v.MBExecutavelLidos), v.RegioesExecutaveis},
		{"Script ou nome de cheat na memoria de dados do jogo", v.MBDadosLidos > 0,
			fmt.Sprintf("%d MB de memoria de dados lidos", v.MBDadosLidos), v.AchadosNaMemoria},
		{"Thread do jogo comecando fora de dll registrada", v.ThreadsAnalisadas > 0,
			fmt.Sprintf("%d threads conferidas", v.ThreadsAnalisadas), v.ThreadsForaDeModulo},
		{"Funcao do Windows desviada dentro do jogo", v.DLLsConferidas > 0,
			fmt.Sprintf("%d dlls comparadas com o arquivo em disco", v.DLLsConferidas), v.HooksEncontrados},
		{"Nome de cheat na memoria de outro programa", v.ProcessosVarridos > 0,
			fmt.Sprintf("%d processos varridos, %d MB lidos", v.ProcessosVarridos, v.MBOutrosLidos), 0},
		{"Mira ou ESP desenhado por cima do jogo", v.JanelasAnalisadas > 0,
			fmt.Sprintf("%d janelas analisadas", v.JanelasAnalisadas), v.OverlaysAcusados},
		{"Driver de kernel carregado", v.DriversCarregados > 0,
			fmt.Sprintf("%d drivers carregados", v.DriversCarregados), v.DriversAcusados},
	}
}

func avaliarConferenciaAoVivo(v ConferidoAoVivo) []Sinal {
	itens := v.lista()
	var rodaram, naoRodaram []string
	achadosTotais := 0
	for _, i := range itens {
		if !i.rodou {
			naoRodaram = append(naoRodaram, "  "+i.nome)
			continue
		}
		marca := "nada encontrado"
		if i.achados > 0 {
			marca = fmt.Sprintf("%d ACHADO(S)", i.achados)
			achadosTotais += i.achados
		}
		rodaram = append(rodaram, fmt.Sprintf("  %-52s %-44s %s", i.nome, i.medida, marca))
	}

	var sinais []Sinal
	if !v.JogoAberto {
		return []Sinal{{Alerta, "As checagens ao vivo NAO valem: o jogo nao estava aberto",
			"Sem o FiveM rodando, nove checagens ficam de fora e este relatorio nao inocenta ninguem.\nPara teste com cheat ativo, entre na cidade, deixe o cheat ligado e so entao rode o scanner.\n" +
				strings.Join(naoRodaram, "\n"), "suspeito"}}
	}

	cabecalho := fmt.Sprintf("Jogo conferido: %s (PID %d), com %d processos no sistema", v.NomeDoJogo, v.PIDDoJogo, v.ProcessosListados)
	detalhe := cabecalho + "\n\n" + strings.Join(rodaram, "\n")
	if len(naoRodaram) > 0 {
		detalhe += "\n\nNao deu para conferir:\n" + strings.Join(naoRodaram, "\n")
	}

	sev := Info
	titulo := fmt.Sprintf("%d de %d checagens ao vivo rodaram e nao acharam nada", len(rodaram), len(itens))
	if achadosTotais > 0 {
		sev = Critico
		titulo = fmt.Sprintf("%d achado(s) nas checagens ao vivo, com o jogo aberto", achadosTotais)
	}
	sinais = append(sinais, Sinal{sev, titulo, detalhe, ""})
	return sinais
}
