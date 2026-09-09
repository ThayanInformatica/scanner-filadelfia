package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

type RastrosDeExecucao struct {
	PrefetchDesligadoNoRegistro bool
	SysMainDesativado           bool
	PrefetchLido                bool
	PrefetchQuantidade          int
	BAMLido                     bool
	BAMQuantidade               int
	UserAssistQuantidade        int
	AmcacheLido                 bool
	AmcacheQuantidade           int
	ShimCacheLido               bool
	ShimCacheQuantidade         int
	LimpezasDoSecurity          int
	LimpezasDeOutrosLogs        int
	LogSecurityVazio            bool
	LogSystemVazio              bool
	JournalRecriado             []string
	RecentesVazio               bool
	DNSVazio                    bool
}

type sinalDeRastro struct {
	peso      int
	texto     string
	explicado string
}

func avaliarRastrosDeExecucao(r RastrosDeExecucao, instalacao time.Time, agora time.Time) []Sinal {
	antigo := !instalacao.IsZero() && agora.Sub(instalacao) > 7*24*time.Hour
	var sinais []sinalDeRastro
	var intactos []string
	marca := func(peso int, texto, explicado string) {
		sinais = append(sinais, sinalDeRastro{peso, texto, explicado})
	}

	if r.PrefetchDesligadoNoRegistro {
		marca(2, "Prefetch desligado no registro (EnablePrefetcher=0)", "o Windows para de gravar o .pf de cada programa executado")
	}
	if r.SysMainDesativado {
		marca(1, "Servico SysMain desativado", "sem ele o Prefetch nao grava nada, mesmo ligado no registro")
	}
	if r.PrefetchLido {
		switch {
		case r.PrefetchQuantidade == 0:
			marca(2, "Pasta Prefetch vazia", "um Windows em uso tem centenas de .pf; vazia e limpeza ou desligamento")
		case r.PrefetchQuantidade < 20 && antigo:
			marca(1, fmt.Sprintf("Prefetch com so %d arquivos", r.PrefetchQuantidade), "poucos .pf num Windows antigo indica limpeza parcial")
		default:
			intactos = append(intactos, fmt.Sprintf("Prefetch (%d .pf)", r.PrefetchQuantidade))
		}
	}
	if r.BAMLido {
		switch {
		case r.BAMQuantidade == 0:
			marca(2, "BAM vazio", "o BAM registra todo executavel que rodou, com hora; vazio e limpeza no registro ou servico parado")
		case r.BAMQuantidade < 15 && antigo:
			marca(1, fmt.Sprintf("BAM com so %d entradas", r.BAMQuantidade), "poucas entradas num Windows antigo indica limpeza recente")
		default:
			intactos = append(intactos, fmt.Sprintf("BAM (%d entradas)", r.BAMQuantidade))
		}
	}
	if r.AmcacheLido {
		switch {
		case r.AmcacheQuantidade == 0:
			marca(2, "Amcache vazio", "o Amcache guarda todo programa que ja executou, com hash; vazio e o Windows recem-instalado ou o arquivo trocado")
		case r.AmcacheQuantidade < 50 && antigo:
			marca(2, fmt.Sprintf("Amcache com so %d entradas", r.AmcacheQuantidade), "um Windows antigo tem centenas ou milhares; poucas entradas indica troca ou limpeza do Amcache.hve")
		default:
			intactos = append(intactos, fmt.Sprintf("Amcache (%d programas)", r.AmcacheQuantidade))
		}
	}
	if r.ShimCacheLido {
		if r.ShimCacheQuantidade == 0 {
			marca(1, "ShimCache vazio", "o AppCompatCache e reescrito no desligamento e so fica vazio com limpeza direta no registro")
		} else {
			intactos = append(intactos, fmt.Sprintf("ShimCache (%d executaveis)", r.ShimCacheQuantidade))
		}
	}
	if r.LimpezasDoSecurity > 0 {
		marca(2, fmt.Sprintf("Log de seguranca limpo %d vez(es) (evento 1102)", r.LimpezasDoSecurity), "limpar o log de seguranca apaga o registro de processos e logins")
	}
	if r.LimpezasDeOutrosLogs > 0 {
		peso := 1
		if r.LimpezasDeOutrosLogs >= 3 {
			peso = 2
		}
		marca(peso, fmt.Sprintf("%d log(s) do Windows limpos (evento 104)", r.LimpezasDeOutrosLogs), "limpeza de log e acao manual, o Windows nunca faz isso sozinho")
	}
	if r.LogSecurityVazio {
		marca(2, "Log de seguranca vazio", "nunca fica vazio em uso normal")
	}
	if r.LogSystemVazio {
		marca(2, "Log do sistema vazio", "nunca fica vazio em uso normal")
	}
	if len(r.JournalRecriado) > 0 {
		marca(1, "Journal do NTFS recriado em "+strings.Join(r.JournalRecriado, ", "), "fsutil usn deletejournal apaga o historico de arquivos criados e apagados")
	}
	if r.RecentesVazio && antigo {
		marca(1, "Pasta de arquivos recentes vazia", "limpeza manual ou por ferramenta")
	}
	if r.DNSVazio {
		marca(1, "Cache DNS praticamente vazio com o PC ligado ha horas", "ipconfig /flushdns antes da checagem")
	}

	if len(sinais) == 0 {
		return nil
	}
	sort.SliceStable(sinais, func(i, j int) bool { return sinais[i].peso > sinais[j].peso })
	total := 0
	var linhas []string
	for _, s := range sinais {
		total += s.peso
		linhas = append(linhas, fmt.Sprintf("- %s: %s", s.texto, s.explicado))
	}
	detalhe := strings.Join(linhas, "\n")
	if len(intactos) > 0 {
		detalhe += "\n\nO que ainda registra execucao neste PC e onde procurar: " + strings.Join(intactos, ", ")
	} else {
		detalhe += "\n\nNenhum registro de execucao sobrou intacto: o que o jogador rodou neste PC nao pode ser reconstruido por rastro"
	}

	switch {
	case total >= 4:
		return []Sinal{{Critico, fmt.Sprintf("PC POSSIVELMENTE 'STOPADO': %d registro(s) de execucao desligados ou limpos", len(sinais)), "Registro de execucao e o que mostra o que rodou neste PC antes da checagem. Desligar ou limpar varios ao mesmo tempo e o padrao de quem prepara a maquina para telagem.\n" + detalhe, "suspeito"}}
	case total >= 2:
		return []Sinal{{Alerta, fmt.Sprintf("Registros de execucao parcialmente desligados ou limpos (%d)", len(sinais)), "Sozinho pode ser otimizacao de PC. Junto com qualquer outro indicio, e preparacao para telagem.\n" + detalhe, "suspeito"}}
	}
	return []Sinal{{Info, "Um registro de execucao fora do normal", detalhe, ""}}
}
