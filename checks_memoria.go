//go:build windows

package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

func checarMemoriaDoJogo(c *Contexto) {
	r := c.R
	r.Secao("MEMORIA DO JOGO E LINHA DO TEMPO DA SESSAO")

	processos, err := listarProcessos()
	if err != nil {
		r.Erro("listar processos: %v", err)
		return
	}
	var alvos []Processo
	for _, p := range processos {
		nome := strings.ToLower(p.Nome)
		if strings.HasPrefix(nome, "fivem") && strings.Contains(nome, "gtaprocess") {
			alvos = append(alvos, p)
		}
	}
	if len(alvos) == 0 {
		r.Add(Alerta, "Memoria do jogo NAO foi analisada: o FiveM estava fechado", "A varredura de memoria e o que pega cheat carregado na marra (manual map), que nao aparece na lista de modulos e sobrevive ao jogador fechar o programa do cheat.\nPara esta checagem valer, o FiveM precisa estar aberto na cidade durante o scanner")
	}

	buscador := NovoBuscador(c.A.TermosParaConteudo())
	for _, p := range alvos {
		if c.DevePular() {
			break
		}
		r.Progresso("Lendo a memoria de %s (PID %d) atras de codigo injetado", p.Nome, p.PID)
		var achados []AchadoDeMemoria
		regioes := 0
		var bytesLidos uint64
		inicio := time.Now()
		err := varrerMemoriaExecutavel(p.PID, 0, func(regiao RegiaoDeMemoria, dados []byte) {
			regioes++
			bytesLidos += uint64(len(dados))
			if regioes%40 == 0 {
				r.Progresso("%d regioes executaveis lidas (%d MB) na memoria do jogo", regioes, bytesLidos/1024/1024)
			}
			if a := analisarRegiao(regiao, dados, buscador); a != nil {
				achados = append(achados, *a)
			}
		})
		if err != nil {
			r.Erro("ler memoria de %s: %v", p.Nome, err)
			continue
		}
		r.Linha("%s (PID %d): %d regioes executaveis fora de dll registrada, %d MB lidos em %s", p.Nome, p.PID, regioes, bytesLidos/1024/1024, time.Since(inicio).Round(time.Second))
		sinais := avaliarMemoriaDoJogo(achados, regioes, p.Nome)
		for _, s := range sinais {
			r.Add(s.Severidade, s.Titulo, s.Detalhe)
		}
		if len(sinais) == 0 {
			r.Ok("Nenhum codigo injetado nem string de cheat na memoria executavel de %s", p.Nome)
		}
		if c.DevePular() {
			break
		}
		checarMemoriaDeDados(c, p, buscador)
		checarThreadsDoJogo(c, p)
		checarHooksNoJogo(c, p)
	}

	checarMemoriaDosOutrosProcessos(c, processos, buscador)

	agora := time.Now()
	sinais := avaliarLinhaDoTempo(c.JogoAbriuEm, agora, c.Execucoes, c.A)
	for _, s := range sinais {
		r.Add(s.Severidade, s.Titulo, s.Detalhe)
	}
	if c.JogoAbriuEm.IsZero() {
		r.Linha("Sem sessao de jogo aberta para cruzar a linha do tempo")
	} else {
		r.Linha("Jogo aberto desde %s (%s de sessao), %d execucoes conhecidas para cruzar", formataHora(c.JogoAbriuEm), agora.Sub(c.JogoAbriuEm).Round(time.Minute), len(c.Execucoes))
		if len(sinais) == 0 {
			r.Ok("Nenhum programa com nome de cheat rodou depois que o jogo abriu")
		}
	}

	var cheatMaisRecente time.Time
	for _, e := range c.Execucoes {
		if classe, _ := c.A.Classificar(e.Caminho); classe != SemMatch && e.Quando.After(cheatMaisRecente) {
			cheatMaisRecente = e.Quando
		}
	}
	for _, s := range avaliarFechamentoRecente(c.TaskmgrAbertoEm, agora, cheatMaisRecente) {
		r.Add(s.Severidade, s.Titulo, s.Detalhe)
	}

	if len(c.Execucoes) > 0 {
		recentes := make([]EventoDeExecucao, 0, len(c.Execucoes))
		for _, e := range c.Execucoes {
			if !e.Quando.IsZero() && agora.Sub(e.Quando) < 6*time.Hour {
				recentes = append(recentes, e)
			}
		}
		sort.Slice(recentes, func(i, j int) bool { return recentes[i].Quando.After(recentes[j].Quando) })
		var linhas []string
		vistos := map[string]bool{}
		for _, e := range recentes {
			chave := strings.ToLower(nomeBase(e.Caminho))
			if vistos[chave] || caminhoDoSistema(e.Caminho) {
				continue
			}
			vistos[chave] = true
			linhas = append(linhas, fmt.Sprintf("%s  %s  (%s)", formataHora(e.Quando), e.Caminho, e.Fonte))
		}
		if len(linhas) > 0 {
			r.Add(Info, fmt.Sprintf("Programas fora do Windows executados nas ultimas 6 horas: %d", len(linhas)), strings.Join(limitaLinhas(linhas, 160), "\n"))
		}
	}
}

func checarMemoriaDosOutrosProcessos(c *Contexto, processos []Processo, buscador *Buscador) {
	r := c.R
	r.Secao("MEMORIA DOS OUTROS PROCESSOS (cheat externo e loader renomeado)")
	var semAssinatura []string
	vistoCaminho := map[string]bool{}
	for _, p := range processos {
		if p.Caminho == "" || ehOProprioScanner(p.Caminho, int(p.PID)) {
			continue
		}
		chave := strings.ToLower(p.Caminho)
		if _, ok := c.AssinaturasDeProcessos[chave]; ok || vistoCaminho[chave] {
			continue
		}
		vistoCaminho[chave] = true
		semAssinatura = append(semAssinatura, p.Caminho)
	}
	if len(semAssinatura) > 0 {
		r.Progresso("Conferindo a assinatura digital de %d programas antes de ler a memoria", len(semAssinatura))
		if c.AssinaturasDeProcessos == nil {
			c.AssinaturasDeProcessos = map[string][2]string{}
		}
		for k, v := range assinaturasAuthenticode(semAssinatura) {
			c.AssinaturasDeProcessos[k] = v
		}
	}

	var alvos []Processo
	for _, p := range processos {
		if ehOProprioScanner(p.Caminho, int(p.PID)) {
			continue
		}
		var status, assinante string
		if v, ok := c.AssinaturasDeProcessos[strings.ToLower(p.Caminho)]; ok {
			status, assinante = v[0], v[1]
		}
		if processoForaDaVarreduraDeMemoria(p.Nome, p.Caminho, assinante) {
			continue
		}
		_ = status
		alvos = append(alvos, p)
	}
	r.Linha("%d processos fora do Windows e fora das protecoes conhecidas para varrer na memoria", len(alvos))
	if len(alvos) == 0 {
		return
	}
	achou := 0
	var totalMB int64
	inicio := time.Now()
	for i, p := range alvos {
		if c.DevePular() {
			r.Linha("Varredura de memoria dos processos interrompida a pedido em %d de %d", i, len(alvos))
			break
		}
		r.Progresso("Memoria %d de %d: %s (PID %d)", i+1, len(alvos), p.Nome, p.PID)
		termosVistos := map[string]bool{}
		var termos []string
		contexto := ""
		lidos, err := varrerMemoriaLegivel(p.PID, 768*1024*1024, func(regiao RegiaoDeMemoria, dados []byte) {
			buscador.Procurar(dados, func(o Ocorrencia) bool {
				if termosVistos[o.Termo] {
					return true
				}
				termosVistos[o.Termo] = true
				termos = append(termos, o.Termo)
				if contexto == "" {
					contexto = trechoEmVolta(dados, o.Inicio, o.Fim, o.UTF16)
				}
				return len(termos) < 5
			})
		})
		totalMB += lidos / 1024 / 1024
		if err != nil {
			continue
		}
		var status, assinante string
		if v, ok := c.AssinaturasDeProcessos[strings.ToLower(p.Caminho)]; ok {
			status, assinante = v[0], v[1]
		}
		for _, s := range avaliarMemoriaDeProcesso(p.Nome, p.Caminho, status, assinante, termos, contexto) {
			achou++
			r.Add(s.Severidade, s.Titulo, s.Detalhe)
		}
	}
	r.Linha("%d MB de memoria lidos em %d processos em %s", totalMB, len(alvos), time.Since(inicio).Round(time.Second))
	if achou == 0 && !c.Pulou() {
		r.Ok("Nenhum processo fora do Windows carrega nome de cheat na memoria")
	}
}

func checarMemoriaDeDados(c *Contexto, p Processo, buscador *Buscador) {
	r := c.R
	r.Progresso("Lendo a memoria de dados de %s (PID %d) atras de script de cheat", p.Nome, p.PID)
	var achados []AchadoDeDados
	vistos := map[string]bool{}
	inicio := time.Now()
	lidos, err := varrerMemoriaDeDados(p.PID, 4*1024*1024*1024, func(regiao RegiaoDeMemoria, dados []byte) {
		buscador.Procurar(dados, func(o Ocorrencia) bool {
			if vistos[o.Termo] {
				return true
			}
			vistos[o.Termo] = true
			achados = append(achados, AchadoDeDados{Endereco: regiao.Base + uint64(o.Inicio), Termos: []string{o.Termo}, Contexto: trechoEmVolta(dados, o.Inicio, o.Fim, o.UTF16)})
			return len(vistos) < 12
		})
	})
	if err != nil {
		r.Erro("ler memoria de dados de %s: %v", p.Nome, err)
		return
	}
	r.Linha("%s (PID %d): %d MB de memoria de dados lidos em %s", p.Nome, p.PID, lidos/1024/1024, time.Since(inicio).Round(time.Second))
	sinais := avaliarMemoriaDeDadosDoJogo(achados, lidos, p.Nome)
	for _, s := range sinais {
		r.Add(s.Severidade, s.Titulo, s.Detalhe)
	}
	if len(sinais) == 0 {
		r.Ok("Nenhum script ou nome de cheat na memoria de dados de %s", p.Nome)
	}
}

func checarThreadsDoJogo(c *Contexto, p Processo) {
	r := c.R
	threads, err := listarThreads(p.PID)
	if err != nil {
		r.Erro("listar threads de %s: %v", p.Nome, err)
		return
	}
	modulos, err := intervalosDeModulos(p.PID)
	if err != nil {
		r.Erro("modulos de %s: %v", p.Nome, err)
		return
	}
	dono := func(endereco uint64) string {
		for _, m := range modulos {
			if endereco >= m.Base && endereco < m.Base+m.Tamanho {
				return m.Nome
			}
		}
		return ""
	}
	var analisadas []ThreadAnalisada
	for _, t := range threads {
		a := ThreadAnalisada{TID: t.TID, Inicial: t.Inicial, Modulo: dono(t.Inicial)}
		if a.Modulo == "" && t.Inicial != 0 {
			a.TipoDaRegiao, a.Protecao, _ = descreverRegiao(p.PID, t.Inicial)
			if dados, err := lerMemoria(p.PID, t.Inicial&^0xFFF, 4096); err == nil {
				a.TemPE = temCabecalhoPE(dados)
			}
		}
		analisadas = append(analisadas, a)
	}
	r.Linha("%s (PID %d): %d threads, %d modulos carregados", p.Nome, p.PID, len(analisadas), len(modulos))
	sinais := avaliarThreadsDoJogo(analisadas, p.Nome)
	for _, s := range sinais {
		r.Add(s.Severidade, s.Titulo, s.Detalhe)
	}
	if len(sinais) == 0 {
		r.Ok("Todas as threads de %s comecam dentro de dll registrada", p.Nome)
	}
}

var modulosParaConferirNoDisco = []string{
	"ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll", "ws2_32.dll", "wininet.dll",
	"d3d11.dll", "dxgi.dll", "gdi32.dll", "advapi32.dll",
}

func checarHooksNoJogo(c *Contexto, p Processo) {
	r := c.R
	modulos, err := intervalosDeModulos(p.PID)
	if err != nil {
		return
	}
	dono := func(endereco uint64) string {
		for _, m := range modulos {
			if endereco >= m.Base && endereco < m.Base+m.Tamanho {
				return m.Nome
			}
		}
		return ""
	}
	interessa := func(nome string) bool {
		lower := strings.ToLower(nome)
		for _, m := range modulosParaConferirNoDisco {
			if lower == m {
				return true
			}
		}
		return false
	}

	var hooks []HookDetectado
	conferidos := 0
	for _, m := range modulos {
		if !interessa(m.Nome) || m.Caminho == "" {
			continue
		}
		if c.DevePular() {
			break
		}
		noDisco, rva, err := secaoTextoNoDisco(m.Caminho)
		if err != nil {
			continue
		}
		naMemoria, err := lerMemoria(p.PID, m.Base+rva, len(noDisco))
		if err != nil || len(naMemoria) != len(noDisco) {
			continue
		}
		conferidos++
		encontrados := 0
		for i := 0; i < len(noDisco) && encontrados < 20; i++ {
			if noDisco[i] == naMemoria[i] {
				continue
			}
			fim := i + 16
			if fim > len(naMemoria) {
				fim = len(naMemoria)
			}
			endereco := m.Base + rva + uint64(i)
			destino, ehDesvio := destinoDoDesvio(naMemoria[i:fim], endereco)
			if !ehDesvio {
				for i < len(noDisco) && noDisco[i] != naMemoria[i] {
					i++
				}
				continue
			}
			encontrados++
			h := HookDetectado{
				Modulo: m.Nome, Deslocamento: rva + uint64(i), Endereco: endereco, Destino: destino,
				BytesEmMemoria: emHexa(naMemoria[i:fim], 8), BytesNoDisco: emHexa(noDisco[i:fim], 8),
			}
			if destino != 0 {
				h.ModuloDoDestino = dono(destino)
				if h.ModuloDoDestino == "" {
					h.TipoDoDestino, _, _ = descreverRegiao(p.PID, destino)
				}
			} else {
				h.TipoDoDestino = "indireta (salto por ponteiro)"
			}
			if h.ModuloDoDestino == "" && (h.TipoDoDestino == "" || h.TipoDoDestino == "livre") {
				encontrados--
				for i < len(noDisco) && noDisco[i] != naMemoria[i] {
					i++
				}
				continue
			}
			hooks = append(hooks, h)
			for i < len(noDisco) && noDisco[i] != naMemoria[i] {
				i++
			}
		}
	}
	r.Linha("%s (PID %d): %d dll(s) do Windows conferidas contra o arquivo em disco", p.Nome, p.PID, conferidos)
	sinais := avaliarHooks(hooks, p.Nome)
	for _, s := range sinais {
		r.Add(s.Severidade, s.Titulo, s.Detalhe)
	}
	if len(sinais) == 0 && conferidos > 0 {
		r.Ok("Nenhuma funcao do Windows desviada dentro de %s", p.Nome)
	}
}
