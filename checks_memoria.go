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
			r.Ok("Nenhum codigo injetado nem string de cheat na memoria de %s", p.Nome)
		}
	}

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
