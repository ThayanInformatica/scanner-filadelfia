package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

type ExecucaoPCA struct {
	Caminho string
	Hora    time.Time
	Fonte   string
}

var formatosDeHoraPCA = []string{
	"2006-01-02 15:04:05.000",
	"2006-01-02 15:04:05",
	"2006-01-02T15:04:05.000",
	"2006-01-02T15:04:05",
}

func horaDoPCA(texto string) (time.Time, bool) {
	texto = strings.TrimSpace(texto)
	for _, f := range formatosDeHoraPCA {
		if t, err := time.ParseInLocation(f, texto, time.Local); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func pareceCaminhoDeExecutavel(campo string) bool {
	c := strings.TrimSpace(campo)
	if len(c) < 4 || !strings.Contains(c, `\`) {
		return false
	}
	lower := strings.ToLower(c)
	return strings.HasSuffix(lower, ".exe") || strings.HasSuffix(lower, ".com") || strings.HasSuffix(lower, ".scr")
}

func lerPCA(conteudo, fonte string) []ExecucaoPCA {
	var lista []ExecucaoPCA
	for _, linha := range strings.Split(conteudo, "\n") {
		linha = strings.TrimRight(linha, "\r")
		if strings.TrimSpace(linha) == "" {
			continue
		}
		campos := strings.Split(linha, "|")
		if len(campos) < 2 {
			continue
		}
		e := ExecucaoPCA{Fonte: fonte}
		for _, campo := range campos {
			if e.Caminho == "" && pareceCaminhoDeExecutavel(campo) {
				e.Caminho = strings.TrimSpace(campo)
				continue
			}
			if e.Hora.IsZero() {
				if t, ok := horaDoPCA(campo); ok {
					e.Hora = t
				}
			}
		}
		if e.Caminho == "" {
			continue
		}
		lista = append(lista, e)
	}
	return lista
}

func avaliarPCA(execucoes []ExecucaoPCA, a *Assinaturas, agora time.Time) []Sinal {
	if len(execucoes) == 0 {
		return nil
	}
	var sinais []Sinal
	vistos := map[string]bool{}
	var recentes []string
	for _, e := range execucoes {
		chave := strings.ToLower(e.Caminho)
		if classe, termo := a.Classificar(e.Caminho); classe != SemMatch && !vistos["m"+chave] {
			vistos["m"+chave] = true
			sinais = append(sinais, Sinal{classe.Severidade(),
				fmt.Sprintf("Programa registrado pelo PCA bate com assinatura '%s': %s", termo, nomeBase(e.Caminho)),
				formataHora(e.Hora) + "\n" + e.Caminho + "\nO PCA do Windows grava o caminho de todo programa com janela que abriu, e sobrevive ao apagamento do arquivo", "cheat"})
			continue
		}
		if motivo := caminhoSuspeito(e.Caminho); motivo != "" && !vistos["s"+chave] {
			vistos["s"+chave] = true
			sinais = append(sinais, Sinal{Alerta,
				"Executavel " + motivo + " registrado pelo PCA: " + nomeBase(e.Caminho),
				formataHora(e.Hora) + "\n" + e.Caminho, "suspeito"})
			continue
		}
		if !e.Hora.IsZero() && agora.Sub(e.Hora) < 7*24*time.Hour && !vistos["r"+chave] {
			vistos["r"+chave] = true
			recentes = append(recentes, fmt.Sprintf("%s  %s", formataHora(e.Hora), e.Caminho))
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(recentes)))
	if len(recentes) > 0 {
		sinais = append(sinais, Sinal{Info,
			fmt.Sprintf("Programas com janela registrados pelo PCA nos ultimos 7 dias: %d", len(recentes)),
			strings.Join(limitaLinhas(recentes, 120), "\n") + "\nEsta lista vem de C:\\Windows\\appcompat\\pca, um arquivo de texto que a maioria dos limpadores de rastro nao apaga", ""})
	}
	return ordenaSinais(sinais)
}
