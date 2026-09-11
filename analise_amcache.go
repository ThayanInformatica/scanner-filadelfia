package main

import (
	"fmt"
	"sort"
	"strings"
)

type EntradaAmcache struct {
	Caminho       string
	Nome          string
	SHA1          string
	Editor        string
	Produto       string
	Tamanho       int64
	ExisteNoDisco bool
	Fonte         string
}

func pastaDeUsuarioVolatil(caminho string) bool {
	lower := strings.ToLower(strings.ReplaceAll(caminho, "/", `\`))
	for _, marca := range []string{`\downloads\`, `\desktop\`, `\appdata\local\temp\`, `\temp\`, `\tmp\`, `\public\`} {
		if strings.Contains(lower, marca) {
			return true
		}
	}
	return false
}

func avaliarAmcache(entradas []EntradaAmcache, a *Assinaturas) []Sinal {
	var sinais []Sinal
	vistos := map[string]bool{}
	var apagadosVolateis []string
	apagados := 0

	for _, e := range entradas {
		if e.Caminho == "" {
			continue
		}
		if !e.ExisteNoDisco {
			apagados++
		}
		base := nomeBase(e.Caminho)
		if ehOProprioScanner(e.Caminho, 0) {
			continue
		}
		sufixo := ""
		if !e.ExisteNoDisco {
			sufixo = "\nO arquivo NAO existe mais no disco: rodou e foi apagado. O Amcache guarda o registro mesmo assim"
		}
		hashInfo := ""
		if e.SHA1 != "" {
			hashInfo = "\nSHA1: " + e.SHA1
		}
		if rotulo := a.HashConhecido(e.SHA1); rotulo != "" && !vistos["h"+e.SHA1] {
			vistos["h"+e.SHA1] = true
			sevHash, notaHash, _ := severidadeDeHashDeDriver(rotulo, e.Caminho)
			situacao := "cheat"
			if sevHash != Critico {
				situacao = "suspeito"
			}
			sinais = append(sinais, Sinal{sevHash, "Amcache: programa com HASH conhecido ja rodou: " + base, e.Caminho + hashInfo + "\nBate com: " + rotulo + "\nO hash nao muda quando o arquivo e renomeado" + sufixo + notaHash, situacao})
			continue
		}
		if t := a.Marca(e.Caminho); t != "" && !vistos["m"+t+strings.ToLower(e.Caminho)] {
			vistos["m"+t+strings.ToLower(e.Caminho)] = true
			sinais = append(sinais, Sinal{Critico, fmt.Sprintf("Amcache: '%s' JA RODOU neste PC: %s", t, base), e.Caminho + hashInfo + "\nEditor: " + valorOuTraco(e.Editor) + "  Produto: " + valorOuTraco(e.Produto) + sufixo, "cheat"})
			continue
		}
		if classe, t := a.Classificar(e.Caminho); classe != SemMatch && !a.TextoInocente(e.Caminho) && !vistos["c"+t+strings.ToLower(e.Caminho)] {
			vistos["c"+t+strings.ToLower(e.Caminho)] = true
			sinais = append(sinais, Sinal{classe.Severidade(), fmt.Sprintf("Amcache: %s '%s' ja rodou: %s", classe.Rotulo(), t, base), e.Caminho + hashInfo + sufixo, "suspeito"})
			continue
		}
		if !e.ExisteNoDisco && pastaDeUsuarioVolatil(e.Caminho) && !caminhoDoSistema(e.Caminho) && !pacoteDeDriverOuInstalador(e.Caminho) {
			if pareceNomeAleatorio(base) {
				apagadosVolateis = append(apagadosVolateis, e.Caminho+hashInfo)
			}
		}
	}

	sort.Strings(apagadosVolateis)
	if len(apagadosVolateis) > 0 {
		sinais = append(sinais, Sinal{Alerta, fmt.Sprintf("Amcache: %d programa(s) com nome aleatorio rodaram de pasta temporaria e foram apagados", len(apagadosVolateis)), strings.Join(limitaLinhas(apagadosVolateis, 60), "\n") + "\nLoader de cheat costuma ter nome aleatorio, rodar do Temp ou Downloads e se apagar depois. Instalador legitimo tambem faz isso, entao confira o hash com a lista da equipe", "suspeito"})
	}
	if len(entradas) > 0 {
		sinais = append(sinais, Sinal{Info, fmt.Sprintf("Amcache: %d programas registrados como executados, %d ja nao existem no disco", len(entradas), apagados), "O Amcache e o registro do Windows de tudo que ja executou, com o hash de cada arquivo. Sobrevive a limpador de rastro e a exclusao do arquivo", ""})
	}
	if len(sinais) == 0 {
		return nil
	}
	return ordenaSinais(sinais)
}

func valorOuTraco(v string) string {
	if strings.TrimSpace(v) == "" {
		return "-"
	}
	return v
}
