package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

type ExecutavelEmDisco struct {
	Caminho          string
	Nome             string
	Tamanho          int64
	Modificado       time.Time
	Assinatura       string
	Assinante        string
	OriginalFilename string
	ProductName      string
	CompanyName      string
}

var donoEsperadoDoPrograma = map[string][]string{
	"ccleaner.exe":       {"piriform", "gen digital", "avast"},
	"discord.exe":        {"discord"},
	"chrome.exe":         {"google"},
	"msedge.exe":         {"microsoft"},
	"firefox.exe":        {"mozilla"},
	"opera.exe":          {"opera"},
	"steam.exe":          {"valve"},
	"fivem.exe":          {"cfx.re", "citizenfx"},
	"obs64.exe":          {"obs project", "obs studio"},
	"medal.exe":          {"medal"},
	"anydesk.exe":        {"anydesk"},
	"teamviewer.exe":     {"teamviewer"},
	"winrar.exe":         {"win.rar", "rarlab"},
	"7z.exe":             {"igor pavlov"},
	"7zfm.exe":           {"igor pavlov"},
	"spotify.exe":        {"spotify"},
	"telegram.exe":       {"telegram"},
	"msiafterburner.exe": {"guru3d", "msi", "micro-star"},
	"cpuz.exe":           {"cpuid"},
	"hwinfo64.exe":       {"hwinfo"},
	"radeonsoftware.exe": {"advanced micro devices", "amd"},
	"nvidia share.exe":   {"nvidia"},
	"javaw.exe":          {"oracle", "azul", "eclipse", "microsoft", "bellsoft", "amazon"},
	"java.exe":           {"oracle", "azul", "eclipse", "microsoft", "bellsoft", "amazon"},
}

func donoBate(assinante, empresa string, esperados []string) bool {
	texto := strings.ToLower(assinante + " " + empresa)
	for _, e := range esperados {
		if strings.Contains(texto, e) {
			return true
		}
	}
	return false
}

func avaliarExecutaveisEmDisco(arquivos []ExecutavelEmDisco) []Sinal {
	if len(arquivos) == 0 {
		return nil
	}
	var sinais []Sinal
	var semAssinatura []string
	vistos := map[string]bool{}

	for _, a := range arquivos {
		nome := strings.ToLower(a.Nome)
		chave := strings.ToLower(a.Caminho)
		if vistos[chave] {
			continue
		}
		vistos[chave] = true
		local := fmt.Sprintf("%s\n%s  %d KB\nAssinatura: %s  Assinante: %s\nNome interno: %s  Produto: %s  Empresa: %s",
			a.Caminho, formataHora(a.Modificado), a.Tamanho/1024,
			valorOuTraco(a.Assinatura), valorOuTraco(a.Assinante),
			valorOuTraco(a.OriginalFilename), valorOuTraco(a.ProductName), valorOuTraco(a.CompanyName))

		if esperados, conhecido := donoEsperadoDoPrograma[nome]; conhecido {
			if !donoBate(a.Assinante, a.CompanyName, esperados) {
				sinais = append(sinais, Sinal{Critico,
					"Arquivo se passando por " + a.Nome + " mas nao e dele",
					local + "\nUm " + a.Nome + " de verdade e assinado por " + strings.Join(esperados, " ou ") +
						". Este nao e, e renomear o loader para um nome inofensivo e a forma mais comum de esconder cheat de quem olha a pasta", "cheat"})
				continue
			}
		}

		if a.OriginalFilename != "" && nomeOriginalDiverge(nome, a.OriginalFilename) {
			sinais = append(sinais, Sinal{Alerta,
				"Executavel com nome diferente do nome interno: " + a.Nome,
				local + "\nO nome gravado dentro do arquivo pelo proprio compilador nao bate com o nome do arquivo. Renomear e o jeito mais simples de escapar de busca por nome", "suspeito"})
			continue
		}

		if !strings.EqualFold(a.Assinatura, "Valid") && a.CompanyName == "" && a.ProductName == "" {
			semAssinatura = append(semAssinatura, fmt.Sprintf("%s  %s  %d KB", formataHora(a.Modificado), a.Caminho, a.Tamanho/1024))
		}
	}

	sort.Sort(sort.Reverse(sort.StringSlice(semAssinatura)))
	if len(semAssinatura) > 0 {
		sinais = append(sinais, Sinal{Info,
			fmt.Sprintf("Executaveis sem assinatura e sem identificacao em pasta de usuario: %d", len(semAssinatura)),
			strings.Join(limitaLinhas(semAssinatura, 80), "\n") +
				"\nPrograma serio traz assinatura digital ou pelo menos nome de empresa e produto gravados dentro. Instalador caseiro e ferramenta de mod tambem aparecem aqui, entao isto e contexto, nao acusacao. Cruzar com o que rodou no BAM e no PCA", ""})
	}
	return ordenaSinais(sinais)
}
