package main

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type ValorDeMetadados struct {
	Nome  string
	Valor float64
}

type ArquivoDeMetadados struct {
	Nome       string
	Caminho    string
	Tamanho    int64
	Modificado time.Time
	Valores    []ValorDeMetadados
}

type MetadadosDoJogo struct {
	Instalacao string
	Arquivos   []ArquivoDeMetadados
}

var reValorDeMetadados = regexp.MustCompile(`<\s*([A-Za-z_][A-Za-z0-9_]*)\s+value\s*=\s*"\s*([-+0-9.eE]+)\s*"`)

func lerValoresDeMetadados(conteudo string) []ValorDeMetadados {
	var lista []ValorDeMetadados
	for _, m := range reValorDeMetadados.FindAllStringSubmatch(conteudo, 500) {
		v, err := strconv.ParseFloat(m[2], 64)
		if err != nil {
			continue
		}
		lista = append(lista, ValorDeMetadados{Nome: strings.ToUpper(m[1]), Valor: v})
	}
	return lista
}

var padraoDoPedAccuracy = map[string]float64{
	"PLAYER_RECOIL_MODIFIER_MIN":       0.8,
	"PLAYER_RECOIL_MODIFIER_MAX":       1.0,
	"PLAYER_RECOIL_CROUCHED_MODIFIER":  0.5,
	"PLAYER_BLIND_FIRE_MODIFIER_MIN":   2.0,
	"PLAYER_BLIND_FIRE_MODIFIER_MAX":   4.0,
	"PLAYER_RECENTLY_DAMAGED_MODIFIER": 0.3,
}

var sentidoDoPedAccuracy = map[string]string{
	"PLAYER_RECOIL_MODIFIER_MIN":       "recuo minimo do jogador",
	"PLAYER_RECOIL_MODIFIER_MAX":       "recuo maximo do jogador",
	"PLAYER_RECOIL_CROUCHED_MODIFIER":  "recuo agachado",
	"PLAYER_BLIND_FIRE_MODIFIER_MIN":   "imprecisao minima atirando sem mirar",
	"PLAYER_BLIND_FIRE_MODIFIER_MAX":   "imprecisao maxima atirando sem mirar",
	"PLAYER_RECENTLY_DAMAGED_MODIFIER": "penalidade de mira depois de levar dano",
}

var camposDeArmaQueViramCheat = map[string]string{
	"ACCURACYSPREAD":                  "dispersao do tiro",
	"RECOILACCURACYMAX":               "perda de precisao pelo recuo",
	"RECOILSHAKEAMPLITUDE":            "tremor da tela ao atirar",
	"FIRSTPERSONRECOILSHAKEAMPLITUDE": "tremor da tela em primeira pessoa",
	"CAMERARECOILSCALING":             "recuo aplicado na camera",
	"RECOILERRORTIME":                 "tempo de erro do recuo",
	"RUNANDGUNACCURACYMODIFIER":       "precisao correndo e atirando",
	"ACCURATEMODEACCURACYMODIFIER":    "precisao no modo preciso",
}

const notaDaPastaDeMetadados = "Uma instalacao limpa do FiveM nao tem nenhum arquivo .meta em citizen\\common\\data: essa pasta so tem gameconfig.xml, gta5_cache_y.dat e a pasta ui. Os unicos .meta legitimos da instalacao ficam em citizen\\platform\\data\\control e sao de tecla, nao de arma. Arquivo de arma solto aqui foi colocado na mao. O pure mode do FiveM ignora arquivo dentro da pasta do FiveM, e o servidor nao tem native para ler esses valores: so a checagem no proprio PC pega isso"

func avaliarMetadadosDoJogo(m MetadadosDoJogo) []Sinal {
	if len(m.Arquivos) == 0 {
		return nil
	}
	var sinais []Sinal
	var linhas []string
	for _, a := range m.Arquivos {
		linhas = append(linhas, fmt.Sprintf("%s  (%s, %s)", a.Caminho, formataTamanho(a.Tamanho), formataHora(a.Modificado)))
	}
	sort.Strings(linhas)
	sinais = append(sinais, Sinal{Critico,
		fmt.Sprintf("%d arquivo(s) .meta colocados dentro da instalacao do FiveM", len(m.Arquivos)),
		strings.Join(limitaLinhas(linhas, 20), "\n") + "\n" + notaDaPastaDeMetadados, "cheat"})

	for _, a := range m.Arquivos {
		if s, tem := desviosDoPedAccuracy(a); tem {
			sinais = append(sinais, s)
		}
		if s, tem := desviosDeArma(a); tem {
			sinais = append(sinais, s)
		}
	}
	return ordenaSinais(sinais)
}

func desviosDoPedAccuracy(a ArquivoDeMetadados) (Sinal, bool) {
	if !strings.EqualFold(a.Nome, "pedaccuracy.meta") || len(a.Valores) == 0 {
		return Sinal{}, false
	}
	var fora []string
	zerados := 0
	for _, v := range a.Valores {
		padrao, conhecido := padraoDoPedAccuracy[v.Nome]
		if !conhecido || math.Abs(v.Valor-padrao) < 0.0001 {
			continue
		}
		fora = append(fora, fmt.Sprintf("%s: %g   padrao do jogo: %g   (%s)", v.Nome, v.Valor, padrao, sentidoDoPedAccuracy[v.Nome]))
		if v.Valor < padrao/10 {
			zerados++
		}
	}
	if len(fora) == 0 {
		return Sinal{}, false
	}
	sort.Strings(fora)
	detalhe := a.Caminho + "\n" + strings.Join(fora, "\n")
	if zerados > 0 {
		detalhe += fmt.Sprintf("\n%d desses valores estao praticamente zerados. Zerar o recuo e a imprecisao do jogador faz a bala sair exatamente onde a mira aponta, com qualquer arma e em qualquer cidade. E o cheat que nao aparece na memoria do jogo e que o anticheat do servidor nao consegue ler", zerados)
	}
	return Sinal{Critico, fmt.Sprintf("pedaccuracy.meta com %d valor(es) fora do padrao do jogo", len(fora)), detalhe, "cheat"}, true
}

func desviosDeArma(a ArquivoDeMetadados) (Sinal, bool) {
	nome := strings.ToLower(a.Nome)
	if nome != "weapons.meta" && nome != "weaponcomponents.meta" {
		return Sinal{}, false
	}
	var zerados []string
	vistos := map[string]bool{}
	for _, v := range a.Valores {
		sentido, conhecido := camposDeArmaQueViramCheat[v.Nome]
		if !conhecido || v.Valor != 0 || vistos[v.Nome] {
			continue
		}
		vistos[v.Nome] = true
		zerados = append(zerados, fmt.Sprintf("%s zerado   (%s)", v.Nome, sentido))
	}
	if len(zerados) == 0 {
		return Sinal{}, false
	}
	sort.Strings(zerados)
	return Sinal{Critico, fmt.Sprintf("%s com %d campo(s) de precisao zerado(s)", a.Nome, len(zerados)),
		a.Caminho + "\n" + strings.Join(zerados, "\n") + "\nDispersao, recuo e tremor de tela zerados deixam a arma perfeita. Arma custom mal configurada tambem aparece com esses campos em zero, entao confira se este arquivo veio de um pacote baixado", "cheat"}, true
}
