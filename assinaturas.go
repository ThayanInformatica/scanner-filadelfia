package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

//go:embed assinaturas.exemplo.json
var assinaturasPadrao []byte

type ServicoEsperado struct {
	Nome      string `json:"nome"`
	Descricao string `json:"descricao"`
	Nivel     string `json:"nivel"`
}

type Assinaturas struct {
	Cheats           []string          `json:"cheats"`
	Ferramentas      []string          `json:"ferramentas"`
	Limpeza          []string          `json:"limpeza"`
	Dominios         []string          `json:"dominios"`
	Drivers          []string          `json:"drivers_vulneraveis"`
	Servicos         []ServicoEsperado `json:"servicos_esperados"`
	PastasExtra      []string          `json:"pastas_extra"`
	IgnorarCaminhos  []string          `json:"ignorar_caminhos"`
	PalavrasWeb      []string          `json:"palavras_web"`
	Marcas           []string          `json:"marcas"`
	StringsConteudo  []string          `json:"strings_conteudo"`
	IgnorarWeb       []string          `json:"ignorar_web"`
	HardwareDMA      []string          `json:"hardware_dma"`
	HardwareEntrada  []string          `json:"hardware_entrada"`
	ControleRemoto   []string          `json:"controle_remoto"`
	ProcessosSistema map[string]string `json:"processos_sistema"`
	SysDoSistema     []string          `json:"sys_do_sistema"`
	Hashes           []string          `json:"hashes"`

	cheats         []termo
	ferramentas    []termo
	limpeza        []termo
	dominios       []termo
	palavrasWeb    []termo
	marcas         []termo
	controleRemoto []termo
	drivers        map[string]bool
	hashes         map[string]string
}

type termo struct {
	texto string
	re    *regexp.Regexp
}

type Classe int

const (
	SemMatch Classe = iota
	ClasseCheat
	ClasseFerramenta
	ClasseLimpeza
)

func (c Classe) Rotulo() string {
	switch c {
	case ClasseCheat:
		return "cheat"
	case ClasseFerramenta:
		return "ferramenta de injecao/debug/macro"
	case ClasseLimpeza:
		return "limpador de rastros"
	}
	return ""
}

func (c Classe) Severidade() Severidade {
	if c == ClasseCheat {
		return Critico
	}
	return Alerta
}

func AssinaturasDeBytes(dados []byte, origem string) (*Assinaturas, string, error) {
	return montarAssinaturas(dados, origem)
}

func CarregarAssinaturas(caminho string) (*Assinaturas, string, error) {
	origem := "lista de exemplo embutida no exe"
	dados := assinaturasPadrao
	if caminho != "" {
		if conteudo, err := os.ReadFile(caminho); err == nil {
			dados = conteudo
			origem = caminho
		} else if !os.IsNotExist(err) {
			return nil, "", fmt.Errorf("ler %s: %w", caminho, err)
		}
	}
	return montarAssinaturas(dados, origem)
}

func montarAssinaturas(dados []byte, origem string) (*Assinaturas, string, error) {
	var a Assinaturas
	if err := json.Unmarshal(dados, &a); err != nil {
		return nil, "", fmt.Errorf("assinaturas invalidas (%s): %w", origem, err)
	}
	a.cheats = compilaTermos(a.Cheats)
	a.ferramentas = compilaTermos(a.Ferramentas)
	a.limpeza = compilaTermos(a.Limpeza)
	a.dominios = compilaTermos(a.Dominios)
	a.palavrasWeb = compilaPalavras(a.PalavrasWeb)
	a.marcas = compilaTermos(a.Marcas)
	a.controleRemoto = compilaTermos(a.ControleRemoto)
	for i, t := range a.HardwareDMA {
		a.HardwareDMA[i] = strings.ToLower(t)
	}
	for i, t := range a.HardwareEntrada {
		a.HardwareEntrada[i] = strings.ToLower(t)
	}
	sistema := map[string]string{}
	for k, v := range a.ProcessosSistema {
		sistema[strings.ToLower(k)] = strings.ToLower(v)
	}
	a.ProcessosSistema = sistema
	for i, t := range a.IgnorarWeb {
		a.IgnorarWeb[i] = strings.ToLower(t)
	}
	a.drivers = map[string]bool{}
	for _, d := range a.Drivers {
		a.drivers[strings.ToLower(d)] = true
	}
	for i, p := range a.IgnorarCaminhos {
		a.IgnorarCaminhos[i] = strings.ToLower(p)
	}
	a.hashes = indexaHashes(a.Hashes)
	return &a, origem, nil
}

func indexaHashes(lista []string) map[string]string {
	idx := map[string]string{}
	for _, linha := range lista {
		campos := strings.Fields(linha)
		if len(campos) == 0 {
			continue
		}
		hex := strings.ToLower(campos[0])
		for _, prefixo := range []string{"sha256:", "sha1:", "md5:"} {
			hex = strings.TrimPrefix(hex, prefixo)
		}
		if len(hex) != 40 && len(hex) != 64 && len(hex) != 32 {
			continue
		}
		rotulo := "hash de cheat conhecido"
		if len(campos) > 1 {
			rotulo = strings.Join(campos[1:], " ")
		}
		idx[hex] = rotulo
	}
	return idx
}

func (a *Assinaturas) HashConhecido(hex string) string {
	return a.hashes[strings.ToLower(strings.TrimSpace(hex))]
}

func compilaTermos(lista []string) []termo {
	var saida []termo
	for _, t := range lista {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" {
			continue
		}
		re := regexp.MustCompile(`(^|[^a-z0-9])` + regexp.QuoteMeta(t) + `s?([^a-z0-9]|$)`)
		saida = append(saida, termo{texto: t, re: re})
	}
	return saida
}

func compilaPalavras(lista []string) []termo {
	var saida []termo
	for _, t := range lista {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" {
			continue
		}
		if strings.ContainsAny(t, "/.") {
			saida = append(saida, termo{texto: t})
			continue
		}
		re := regexp.MustCompile(`(^|[^a-z0-9])` + regexp.QuoteMeta(t) + `([^a-z0-9]|$)`)
		saida = append(saida, termo{texto: t, re: re})
	}
	return saida
}

var trocaSeparadores = strings.NewReplacer("_", " ", "-", " ", ".", " ", "+", " ", "%20", " ")

func procuraTermo(texto string, termos []termo) string {
	texto = strings.ToLower(texto)
	normalizado := trocaSeparadores.Replace(texto)
	for _, t := range termos {
		if strings.Contains(t.texto, " ") && t.re != nil && t.re.MatchString(normalizado) {
			return t.texto
		}
		if t.re != nil {
			if t.re.MatchString(texto) {
				return t.texto
			}
			continue
		}
		if strings.Contains(texto, t.texto) {
			return t.texto
		}
	}
	return ""
}

func (a *Assinaturas) Classificar(texto string) (Classe, string) {
	if t := procuraTermo(texto, a.cheats); t != "" {
		return ClasseCheat, t
	}
	if t := procuraTermo(texto, a.ferramentas); t != "" {
		return ClasseFerramenta, t
	}
	if t := procuraTermo(texto, a.limpeza); t != "" {
		return ClasseLimpeza, t
	}
	return SemMatch, ""
}

func (a *Assinaturas) Dominio(texto string) string {
	return procuraTermo(texto, a.dominios)
}

func (a *Assinaturas) PalavraWeb(texto string) string {
	if a.TextoInocente(texto) {
		return ""
	}
	return procuraTermo(texto, a.palavrasWeb)
}

func (a *Assinaturas) Marca(texto string) string {
	return procuraTermo(texto, a.marcas)
}

func (a *Assinaturas) ControleRemotoAtivo(texto string) string {
	return procuraTermo(texto, a.controleRemoto)
}

func contemAlgum(texto string, lista []string) string {
	t := strings.ToLower(texto)
	for _, item := range lista {
		if item != "" && strings.Contains(t, item) {
			return item
		}
	}
	return ""
}

func (a *Assinaturas) SysConhecidoDoSistema(nome string) bool {
	nome = strings.ToLower(nome)
	for _, s := range a.SysDoSistema {
		if strings.EqualFold(s, nome) {
			return true
		}
	}
	return false
}

func (a *Assinaturas) HardwareDMASuspeito(descricao string) string {
	return contemAlgum(descricao, a.HardwareDMA)
}

func (a *Assinaturas) HardwareEntradaSuspeito(descricao string) string {
	return contemAlgum(descricao, a.HardwareEntrada)
}

func (a *Assinaturas) TextoInocente(texto string) bool {
	t := strings.ToLower(texto)
	for _, i := range a.IgnorarWeb {
		if strings.Contains(t, i) {
			return true
		}
	}
	return false
}

func (a *Assinaturas) TermosParaConteudo() []string {
	if len(a.StringsConteudo) > 0 {
		return a.StringsConteudo
	}
	return append(append([]string{}, a.Marcas...), a.Dominios...)
}

func (a *Assinaturas) DriverVulneravel(nomeArquivo string) bool {
	return a.drivers[strings.ToLower(nomeArquivo)]
}

func (a *Assinaturas) Ignorar(caminho string) bool {
	c := strings.ToLower(caminho)
	for _, p := range a.IgnorarCaminhos {
		if strings.Contains(c, p) {
			return true
		}
	}
	return false
}

func (a *Assinaturas) Exportar(caminho string) error {
	return os.WriteFile(caminho, assinaturasPadrao, 0o644)
}
