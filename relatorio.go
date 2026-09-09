package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Severidade int

const (
	Info Severidade = iota
	Alerta
	Critico
)

func (s Severidade) String() string {
	switch s {
	case Critico:
		return "CRITICO"
	case Alerta:
		return "ALERTA"
	}
	return "INFO"
}

func (s Severidade) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

type Achado struct {
	Severidade Severidade `json:"severidade"`
	Categoria  string     `json:"categoria"`
	Titulo     string     `json:"titulo"`
	Detalhe    string     `json:"detalhe,omitempty"`
	Caminhos   []string   `json:"caminhos,omitempty"`
}

type Relatorio struct {
	GeradoEm time.Time         `json:"gerado_em"`
	Maquina  string            `json:"maquina"`
	Usuario  string            `json:"usuario"`
	Versao   string            `json:"versao_telador"`
	Sistema  map[string]string `json:"sistema"`
	Achados  []Achado          `json:"achados"`
	Erros    []string          `json:"erros"`

	Etapa       string             `json:"etapa_atual,omitempty"`
	CaminhoTxt  string             `json:"caminho_txt,omitempty"`
	CaminhoJSON string             `json:"caminho_json,omitempty"`
	Incompletas []string           `json:"etapas_incompletas,omitempty"`
	Criticos    int                `json:"criticos"`
	Alertas     int                `json:"alertas"`
	Infos       int                `json:"infos"`
	Veredito    string             `json:"veredito,omitempty"`
	Processos   []ProcessoRelatado `json:"processos"`

	cor        bool
	secao      string
	texto      strings.Builder
	inicio     time.Time
	silencioso bool
	mu         sync.Mutex
	emitir     func(Evento)
}

type ProcessoRelatado struct {
	PID      int    `json:"pid"`
	Nome     string `json:"nome"`
	Caminho  string `json:"caminho"`
	Situacao string `json:"situacao"`
	Pai      string `json:"pai,omitempty"`
}

type Evento struct {
	Tipo       string   `json:"tipo"`
	Secao      string   `json:"secao,omitempty"`
	Texto      string   `json:"texto,omitempty"`
	Severidade string   `json:"severidade,omitempty"`
	Titulo     string   `json:"titulo,omitempty"`
	Detalhe    string   `json:"detalhe,omitempty"`
	Chave      string   `json:"chave,omitempty"`
	Valor      string   `json:"valor,omitempty"`
	Etapa      int      `json:"etapa,omitempty"`
	Total      int      `json:"total,omitempty"`
	Caminhos   []string `json:"caminhos,omitempty"`
	Seq        int      `json:"seq,omitempty"`
}

const (
	corReset    = "\x1b[0m"
	corNegrito  = "\x1b[1m"
	corVermelho = "\x1b[91m"
	corAmarelo  = "\x1b[93m"
	corCinza    = "\x1b[90m"
	corCiano    = "\x1b[96m"
	corVerde    = "\x1b[92m"
)

func NovoRelatorio(versao string, cor bool) *Relatorio {
	host, _ := os.Hostname()
	return &Relatorio{
		GeradoEm:  time.Now(),
		Maquina:   host,
		Usuario:   usuarioAtual(),
		Versao:    versao,
		Sistema:   map[string]string{},
		Achados:   []Achado{},
		Erros:     []string{},
		Processos: []ProcessoRelatado{},
		cor:       cor,
		inicio:    time.Now(),
	}
}

func (r *Relatorio) pinta(cor, texto string) string {
	if !r.cor {
		return texto
	}
	return cor + texto + corReset
}

func (r *Relatorio) escreve(console, arquivo string) {
	if !r.silencioso {
		fmt.Println(console)
	}
	r.mu.Lock()
	r.texto.WriteString(arquivo)
	r.texto.WriteString("\n")
	r.mu.Unlock()
}

func (r *Relatorio) emite(e Evento) {
	if r.emitir != nil {
		r.emitir(e)
	}
}

func (r *Relatorio) Processo(pid int, nome, caminho, situacao, pai string) {
	r.mu.Lock()
	r.Processos = append(r.Processos, ProcessoRelatado{PID: pid, Nome: nome, Caminho: caminho, Situacao: situacao, Pai: pai})
	r.mu.Unlock()
	r.emite(Evento{Tipo: "processo", Etapa: pid, Chave: nome, Valor: caminho, Texto: situacao, Detalhe: pai})
}

func (r *Relatorio) Modulo(pid int, nome, caminho, situacao string) {
	r.emite(Evento{Tipo: "modulo", Etapa: pid, Chave: nome, Valor: caminho, Texto: situacao})
}

func (r *Relatorio) Progresso(formato string, args ...any) {
	msg := fmt.Sprintf(formato, args...)
	if !r.silencioso {
		fmt.Printf("\r  ... %-100s", msg)
	}
	r.emite(Evento{Tipo: "progresso", Secao: r.secao, Texto: msg})
}

func (r *Relatorio) Etapas(nome string, indice, total int) {
	r.Etapa = nome
	r.emite(Evento{Tipo: "etapa", Texto: nome, Etapa: indice, Total: total})
}

func (r *Relatorio) Secao(nome string) {
	r.secao = nome
	linha := strings.Repeat("=", 70)
	r.escreve("\n"+r.pinta(corNegrito+corCiano, linha)+"\n"+r.pinta(corNegrito+corCiano, "  "+nome)+"\n"+r.pinta(corNegrito+corCiano, linha), "\n"+linha+"\n  "+nome+"\n"+linha)
	r.emite(Evento{Tipo: "secao", Secao: nome})
}

func (r *Relatorio) Linha(formato string, args ...any) {
	msg := fmt.Sprintf(formato, args...)
	r.escreve(r.pinta(corCinza, "  "+msg), "  "+msg)
	r.emite(Evento{Tipo: "linha", Secao: r.secao, Texto: msg})
}

func (r *Relatorio) Ok(formato string, args ...any) {
	msg := fmt.Sprintf(formato, args...)
	r.escreve(r.pinta(corVerde, "  [OK] "+msg), "  [OK] "+msg)
	r.emite(Evento{Tipo: "ok", Secao: r.secao, Texto: msg})
}

func (r *Relatorio) Erro(formato string, args ...any) {
	msg := fmt.Sprintf(formato, args...)
	r.Erros = append(r.Erros, r.secao+": "+msg)
	r.escreve(r.pinta(corCinza, "  [erro] "+msg), "  [erro] "+msg)
	r.emite(Evento{Tipo: "falha", Secao: r.secao, Texto: msg})
}

func (r *Relatorio) MarcaIncompleta(etapa string) {
	r.mu.Lock()
	for _, e := range r.Incompletas {
		if e == etapa {
			r.mu.Unlock()
			return
		}
	}
	r.Incompletas = append(r.Incompletas, etapa)
	r.mu.Unlock()
}

func (r *Relatorio) Add(sev Severidade, titulo, detalhe string) {
	if strings.Contains(titulo, "INCOMPLETA") || strings.Contains(titulo, "INCOMPLETO") {
		r.MarcaIncompleta(r.secao)
	}
	caminhos := caminhosNoTexto(titulo, detalhe)
	r.Achados = append(r.Achados, Achado{Severidade: sev, Categoria: r.secao, Titulo: titulo, Detalhe: detalhe, Caminhos: caminhos})
	cor := corCinza
	switch sev {
	case Critico:
		cor = corNegrito + corVermelho
	case Alerta:
		cor = corAmarelo
	}
	texto := fmt.Sprintf("  [%s] %s", sev, titulo)
	if detalhe != "" {
		texto += "\n        " + strings.ReplaceAll(detalhe, "\n", "\n        ")
	}
	r.escreve(r.pinta(cor, texto), texto)
	r.emite(Evento{Tipo: "achado", Secao: r.secao, Severidade: sev.String(), Titulo: titulo, Detalhe: detalhe, Caminhos: caminhos})
}

func (r *Relatorio) Sistema_(chave, valor string) {
	r.Sistema[chave] = valor
	if !r.silencioso {
		fmt.Println(r.pinta(corCinza, fmt.Sprintf("  %-28s %s", chave+":", valor)))
	}
	r.mu.Lock()
	r.texto.WriteString(fmt.Sprintf("  %-28s %s\n", chave+":", valor))
	r.mu.Unlock()
	r.emite(Evento{Tipo: "sistema", Secao: r.secao, Chave: chave, Valor: valor})
}

func (r *Relatorio) contagem() (criticos, alertas, infos int) {
	for _, a := range r.Achados {
		switch a.Severidade {
		case Critico:
			criticos++
		case Alerta:
			alertas++
		default:
			infos++
		}
	}
	return
}

func (r *Relatorio) Resumo() {
	r.Secao("RESUMO")
	criticos, alertas, infos := r.contagem()
	r.Linha("Duracao da analise: %s", time.Since(r.inicio).Round(time.Second))
	r.Linha("Criticos: %d   Alertas: %d   Informativos: %d   Erros: %d", criticos, alertas, infos, len(r.Erros))

	ordenados := append([]Achado(nil), r.Achados...)
	sort.SliceStable(ordenados, func(i, j int) bool { return ordenados[i].Severidade > ordenados[j].Severidade })
	for _, a := range ordenados {
		if a.Severidade == Info {
			continue
		}
		cor := corAmarelo
		if a.Severidade == Critico {
			cor = corNegrito + corVermelho
		}
		texto := fmt.Sprintf("  [%s] (%s) %s", a.Severidade, a.Categoria, a.Titulo)
		r.escreve(r.pinta(cor, texto), texto)
	}

	if len(r.Incompletas) > 0 {
		r.escreve(r.pinta(corAmarelo, "\n  ATENCAO: estas etapas nao terminaram e podem ter deixado coisa de fora:"), "\n  ATENCAO: estas etapas nao terminaram e podem ter deixado coisa de fora:")
		for _, e := range r.Incompletas {
			r.escreve(r.pinta(corAmarelo, "    - "+e), "    - "+e)
		}
		r.escreve(r.pinta(corAmarelo, "  Rode a checagem completa sem limite de tempo antes de concluir."), "  Rode a checagem completa sem limite de tempo antes de concluir.")
	}

	veredito := "NENHUM INDICIO FORTE ENCONTRADO"
	cor := corVerde
	switch {
	case criticos > 0:
		veredito = "INDICIOS FORTES DE TRAPACA OU OCULTACAO DE RASTROS"
		cor = corNegrito + corVermelho
	case alertas > 0:
		veredito = "INDICIOS FRACOS: REVISAR OS ALERTAS MANUALMENTE"
		cor = corAmarelo
	}
	r.escreve("\n"+r.pinta(cor, "  >>> "+veredito+" <<<"), "\n  >>> "+veredito+" <<<")
	r.Criticos, r.Alertas, r.Infos = criticos, alertas, infos
	r.Veredito = veredito
}

func (r *Relatorio) Salvar(dir string) (string, string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", err
	}
	base := fmt.Sprintf("scanner-%s-%s", sanitizaNome(r.Maquina), r.GeradoEm.Format("20060102-150405"))
	caminhoTxt := filepath.Join(dir, base+".txt")
	caminhoJSON := filepath.Join(dir, base+".json")

	cabecalho := fmt.Sprintf("Scanner Filadelfia %s\nMaquina: %s   Usuario: %s   Gerado em: %s\n", r.Versao, r.Maquina, r.Usuario, r.GeradoEm.Format("02/01/2006 15:04:05"))
	if err := os.WriteFile(caminhoTxt, []byte(cabecalho+r.texto.String()), 0o644); err != nil {
		return "", "", err
	}
	dados, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(caminhoJSON, dados, 0o644); err != nil {
		return "", "", err
	}
	r.CaminhoTxt, r.CaminhoJSON = caminhoTxt, caminhoJSON
	return caminhoTxt, caminhoJSON, nil
}

func sanitizaNome(s string) string {
	var b strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			b.WriteRune(c)
		}
	}
	if b.Len() == 0 {
		return "maquina"
	}
	return b.String()
}

func usuarioAtual() string {
	for _, chave := range []string{"USERNAME", "USER", "LOGNAME"} {
		if v := os.Getenv(chave); v != "" {
			return v
		}
	}
	return "desconhecido"
}
