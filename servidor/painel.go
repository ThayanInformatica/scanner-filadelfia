package main

import (
	"crypto/subtle"
	_ "embed"
	"net/http"
	"strconv"
	"strings"
	"time"
)

//go:embed painel.html
var paginaDoPainel []byte

func (s *Servico) autenticado(r *http.Request) bool {
	c, err := r.Cookie("sessao")
	if err != nil {
		return false
	}
	s.mu.Lock()
	ate, ok := s.sessoes[c.Value]
	s.mu.Unlock()
	if ok && time.Now().Before(ate) {
		return true
	}
	var expira time.Time
	if err := s.db.QueryRow(`select expira_em from scanner_painel_sessoes where token = $1`, c.Value).Scan(&expira); err != nil {
		return false
	}
	if time.Now().After(expira) {
		s.db.Exec(`delete from scanner_painel_sessoes where token = $1`, c.Value)
		return false
	}
	s.mu.Lock()
	s.sessoes[c.Value] = expira
	s.mu.Unlock()
	return true
}

func (s *Servico) exige(w http.ResponseWriter, r *http.Request) bool {
	if s.autenticado(r) {
		return true
	}
	responde(w, 401, map[string]any{"ok": false, "erro": "faca login"})
	return false
}

func (s *Servico) painel(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(paginaDoPainel)
}

func (s *Servico) entrar(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Senha string `json:"senha"`
	}
	if err := leCorpo(r, &p); err != nil {
		responde(w, 400, map[string]any{"ok": false, "erro": "pedido invalido"})
		return
	}
	if subtle.ConstantTimeCompare([]byte(p.Senha), []byte(s.senha)) != 1 {
		time.Sleep(time.Second)
		responde(w, 200, map[string]any{"ok": false, "erro": "senha errada"})
		return
	}
	token := novoToken()
	expira := time.Now().Add(7 * 24 * time.Hour)
	s.db.Exec(`delete from scanner_painel_sessoes where expira_em < now()`)
	if _, err := s.db.Exec(`insert into scanner_painel_sessoes (token, expira_em) values ($1,$2)`, token, expira); err != nil {
		responde(w, 500, map[string]any{"ok": false, "erro": "nao consegui abrir a sessao"})
		return
	}
	s.mu.Lock()
	s.sessoes[token] = expira
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "sessao", Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 7 * 24 * 3600})
	responde(w, 200, map[string]any{"ok": true})
}

type linhaDeLicenca struct {
	ID         int64  `json:"id"`
	Codigo     string `json:"codigo"`
	Jogador    string `json:"jogador"`
	Staff      string `json:"staff"`
	Observacao string `json:"observacao"`
	CriadoEm   string `json:"criado_em"`
	ExpiraEm   string `json:"expira_em"`
	UsadoEm    string `json:"usado_em"`
	Maquina    string `json:"maquina"`
	HWID       string `json:"hwid"`
	Revogada   bool   `json:"revogada"`
	Situacao   string `json:"situacao"`
	Sessoes    int    `json:"sessoes"`
}

func (s *Servico) dados(w http.ResponseWriter, r *http.Request) {
	if !s.exige(w, r) {
		return
	}
	linhas, err := s.db.Query(`select l.id, l.codigo, l.jogador, l.staff, l.observacao, l.criado_em, l.expira_em,
			l.usado_em, coalesce(l.maquina,''), coalesce(l.hwid,''), l.revogada,
			(select count(*) from scanner_sessoes se where se.licenca_id = l.id)
		from scanner_licencas l order by l.criado_em desc limit 300`)
	if err != nil {
		responde(w, 500, map[string]any{"ok": false, "erro": err.Error()})
		return
	}
	defer linhas.Close()
	lista := []linhaDeLicenca{}
	for linhas.Next() {
		var v linhaDeLicenca
		var criado, expira time.Time
		var usado *time.Time
		if err := linhas.Scan(&v.ID, &v.Codigo, &v.Jogador, &v.Staff, &v.Observacao, &criado, &expira, &usado, &v.Maquina, &v.HWID, &v.Revogada, &v.Sessoes); err != nil {
			continue
		}
		v.CriadoEm = criado.Local().Format("02/01 15:04")
		v.ExpiraEm = expira.Local().Format("02/01 15:04")
		switch {
		case v.Revogada:
			v.Situacao = "cancelado"
		case usado != nil:
			v.UsadoEm = usado.Local().Format("02/01 15:04")
			v.Situacao = "usado"
		case time.Now().After(expira):
			v.Situacao = "vencido"
		default:
			v.Situacao = "aguardando"
		}
		lista = append(lista, v)
	}
	responde(w, 200, map[string]any{"ok": true, "licencas": lista, "versao_minima": s.config("versao_minima"), "assinaturas": s.resumoDasAssinaturas()})
}

func (s *Servico) gerar(w http.ResponseWriter, r *http.Request) {
	if !s.exige(w, r) {
		return
	}
	var p struct {
		Jogador    string `json:"jogador"`
		Staff      string `json:"staff"`
		Observacao string `json:"observacao"`
		Minutos    int    `json:"minutos"`
	}
	if err := leCorpo(r, &p); err != nil {
		responde(w, 400, map[string]any{"ok": false, "erro": "pedido invalido"})
		return
	}
	if p.Minutos <= 0 || p.Minutos > 7*24*60 {
		p.Minutos = 30
	}
	codigo := novoCodigo()
	expira := time.Now().Add(time.Duration(p.Minutos) * time.Minute)
	_, err := s.db.Exec(`insert into scanner_licencas (codigo, jogador, staff, observacao, expira_em) values ($1,$2,$3,$4,$5)`,
		codigo, strings.TrimSpace(p.Jogador), strings.TrimSpace(p.Staff), strings.TrimSpace(p.Observacao), expira)
	if err != nil {
		responde(w, 500, map[string]any{"ok": false, "erro": err.Error()})
		return
	}
	responde(w, 200, map[string]any{"ok": true, "codigo": codigo, "expira_em": expira.Local().Format("02/01 15:04")})
}

func (s *Servico) revogar(w http.ResponseWriter, r *http.Request) {
	if !s.exige(w, r) {
		return
	}
	var p struct {
		ID int64 `json:"id"`
	}
	if err := leCorpo(r, &p); err != nil {
		responde(w, 400, map[string]any{"ok": false, "erro": "pedido invalido"})
		return
	}
	s.db.Exec(`update scanner_licencas set revogada = true where id = $1`, p.ID)
	s.db.Exec(`update scanner_sessoes set encerrada_em = now() where licenca_id = $1 and encerrada_em is null`, p.ID)
	responde(w, 200, map[string]any{"ok": true})
}

func (s *Servico) versaoMinima(w http.ResponseWriter, r *http.Request) {
	if !s.exige(w, r) {
		return
	}
	var p struct {
		Versao string `json:"versao"`
	}
	if err := leCorpo(r, &p); err != nil {
		responde(w, 400, map[string]any{"ok": false, "erro": "pedido invalido"})
		return
	}
	limpa := strings.TrimSpace(p.Versao)
	for _, parte := range strings.Split(limpa, ".") {
		if _, err := strconv.Atoi(parte); err != nil {
			responde(w, 200, map[string]any{"ok": false, "erro": "use o formato 2.9.0"})
			return
		}
	}
	s.db.Exec(`insert into scanner_config (chave, valor) values ('versao_minima', $1)
		on conflict (chave) do update set valor = excluded.valor`, limpa)
	responde(w, 200, map[string]any{"ok": true, "versao_minima": limpa})
}
