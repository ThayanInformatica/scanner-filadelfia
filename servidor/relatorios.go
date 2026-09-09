package main

import (
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"math/big"
	"net/http"
	"strings"
	"time"
)

//go:embed relatorio.html
var paginaDoRelatorio []byte

func novoProtocolo() string {
	bloco := func(n int) string {
		var b strings.Builder
		for i := 0; i < n; i++ {
			k, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alfabetoDoCodigo))))
			b.WriteByte(alfabetoDoCodigo[k.Int64()])
		}
		return b.String()
	}
	return "REL-" + bloco(4) + "-" + bloco(4)
}

type pedidoDeRelatorio struct {
	Token     string          `json:"token"`
	Relatorio json.RawMessage `json:"relatorio"`
	Criticos  int             `json:"criticos"`
	Alertas   int             `json:"alertas"`
	Infos     int             `json:"infos"`
	Erros     int             `json:"erros"`
	Veredito  string          `json:"veredito"`
	Duracao   string          `json:"duracao"`
	Maquina   string          `json:"maquina"`
	Usuario   string          `json:"usuario"`
	Versao    string          `json:"versao"`
	Parcial   bool            `json:"parcial"`
}

func (s *Servico) receberRelatorio(w http.ResponseWriter, r *http.Request) {
	var p pedidoDeRelatorio
	if err := leCorpoAte(r, &p, 64<<20); err != nil {
		recusa(w, "pedido", "nao consegui ler o relatorio: "+err.Error())
		return
	}
	if p.Token == "" || len(p.Relatorio) == 0 {
		recusa(w, "pedido", "faltou o token ou o relatorio")
		return
	}
	var sessaoID, licencaID int64
	var expira time.Time
	var jogador, staff string
	err := s.db.QueryRow(`select se.id, se.licenca_id, se.expira_em, l.jogador, l.staff
		from scanner_sessoes se join scanner_licencas l on l.id = se.licenca_id
		where se.token = $1`, p.Token).Scan(&sessaoID, &licencaID, &expira, &jogador, &staff)
	if err != nil {
		recusa(w, "token", "sessao nao encontrada. O codigo pode ter sido cancelado")
		return
	}
	if time.Now().After(expira.Add(12 * time.Hour)) {
		recusa(w, "expirada", "esta sessao venceu ha tempo demais para receber relatorio")
		return
	}

	protocolo := novoProtocolo()
	_, err = s.db.Exec(`insert into scanner_relatorios
		(protocolo, licenca_id, sessao_id, jogador, staff, maquina, usuario, versao,
		 criticos, alertas, infos, erros, veredito, duracao, parcial, dados)
		values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
		protocolo, licencaID, sessaoID, jogador, staff, p.Maquina, p.Usuario, p.Versao,
		p.Criticos, p.Alertas, p.Infos, p.Erros, p.Veredito, p.Duracao, p.Parcial, []byte(p.Relatorio))
	if err != nil {
		recusa(w, "interno", "nao consegui guardar o relatorio")
		return
	}
	if !p.Parcial {
		s.db.Exec(`update scanner_licencas set consumida_em = now() where id = $1`, licencaID)
		s.db.Exec(`update scanner_sessoes set encerrada_em = now() where id = $1`, sessaoID)
	}
	responde(w, 200, map[string]any{"ok": true, "protocolo": protocolo})
}

type linhaDeRelatorio struct {
	Protocolo string `json:"protocolo"`
	Jogador   string `json:"jogador"`
	Staff     string `json:"staff"`
	Maquina   string `json:"maquina"`
	Usuario   string `json:"usuario"`
	Versao    string `json:"versao"`
	Criticos  int    `json:"criticos"`
	Alertas   int    `json:"alertas"`
	Infos     int    `json:"infos"`
	Erros     int    `json:"erros"`
	Veredito  string `json:"veredito"`
	Duracao   string `json:"duracao"`
	Parcial   bool   `json:"parcial"`
	CriadoEm  string `json:"criado_em"`
}

func (s *Servico) listarRelatorios(w http.ResponseWriter, r *http.Request) {
	if !s.exige(w, r) {
		return
	}
	linhas, err := s.db.Query(`select protocolo, jogador, staff, maquina, usuario, versao,
			criticos, alertas, infos, erros, veredito, duracao, parcial, criado_em
		from scanner_relatorios order by criado_em desc limit 200`)
	if err != nil {
		responde(w, 500, map[string]any{"ok": false, "erro": err.Error()})
		return
	}
	defer linhas.Close()
	lista := []linhaDeRelatorio{}
	for linhas.Next() {
		var v linhaDeRelatorio
		var criado time.Time
		if err := linhas.Scan(&v.Protocolo, &v.Jogador, &v.Staff, &v.Maquina, &v.Usuario, &v.Versao,
			&v.Criticos, &v.Alertas, &v.Infos, &v.Erros, &v.Veredito, &v.Duracao, &v.Parcial, &criado); err != nil {
			continue
		}
		v.CriadoEm = criado.Local().Format("02/01 15:04")
		lista = append(lista, v)
	}
	responde(w, 200, map[string]any{"ok": true, "relatorios": lista})
}

func (s *Servico) verRelatorio(w http.ResponseWriter, r *http.Request) {
	if !s.exige(w, r) {
		return
	}
	var p struct {
		Protocolo string `json:"protocolo"`
	}
	if err := leCorpo(r, &p); err != nil {
		responde(w, 400, map[string]any{"ok": false, "erro": "pedido invalido"})
		return
	}
	var dados []byte
	var v linhaDeRelatorio
	var criado time.Time
	err := s.db.QueryRow(`select dados, protocolo, jogador, staff, maquina, usuario, versao,
			criticos, alertas, infos, erros, veredito, duracao, parcial, criado_em
		from scanner_relatorios where protocolo = $1`, strings.ToUpper(strings.TrimSpace(p.Protocolo))).
		Scan(&dados, &v.Protocolo, &v.Jogador, &v.Staff, &v.Maquina, &v.Usuario, &v.Versao,
			&v.Criticos, &v.Alertas, &v.Infos, &v.Erros, &v.Veredito, &v.Duracao, &v.Parcial, &criado)
	if err != nil {
		responde(w, 404, map[string]any{"ok": false, "erro": "relatorio nao encontrado"})
		return
	}
	v.CriadoEm = criado.Local().Format("02/01/2006 15:04")
	responde(w, 200, map[string]any{"ok": true, "resumo": v, "relatorio": json.RawMessage(dados)})
}

func (s *Servico) paginaRelatorio(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(paginaDoRelatorio)
}
