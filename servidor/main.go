package main

import (
	"compress/gzip"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const versaoDoServico = "1.0.0"

type Servico struct {
	db      *sql.DB
	senha   string
	mu      sync.Mutex
	sessoes map[string]time.Time
}

func main() {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		log.Fatal("defina DATABASE_URL")
	}
	senha := os.Getenv("PAINEL_SENHA")
	if senha == "" {
		log.Fatal("defina PAINEL_SENHA")
	}
	porta := os.Getenv("PORTA")
	if porta == "" {
		porta = "8090"
	}

	db, err := sql.Open("pgx", url)
	if err != nil {
		log.Fatal(err)
	}
	if err := db.Ping(); err != nil {
		log.Fatal("nao consegui falar com o postgres: ", err)
	}
	s := &Servico{db: db, senha: senha, sessoes: map[string]time.Time{}}
	if err := s.migrar(); err != nil {
		log.Fatal("migracao: ", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sessao", s.abrirSessao)
	mux.HandleFunc("/v1/encerrar", s.encerrarSessao)
	mux.HandleFunc("/v1/relatorio", s.receberRelatorio)
	mux.HandleFunc("/v1/assinaturas", s.entregarAssinaturas)
	mux.HandleFunc("/v1/saude", func(w http.ResponseWriter, r *http.Request) {
		responde(w, 200, map[string]any{"ok": true, "versao": versaoDoServico})
	})
	mux.HandleFunc("/", s.painel)
	mux.HandleFunc("/painel/entrar", s.entrar)
	mux.HandleFunc("/painel/dados", s.dados)
	mux.HandleFunc("/painel/gerar", s.gerar)
	mux.HandleFunc("/painel/revogar", s.revogar)
	mux.HandleFunc("/painel/versao-minima", s.versaoMinima)
	mux.HandleFunc("/painel/assinaturas", s.receberAssinaturas)
	mux.HandleFunc("/painel/relatorios", s.listarRelatorios)
	mux.HandleFunc("/painel/relatorio", s.verRelatorio)
	mux.HandleFunc("/r/", s.paginaRelatorio)

	log.Println("scanner-auth", versaoDoServico, "escutando na porta", porta)
	servidor := &http.Server{
		Addr:              ":" + porta,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Fatal(servidor.ListenAndServe())
}

func (s *Servico) migrar() error {
	comandos := []string{
		`create table if not exists scanner_licencas (
			id bigserial primary key,
			codigo text unique not null,
			jogador text not null default '',
			staff text not null default '',
			observacao text not null default '',
			criado_em timestamptz not null default now(),
			expira_em timestamptz not null,
			usado_em timestamptz,
			hwid text,
			maquina text,
			revogada boolean not null default false
		)`,
		`create table if not exists scanner_sessoes (
			id bigserial primary key,
			licenca_id bigint not null references scanner_licencas(id) on delete cascade,
			token text unique not null,
			hwid text not null,
			maquina text not null default '',
			usuario text not null default '',
			versao text not null default '',
			ip text not null default '',
			criado_em timestamptz not null default now(),
			expira_em timestamptz not null,
			encerrada_em timestamptz
		)`,
		`create table if not exists scanner_relatorios (
			id bigserial primary key,
			protocolo text unique not null,
			licenca_id bigint references scanner_licencas(id) on delete set null,
			sessao_id bigint references scanner_sessoes(id) on delete set null,
			jogador text not null default '',
			staff text not null default '',
			maquina text not null default '',
			usuario text not null default '',
			versao text not null default '',
			criticos int not null default 0,
			alertas int not null default 0,
			infos int not null default 0,
			erros int not null default 0,
			veredito text not null default '',
			duracao text not null default '',
			parcial boolean not null default false,
			criado_em timestamptz not null default now(),
			dados jsonb not null
		)`,
		`alter table scanner_licencas add column if not exists consumida_em timestamptz`,
		`create table if not exists scanner_painel_sessoes (
			token text primary key,
			criado_em timestamptz not null default now(),
			expira_em timestamptz not null
		)`,
		`create table if not exists scanner_config (chave text primary key, valor text not null)`,
		`insert into scanner_config (chave, valor) values ('versao_minima', '0.0.0') on conflict do nothing`,
		`create index if not exists scanner_sessoes_licenca on scanner_sessoes (licenca_id)`,
	}
	for _, c := range comandos {
		if _, err := s.db.Exec(c); err != nil {
			return err
		}
	}
	return nil
}

const alfabetoDoCodigo = "ACDEFGHJKLMNPQRTUVWXYZ34679"

func novoCodigo() string {
	bloco := func(n int) string {
		var b strings.Builder
		for i := 0; i < n; i++ {
			k, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alfabetoDoCodigo))))
			b.WriteByte(alfabetoDoCodigo[k.Int64()])
		}
		return b.String()
	}
	return "FLD-" + bloco(4) + "-" + bloco(4)
}

func novoToken() string {
	b := make([]byte, 24)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func responde(w http.ResponseWriter, status int, corpo any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(corpo)
}

func recusa(w http.ResponseWriter, motivo, mensagem string) {
	responde(w, 200, map[string]any{"ok": false, "motivo": motivo, "erro": mensagem})
}

func leCorpo(r *http.Request, destino any) error {
	return leCorpoAte(r, destino, 1<<20)
}

func leCorpoAte(r *http.Request, destino any, limite int64) error {
	if r.Method != http.MethodPost {
		return errors.New("use POST")
	}
	r.Body = http.MaxBytesReader(nil, r.Body, limite)
	corpo := io.Reader(r.Body)
	if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
		z, err := gzip.NewReader(r.Body)
		if err != nil {
			return err
		}
		defer z.Close()
		corpo = io.LimitReader(z, limite*20)
	}
	return json.NewDecoder(corpo).Decode(destino)
}

func enderecoDe(r *http.Request) string {
	if v := r.Header.Get("CF-Connecting-IP"); v != "" {
		return v
	}
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		return strings.TrimSpace(strings.Split(v, ",")[0])
	}
	return strings.Split(r.RemoteAddr, ":")[0]
}

func versaoAceita(atual, minima string) bool {
	parte := func(v string) []int {
		var n []int
		for _, p := range strings.Split(strings.TrimSpace(v), ".") {
			x, _ := strconv.Atoi(strings.TrimFunc(p, func(r rune) bool { return r < '0' || r > '9' }))
			n = append(n, x)
		}
		for len(n) < 3 {
			n = append(n, 0)
		}
		return n
	}
	a, m := parte(atual), parte(minima)
	for i := 0; i < 3; i++ {
		if a[i] != m[i] {
			return a[i] > m[i]
		}
	}
	return true
}

func (s *Servico) config(chave string) string {
	var v string
	s.db.QueryRow(`select valor from scanner_config where chave = $1`, chave).Scan(&v)
	return v
}

type pedidoDeSessao struct {
	Codigo  string `json:"codigo"`
	HWID    string `json:"hwid"`
	Versao  string `json:"versao"`
	Maquina string `json:"maquina"`
	Usuario string `json:"usuario"`
}

func (s *Servico) abrirSessao(w http.ResponseWriter, r *http.Request) {
	var p pedidoDeSessao
	if err := leCorpo(r, &p); err != nil {
		recusa(w, "pedido", "pedido invalido")
		return
	}
	p.Codigo = strings.ToUpper(strings.TrimSpace(p.Codigo))
	if p.Codigo == "" || p.HWID == "" {
		recusa(w, "pedido", "informe o codigo de autorizacao")
		return
	}
	minima := s.config("versao_minima")
	if minima != "" && !versaoAceita(p.Versao, minima) {
		recusa(w, "versao", fmt.Sprintf("esta versao do scanner (%s) foi aposentada. Baixe a versao %s ou mais nova com a equipe", p.Versao, minima))
		return
	}

	tx, err := s.db.Begin()
	if err != nil {
		recusa(w, "interno", "erro interno")
		return
	}
	defer tx.Rollback()

	var id int64
	var expira time.Time
	var usado sql.NullTime
	var hwid sql.NullString
	var revogada bool
	var jogador, staff string
	var consumida sql.NullTime
	err = tx.QueryRow(`select id, expira_em, usado_em, hwid, revogada, jogador, staff, consumida_em
		from scanner_licencas where codigo = $1 for update`, p.Codigo).
		Scan(&id, &expira, &usado, &hwid, &revogada, &jogador, &staff, &consumida)
	if err == sql.ErrNoRows {
		recusa(w, "codigo", "codigo nao existe. Peca um novo para a equipe")
		return
	}
	if err != nil {
		recusa(w, "interno", "erro interno")
		return
	}
	if revogada {
		recusa(w, "revogada", "este codigo foi cancelado pela equipe")
		return
	}
	if time.Now().After(expira) {
		recusa(w, "expirada", "este codigo venceu. Peca um novo para a equipe")
		return
	}
	if consumida.Valid {
		recusa(w, "consumida", "este codigo ja foi usado e o relatorio dele ja foi entregue. Peca um novo para a equipe")
		return
	}
	if hwid.Valid && hwid.String != p.HWID {
		recusa(w, "outro_pc", "este codigo ja foi usado em outro computador")
		return
	}

	token := novoToken()
	validade := time.Now().Add(6 * time.Hour)
	if _, err := tx.Exec(`update scanner_licencas set usado_em = coalesce(usado_em, now()), hwid = $2, maquina = $3 where id = $1`,
		id, p.HWID, p.Maquina); err != nil {
		recusa(w, "interno", "erro interno")
		return
	}
	if _, err := tx.Exec(`insert into scanner_sessoes (licenca_id, token, hwid, maquina, usuario, versao, ip, expira_em)
		values ($1,$2,$3,$4,$5,$6,$7,$8)`,
		id, token, p.HWID, p.Maquina, p.Usuario, p.Versao, enderecoDe(r), validade); err != nil {
		recusa(w, "interno", "erro interno")
		return
	}
	if err := tx.Commit(); err != nil {
		recusa(w, "interno", "erro interno")
		return
	}
	responde(w, 200, map[string]any{
		"ok": true, "token": token, "expira_em": validade.Format(time.RFC3339),
		"jogador": jogador, "staff": staff,
	})
}

func (s *Servico) encerrarSessao(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Token string `json:"token"`
	}
	if err := leCorpo(r, &p); err != nil || p.Token == "" {
		recusa(w, "pedido", "pedido invalido")
		return
	}
	s.db.Exec(`update scanner_sessoes set encerrada_em = now() where token = $1 and encerrada_em is null`, p.Token)
	responde(w, 200, map[string]any{"ok": true})
}
