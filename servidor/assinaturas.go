package main

import (
	"encoding/json"
	"net/http"
	"time"
)

func (s *Servico) entregarAssinaturas(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Token string `json:"token"`
	}
	if err := leCorpo(r, &p); err != nil || p.Token == "" {
		recusa(w, "pedido", "pedido invalido")
		return
	}
	var expira time.Time
	if err := s.db.QueryRow(`select expira_em from scanner_sessoes where token = $1 and encerrada_em is null`, p.Token).Scan(&expira); err != nil {
		recusa(w, "token", "sessao nao encontrada")
		return
	}
	if time.Now().After(expira) {
		recusa(w, "expirada", "sessao vencida")
		return
	}
	bruto := s.config("assinaturas")
	if bruto == "" {
		recusa(w, "vazio", "a equipe ainda nao subiu a lista de assinaturas")
		return
	}
	responde(w, 200, map[string]any{"ok": true, "assinaturas": json.RawMessage(bruto)})
}

func (s *Servico) receberAssinaturas(w http.ResponseWriter, r *http.Request) {
	if !s.exige(w, r) {
		return
	}
	var p struct {
		Assinaturas json.RawMessage `json:"assinaturas"`
	}
	if err := leCorpoAte(r, &p, 16<<20); err != nil {
		responde(w, 400, map[string]any{"ok": false, "erro": "pedido invalido"})
		return
	}
	var teste struct {
		Cheats   []string `json:"cheats"`
		Marcas   []string `json:"marcas"`
		Dominios []string `json:"dominios"`
	}
	if err := json.Unmarshal(p.Assinaturas, &teste); err != nil {
		responde(w, 200, map[string]any{"ok": false, "erro": "esse arquivo nao e um assinaturas.json valido"})
		return
	}
	if len(teste.Cheats) == 0 {
		responde(w, 200, map[string]any{"ok": false, "erro": "a lista veio sem nenhum cheat, nao vou substituir"})
		return
	}
	if _, err := s.db.Exec(`insert into scanner_config (chave, valor) values ('assinaturas', $1)
		on conflict (chave) do update set valor = excluded.valor`, string(p.Assinaturas)); err != nil {
		responde(w, 500, map[string]any{"ok": false, "erro": err.Error()})
		return
	}
	s.db.Exec(`insert into scanner_config (chave, valor) values ('assinaturas_em', $1)
		on conflict (chave) do update set valor = excluded.valor`, time.Now().Format(time.RFC3339))
	responde(w, 200, map[string]any{"ok": true, "cheats": len(teste.Cheats), "marcas": len(teste.Marcas), "dominios": len(teste.Dominios)})
}

func (s *Servico) resumoDasAssinaturas() map[string]any {
	bruto := s.config("assinaturas")
	if bruto == "" {
		return map[string]any{"tem": false}
	}
	var teste struct {
		Cheats   []string `json:"cheats"`
		Marcas   []string `json:"marcas"`
		Dominios []string `json:"dominios"`
	}
	json.Unmarshal([]byte(bruto), &teste)
	atualizado := ""
	if v := s.config("assinaturas_em"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			atualizado = t.Local().Format("02/01/2006 15:04")
		}
	}
	return map[string]any{
		"tem": true, "cheats": len(teste.Cheats), "marcas": len(teste.Marcas),
		"dominios": len(teste.Dominios), "atualizado": atualizado,
	}
}
