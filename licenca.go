package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

var apiPadrao = ""

type Autorizacao struct {
	API string

	mu      sync.Mutex
	token   string
	expira  time.Time
	jogador string
	staff   string
}

type respostaDeSessao struct {
	OK      bool   `json:"ok"`
	Token   string `json:"token"`
	Expira  string `json:"expira_em"`
	Jogador string `json:"jogador"`
	Staff   string `json:"staff"`
	Motivo  string `json:"motivo"`
	Erro    string `json:"erro"`
}

func (a *Autorizacao) Exigida() bool {
	return a != nil && strings.TrimSpace(a.API) != ""
}

func (a *Autorizacao) Liberado() bool {
	if !a.Exigida() {
		return true
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.token != "" && time.Now().Before(a.expira)
}

func (a *Autorizacao) Descricao() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.token == "" {
		return ""
	}
	partes := []string{"Autorizado pela equipe"}
	if a.jogador != "" {
		partes = append(partes, "jogador informado: "+a.jogador)
	}
	if a.staff != "" {
		partes = append(partes, "liberado por: "+a.staff)
	}
	return strings.Join(partes, ", ")
}

func (a *Autorizacao) Entrar(codigo string) error {
	if !a.Exigida() {
		return nil
	}
	codigo = strings.ToUpper(strings.TrimSpace(codigo))
	if codigo == "" {
		return fmt.Errorf("digite o codigo que a equipe passou")
	}
	corpo, _ := json.Marshal(map[string]string{
		"codigo":  codigo,
		"hwid":    identificadorDoPC(),
		"versao":  versao,
		"maquina": nomeDaMaquina(),
		"usuario": usuarioAtual(),
	})
	cliente := &http.Client{Timeout: 20 * time.Second}
	resp, err := cliente.Post(strings.TrimRight(a.API, "/")+"/v1/sessao", "application/json", bytes.NewReader(corpo))
	if err != nil {
		return fmt.Errorf("nao consegui falar com o servidor da equipe. Confira a internet e tente de novo")
	}
	defer resp.Body.Close()
	var r respostaDeSessao
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return fmt.Errorf("o servidor da equipe respondeu de um jeito que nao entendi")
	}
	if !r.OK {
		if r.Erro != "" {
			return fmt.Errorf("%s", r.Erro)
		}
		return fmt.Errorf("codigo recusado pelo servidor da equipe")
	}
	expira, err := time.Parse(time.RFC3339, r.Expira)
	if err != nil {
		expira = time.Now().Add(6 * time.Hour)
	}
	a.mu.Lock()
	a.token, a.expira, a.jogador, a.staff = r.Token, expira, r.Jogador, r.Staff
	a.mu.Unlock()
	return nil
}

func (a *Autorizacao) Encerrar() {
	if !a.Exigida() {
		return
	}
	a.mu.Lock()
	token := a.token
	a.token = ""
	a.mu.Unlock()
	if token == "" {
		return
	}
	corpo, _ := json.Marshal(map[string]string{"token": token})
	cliente := &http.Client{Timeout: 5 * time.Second}
	resp, err := cliente.Post(strings.TrimRight(a.API, "/")+"/v1/encerrar", "application/json", bytes.NewReader(corpo))
	if err == nil {
		resp.Body.Close()
	}
}

func identificadorDoPC() string {
	soma := sha256.Sum256([]byte("scanner-filadelfia|" + marcasDoHardware()))
	return hex.EncodeToString(soma[:])[:32]
}

type respostaDeRelatorio struct {
	OK        bool   `json:"ok"`
	Protocolo string `json:"protocolo"`
	Erro      string `json:"erro"`
}

func (a *Autorizacao) EnviarRelatorio(r *Relatorio, duracao string, parcial bool) (string, error) {
	if !a.Exigida() {
		return "", nil
	}
	a.mu.Lock()
	token := a.token
	a.mu.Unlock()
	if token == "" {
		return "", fmt.Errorf("sem sessao aberta com o servidor da equipe")
	}
	bruto, err := json.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("nao consegui montar o relatorio para envio")
	}
	corpo, _ := json.Marshal(map[string]any{
		"token": token, "relatorio": json.RawMessage(bruto),
		"criticos": r.Criticos, "alertas": r.Alertas, "infos": r.Infos, "erros": len(r.Erros),
		"veredito": r.Veredito, "duracao": duracao, "maquina": r.Maquina, "usuario": r.Usuario,
		"versao": r.Versao, "parcial": parcial,
	})
	var comprimido bytes.Buffer
	z := gzip.NewWriter(&comprimido)
	z.Write(corpo)
	z.Close()

	pedido, err := http.NewRequest(http.MethodPost, strings.TrimRight(a.API, "/")+"/v1/relatorio", bytes.NewReader(comprimido.Bytes()))
	if err != nil {
		return "", fmt.Errorf("nao consegui montar o envio do relatorio")
	}
	pedido.Header.Set("Content-Type", "application/json")
	pedido.Header.Set("Content-Encoding", "gzip")
	cliente := &http.Client{Timeout: 10 * time.Minute}
	var resp *http.Response
	for tentativa := 1; tentativa <= 3; tentativa++ {
		pedido.Body = io.NopCloser(bytes.NewReader(comprimido.Bytes()))
		resp, err = cliente.Do(pedido)
		if err == nil {
			break
		}
		if tentativa < 3 {
			time.Sleep(time.Duration(tentativa*5) * time.Second)
		}
	}
	if err != nil {
		return "", fmt.Errorf("nao consegui enviar o relatorio para a equipe depois de 3 tentativas: %v", err)
	}
	defer resp.Body.Close()
	var rr respostaDeRelatorio
	if err := json.NewDecoder(resp.Body).Decode(&rr); err != nil {
		return "", fmt.Errorf("o servidor da equipe respondeu de um jeito que nao entendi")
	}
	if !rr.OK {
		return "", fmt.Errorf("%s", rr.Erro)
	}
	return rr.Protocolo, nil
}

func (a *Autorizacao) BaixarAssinaturas() ([]byte, error) {
	if !a.Exigida() {
		return nil, nil
	}
	a.mu.Lock()
	token := a.token
	a.mu.Unlock()
	if token == "" {
		return nil, fmt.Errorf("sem sessao aberta com o servidor da equipe")
	}
	corpo, _ := json.Marshal(map[string]string{"token": token})
	cliente := &http.Client{Timeout: 60 * time.Second}
	resp, err := cliente.Post(strings.TrimRight(a.API, "/")+"/v1/assinaturas", "application/json", bytes.NewReader(corpo))
	if err != nil {
		return nil, fmt.Errorf("nao consegui baixar a lista de assinaturas: %v", err)
	}
	defer resp.Body.Close()
	var r struct {
		OK          bool            `json:"ok"`
		Assinaturas json.RawMessage `json:"assinaturas"`
		Erro        string          `json:"erro"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, fmt.Errorf("resposta da lista de assinaturas veio quebrada")
	}
	if !r.OK {
		return nil, fmt.Errorf("%s", r.Erro)
	}
	return r.Assinaturas, nil
}
