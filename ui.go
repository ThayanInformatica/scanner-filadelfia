package main

import (
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

//go:embed ui.html
var paginaHTML []byte

type Servidor struct {
	assinaturas *Assinaturas
	origem      string
	pastaSaida  string
	token       string
	corConsole  bool
	demo        bool
	limiteEtapa time.Duration
	auth        *Autorizacao

	mu        sync.Mutex
	rodando   bool
	modo      string
	historico []Evento
	relatorio *Relatorio
	contexto  *Contexto
	ouvintes  map[chan Evento]bool
	encerrar  chan struct{}
}

func NovoServidor(a *Assinaturas, origem, pastaSaida string) *Servidor {
	b := make([]byte, 16)
	rand.Read(b)
	return &Servidor{
		assinaturas: a,
		auth:        &Autorizacao{},
		origem:      origem,
		pastaSaida:  pastaSaida,
		token:       hex.EncodeToString(b),
		ouvintes:    map[chan Evento]bool{},
		encerrar:    make(chan struct{}),
	}
}

func (s *Servidor) publica(e Evento) {
	s.mu.Lock()
	s.historico = append(s.historico, e)
	ouvintes := make([]chan Evento, 0, len(s.ouvintes))
	for c := range s.ouvintes {
		ouvintes = append(ouvintes, c)
	}
	s.mu.Unlock()
	for _, c := range ouvintes {
		select {
		case c <- e:
		default:
		}
	}
}

func (s *Servidor) estado() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	estado := map[string]any{
		"rodando":        s.rodando,
		"modo":           s.modo,
		"historico":      s.historico,
		"admin":          estaElevado(),
		"windows":        suportaChecagemReal,
		"maquina":        nomeDaMaquina(),
		"usuario":        usuarioAtual(),
		"assinaturas":    s.origem,
		"total_cheats":   len(s.assinaturas.Cheats),
		"total_drivers":  len(s.assinaturas.Drivers),
		"total_dominios": len(s.assinaturas.Dominios),
		"versao":         versao,
		"demo":           s.demo,
		"aceita_codigo":  s.auth.Configurada(),
		"autorizado":     s.auth.Liberado(),
		"autorizacao":    s.auth.Descricao(),
	}
	if s.relatorio != nil && !s.rodando {
		estado["relatorio"] = s.relatorio
	}
	return estado
}

func (s *Servidor) iniciar(modo string, rapido bool) error {
	s.mu.Lock()
	if s.rodando {
		s.mu.Unlock()
		return fmt.Errorf("ja existe uma checagem em andamento")
	}
	s.rodando = true
	s.modo = modo
	s.historico = nil
	s.relatorio = nil
	s.mu.Unlock()

	go s.executar(modo, rapido)
	return nil
}

func (s *Servidor) executar(modo string, rapido bool) {
	r := NovoRelatorio(versao, s.corConsole)
	r.silencioso = false
	r.emitir = s.publica
	fmt.Println()
	fmt.Println(r.pinta(corNegrito+corCiano, ">>> Checagem iniciada pela tela: modo "+modo))

	s.mu.Lock()
	s.relatorio = r
	s.mu.Unlock()

	simulacao := ehSimulacao(modo)
	if simulacao {
		r.Maquina = "PC-SIMULADO"
		r.Usuario = "jogador"
	}

	etapas := etapasDoSistema()
	if simulacao {
		etapas = etapasSimuladas(modo)
	}
	if rapido && !simulacao {
		var filtradas []Etapa
		for _, e := range etapas {
			if !e.Pesada {
				filtradas = append(filtradas, e)
			}
		}
		etapas = filtradas
	}

	if d := s.auth.Descricao(); d != "" {
		r.Linha("%s", d)
	}
	s.mu.Lock()
	assinaturas := s.assinaturas
	s.mu.Unlock()
	c := &Contexto{R: r, A: assinaturas, Rapido: rapido, LimiteEtapa: s.limiteEtapa}
	if rapido {
		c.LimiteEtapa = 2 * time.Minute
	}
	s.mu.Lock()
	s.contexto = c
	s.mu.Unlock()
	s.publica(Evento{Tipo: "inicio", Texto: modo, Total: len(etapas)})

	for i, etapa := range etapas {
		r.Etapas(etapa.Nome, i+1, len(etapas))
		c.ComecaEtapa()
		executaProtegido(r, etapa.Nome, etapa.Fn, c)
		if c.DevePular() {
			r.Add(Alerta, "ETAPA PULADA A PEDIDO: "+etapa.Nome, "Alguem clicou em pular durante esta etapa, entao ela nao terminou. O que ela mediria ficou de fora deste relatorio")
			r.MarcaIncompleta(etapa.Nome)
		}
	}

	r.Resumo()
	txt, js, err := r.Salvar(s.pastaSaida)
	if err != nil {
		r.Erro("salvar relatorio: %v", err)
	}

	s.mu.Lock()
	s.rodando = false
	s.mu.Unlock()

	protocolo, envio := "", ""
	if s.auth.Liberado() {
		r.Progresso("Enviando o relatorio para a equipe...")
		p, err := s.auth.EnviarRelatorio(r, time.Since(r.inicio).Round(time.Second).String(), false)
		if err != nil {
			envio = err.Error()
			r.Add(Alerta, "NAO CONSEGUI ENVIAR O RELATORIO PARA A EQUIPE", "O arquivo local continua valendo, mas a equipe nao recebeu a copia pelo servidor.\n"+envio)
		} else {
			protocolo = p
		}
	}

	dados, _ := json.Marshal(map[string]any{
		"criticos":    r.Criticos,
		"alertas":     r.Alertas,
		"infos":       r.Infos,
		"erros":       len(r.Erros),
		"veredito":    r.Veredito,
		"caminho_txt": txt,
		"caminho_js":  js,
		"duracao":     time.Since(r.inicio).Round(time.Second).String(),
		"protocolo":   protocolo,
		"erro_envio":  envio,
	})
	s.publica(Evento{Tipo: "fim", Texto: string(dados)})
	fmt.Println(r.pinta(corNegrito+corCiano, ">>> Checagem concluida. Relatorio: "+txt))
}

func (s *Servidor) atualizarAssinaturas() {
	bruto, err := s.auth.BaixarAssinaturas()
	if err != nil || len(bruto) == 0 {
		if err != nil {
			fmt.Println("aviso: " + err.Error() + ". Seguindo com a lista local")
		}
		return
	}
	novas, origem, err := AssinaturasDeBytes(bruto, "servidor da equipe")
	if err != nil {
		fmt.Println("aviso: lista de assinaturas do servidor veio invalida:", err)
		return
	}
	s.mu.Lock()
	s.assinaturas = novas
	s.origem = origem
	s.mu.Unlock()
}

func (s *Servidor) autorizado(req *http.Request) bool {
	if req.URL.Query().Get("t") == s.token {
		return true
	}
	return req.Header.Get("X-Token") == s.token
}

func (s *Servidor) rotas() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/" {
			http.NotFound(w, req)
			return
		}
		if !s.autorizado(req) {
			http.Error(w, "token invalido", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(paginaHTML)
	})

	mux.HandleFunc("/api/estado", func(w http.ResponseWriter, req *http.Request) {
		if !s.autorizado(req) {
			http.Error(w, "token invalido", http.StatusForbidden)
			return
		}
		escreveJSON(w, s.estado())
	})

	mux.HandleFunc("/api/iniciar", func(w http.ResponseWriter, req *http.Request) {
		if !s.autorizado(req) {
			http.Error(w, "token invalido", http.StatusForbidden)
			return
		}
		modo := req.URL.Query().Get("modo")
		rapido := req.URL.Query().Get("rapido") == "1"
		if modo == "" {
			modo = "completo"
		}
		if ehSimulacao(modo) && !s.demo {
			escreveJSON(w, map[string]any{"ok": false, "erro": "modo de demonstracao desligado"})
			return
		}
		if err := s.iniciar(modo, rapido); err != nil {
			escreveJSON(w, map[string]any{"ok": false, "erro": err.Error()})
			return
		}
		escreveJSON(w, map[string]any{"ok": true, "modo": modo})
	})

	mux.HandleFunc("/api/eventos", func(w http.ResponseWriter, req *http.Request) {
		if !s.autorizado(req) {
			http.Error(w, "token invalido", http.StatusForbidden)
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming nao suportado", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		canal := make(chan Evento, 512)
		s.mu.Lock()
		s.ouvintes[canal] = true
		s.mu.Unlock()
		defer func() {
			s.mu.Lock()
			delete(s.ouvintes, canal)
			s.mu.Unlock()
		}()

		pulso := time.NewTicker(20 * time.Second)
		defer pulso.Stop()
		for {
			select {
			case <-req.Context().Done():
				return
			case <-pulso.C:
				fmt.Fprint(w, ": ping\n\n")
				flusher.Flush()
			case e := <-canal:
				dados, _ := json.Marshal(e)
				fmt.Fprintf(w, "data: %s\n\n", dados)
				flusher.Flush()
			}
		}
	})

	mux.HandleFunc("/api/abrir", func(w http.ResponseWriter, req *http.Request) {
		if !s.autorizado(req) {
			http.Error(w, "token invalido", http.StatusForbidden)
			return
		}
		s.mu.Lock()
		r := s.relatorio
		s.mu.Unlock()
		if r == nil || r.CaminhoTxt == "" {
			escreveJSON(w, map[string]any{"ok": false, "erro": "nenhum relatorio salvo ainda"})
			return
		}
		var err error
		if req.URL.Query().Get("alvo") == "pasta" {
			err = selecionarNoExplorer(r.CaminhoTxt)
		} else {
			err = abrirNoSistema(r.CaminhoTxt)
		}
		if err != nil {
			escreveJSON(w, map[string]any{"ok": false, "erro": err.Error()})
			return
		}
		escreveJSON(w, map[string]any{"ok": true})
	})

	mux.HandleFunc("/api/relatorio.txt", func(w http.ResponseWriter, req *http.Request) {
		if !s.autorizado(req) {
			http.Error(w, "token invalido", http.StatusForbidden)
			return
		}
		s.mu.Lock()
		r := s.relatorio
		s.mu.Unlock()
		if r == nil {
			http.Error(w, "nenhum relatorio", http.StatusNotFound)
			return
		}
		cabecalho := fmt.Sprintf("Scanner Filadelfia %s\nMaquina: %s   Usuario: %s   Gerado em: %s\n", r.Versao, r.Maquina, r.Usuario, r.GeradoEm.Format("02/01/2006 15:04:05"))
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(cabecalho + r.texto.String()))
	})

	mux.HandleFunc("/api/entrar", func(w http.ResponseWriter, req *http.Request) {
		if !s.autorizado(req) {
			http.Error(w, "token invalido", http.StatusForbidden)
			return
		}
		if err := s.auth.Entrar(req.URL.Query().Get("codigo")); err != nil {
			escreveJSON(w, map[string]any{"ok": false, "erro": err.Error()})
			return
		}
		s.atualizarAssinaturas()
		escreveJSON(w, map[string]any{"ok": true, "autorizacao": s.auth.Descricao(), "assinaturas": s.origem})
	})

	mux.HandleFunc("/api/pular", func(w http.ResponseWriter, req *http.Request) {
		if !s.autorizado(req) {
			http.Error(w, "token invalido", http.StatusForbidden)
			return
		}
		s.mu.Lock()
		c := s.contexto
		rodando := s.rodando
		s.mu.Unlock()
		if !rodando || c == nil {
			escreveJSON(w, map[string]any{"ok": false, "erro": "nao ha checagem rodando"})
			return
		}
		c.PedirParaPular()
		escreveJSON(w, map[string]any{"ok": true})
	})

	mux.HandleFunc("/api/revelar", func(w http.ResponseWriter, req *http.Request) {
		if !s.autorizado(req) {
			http.Error(w, "token invalido", http.StatusForbidden)
			return
		}
		caminho := strings.TrimSpace(req.URL.Query().Get("caminho"))
		if caminho == "" {
			escreveJSON(w, map[string]any{"ok": false, "erro": "caminho vazio"})
			return
		}
		info, err := os.Stat(caminho)
		if err != nil {
			pai := filepath.Dir(caminho)
			if _, errPai := os.Stat(pai); errPai != nil {
				escreveJSON(w, map[string]any{"ok": false, "erro": "esse arquivo nao existe mais no disco"})
				return
			}
			if err := abrirNoSistema(pai); err != nil {
				escreveJSON(w, map[string]any{"ok": false, "erro": err.Error()})
				return
			}
			escreveJSON(w, map[string]any{"ok": true, "aviso": "o arquivo nao existe mais, abri a pasta onde ele estava"})
			return
		}
		var erroAbrir error
		if info.IsDir() {
			erroAbrir = abrirNoSistema(caminho)
		} else {
			erroAbrir = selecionarNoExplorer(caminho)
		}
		if erroAbrir != nil {
			escreveJSON(w, map[string]any{"ok": false, "erro": erroAbrir.Error()})
			return
		}
		escreveJSON(w, map[string]any{"ok": true})
	})

	mux.HandleFunc("/api/buscar", func(w http.ResponseWriter, req *http.Request) {
		if !s.autorizado(req) {
			http.Error(w, "token invalido", http.StatusForbidden)
			return
		}
		termo := strings.TrimSpace(req.URL.Query().Get("termo"))
		if len(termo) < 3 {
			escreveJSON(w, map[string]any{"ok": false, "erro": "digite pelo menos 3 letras"})
			return
		}
		s.mu.Lock()
		c := s.contexto
		rodando := s.rodando
		s.mu.Unlock()
		if rodando {
			escreveJSON(w, map[string]any{"ok": false, "erro": "espere a checagem terminar"})
			return
		}
		if c == nil {
			c = &Contexto{R: NovoRelatorio(versao, false), A: s.assinaturas}
			c.R.silencioso = true
			preencherPerfis(c)
		}
		res := buscaLivre(c, termo)
		escreveJSON(w, map[string]any{"ok": true, "resultado": res})
	})

	mux.HandleFunc("/api/sair", func(w http.ResponseWriter, req *http.Request) {
		if !s.autorizado(req) {
			http.Error(w, "token invalido", http.StatusForbidden)
			return
		}
		escreveJSON(w, map[string]any{"ok": true})
		go func() {
			time.Sleep(400 * time.Millisecond)
			close(s.encerrar)
		}()
	})

	return mux
}

func (s *Servidor) Servir(porta int, abrirNavegador bool) (string, error) {
	ouvinte, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", porta))
	if err != nil && porta != 0 {
		ouvinte, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		return "", err
	}
	endereco := fmt.Sprintf("http://127.0.0.1:%d/?t=%s", ouvinte.Addr().(*net.TCPAddr).Port, s.token)
	servidor := &http.Server{Handler: s.rotas()}

	go servidor.Serve(ouvinte)
	if abrirNavegador {
		go func() {
			time.Sleep(300 * time.Millisecond)
			abrirNoSistema(endereco)
		}()
	}
	return endereco, nil
}

func (s *Servidor) Espera() {
	<-s.encerrar
}

func escreveJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}

func nomeDaMaquina() string {
	nome, err := os.Hostname()
	if err != nil || strings.TrimSpace(nome) == "" {
		return "desconhecido"
	}
	return nome
}
