package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const versao = "2.13.1"

func main() {
	exe, _ := os.Executable()
	pastaExe := filepath.Dir(exe)

	assinaturasPadrao := filepath.Join(pastaExe, "assinaturas.json")
	caminhoAssinaturas := flag.String("assinaturas", assinaturasPadrao, "arquivo JSON com as assinaturas (nomes de cheat, ferramentas, dominios, drivers)")
	saida := flag.String("saida", pastaExe, "pasta onde salvar o relatorio .txt e .json")
	console := flag.Bool("console", false, "roda no modo texto antigo, sem abrir a tela")
	simular := flag.String("simular", "", "abre a tela e roda um cenario de demonstracao: ativo, fechou, suspeito, rastros ou limpo")
	porta := flag.Int("porta", 8777, "porta local da tela")
	semNavegador := flag.Bool("sem-navegador", false, "nao abre o navegador sozinho, so mostra o endereco")
	rapido := flag.Bool("rapido", false, "pula a varredura de arquivos do disco")
	limiteMin := flag.Int("limite-minutos", 0, "tempo maximo por etapa pesada; 0 = sem limite (padrao), analisa o PC inteiro")
	semPausa := flag.Bool("sem-pausa", false, "nao espera Enter no final (modo console)")
	semElevar := flag.Bool("sem-elevar", false, "nao tenta reabrir como administrador")
	verboso := flag.Bool("verboso", false, "mostra detalhes extras")
	demo := flag.Bool("demo", false, "mostra os botoes de demonstracao na tela (uso interno da equipe)")
	api := flag.String("api", apiPadrao, "endereco do servidor da equipe, usado junto com -codigo")
	codigo := flag.String("codigo", "", "codigo da equipe: baixa a lista atualizada e entrega o relatorio pelo painel")
	exportar := flag.Bool("exportar-assinaturas", false, "grava o assinaturas.json padrao ao lado do exe e sai")
	autodestruir := flag.Bool("autodestruir", false, "ao encerrar, apaga o proprio exe (e o assinaturas.json ao lado); o relatorio salvo e mantido")
	flag.Parse()

	if *exportar {
		a, _, err := CarregarAssinaturas("")
		if err == nil {
			err = a.Exportar(assinaturasPadrao)
		}
		if err != nil {
			fmt.Println("erro:", err)
			os.Exit(1)
		}
		fmt.Println("assinaturas gravadas em", assinaturasPadrao)
		return
	}

	precisaAdmin := suportaChecagemReal && !ehSimulacao(*simular)
	if precisaAdmin && !estaElevado() && !*semElevar {
		fmt.Println("O Windows precisa aprovar a execucao como administrador.")
		fmt.Println("Reabrindo como administrador...")
		if err := relancarElevado(); err != nil {
			fmt.Println("Nao foi possivel elevar:", err)
			fmt.Println("Clique com o botao direito no exe e escolha 'Executar como administrador'.")
			pausa(*semPausa)
			os.Exit(1)
		}
		return
	}

	a, origem, err := CarregarAssinaturas(*caminhoAssinaturas)
	if err != nil {
		fmt.Println("erro nas assinaturas:", err)
		pausa(*semPausa)
		os.Exit(1)
	}
	resumoAssinaturas := fmt.Sprintf("Assinaturas: %s (%d cheats, %d ferramentas, %d limpadores, %d dominios, %d drivers)", origem, len(a.Cheats), len(a.Ferramentas), len(a.Limpeza), len(a.Dominios), len(a.Drivers))

	auth := &Autorizacao{API: *api}

	sidecar := ""
	if info, err := os.Stat(assinaturasPadrao); err == nil && !info.IsDir() {
		sidecar = assinaturasPadrao
	}
	limpar := func() {
		if !*autodestruir {
			return
		}
		if err := agendarAutodestruicao(exe, sidecar); err != nil {
			fmt.Println("nao foi possivel agendar a autodestruicao:", err)
		}
	}

	if *console {
		if auth.Configurada() && *codigo != "" {
			if err := auth.Entrar(*codigo); err != nil {
				fmt.Println("Codigo recusado:", err)
				fmt.Println("Seguindo sem entregar o relatorio para a equipe.")
			} else {
				defer auth.Encerrar()
			}
		}
		if bruto, err := auth.BaixarAssinaturas(); err == nil && len(bruto) > 0 && auth.Liberado() {
			if novas, origem, err := AssinaturasDeBytes(bruto, "servidor da equipe"); err == nil {
				a = novas
				resumoAssinaturas = fmt.Sprintf("Assinaturas: %s (%d cheats, %d ferramentas, %d limpadores, %d dominios, %d drivers)", origem, len(a.Cheats), len(a.Ferramentas), len(a.Limpeza), len(a.Dominios), len(a.Drivers))
			}
		}
		rodarConsole(a, resumoAssinaturas, *saida, *rapido, *verboso, *semPausa, time.Duration(*limiteMin)*time.Minute, auth)
		limpar()
		return
	}

	servidor := NovoServidor(a, origem, *saida)
	servidor.demo = *demo || ehSimulacao(*simular)
	servidor.corConsole = habilitarCoresConsole()
	servidor.limiteEtapa = time.Duration(*limiteMin) * time.Minute
	servidor.auth = auth
	if *codigo != "" {
		if err := auth.Entrar(*codigo); err != nil {
			fmt.Println("Codigo recusado:", err)
		} else {
			servidor.atualizarAssinaturas()
		}
	}
	endereco, err := servidor.Servir(*porta, !*semNavegador)
	if err != nil {
		fmt.Println("nao foi possivel abrir a tela:", err)
		pausa(*semPausa)
		os.Exit(1)
	}

	fmt.Println("SCANNER FILADELFIA " + versao)
	fmt.Println(resumoAssinaturas)
	fmt.Println()
	fmt.Println("Tela aberta em: " + endereco)
	fmt.Println("Deixe esta janela aberta enquanto usa o scanner. Feche-a para encerrar.")

	if ehSimulacao(*simular) {
		servidor.iniciar(*simular, *rapido)
	}
	servidor.Espera()
	auth.Encerrar()
	limpar()
}

func rodarConsole(a *Assinaturas, resumoAssinaturas, saida string, rapido, verboso, semPausa bool, limite time.Duration, auth *Autorizacao) {
	cor := habilitarCoresConsole()
	r := NovoRelatorio(versao, cor)
	fmt.Println(r.pinta(corNegrito+corCiano, "SCANNER FILADELFIA "+versao+"  -  checagem de PC para deteccao de cheat e ocultacao de rastros"))
	if !estaElevado() {
		fmt.Println(r.pinta(corAmarelo, "AVISO: rodando SEM administrador. Varias checagens vao falhar."))
	}
	fmt.Println(r.pinta(corCinza, resumoAssinaturas))

	c := &Contexto{R: r, A: a, Rapido: rapido, Verboso: verboso, LimiteEtapa: limite}
	preencherPerfis(c)
	etapas := etapasDoSistema()
	for i, etapa := range etapas {
		r.Etapas(etapa.Nome, i+1, len(etapas))
		c.ComecaEtapa()
		executaProtegido(r, etapa.Nome, etapa.Fn, c)
	}

	r.Resumo()
	if auth.Liberado() {
		if protocolo, err := auth.EnviarRelatorio(r, time.Since(r.inicio).Round(time.Second).String(), false); err != nil {
			fmt.Println(r.pinta(corAmarelo, "Nao consegui enviar o relatorio para a equipe: "+err.Error()))
		} else {
			fmt.Println(r.pinta(corVerde, "Relatorio entregue para a equipe. Protocolo: "+protocolo))
		}
	}
	txt, js, err := r.Salvar(saida)
	if err != nil {
		fmt.Println(r.pinta(corVermelho, "Nao foi possivel salvar o relatorio: "+err.Error()))
	} else {
		fmt.Println()
		fmt.Println(r.pinta(corNegrito, "Relatorio salvo em:"))
		fmt.Println("  " + txt)
		fmt.Println("  " + js)
	}
	pausa(semPausa)
}

func executaProtegido(r *Relatorio, nome string, fn func(*Contexto), c *Contexto) {
	defer func() {
		if p := recover(); p != nil {
			r.Erro("etapa %s falhou: %v", nome, p)
		}
	}()
	fn(c)
}

func pausa(pular bool) {
	if pular {
		return
	}
	fmt.Print("\nPressione Enter para fechar...")
	leitor := bufio.NewReader(os.Stdin)
	texto, _ := leitor.ReadString('\n')
	_ = strings.TrimSpace(texto)
}
