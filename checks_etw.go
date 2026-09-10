//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const nomeSessaoScanner = "ScannerTrace"

var reLinhaSessao = regexp.MustCompile(`^(\S.*?)\s{2,}(\S+)\s*$`)

func converterEventos(prov string, brutos []evento) []EventoETW {
	var lista []EventoETW
	for _, e := range brutos {
		ev := EventoETW{Provedor: prov, ID: e.ID, Hora: e.Hora, Dados: map[string]string{}}
		for k, v := range e.Dados {
			ev.Dados[k] = v
		}
		lista = append(lista, ev)
	}
	return lista
}

func sessoesETWAtivas() ([]SessaoETW, error) {
	saida, err := executar("logman", "query", "-ets")
	if err != nil && saida == "" {
		return nil, err
	}
	return lerSessoesDoLogman(saida), nil
}

func pararSessaoScanner() {
	executar("logman", "stop", nomeSessaoScanner, "-ets")
}

func comandosDeCaptura(etl string) [][]string {
	base := []string{"create", "trace", nomeSessaoScanner, "-ets",
		"-p", "Microsoft-Windows-Kernel-Process", "0x50", "win:Informational",
		"-p", "Microsoft-Windows-DNS-Client", "0xffffffffffffffff", "win:Informational",
		"-o", etl}
	comBuffer := append(append([]string{}, base...), "-nb", "16", "64", "-bs", "64", "-max", "64", "-f", "bincirc")
	simples := append([]string{}, base...)
	porGUID := []string{"create", "trace", nomeSessaoScanner, "-ets",
		"-p", "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}", "0x50", "win:Informational",
		"-p", "{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}", "0xffffffffffffffff", "win:Informational",
		"-o", etl}
	return [][]string{comBuffer, simples, porGUID}
}

func iniciarSessaoETW(etl string, aoVivo func(string)) (func(), error) {
	var erros []string
	registra := func(modo string, err error, saida string) {
		erros = append(erros, fmt.Sprintf("%s: %v %s", modo, err, resume(paraUTF8(saida), 160)))
	}

	executar("logman", "stop", nomeSessaoScanner)
	executar("logman", "delete", nomeSessaoScanner)
	argsDCS := []string{"create", "trace", nomeSessaoScanner,
		"-p", "Microsoft-Windows-Kernel-Process", "0x50", "win:Informational",
		"-p", "Microsoft-Windows-DNS-Client", "0xffffffffffffffff", "win:Informational",
		"-o", etl, "-f", "bincirc", "-max", "64", "-y"}
	if saida, err := executar("logman", argsDCS...); err == nil {
		if saidaStart, errStart := executar("logman", "start", nomeSessaoScanner); errStart == nil {
			if aoVivo != nil {
				aoVivo("Sessao do kernel iniciada como conjunto de coletores (logman start)")
			}
			return func() {
				executar("logman", "stop", nomeSessaoScanner)
				executar("logman", "delete", nomeSessaoScanner)
			}, nil
		} else {
			registra("logman start", errStart, saidaStart)
			executar("logman", "delete", nomeSessaoScanner)
		}
	} else {
		registra("logman create (conjunto de coletores)", err, saida)
	}

	for i, args := range comandosDeCaptura(etl) {
		saida, err := executar("logman", args...)
		if err == nil {
			if aoVivo != nil {
				aoVivo(fmt.Sprintf("Sessao do kernel iniciada em tempo real (variante %d)", i+1))
			}
			return pararSessaoScanner, nil
		}
		registra(fmt.Sprintf("logman -ets variante %d", i+1), err, saida)
		pararSessaoScanner()
	}
	return nil, fmt.Errorf("iniciar sessao ETW falhou em todas as formas:\n%s", strings.Join(erros, "\n"))
}

func capturarETW(duracao time.Duration, aoVivo func(string), cancelar func() bool) ([]EventoETW, error) {
	pasta, err := os.MkdirTemp("", "scanner-etw-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(pasta)
	etl := pastaDeCapturaDoServico(filepath.Join(pasta, "captura.etl"))
	defer os.Remove(etl)
	xmlSaida := filepath.Join(pasta, "captura.xml")

	pararSessaoScanner()
	parar, err := iniciarSessaoETW(etl, aoVivo)
	if err != nil {
		return nil, err
	}
	defer parar()

	fim := time.Now().Add(duracao)
	marcadores := 0
	for time.Now().Before(fim) {
		if cancelar != nil && cancelar() {
			return nil, errCancelado
		}
		restante := time.Until(fim).Round(time.Second)
		if aoVivo != nil {
			aoVivo(fmt.Sprintf("Gravando eventos do kernel (ImageLoad, ProcessStart, DNS). Faltam %s", restante))
		}
		executar("cmd", "/c", "ver")
		marcadores++
		time.Sleep(2 * time.Second)
	}
	parar()
	if aoVivo != nil {
		aoVivo("Convertendo a captura do kernel para leitura (tracerpt)")
	}
	if _, err := os.Stat(etl); err != nil {
		gerados, _ := filepath.Glob(filepath.Join(filepath.Dir(etl), "scanner-captura*.etl"))
		if len(gerados) == 0 {
			gerados, _ = filepath.Glob(filepath.Join(pasta, "*.etl"))
		}
		if len(gerados) == 0 {
			listagem, _ := os.ReadDir(filepath.Dir(etl))
			var nomes []string
			for _, e := range listagem {
				nomes = append(nomes, e.Name())
			}
			return nil, fmt.Errorf("a sessao rodou mas nao gravou .etl em %s (conteudo da pasta: %s)", filepath.Dir(etl), strings.Join(limitaLinhas(nomes, 12), ", "))
		}
		etl = gerados[0]
	}
	saidaConv, errConv := executar("tracerpt", etl, "-o", xmlSaida, "-of", "XML", "-y")
	if _, err := os.Stat(xmlSaida); err != nil {
		alternativos, _ := filepath.Glob(filepath.Join(pasta, "*.xml"))
		if len(alternativos) > 0 {
			xmlSaida = alternativos[0]
		} else {
			return nil, fmt.Errorf("tracerpt nao gerou o arquivo de leitura: %v %s", errConv, resume(saidaConv, 200))
		}
	}
	arquivo, err := os.Open(xmlSaida)
	if err != nil {
		return nil, err
	}
	defer arquivo.Close()
	return lerEventosTracerpt(arquivo)
}

func contaMarcadores(res resumoETW) int {
	total := 0
	for _, e := range res.ProcessosNovos {
		nome := strings.ToLower(valorDe(e, "ImageName", "ProcessName", "FileName"))
		if strings.HasSuffix(nome, "cmd.exe") {
			total++
		}
	}
	return total
}

func checarETW(c *Contexto) {
	r := c.R
	r.Secao("ETW / KERNEL (rastreamento do proprio Windows)")

	sessoes, err := sessoesETWAtivas()
	if err != nil {
		r.Erro("listar sessoes ETW: %v", err)
	} else {
		r.Linha("%d sessoes de rastreamento ETW ativas no sistema", len(sessoes))
		sinais := avaliarSessoesETW(sessoes)
		for _, s := range sinais {
			r.Add(s.Severidade, s.Titulo, s.Detalhe)
		}
		if len(sinais) == 0 {
			r.Ok("Sessoes ETW essenciais do Windows estao rodando (o sistema ainda registra eventos)")
		}
	}

	var integridade []EventoETW
	for _, canal := range []string{"Microsoft-Windows-CodeIntegrity/Operational", "Microsoft-Windows-CodeIntegrity/Verbose"} {
		brutos, err := consultarEventos(canal, xpathUltimosDias([]int{3004, 3023, 3033, 3077}, 90), 60, true)
		if err != nil {
			continue
		}
		integridade = append(integridade, converterEventos(canal, brutos)...)
	}
	sinaisCI := avaliarEventosDeIntegridade(integridade, c.A)
	for _, s := range sinaisCI {
		r.Add(s.Severidade, s.Titulo, s.Detalhe)
	}
	if len(sinaisCI) == 0 {
		r.Ok("Code Integrity nao registrou driver ou binario nao assinado bloqueado nos ultimos 90 dias")
	}

	if brutos, err := consultarEventos("Microsoft-Windows-Kernel-EventTracing/Admin", xpathUltimosDias([]int{3, 4, 5, 6, 26}, 30), 80, true); err == nil {
		var linhas []string
		for _, e := range brutos {
			nome := e.Dados["SessionName"]
			if nome == "" {
				nome = e.Dados["LoggerName"]
			}
			lower := strings.ToLower(nome)
			if strings.Contains(lower, "scanner") {
				continue
			}
			linha := formataHora(e.Hora) + "  evento " + strconv.Itoa(e.ID) + "  " + nome
			if sessaoDeRotina(lower) {
				linhas = append(linhas, linha)
				continue
			}
			for _, alvo := range []string{"defender", "faceit", "easyanticheat", "vanguard", "battleye", "sysmon", "eventlog"} {
				if strings.Contains(lower, alvo) {
					r.Add(Alerta, "Sessao ETW de seguranca foi PARADA: "+nome, linha+"\nParar a sessao de rastreamento do antivirus ou do anticheat e forma de cegar a protecao sem desinstalar nada")
					break
				}
			}
			linhas = append(linhas, linha)
		}
		if len(linhas) > 0 {
			r.Add(Info, fmt.Sprintf("Sessoes ETW iniciadas/paradas nos ultimos 30 dias: %d", len(linhas)), strings.Join(limitaLinhas(linhas, 100), "\n"))
		}
	}

	if c.Rapido {
		r.Linha("Modo rapido: captura ao vivo do kernel pulada")
		return
	}

	duracao := 20 * time.Second
	inicio := time.Now()
	r.Progresso("Iniciando captura ao vivo do kernel por %s", duracao)
	eventos, err := capturarETW(duracao, func(msg string) { r.Progresso("%s", msg) }, c.DevePular)
	if err == errCancelado {
		r.Linha("Captura ao vivo do kernel interrompida a pedido")
		return
	}
	if err != nil {
		r.Erro("captura ETW ao vivo: %v", err)
		r.Add(Info, "Captura ao vivo do kernel nao pode ser feita neste PC", fmt.Sprintf("%v\nO logman e o tracerpt do Windows nao entregaram a captura. Na maioria das vezes e limitacao da ferramenta, nao indicio. As demais checagens de ETW (sessoes e Code Integrity) rodaram normalmente", err))
		return
	}
	res := resumirETW(eventos)
	r.Linha("Captura do kernel: %d eventos em %s (%d carregamentos de imagem, %d processos novos, %d consultas DNS)", res.Total, time.Since(inicio).Round(time.Second), len(res.Imagens), len(res.ProcessosNovos), len(res.DNS))

	marcadores := contaMarcadores(res)
	if marcadores == 0 {
		r.Add(Critico, "Teste ativo do ETW FALHOU", fmt.Sprintf("Durante a captura o scanner iniciou varios processos de proposito e o kernel nao registrou nenhum deles (%d eventos no total). Isso significa que o rastreamento do Windows esta comprometido: e assim que cheat esconde carregamento de dll e execucao de processo do anticheat", res.Total))
	} else {
		r.Ok("Teste ativo do ETW passou: o kernel registrou os %d processos que o scanner iniciou de proposito", marcadores)
	}

	sinais := avaliarETW(res, c.A, duracao)
	for _, s := range sinais {
		r.Add(s.Severidade, s.Titulo, s.Detalhe)
	}

	var carregadas []string
	vistos := map[string]bool{}
	for _, e := range res.Imagens {
		nome := valorDe(e, "ImageName", "FileName")
		lower := strings.ToLower(nome)
		if nome == "" || vistos[lower] {
			continue
		}
		vistos[lower] = true
		if caminhoDoSistema(nome) || strings.Contains(lower, "fivem.app") {
			continue
		}
		carregadas = append(carregadas, nome)
	}
	if len(carregadas) > 0 {
		r.Add(Info, fmt.Sprintf("DLLs/EXEs fora do Windows carregados durante a captura: %d", len(carregadas)), strings.Join(limitaLinhas(carregadas, 120), "\n"))
	}
}

func pastaDeCapturaDoServico(padrao string) string {
	perflogs := filepath.Join(os.Getenv("SystemDrive")+`\`, "PerfLogs")
	if perflogs == `\PerfLogs` {
		perflogs = `C:\PerfLogs`
	}
	if err := os.MkdirAll(perflogs, 0o755); err != nil {
		return padrao
	}
	alvo := filepath.Join(perflogs, "scanner-captura.etl")
	os.Remove(alvo)
	f, err := os.Create(alvo)
	if err != nil {
		return padrao
	}
	f.Close()
	os.Remove(alvo)
	return alvo
}
