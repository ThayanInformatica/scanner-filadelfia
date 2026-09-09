package main

import (
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
)

type EventoETW struct {
	Provedor string
	ID       int
	Hora     time.Time
	PID      int
	Dados    map[string]string
}

type resumoETW struct {
	Total          int
	ImagensPorPID  map[int][]string
	ProcessosNovos []EventoETW
	Imagens        []EventoETW
	DNS            []EventoETW
	Rede           []EventoETW
}

func lerEventosTracerpt(r io.Reader) ([]EventoETW, error) {
	dec := xml.NewDecoder(r)
	dec.Strict = false
	var eventos []EventoETW
	var atual *EventoETW
	var chave string
	var dentroDeDados bool
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return eventos, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "Event":
				atual = &EventoETW{Dados: map[string]string{}}
			case "Provider":
				if atual != nil {
					atual.Provedor = atributo(t, "Name")
				}
			case "EventID":
				chave = "#EventID"
			case "TimeCreated":
				if atual != nil {
					if v := atributo(t, "SystemTime"); v != "" {
						if hora, err := time.Parse(time.RFC3339Nano, v); err == nil {
							atual.Hora = hora.Local()
						}
					}
				}
			case "Execution":
				if atual != nil {
					atual.Dados["ProcessID"] = atributo(t, "ProcessID")
				}
			case "EventData", "UserData":
				dentroDeDados = true
			case "Data":
				if dentroDeDados {
					chave = atributo(t, "Name")
					if chave == "" {
						chave = fmt.Sprintf("Data%d", len(atual.Dados))
					}
				}
			default:
				if dentroDeDados && atual != nil {
					chave = t.Name.Local
				}
			}
		case xml.CharData:
			if atual != nil && chave != "" {
				texto := strings.TrimSpace(string(t))
				if texto != "" {
					if chave == "#EventID" {
						fmt.Sscanf(texto, "%d", &atual.ID)
					} else {
						atual.Dados[chave] = texto
					}
				}
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "Event":
				if atual != nil {
					fmt.Sscanf(atual.Dados["ProcessID"], "%d", &atual.PID)
					eventos = append(eventos, *atual)
					atual = nil
				}
			case "EventData", "UserData":
				dentroDeDados = false
			}
			chave = ""
		}
	}
	return eventos, nil
}

func atributo(e xml.StartElement, nome string) string {
	for _, a := range e.Attr {
		if strings.EqualFold(a.Name.Local, nome) {
			return a.Value
		}
	}
	return ""
}

func valorDe(e EventoETW, nomes ...string) string {
	for _, n := range nomes {
		for k, v := range e.Dados {
			if strings.EqualFold(k, n) {
				return v
			}
		}
	}
	return ""
}

func resumirETW(eventos []EventoETW) resumoETW {
	res := resumoETW{ImagensPorPID: map[int][]string{}}
	res.Total = len(eventos)
	for _, e := range eventos {
		prov := strings.ToLower(e.Provedor)
		switch {
		case strings.Contains(prov, "kernel-process") && e.ID == 5:
			res.Imagens = append(res.Imagens, e)
			pid := 0
			fmt.Sscanf(valorDe(e, "ProcessID", "ProcessId"), "%d", &pid)
			nome := valorDe(e, "ImageName", "FileName")
			if nome != "" {
				res.ImagensPorPID[pid] = append(res.ImagensPorPID[pid], nome)
			}
		case strings.Contains(prov, "kernel-process") && e.ID == 1:
			res.ProcessosNovos = append(res.ProcessosNovos, e)
		case strings.Contains(prov, "dns-client"):
			res.DNS = append(res.DNS, e)
		case strings.Contains(prov, "kernel-network"):
			res.Rede = append(res.Rede, e)
		}
	}
	return res
}

func avaliarETW(res resumoETW, a *Assinaturas, duracao time.Duration) []Sinal {
	var sinais []Sinal

	if res.Total == 0 {
		sinais = append(sinais, Sinal{Critico, "Captura ETW do kernel voltou VAZIA", fmt.Sprintf("Em %s de captura o kernel nao entregou nenhum evento de carregamento de imagem, processo ou DNS. Em um Windows em uso isso nao acontece. Padrao de ETW patching, tecnica que cheat usa para cegar anticheat", duracao.Round(time.Second)), "cheat"})
		return sinais
	}
	if len(res.Imagens) == 0 {
		sinais = append(sinais, Sinal{Alerta, "Nenhum carregamento de DLL registrado pelo kernel na captura", fmt.Sprintf("%d eventos capturados em %s, mas zero ImageLoad. Pode ser sistema ocioso ou provedor Kernel-Process bloqueado", res.Total, duracao.Round(time.Second)), "suspeito"})
	}

	vistos := map[string]bool{}
	for _, e := range res.Imagens {
		nome := valorDe(e, "ImageName", "FileName")
		if nome == "" || vistos[strings.ToLower(nome)] {
			continue
		}
		vistos[strings.ToLower(nome)] = true
		if classe, t := a.Classificar(nome); classe != SemMatch {
			sinais = append(sinais, Sinal{Critico, fmt.Sprintf("Kernel registrou carregamento de DLL/EXE com assinatura '%s'", t), nome + "\nCapturado ao vivo pelo ETW durante a checagem, mesmo que o arquivo tenha sido apagado depois", "cheat"})
		}
	}

	vistos = map[string]bool{}
	for _, e := range res.ProcessosNovos {
		nome := valorDe(e, "ImageName", "ProcessName", "FileName")
		if nome == "" || vistos[strings.ToLower(nome)] {
			continue
		}
		vistos[strings.ToLower(nome)] = true
		if classe, t := a.Classificar(nome); classe != SemMatch {
			sinais = append(sinais, Sinal{Critico, fmt.Sprintf("Kernel registrou processo iniciado com assinatura '%s'", t), nome + "\nO processo subiu durante a checagem e o kernel gravou, mesmo que ja tenha fechado", "cheat"})
		}
	}

	vistos = map[string]bool{}
	for _, e := range res.DNS {
		nome := valorDe(e, "QueryName", "DnsQueryName", "Name")
		if nome == "" || vistos[strings.ToLower(nome)] {
			continue
		}
		vistos[strings.ToLower(nome)] = true
		if t := a.Dominio(nome); t != "" {
			sinais = append(sinais, Sinal{Critico, fmt.Sprintf("Consulta DNS a dominio de cheat ('%s') durante a checagem: %s", t, nome), "Capturada ao vivo pelo ETW. Loader de cheat consulta o servidor de licenca de tempos em tempos, entao isso indica cheat ativo agora", "cheat"})
		}
	}
	return ordenaSinais(sinais)
}

type SessaoETW struct {
	Nome       string
	Estado     string
	Provedores int
}

var sessoesDeSegurancaEsperadas = []string{
	"eventlog-system", "eventlog-application", "eventlog-security", "defender", "diagtrack", "wdiContextLog",
	"sgrmbroker", "faceit", "easyanticheat", "vanguard", "battleye", "sysmon",
}

func avaliarSessoesETW(sessoes []SessaoETW) []Sinal {
	var sinais []Sinal
	if len(sessoes) < 10 {
		return []Sinal{{Info, "Nao consegui ler a lista de sessoes ETW deste Windows", fmt.Sprintf("O comando logman devolveu %d sessoes, numero baixo demais para um Windows em uso. Isso acontece quando a saida vem em outro idioma ou formato. A checagem foi descartada em vez de acusar sessao parada por engano", len(sessoes)), ""}}
	}
	presentes := map[string]bool{}
	for _, s := range sessoes {
		presentes[strings.ToLower(s.Nome)] = true
	}
	essenciais := map[string]string{
		"eventlog-system":      "canal ETW que alimenta o log de Sistema",
		"eventlog-application": "canal ETW que alimenta o log de Aplicativo",
		"eventlog-security":    "canal ETW que alimenta o log de Seguranca",
	}
	var faltando []string
	for nome, desc := range essenciais {
		achou := false
		for p := range presentes {
			if strings.Contains(p, nome) {
				achou = true
				break
			}
		}
		if !achou {
			faltando = append(faltando, nome+" ("+desc+")")
		}
	}
	sort.Strings(faltando)
	if len(faltando) > 0 {
		sinais = append(sinais, Sinal{Critico, fmt.Sprintf("%d sessao(oes) ETW essencial(is) do Windows PARADA(S)", len(faltando)), strings.Join(faltando, "\n") + "\nParar essas sessoes faz o Windows deixar de gravar eventos sem que o log pareca limpo. Tecnica de ocultacao mais fina que apagar o log", "cheat"})
	}
	return sinais
}

func binarioDeFabricanteConhecido(caminho string) bool {
	c := strings.ToLower(caminho)
	for _, marca := range []string{`\windows defender\`, `\microsoft\windows defender\`, `\program files\`, `\program files (x86)\`,
		`\programdata\microsoft\`, `\windows\system32\`, `\windows\syswow64\`, `\windows\winsxs\`, `\riot vanguard\`, `\easyanticheat`} {
		if strings.Contains(c, marca) {
			return true
		}
	}
	return false
}

func avaliarEventosDeIntegridade(eventos []EventoETW, a *Assinaturas) []Sinal {
	var sinais []Sinal
	vistos := map[string]bool{}
	for _, e := range eventos {
		arquivo := valorDe(e, "FileNameBuffer", "FileName", "File Name", "ImageName", "Data0")
		chave := fmt.Sprintf("%d|%s", e.ID, strings.ToLower(arquivo))
		if vistos[chave] {
			continue
		}
		vistos[chave] = true
		quando := formataHora(e.Hora)
		switch e.ID {
		case 3004, 3033:
			base := nomeBase(arquivo)
			ehDriver := strings.HasSuffix(strings.ToLower(base), ".sys")
			quente := pastaQuente(arquivo)
			if binarioDeFabricanteConhecido(arquivo) {
				continue
			}
			if !ehDriver && !quente {
				continue
			}
			sev := Alerta
			titulo := "Windows bloqueou um binario nao assinado em pasta de usuario"
			detalhe := arquivo + "\n" + quando + "\nEvento " + fmt.Sprint(e.ID) + " do Code Integrity"
			if ehDriver {
				sev = Critico
				titulo = "Windows BLOQUEOU um DRIVER nao assinado"
				detalhe += "\nDriver sem assinatura valida e o rastro classico de tentativa de carregar cheat de kernel"
			}
			if a.DriverVulneravel(base) {
				sev = Critico
				detalhe += "\nO arquivo esta na lista de drivers vulneraveis (BYOVD)"
			}
			sinais = append(sinais, Sinal{sev, titulo, detalhe, "cheat"})
		case 3023:
			sinais = append(sinais, Sinal{Critico, "Driver bloqueado por estar na lista de vulneraveis da Microsoft", arquivo + "\n" + quando + "\nEvento 3023. Alguem tentou carregar um driver conhecido por permitir acesso ao kernel (BYOVD)", "cheat"})
		case 3077:
			sinais = append(sinais, Sinal{Alerta, "Binario bloqueado por politica de integridade de codigo", arquivo + "\n" + quando + "\nEvento 3077", "suspeito"})
		}
	}
	return sinais
}

func sessaoDeRotina(nome string) bool {
	for _, marca := range []string{"defenderapilogger", "diagtrack", "wdi", "perfdiag", "ruximlog", "sqmlogger", "netcore", "circular kernel", "mssense"} {
		if strings.Contains(nome, marca) {
			return true
		}
	}
	return false
}

var reColunasDaSessao = regexp.MustCompile(`^(\S.*?)\s{2,}(\S.*?)\s*$`)

func lerSessoesDoLogman(saida string) []SessaoETW {
	var lista []SessaoETW
	vistos := map[string]bool{}
	for _, linha := range strings.Split(saida, "\n") {
		linha = strings.TrimRight(linha, "\r")
		limpa := strings.TrimSpace(linha)
		if limpa == "" || strings.HasPrefix(limpa, "-") || strings.HasPrefix(limpa, "=") {
			continue
		}
		lower := strings.ToLower(limpa)
		if strings.Contains(lower, "data collector set") || strings.Contains(lower, "coletor de dados") ||
			strings.Contains(lower, "o comando foi concluido") || strings.Contains(lower, "the command completed") ||
			strings.Contains(lower, "erro:") || strings.Contains(lower, "error:") {
			continue
		}
		m := reColunasDaSessao.FindStringSubmatch(linha)
		if m == nil {
			continue
		}
		nome := strings.TrimSpace(m[1])
		if nome == "" || strings.ContainsAny(nome, "<>|") || vistos[strings.ToLower(nome)] {
			continue
		}
		resto := strings.Fields(m[2])
		estado := ""
		if len(resto) > 0 {
			estado = resto[len(resto)-1]
		}
		vistos[strings.ToLower(nome)] = true
		lista = append(lista, SessaoETW{Nome: nome, Estado: estado})
	}
	return lista
}
