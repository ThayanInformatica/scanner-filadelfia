//go:build windows

package main

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	reSystemTime  = regexp.MustCompile(`SystemTime=['"]([^'"]+)['"]`)
	reEventID     = regexp.MustCompile(`<EventID[^>]*>(\d+)</EventID>`)
	reDado        = regexp.MustCompile(`<Data Name=['"]([^'"]+)['"]>([^<]*)</Data>`)
	reRegistros   = regexp.MustCompile(`numberOfLogRecords:\s*(\d+)`)
	reTamanhoMax  = regexp.MustCompile(`maxSize:\s*(\d+)`)
	reHabilitado  = regexp.MustCompile(`enabled:\s*(\w+)`)
	reSeparaEvent = regexp.MustCompile(`(?s)<Event .*?</Event>`)
	reTagSimples  = regexp.MustCompile(`<(SubjectUserName|Channel|BackupPath)>([^<]*)</`)
)

type evento struct {
	ID    int
	Hora  time.Time
	Dados map[string]string
}

func consultarEventos(log, xpath string, max int, maisRecentesPrimeiro bool) ([]evento, error) {
	args := []string{"qe", log, "/q:" + xpath, "/c:" + strconv.Itoa(max), "/f:xml"}
	if maisRecentesPrimeiro {
		args = append(args, "/rd:true")
	}
	saida, err := executar("wevtutil", args...)
	if err != nil {
		return nil, err
	}
	var lista []evento
	for _, bloco := range reSeparaEvent.FindAllString(saida, -1) {
		e := evento{Dados: map[string]string{}}
		if m := reEventID.FindStringSubmatch(bloco); m != nil {
			e.ID, _ = strconv.Atoi(m[1])
		}
		if m := reSystemTime.FindStringSubmatch(bloco); m != nil {
			if t, err := time.Parse(time.RFC3339Nano, m[1]); err == nil {
				e.Hora = t.Local()
			}
		}
		for _, d := range reDado.FindAllStringSubmatch(bloco, -1) {
			e.Dados[d[1]] = d[2]
		}
		for _, d := range reTagSimples.FindAllStringSubmatch(bloco, -1) {
			if e.Dados[d[1]] == "" {
				e.Dados[d[1]] = d[2]
			}
		}
		lista = append(lista, e)
	}
	return lista, nil
}

func xpathUltimosDias(ids []int, dias int) string {
	var partes []string
	for _, id := range ids {
		partes = append(partes, fmt.Sprintf("EventID=%d", id))
	}
	return fmt.Sprintf("*[System[(%s) and TimeCreated[timediff(@SystemTime) <= %d]]]", strings.Join(partes, " or "), dias*24*3600*1000)
}

func checarLogsDeEventos(c *Contexto) {
	r := c.R
	r.Secao("LOGS DE EVENTOS DO WINDOWS")

	limpezas, err := consultarEventos("Security", "*[System[(EventID=1102)]]", 20, true)
	if err != nil {
		r.Erro("consultar Security 1102: %v", err)
	} else if len(limpezas) == 0 {
		r.Ok("Nenhum registro de limpeza do log Security (evento 1102)")
	}
	c.Rastros.LimpezasDoSecurity = len(limpezas)
	for _, e := range limpezas {
		r.Add(Critico, "Log de SEGURANCA foi LIMPO em "+formataHora(e.Hora), "Evento 1102, usuario: "+e.Dados["SubjectUserName"]+". O evento 1102 sobrevive a limpeza justamente para marcar quem limpou")
	}

	limpezasSistema, err := consultarEventos("System", "*[System[(EventID=104)]]", 30, true)
	if err != nil {
		r.Erro("consultar System 104: %v", err)
	} else if len(limpezasSistema) == 0 {
		r.Ok("Nenhum registro de limpeza de logs do sistema (evento 104)")
	}
	limpezasVistas := map[string]bool{}
	for _, e := range limpezasSistema {
		canal := e.Dados["Channel"]
		if canal == "" {
			canal = "?"
		}
		chaveLimpeza := canal + "|" + e.Hora.Format(time.RFC3339)
		if limpezasVistas[chaveLimpeza] {
			continue
		}
		limpezasVistas[chaveLimpeza] = true
		c.Rastros.LimpezasDeOutrosLogs++
		sev := Critico
		nota := ""
		if !e.Hora.IsZero() && time.Since(e.Hora) > 60*24*time.Hour {
			sev = Alerta
			nota = ". Limpeza antiga (mais de 60 dias), pesa menos"
		}
		r.Add(sev, fmt.Sprintf("Log '%s' foi LIMPO em %s", canal, formataHora(e.Hora)), "Evento 104, usuario: "+e.Dados["SubjectUserName"]+nota)
	}

	logs := []string{"Security", "System", "Application", "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-Kernel-PnP/Configuration", "Microsoft-Windows-Application-Experience/Program-Inventory"}
	for _, nome := range logs {
		info, err := executar("wevtutil", "gli", nome)
		if err != nil {
			continue
		}
		registros := 0
		if m := reRegistros.FindStringSubmatch(info); m != nil {
			registros, _ = strconv.Atoi(m[1])
		}
		config, _ := executar("wevtutil", "gl", nome)
		tamanhoMax := 0
		if m := reTamanhoMax.FindStringSubmatch(config); m != nil {
			tamanhoMax, _ = strconv.Atoi(m[1])
		}
		habilitado := true
		if m := reHabilitado.FindStringSubmatch(config); m != nil && strings.EqualFold(m[1], "false") {
			habilitado = false
		}
		primeiro, _ := consultarEventos(nome, "*", 1, false)
		maisAntigo := time.Time{}
		if len(primeiro) > 0 {
			maisAntigo = primeiro[0].Hora
		}
		r.Linha("%-58s registros: %-7d mais antigo: %s  limite: %d MB", nome, registros, formataHora(maisAntigo), tamanhoMax/1024/1024)
		if !habilitado {
			r.Add(Alerta, "Log '"+nome+"' esta DESABILITADO", "Log desligado nao registra nada")
			continue
		}
		if registros == 0 && nome == "Security" {
			c.Rastros.LogSecurityVazio = true
		}
		if registros == 0 && nome == "System" {
			c.Rastros.LogSystemVazio = true
		}
		if registros == 0 && (nome == "Security" || nome == "System" || nome == "Application") {
			r.Add(Critico, "Log '"+nome+"' esta VAZIO", "Um log principal nunca fica vazio em um Windows em uso")
			continue
		}
		if strings.Contains(nome, "PowerShell") {
			continue
		}
		if !maisAntigo.IsZero() && !c.Instalacao.IsZero() && time.Since(c.Instalacao) > 72*time.Hour && time.Since(maisAntigo) < 48*time.Hour {
			r.Add(Alerta, fmt.Sprintf("Log '%s' so tem eventos das ultimas %s", nome, time.Since(maisAntigo).Round(time.Hour)), fmt.Sprintf("Windows instalado em %s. Pode ser limpeza ou rotacao por tamanho (limite %d MB, %d registros)", formataHora(c.Instalacao), tamanhoMax/1024/1024, registros))
		}
	}

	mudancasHora, err := consultarEventos("Security", xpathUltimosDias([]int{4616}, 30), 20, true)
	if err == nil {
		var manuais []string
		for _, e := range mudancasHora {
			usuario := e.Dados["SubjectUserName"]
			if usuario == "" || strings.HasSuffix(usuario, "$") || contaDeServicoDoWindows(usuario) {
				continue
			}
			manuais = append(manuais, fmt.Sprintf("%s por %s (de %s para %s)", formataHora(e.Hora), usuario, e.Dados["PreviousTime"], e.Dados["NewTime"]))
		}
		if len(manuais) > 0 {
			r.Add(Alerta, fmt.Sprintf("%d alteracao(oes) manual(is) de hora nos ultimos 30 dias", len(manuais)), strings.Join(manuais, "\n"))
		}
	}

	servicosNovos, err := consultarEventos("System", xpathUltimosDias([]int{7045}, 30), 200, true)
	if err == nil {
		var linhas []string
		vistosServico := map[string]int{}
		repetidos := map[string]string{}
		porAssinatura := map[string]*InstalacaoDeDriver{}
		porVulneravel := map[string]*InstalacaoDeDriver{}
		var ordemAssinatura, ordemVulneravel []string
		acumula := func(destino map[string]*InstalacaoDeDriver, ordem *[]string, chave, nome, imagem, tipo, termo string, hora time.Time) {
			d, existe := destino[chave]
			if !existe {
				d = &InstalacaoDeDriver{Nome: nome, Imagem: imagem, Tipo: tipo, Termo: termo}
				destino[chave] = d
				*ordem = append(*ordem, chave)
			}
			d.Vezes++
			if d.Primeira.IsZero() || hora.Before(d.Primeira) {
				d.Primeira = hora
			}
			if hora.After(d.Ultima) {
				d.Ultima = hora
			}
		}
		for _, e := range servicosNovos {
			nome := e.Dados["ServiceName"]
			imagem := e.Dados["ImagePath"]
			tipo := e.Dados["ServiceType"]
			linha := fmt.Sprintf("%s  %s  [%s]  %s", formataHora(e.Hora), nome, tipo, imagem)
			if classe, t := c.A.Classificar(nome + " " + imagem); classe != SemMatch {
				acumula(porAssinatura, &ordemAssinatura, strings.ToLower(nome+"|"+imagem)+"|"+t, nome, imagem, tipo, t, e.Hora)
				continue
			}
			if base := strings.ToLower(nomeBase(imagem)); c.A.DriverVulneravel(base) {
				acumula(porVulneravel, &ordemVulneravel, strings.ToLower(imagem), base, imagem, tipo, "", e.Hora)
				continue
			}
			img := strings.ToLower(imagem)
			if strings.Contains(strings.ToLower(tipo), "kernel") && !strings.Contains(img, "\\windows\\") && !strings.Contains(img, "\\systemroot\\") && !strings.HasPrefix(strings.TrimLeft(img, "\\"), "system32\\") && !strings.HasPrefix(img, "\\??\\c:\\windows") && !strings.Contains(img, "\\program files") {
				if strings.Contains(img, `\cpuid software\`) || strings.Contains(img, `\cpuid\`) {
					r.Add(Info, "Driver do CPU-Z/HWMonitor instalado com nome aleatorio: "+nome, linha+"\nA CPUID gera um nome novo a cada instalacao. E o comportamento normal do CPU-Z, HWMonitor e afins")
				} else {
					r.Add(Alerta, "Driver de kernel instalado fora das pastas do sistema: "+nome, linha)
				}
				continue
			}
			linhas = append(linhas, linha)
		}
		for _, chave := range ordemAssinatura {
			d := porAssinatura[chave]
			classe, _ := c.A.Classificar(d.Nome + " " + d.Imagem)
			r.Add(classe.Severidade(), "Servico/driver instalado bate com assinatura '"+d.Termo+"': "+d.Nome, d.Descrever())
		}
		for _, chave := range ordemVulneravel {
			d := porVulneravel[chave]
			sev, nota := severidadeDeDriverInstalado(d.Imagem)
			r.Add(sev, "Driver VULNERAVEL instalado como servico: "+d.Nome, d.Descrever()+nota)
		}
		if len(linhas) > 0 {
			r.Add(Info, fmt.Sprintf("%d servico(s)/driver(s) instalado(s) nos ultimos 30 dias", len(linhas)), strings.Join(limita(linhas, 100), "\n"))
		}
		if len(repetidos) > 0 {
			var reg []string
			for chave, linha := range repetidos {
				reg = append(reg, fmt.Sprintf("%s  (registrado %d vezes)", linha, vistosServico[chave]))
			}
			sort.Strings(reg)
			r.Add(Info, fmt.Sprintf("%d servico(s) reinstalado(s) varias vezes (normal em driver que sobe a cada boot)", len(reg)), strings.Join(limita(reg, 60), "\n"))
		}
	}

	defenderOff, err := consultarEventos("Microsoft-Windows-Windows Defender/Operational", xpathUltimosDias([]int{5001, 5010, 5012}, 30), 30, true)
	if err == nil && len(defenderOff) > 0 {
		var linhas []string
		for _, e := range defenderOff {
			motivo := map[int]string{5001: "protecao em tempo real desligada", 5010: "antispyware desligado", 5012: "antivirus desligado"}[e.ID]
			linhas = append(linhas, formataHora(e.Hora)+"  "+motivo)
		}
		r.Add(Alerta, fmt.Sprintf("Defender foi desligado %d vez(es) nos ultimos 30 dias", len(defenderOff)), strings.Join(limita(linhas, 60), "\n"))
	}

	deteccoes, err := consultarEventos("Microsoft-Windows-Windows Defender/Operational", xpathUltimosDias([]int{1116, 1117, 1015}, 60), 40, true)
	if err == nil && len(deteccoes) > 0 {
		vistos := map[string]bool{}
		var linhas []string
		for _, e := range deteccoes {
			ameaca := e.Dados["Threat Name"]
			caminho := e.Dados["Path"]
			chave := ameaca + caminho
			if vistos[chave] {
				continue
			}
			vistos[chave] = true
			linhas = append(linhas, fmt.Sprintf("%s  %s  %s", formataHora(e.Hora), ameaca, caminho))
		}
		sev := Alerta
		for _, l := range linhas {
			lower := strings.ToLower(l)
			if strings.Contains(lower, "hacktool") || strings.Contains(lower, "gamehack") || strings.Contains(lower, "cheat") || strings.Contains(lower, "vulnerabledriver") {
				sev = Critico
				break
			}
		}
		r.Add(sev, fmt.Sprintf("Defender detectou %d ameaca(s) nos ultimos 60 dias", len(linhas)), strings.Join(limita(linhas, 80), "\n"))
	}

	scriptsPS, err := consultarEventos("Microsoft-Windows-PowerShell/Operational", xpathUltimosDias([]int{4104}, 30), 300, true)
	if err == nil {
		var suspeitos []string
		for _, e := range scriptsPS {
			texto := e.Dados["ScriptBlockText"]
			if scriptDoSistemaOuDoScanner(texto) {
				continue
			}
			if !e.Hora.IsZero() && !c.R.inicio.IsZero() && !e.Hora.Before(c.R.inicio.Add(-1*time.Minute)) {
				continue
			}
			if motivo := comandoDeOcultacao(texto); motivo != "" {
				suspeitos = append(suspeitos, fmt.Sprintf("%s  [%s]  %s", formataHora(e.Hora), motivo, resume(texto, 160)))
			} else if classe, t := c.A.Classificar(texto); classe != SemMatch {
				suspeitos = append(suspeitos, fmt.Sprintf("%s  [assinatura %s]  %s", formataHora(e.Hora), t, resume(texto, 160)))
			}
		}
		if len(suspeitos) > 0 {
			r.Add(Critico, fmt.Sprintf("%d script(s) PowerShell de ocultacao/cheat registrados", len(suspeitos)), strings.Join(limita(suspeitos, 80), "\n"))
		}
	}
}
