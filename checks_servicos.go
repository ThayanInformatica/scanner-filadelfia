//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func nomeEstado(s svc.State) string {
	switch s {
	case svc.Running:
		return "rodando"
	case svc.Stopped:
		return "PARADO"
	case svc.StartPending:
		return "iniciando"
	case svc.StopPending:
		return "parando"
	case svc.Paused:
		return "pausado"
	}
	return fmt.Sprintf("estado %d", s)
}

func nomeInicio(t uint32) string {
	switch t {
	case mgr.StartAutomatic:
		return "automatico"
	case mgr.StartManual:
		return "manual"
	case mgr.StartDisabled:
		return "DESATIVADO"
	case windows.SERVICE_BOOT_START, windows.SERVICE_SYSTEM_START:
		return "boot"
	}
	return fmt.Sprintf("tipo %d", t)
}

func checarServicos(c *Contexto) {
	r := c.R
	r.Secao("SERVICOS DO WINDOWS (rastreio e protecao)")

	m, err := mgr.Connect()
	if err != nil {
		r.Erro("conectar ao gerenciador de servicos: %v", err)
		return
	}
	defer m.Disconnect()

	for _, esperado := range c.A.Servicos {
		nome16, _ := windows.UTF16PtrFromString(esperado.Nome)
		h, err := windows.OpenService(m.Handle, nome16, windows.SERVICE_QUERY_STATUS|windows.SERVICE_QUERY_CONFIG)
		if err != nil {
			sevInexistente := Alerta
			if esperado.Nivel == "info" {
				sevInexistente = Info
			}
			r.Add(sevInexistente, "Servico "+esperado.Nome+" NAO EXISTE", esperado.Descricao+". Servico removido do sistema ou inexistente nesta versao do Windows")
			continue
		}
		s := &mgr.Service{Name: esperado.Nome, Handle: h}
		status, errStatus := s.Query()
		config, errConfig := s.Config()
		s.Close()
		if errStatus != nil {
			r.Erro("estado de %s: %v", esperado.Nome, errStatus)
			continue
		}
		inicio := "?"
		if errConfig == nil {
			inicio = nomeInicio(config.StartType)
		}
		r.Linha("%-24s %-10s inicio: %-11s %s", esperado.Nome, nomeEstado(status.State), inicio, esperado.Descricao)

		sev := Info
		switch esperado.Nivel {
		case "critico":
			sev = Critico
		case "alerta":
			sev = Alerta
		}
		if errConfig == nil && config.StartType == mgr.StartDisabled {
			if strings.EqualFold(esperado.Nome, "SysMain") {
				c.SysMainDesativado = true
			}
			r.Add(sev, "Servico "+esperado.Nome+" esta DESATIVADO", esperado.Descricao)
			continue
		}
		if status.State == svc.Stopped {
			if sev == Critico {
				sev = Alerta
			}
			r.Add(sev, "Servico "+esperado.Nome+" esta PARADO", esperado.Descricao)
		}
	}
}

func checarDefender(c *Contexto) {
	r := c.R
	r.Secao("WINDOWS DEFENDER")

	politicas := []struct {
		chave, valor, titulo string
	}{
		{`SOFTWARE\Policies\Microsoft\Windows Defender`, "DisableAntiSpyware", "Defender desativado por politica (DisableAntiSpyware)"},
		{`SOFTWARE\Policies\Microsoft\Windows Defender`, "DisableAntiVirus", "Antivirus desativado por politica (DisableAntiVirus)"},
		{`SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection`, "DisableRealtimeMonitoring", "Protecao em tempo real desativada por politica"},
		{`SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection`, "DisableBehaviorMonitoring", "Monitoramento de comportamento desativado por politica"},
		{`SOFTWARE\Microsoft\Windows Defender\Real-Time Protection`, "DisableRealtimeMonitoring", "Protecao em tempo real desativada"},
	}
	for _, p := range politicas {
		if v, ok := lerDword(registry.LOCAL_MACHINE, p.chave, p.valor); ok && v == 1 {
			r.Add(Critico, p.titulo, `HKLM\`+p.chave+` -> `+p.valor+"=1. Ferramentas tipo Defender Control gravam isso")
		}
	}

	raizes := []string{`SOFTWARE\Microsoft\Windows Defender\Exclusions`, `SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions`}
	total := 0
	for _, raiz := range raizes {
		for _, tipo := range []string{"Paths", "Processes", "Extensions", "TemporaryPaths"} {
			for _, nome := range nomesDeValores(registry.LOCAL_MACHINE, raiz+`\`+tipo) {
				total++
				lowerNome := strings.ToLower(nome)
				sev := Alerta
				detalhe := "Exclusao de " + strings.ToLower(tipo) + " no Defender. Loaders de cheat pedem para excluir a pasta antes de rodar"
				switch {
				case func() bool { cl, _ := c.A.Classificar(nome); return cl != SemMatch }():
					_, t := c.A.Classificar(nome)
					sev = Critico
					detalhe = "Bate com assinatura '" + t + "'. " + detalhe
				case strings.Contains(lowerNome, `\temp\`) || strings.Contains(lowerNome, `\downloads\`) || strings.Contains(lowerNome, `\desktop\`) || strings.Contains(lowerNome, `\users\public\`):
					sev = Critico
					detalhe = "Exclusao em pasta de download, temporaria ou area de trabalho: e ali que loader de cheat roda. " + detalhe
				case strings.Contains(lowerNome, "fivem") || strings.Contains(lowerNome, "gta"):
					detalhe = "Exclusao na pasta do jogo. " + detalhe
				case pastaDeDesenvolvimento(lowerNome):
					sev = Info
					detalhe = "Pasta de desenvolvimento (IDE, projetos, SDK): exclusao comum de programador, indicio fraco. " + detalhe
				}
				r.Add(sev, "Exclusao no Defender: "+nome, detalhe)
			}
		}
	}
	if total == 0 {
		r.Ok("Nenhuma exclusao configurada no Defender (via registro)")
	}

	saida, err := powershell(`Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,IsTamperProtected,BehaviorMonitorEnabled,AntivirusSignatureLastUpdated,QuickScanEndTime,AMRunningMode | ConvertTo-Json -Compress`)
	if err != nil {
		r.Erro("Get-MpComputerStatus: %v", err)
	} else {
		var st map[string]any
		if json.Unmarshal([]byte(strings.TrimSpace(saida)), &st) == nil {
			ligado := func(k string) bool { v, _ := st[k].(bool); return v }
			r.Linha("Servico AM: %v  Antivirus: %v  Tempo real: %v  Tamper protection: %v  Modo: %v", st["AMServiceEnabled"], st["AntivirusEnabled"], st["RealTimeProtectionEnabled"], st["IsTamperProtected"], st["AMRunningMode"])
			r.Linha("Assinaturas atualizadas: %s   Ultimo scan rapido: %s", dataDoJSONPowershell(st["AntivirusSignatureLastUpdated"]), dataDoJSONPowershell(st["QuickScanEndTime"]))
			if !ligado("AMServiceEnabled") || !ligado("AntivirusEnabled") {
				r.Add(Critico, "Windows Defender esta DESLIGADO", "Sem antivirus ativo no momento (pode haver outro antivirus instalado, conferir)")
			} else if !ligado("RealTimeProtectionEnabled") {
				r.Add(Critico, "Protecao em tempo real do Defender DESLIGADA", "Sem tempo real o Defender nao bloqueia loader de cheat")
			} else {
				r.Ok("Defender ativo com protecao em tempo real")
			}
			if !ligado("IsTamperProtected") {
				r.Add(Info, "Tamper Protection do Defender desligada", "Permite desligar o Defender por registro/script")
			}
		} else {
			r.Erro("resposta inesperada do Get-MpComputerStatus: %s", resume(saida, 200))
		}
	}

	saida, err = powershell(`Get-MpPreference | Select-Object ExclusionPath,ExclusionProcess,ExclusionExtension | ConvertTo-Json -Compress`)
	if err == nil {
		var pref map[string]any
		if json.Unmarshal([]byte(strings.TrimSpace(saida)), &pref) == nil {
			for _, k := range []string{"ExclusionPath", "ExclusionProcess", "ExclusionExtension"} {
				for _, item := range listaDeQualquer(pref[k]) {
					if total > 0 {
						continue
					}
					sev := Alerta
					if classe, _ := c.A.Classificar(item); classe != SemMatch {
						sev = Critico
					}
					r.Add(sev, "Exclusao no Defender ("+k+"): "+item, "Retornada pelo Get-MpPreference")
				}
			}
		}
	}

	saida, err = powershell(`Get-MpThreat | Select-Object ThreatName,SeverityID,DidThreatExecute | ConvertTo-Json -Compress`)
	if err == nil && strings.TrimSpace(saida) != "" {
		var bruto any
		if json.Unmarshal([]byte(strings.TrimSpace(saida)), &bruto) == nil {
			var linhas []string
			sev := Info
			for _, item := range objetosDeQualquer(bruto) {
				nome, _ := item["ThreatName"].(string)
				executou, _ := item["DidThreatExecute"].(bool)
				linha := nome
				if executou {
					linha += "  (CHEGOU A EXECUTAR)"
				}
				lower := strings.ToLower(nome)
				if strings.Contains(lower, "hacktool") || strings.Contains(lower, "gamehack") || strings.Contains(lower, "cheat") || strings.Contains(lower, "vulnerabledriver") || strings.Contains(lower, "keygen") {
					sev = Critico
				} else if sev < Alerta {
					sev = Alerta
				}
				linhas = append(linhas, linha)
			}
			if len(linhas) > 0 {
				r.Add(sev, fmt.Sprintf("Historico do Defender tem %d ameaca(s)", len(linhas)), strings.Join(limita(linhas, 80), "\n"))
			}
		}
	}
}

var reDataJSON = regexp.MustCompile(`/Date\((\d+)\)/`)

func dataDoJSONPowershell(v any) string {
	texto := fmt.Sprint(v)
	if m := reDataJSON.FindStringSubmatch(texto); m != nil {
		ms, _ := strconv.ParseInt(m[1], 10, 64)
		return formataHora(time.UnixMilli(ms))
	}
	return texto
}
