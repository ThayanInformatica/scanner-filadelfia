//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/mgr"
)

func servicoExiste(m *mgr.Mgr, nome string) bool {
	nome16, err := windows.UTF16PtrFromString(nome)
	if err != nil {
		return false
	}
	h, err := windows.OpenService(m.Handle, nome16, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return false
	}
	windows.CloseServiceHandle(h)
	return true
}

func coletarEstadoDoWindows(c *Contexto) EstadoDoWindows {
	e := EstadoDoWindows{}
	const chaveVersao = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	e.Edicao, _ = lerString(registry.LOCAL_MACHINE, chaveVersao, "ProductName")
	e.Build, _ = lerString(registry.LOCAL_MACHINE, chaveVersao, "CurrentBuild")

	if m, err := mgr.Connect(); err == nil {
		defer m.Disconnect()
		for nome, descricao := range servicosDeFabrica {
			if !servicoExiste(m, nome) {
				e.ServicosAusentes = append(e.ServicosAusentes, nome+" ("+descricao+")")
			}
		}
	}

	raiz := os.Getenv("SystemDrive")
	if raiz == "" {
		raiz = "C:"
	}
	for relativo, descricao := range arquivosDeFabrica {
		if !arquivoDeFabricaEsperado(relativo) {
			continue
		}
		if !existe(filepath.Join(raiz+`\`, relativo)) {
			e.ArquivosAusentes = append(e.ArquivosAusentes, filepath.Base(relativo)+" ("+descricao+")")
		}
	}

	marcas := map[string]bool{}
	registraMarca := func(texto, onde string) {
		t := strings.ToLower(texto)
		for chave, nome := range marcasDeISOModificada {
			if strings.Contains(t, chave) {
				marcas[nome+" em "+onde] = true
			}
		}
	}
	for _, campo := range []string{"BuildLab", "BuildLabEx", "ProductName", "EditionID", "RegisteredOrganization", "RegisteredOwner", "CompositionEditionID"} {
		if v, ok := lerString(registry.LOCAL_MACHINE, chaveVersao, campo); ok {
			registraMarca(v, campo)
		}
	}
	if v, ok := lerString(registry.LOCAL_MACHINE, `SYSTEM\Setup`, "CloneTag"); ok {
		registraMarca(v, "SYSTEM\\Setup")
	}
	for _, pasta := range []string{`Atlas`, `AtlasModules`, `GhostSpectre`, `Ghost`, `ReviOS`, `Windows\GhostSpectre`, `Windows\Atlas`, `Windows\Setup\Scripts`} {
		if existe(filepath.Join(raiz+`\`, pasta)) {
			registraMarca(pasta, "pasta "+pasta)
		}
	}
	for _, servico := range []string{"AtlasModules", "GhostSpectre", "SppExtComObjPatcher", "KMS_VL_ALL", "AutoPico"} {
		if _, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+servico, registry.READ); err == nil {
			registraMarca(servico, "servico "+servico)
		}
	}
	if tarefas, err := lerTarefasAgendadas(); err == nil {
		for _, t := range tarefas {
			registraMarca(t.Nome+" "+t.Comando, "tarefa agendada")
		}
	}
	for m := range marcas {
		e.MarcasDeISO = append(e.MarcasDeISO, m)
	}

	if saida, err := powershell(`Get-CimInstance SoftwareLicensingProduct -Filter "PartialProductKey is not null and ApplicationId='55c92734-d682-4d71-983e-d6ec3f16059f'" | Select-Object Name,Description,@{n='Status';e={$_.LicenseStatus}} | ConvertTo-Json -Compress`); err == nil {
		var bruto any
		if json.Unmarshal([]byte(strings.TrimSpace(saida)), &bruto) == nil {
			for _, item := range objetosDeQualquer(bruto) {
				descricao, _ := item["Description"].(string)
				d := strings.ToLower(descricao)
				if strings.Contains(d, "kms") || strings.Contains(d, "volume") {
					e.Ativacao = resumeTexto(descricao, 110)
				}
			}
		}
	}

	if _, err := powershell(`Get-MpComputerStatus | Out-Null`); err == nil {
		e.DefenderResponde = true
	}
	if !e.DefenderResponde {
		e.ComponentesRemovidos = append(e.ComponentesRemovidos, "o comando do Defender (Get-MpComputerStatus) nao existe neste Windows")
	}
	return e
}

func checarWindowsOriginal(c *Contexto) {
	r := c.R
	r.Secao("ORIGEM DO WINDOWS (instalacao original ou modificada)")
	r.Progresso("Conferindo servicos, arquivos e marcas de fabrica do Windows")
	e := coletarEstadoDoWindows(c)

	r.Linha("Edicao: %s  build %s", e.Edicao, e.Build)
	r.Linha("Servicos de fabrica ausentes: %d   Arquivos de fabrica ausentes: %d   Marcas de ISO modificada: %d", len(e.ServicosAusentes), len(e.ArquivosAusentes), len(e.MarcasDeISO))

	sinais := avaliarWindowsModificado(e)
	for _, s := range sinais {
		r.Add(s.Severidade, s.Titulo, s.Detalhe)
	}
	if len(sinais) == 0 {
		r.Ok("Windows com cara de instalacao original: servicos, arquivos e componentes de fabrica no lugar")
		return
	}
	if len(e.ServicosAusentes) > 0 {
		r.Add(Info, fmt.Sprintf("Lista completa dos servicos de fabrica que nao existem (%d)", len(e.ServicosAusentes)), strings.Join(e.ServicosAusentes, "\n"))
	}
	if len(e.ArquivosAusentes) > 0 {
		r.Add(Info, fmt.Sprintf("Lista completa dos arquivos de fabrica removidos (%d)", len(e.ArquivosAusentes)), strings.Join(e.ArquivosAusentes, "\n"))
	}
}

func arquivoDeFabricaEsperado(relativo string) bool {
	if !strings.EqualFold(filepath.Base(relativo), "MRT.exe") {
		return true
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\RemovalTools\MRT`, registry.READ)
	if err != nil {
		return false
	}
	k.Close()
	return true
}
