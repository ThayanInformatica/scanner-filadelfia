//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const suportaChecagemReal = true

func etapasDoSistema() []Etapa {
	return []Etapa{
		{"Sistema e integridade de codigo", checarSistema, false},
		{"Origem do Windows (original ou modificado)", checarWindowsOriginal, false},
		{"Servicos de rastreio e protecao", checarServicos, false},
		{"Windows Defender", checarDefender, false},
		{"Logs de eventos", checarLogsDeEventos, false},
		{"ETW / kernel", checarETW, false},
		{"Historico de execucao no registro", checarRegistro, false},
		{"Prefetch", checarPrefetch, false},
		{"Artefatos do Windows (ShimCache, crashes, atalhos)", checarArtefatos, false},
		{"Amcache (programas executados, com hash)", checarAmcache, false},
		{"Conteudo dos pacotes baixados", checarPacotes, false},
		{"Varredura manual (journal, tarefas, ADS)", checarVarreduraManual, true},
		{"Arquivos recentes e lixeira", checarRecentesELixeira, false},
		{"Processos, handles, overlay e drivers", checarProcessos, false},
		{"Memoria do jogo, dos outros processos e linha do tempo", checarMemoriaDoJogo, false},
		{"Hardware (DMA, KMBox, aim assist)", checarHardware, false},
		{"FiveM", checarFiveM, false},
		{"Integridade do jogo (FiveM e GTA V)", checarJogo, false},
		{"Cache DNS e journal USN", checarRede, false},
		{"Rastros de execucao (PC stopado?)", checarRastrosDeExecucao, false},
		{"Historico dos navegadores", checarNavegadores, false},
		{"Discord", checarDiscord, false},
		{"Varredura de arquivos", checarArquivos, true},
		{"Strings de cheat no conteudo dos arquivos", checarConteudo, true},
	}
}

func preencherPerfis(c *Contexto) {
	c.Perfis = perfisDeUsuario()
}

func abrirNoSistema(alvo string) error {
	cmd := exec.Command("cmd", "/c", "start", "", alvo)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Start()
}

func selecionarNoExplorer(caminho string) error {
	return exec.Command("explorer", "/select,"+caminho).Start()
}

func marcasDoHardware() string {
	partes := []string{}
	if v, ok := lerString(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, "MachineGuid"); ok {
		partes = append(partes, v)
	}
	if v, ok := lerString(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001`, "HwProfileGuid"); ok {
		partes = append(partes, v)
	}
	var serial uint32
	if raiz, err := windows.UTF16PtrFromString(`C:\`); err == nil {
		windows.GetVolumeInformation(raiz, nil, 0, &serial, nil, nil, nil, 0)
	}
	partes = append(partes, fmt.Sprintf("%08X", serial), nomeDaMaquina())
	return strings.Join(partes, "|")
}
