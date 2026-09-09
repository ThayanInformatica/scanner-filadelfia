package main

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

const xmlTracerpt = `<?xml version="1.0"?>
<Events>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
 <System>
  <Provider Name="Microsoft-Windows-Kernel-Process" Guid="{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}"/>
  <EventID>5</EventID>
  <TimeCreated SystemTime="2026-09-09T10:30:00.1234567Z"/>
  <Execution ProcessID="6210" ThreadID="900"/>
 </System>
 <EventData>
  <Data Name="ImageBase">0x7ff000000</Data>
  <Data Name="ProcessID">6210</Data>
  <Data Name="ImageName">C:\Users\jogador\AppData\Local\Temp\eulen.dll</Data>
 </EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
 <System>
  <Provider Name="Microsoft-Windows-Kernel-Process"/>
  <EventID>5</EventID>
  <TimeCreated SystemTime="2026-09-09T10:30:01.0000000Z"/>
  <Execution ProcessID="812"/>
 </System>
 <EventData>
  <Data Name="ProcessID">812</Data>
  <Data Name="ImageName">C:\Windows\System32\ntdll.dll</Data>
 </EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
 <System>
  <Provider Name="Microsoft-Windows-Kernel-Process"/>
  <EventID>1</EventID>
  <TimeCreated SystemTime="2026-09-09T10:30:02.0000000Z"/>
  <Execution ProcessID="4"/>
 </System>
 <EventData>
  <Data Name="ProcessID">9100</Data>
  <Data Name="ImageName">C:\Windows\System32\cmd.exe</Data>
 </EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
 <System>
  <Provider Name="Microsoft-Windows-DNS-Client"/>
  <EventID>3006</EventID>
  <TimeCreated SystemTime="2026-09-09T10:30:03.0000000Z"/>
  <Execution ProcessID="8102"/>
 </System>
 <EventData>
  <Data Name="QueryName">auth.eulen.gg</Data>
  <Data Name="QueryType">1</Data>
 </EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
 <System>
  <Provider Name="Microsoft-Windows-DNS-Client"/>
  <EventID>3006</EventID>
  <TimeCreated SystemTime="2026-09-09T10:30:04.0000000Z"/>
  <Execution ProcessID="2388"/>
 </System>
 <EventData>
  <Data Name="QueryName">www.google.com</Data>
 </EventData>
</Event>
</Events>`

func TestParserTracerpt(t *testing.T) {
	eventos, err := lerEventosTracerpt(strings.NewReader(xmlTracerpt))
	if err != nil {
		t.Fatal(err)
	}
	if len(eventos) != 5 {
		t.Fatalf("esperava 5 eventos, veio %d", len(eventos))
	}
	if eventos[0].Provedor != "Microsoft-Windows-Kernel-Process" || eventos[0].ID != 5 {
		t.Errorf("primeiro evento errado: %+v", eventos[0])
	}
	if eventos[0].PID != 6210 {
		t.Errorf("PID errado: %d", eventos[0].PID)
	}
	if !strings.HasSuffix(valorDe(eventos[0], "ImageName"), "eulen.dll") {
		t.Errorf("ImageName errado: %q", valorDe(eventos[0], "ImageName"))
	}
	if eventos[0].Hora.IsZero() {
		t.Errorf("hora nao foi lida")
	}
	if valorDe(eventos[3], "QueryName") != "auth.eulen.gg" {
		t.Errorf("QueryName errado: %q", valorDe(eventos[3], "QueryName"))
	}
}

func TestResumirEAvaliarETW(t *testing.T) {
	eventos, _ := lerEventosTracerpt(strings.NewReader(xmlTracerpt))
	res := resumirETW(eventos)
	if len(res.Imagens) != 2 || len(res.ProcessosNovos) != 1 || len(res.DNS) != 2 {
		t.Fatalf("resumo errado: imagens=%d processos=%d dns=%d", len(res.Imagens), len(res.ProcessosNovos), len(res.DNS))
	}
	if contaMarcadoresTeste(res) != 1 {
		t.Errorf("devia contar 1 marcador cmd.exe")
	}
	sinais := avaliarETW(res, assinaturasDeTeste(t), 20*time.Second)
	if !sinaisTem(sinais, Critico, "eulen.dll") {
		t.Errorf("devia detectar eulen.dll carregada: %+v", sinais)
	}
	if !sinaisTem(sinais, Critico, "auth.eulen.gg") {
		t.Errorf("devia detectar DNS do eulen: %+v", sinais)
	}
	for _, limpo := range []string{"ntdll.dll", "google.com"} {
		if sinaisTem(sinais, Critico, limpo) || sinaisTem(sinais, Alerta, limpo) {
			t.Errorf("%s nao devia ser flagrado: %+v", limpo, sinais)
		}
	}
}

func contaMarcadoresTeste(res resumoETW) int {
	total := 0
	for _, e := range res.ProcessosNovos {
		nome := strings.ToLower(valorDe(e, "ImageName", "ProcessName", "FileName"))
		if strings.HasSuffix(nome, "cmd.exe") {
			total++
		}
	}
	return total
}

func TestETWVazioEhCritico(t *testing.T) {
	sinais := avaliarETW(resumoETW{ImagensPorPID: map[int][]string{}}, assinaturasDeTeste(t), 20*time.Second)
	if !sinaisTem(sinais, Critico, "VAZIA") {
		t.Errorf("captura vazia devia ser critica: %+v", sinais)
	}
}

func TestSessoesETWNaoLidasNaoAcusam(t *testing.T) {
	s := avaliarSessoesETW([]SessaoETW{{Nome: "EventLog-Application", Estado: "Running"}})
	if !sinaisTem(s, Info, "Nao consegui ler") {
		t.Errorf("lista curta demais devia virar informativo, nao acusacao: %+v", s)
	}
	for _, x := range s {
		if x.Severidade == Critico {
			t.Errorf("nao pode acusar com lista incompleta: %+v", s)
		}
	}
}

func TestSessoesETWEssenciais(t *testing.T) {
	completas := []SessaoETW{{Nome: "EventLog-System", Estado: "Running"}, {Nome: "EventLog-Application", Estado: "Running"}, {Nome: "EventLog-Security", Estado: "Running"}, {Nome: "DiagTrack-Listener", Estado: "Running"}}
	for i := 0; i < 20; i++ {
		completas = append(completas, SessaoETW{Nome: fmt.Sprintf("Sessao%d", i), Estado: "Running"})
	}
	if s := avaliarSessoesETW(completas); len(s) != 0 {
		t.Errorf("sistema completo nao devia gerar sinal: %+v", s)
	}
	faltando := []SessaoETW{{Nome: "EventLog-Application", Estado: "Running"}}
	for i := 0; i < 20; i++ {
		faltando = append(faltando, SessaoETW{Nome: fmt.Sprintf("Sessao%d", i), Estado: "Running"})
	}
	s := avaliarSessoesETW(faltando)
	if !sinaisTem(s, Critico, "eventlog-security") || !sinaisTem(s, Critico, "eventlog-system") {
		t.Errorf("devia apontar as sessoes paradas: %+v", s)
	}
}

func TestEventosDeIntegridadeDeCodigo(t *testing.T) {
	a := assinaturasDeTeste(t)
	eventos := []EventoETW{
		{Provedor: "Microsoft-Windows-CodeIntegrity/Operational", ID: 3033, Hora: time.Now().Add(-2 * time.Hour), Dados: map[string]string{"FileNameBuffer": `\Device\HarddiskVolume3\Users\jogador\AppData\Local\Temp\drv.sys`}},
		{Provedor: "Microsoft-Windows-CodeIntegrity/Operational", ID: 3023, Hora: time.Now().Add(-3 * time.Hour), Dados: map[string]string{"FileNameBuffer": `\Device\HarddiskVolume3\Temp\iqvw64e.sys`}},
	}
	s := avaliarEventosDeIntegridade(eventos, a)
	if !sinaisTem(s, Critico, "nao assinado") {
		t.Errorf("3033 devia ser critico: %+v", s)
	}
	if !sinaisTem(s, Critico, "lista de vulneraveis") {
		t.Errorf("3023 devia ser critico: %+v", s)
	}
}

const saidaLogmanPT = `
Nome do Coletor de Dados                 Tipo                          Status
-------------------------------------------------------------------------------
EventLog-Application                     Rastreamento                  Executando
EventLog-Security                        Rastreamento                  Executando
EventLog-System                          Rastreamento                  Executando
DiagTrack-Listener                       Rastreamento                  Executando
Circular Kernel Context Logger           Rastreamento                  Executando
DefenderApiLogger                        Rastreamento                  Executando

O comando foi concluído com êxito.
`

const saidaLogmanEN = `
Data Collector Set                        Type                          Status
-------------------------------------------------------------------------------
EventLog-Application                      Trace                         Running
EventLog-System                           Trace                         Running
NtfsLog                                   Trace                         Running

The command completed successfully.
`

func TestParserDoLogmanEmQualquerIdioma(t *testing.T) {
	pt := lerSessoesDoLogman(saidaLogmanPT)
	if len(pt) != 6 {
		t.Fatalf("saida em portugues: esperava 6 sessoes, veio %d: %+v", len(pt), pt)
	}
	if pt[0].Nome != "EventLog-Application" {
		t.Errorf("nome errado: %q", pt[0].Nome)
	}
	if pt[4].Nome != "Circular Kernel Context Logger" {
		t.Errorf("nome com espaco foi cortado: %q", pt[4].Nome)
	}
	en := lerSessoesDoLogman(saidaLogmanEN)
	if len(en) != 3 {
		t.Fatalf("saida em ingles: esperava 3 sessoes, veio %d: %+v", len(en), en)
	}
	if len(lerSessoesDoLogman("")) != 0 {
		t.Errorf("saida vazia nao pode virar sessao")
	}
}
