package main

import (
	"strings"
	"testing"
	"time"
)

func TestLicencaDoFiveMApagadaOuRecriada(t *testing.T) {
	instalado := time.Now().Add(-120 * 24 * time.Hour)
	s := avaliarLicencaDoFiveM(EstadoDaLicencaDoFiveM{FiveMInstalado: true, PastaExiste: false}, instalado, time.Now())
	if len(s) != 1 || s[0].Severidade != Alerta || !strings.Contains(s[0].Titulo, "NAO EXISTE") {
		t.Fatalf("FiveM instalado sem DigitalEntitlements e alerta: %+v", s)
	}
	s = avaliarLicencaDoFiveM(EstadoDaLicencaDoFiveM{FiveMInstalado: true, PastaExiste: true, PastaCriadaEm: time.Now().Add(-2 * 24 * time.Hour)}, instalado, time.Now())
	if len(s) != 1 || !strings.Contains(s[0].Titulo, "recriada") {
		t.Fatalf("pasta recriada ha 2 dias num Windows de 4 meses e alerta: %+v", s)
	}
	if s := avaliarLicencaDoFiveM(EstadoDaLicencaDoFiveM{FiveMInstalado: true, PastaExiste: true, PastaCriadaEm: instalado.Add(24 * time.Hour)}, instalado, time.Now()); s != nil {
		t.Fatalf("pasta antiga e normal: %+v", s)
	}
	if s := avaliarLicencaDoFiveM(EstadoDaLicencaDoFiveM{FiveMInstalado: true, PastaExiste: false}, time.Now().Add(-24*time.Hour), time.Now()); s != nil {
		t.Fatalf("Windows de ontem sem a pasta e normal: %+v", s)
	}
	s = avaliarLicencaDoFiveM(EstadoDaLicencaDoFiveM{FiveMInstalado: false, PastaBladeGroupExiste: true}, instalado, time.Now())
	if len(s) != 1 || s[0].Severidade != Critico || !strings.Contains(s[0].Titulo, "Blade Group") {
		t.Fatalf("pasta Blade Group e marca de bypass: %+v", s)
	}
}

func TestAutodestruicaoNoJournal(t *testing.T) {
	agora := time.Now()
	eventos := []EventoUSN{
		{Nome: "xk9f2m1pq7zt.exe", Motivo: "apagado", Hora: agora.Add(-2 * time.Hour)},
		{Nome: "a1b2c3d4e5f6.dll", Motivo: "apagado", Hora: agora.Add(-5 * time.Hour)},
		{Nome: "setup.exe", Motivo: "apagado", Hora: agora.Add(-1 * time.Hour)},
		{Nome: "q9w8e7r6t5y4.exe", Motivo: "criado", Hora: agora.Add(-1 * time.Hour)},
		{Nome: "zz11kk22ll33.exe", Motivo: "apagado", Hora: agora.Add(-10 * 24 * time.Hour)},
	}
	s := avaliarAutodestruicaoNoJournal("C:", eventos, agora)
	if len(s) != 1 || !strings.Contains(s[0].Titulo, "2 executavel") {
		t.Fatalf("dois aleatorios apagados em 72h viram alerta, setup.exe e criado nao contam: %+v", s)
	}
	if s := avaliarAutodestruicaoNoJournal("C:", eventos[:1], agora); s != nil {
		t.Fatalf("um so nao basta: %+v", s)
	}
}
