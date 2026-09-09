//go:build windows

package main

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

func dispositivosDoRegistro() []DispositivoVisto {
	var lista []DispositivoVisto
	presentes := map[string]bool{}
	saida, err := executar("pnputil", "/enum-devices", "/connected")
	if err == nil {
		for _, l := range strings.Split(saida, "\n") {
			l = strings.TrimSpace(l)
			if i := strings.Index(l, ":"); i > 0 && strings.Contains(strings.ToUpper(l[:i]), "ID") {
				presentes[strings.ToUpper(strings.TrimSpace(l[i+1:]))] = true
			}
		}
	}
	for _, classe := range []string{"PCI", "USB", "HID", "USBSTOR"} {
		raiz := `SYSTEM\CurrentControlSet\Enum\` + classe
		for _, dispositivo := range subchaves(registry.LOCAL_MACHINE, raiz) {
			for _, instancia := range subchaves(registry.LOCAL_MACHINE, raiz+`\`+dispositivo) {
				chave := raiz + `\` + dispositivo + `\` + instancia
				desc, _ := lerString(registry.LOCAL_MACHINE, chave, "DeviceDesc")
				amigavel, _ := lerString(registry.LOCAL_MACHINE, chave, "FriendlyName")
				fabricante, _ := lerString(registry.LOCAL_MACHINE, chave, "Mfg")
				if i := strings.LastIndex(desc, ";"); i >= 0 {
					desc = desc[i+1:]
				}
				if i := strings.LastIndex(fabricante, ";"); i >= 0 {
					fabricante = fabricante[i+1:]
				}
				id := classe + `\` + dispositivo + `\` + instancia
				lista = append(lista, DispositivoVisto{
					Classe:     classe,
					Descricao:  strings.TrimSpace(strings.Join([]string{amigavel, desc, fabricante}, " ")),
					HardwareID: id,
					Presente:   presentes[strings.ToUpper(id)] || len(presentes) == 0,
				})
			}
		}
	}
	return lista
}

func checarHardware(c *Contexto) {
	r := c.R
	r.Secao("HARDWARE (placa DMA, KMBox, dispositivos de aim assist)")
	dispositivos := dispositivosDoRegistro()
	r.Linha("%d dispositivos PCI/USB/HID conhecidos pelo Windows (conectados agora ou no passado)", len(dispositivos))
	sinais := avaliarDispositivos(dispositivos, c.A)
	for _, s := range sinais {
		r.Add(s.Severidade, s.Titulo, s.Detalhe)
	}
	if len(sinais) == 0 {
		r.Ok("Nenhuma placa DMA/FPGA nem dispositivo de aim assist (KMBox, MAKCU, Xim, Cronus, Arduino) no historico de hardware")
	}
	var seriais []string
	for _, d := range dispositivos {
		desc := strings.ToLower(d.Descricao)
		if d.Classe == "USB" && (strings.Contains(desc, "serial") || strings.Contains(desc, "ch340") || strings.Contains(desc, "cp210") || strings.Contains(desc, "ftdi") || strings.Contains(desc, "arduino")) {
			seriais = append(seriais, fmt.Sprintf("%s  [%s]", d.Descricao, d.HardwareID))
		}
	}
	if len(seriais) > 0 {
		r.Add(Info, fmt.Sprintf("Conversores USB-serial ja conectados: %d", len(seriais)), strings.Join(limitaLinhas(seriais, 60), "\n")+"\nKMBox e placas de aim assist aparecem como USB-serial generico. Sem outro indicio, e so informativo")
	}
}
