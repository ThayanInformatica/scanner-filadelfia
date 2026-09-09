//go:build windows

package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

func coletarArquivosDoJogo(raiz string, limite int) []ArquivoDoJogo {
	var lista []ArquivoDoJogo
	base := strings.Count(filepath.Clean(raiz), string(os.PathSeparator))
	filepath.WalkDir(raiz, func(caminho string, d fs.DirEntry, err error) error {
		if err != nil || len(lista) >= limite {
			return nil
		}
		if d.IsDir() {
			nome := strings.ToLower(d.Name())
			if nome == "cache" || nome == "logs" || nome == "crashes" || nome == "data" && strings.Contains(strings.ToLower(caminho), "fivem.app") {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext != ".exe" && ext != ".dll" && ext != ".asi" && ext != ".sys" {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		lista = append(lista, ArquivoDoJogo{
			Caminho: caminho, Nome: d.Name(), Tamanho: info.Size(), Modificado: info.ModTime(),
			NaRaiz: strings.Count(filepath.Clean(caminho), string(os.PathSeparator))-base <= 1,
		})
		return nil
	})
	return lista
}

func preencherAssinaturas(arquivos []ArquivoDoJogo, r *Relatorio, rotulo string) []ArquivoDoJogo {
	var caminhos []string
	for _, a := range arquivos {
		caminhos = append(caminhos, a.Caminho)
	}
	const lote = 60
	mapa := map[string][2]string{}
	for i := 0; i < len(caminhos); i += lote {
		fim := i + lote
		if fim > len(caminhos) {
			fim = len(caminhos)
		}
		r.Progresso("Conferindo assinatura digital de %s (%d de %d arquivos)", rotulo, fim, len(caminhos))
		for k, v := range assinaturasAuthenticode(caminhos[i:fim]) {
			mapa[k] = v
		}
	}
	for i := range arquivos {
		if v, ok := mapa[strings.ToLower(arquivos[i].Caminho)]; ok {
			arquivos[i].Assinatura = v[0]
			arquivos[i].Assinante = v[1]
		}
	}
	return arquivos
}

func pastasDoGTA(c *Contexto) []string {
	var pastas []string
	vistos := map[string]bool{}
	adiciona := func(p string) {
		if p == "" {
			return
		}
		lower := strings.ToLower(p)
		if vistos[lower] || !existe(filepath.Join(p, "GTA5.exe")) && !existe(filepath.Join(p, "PlayGTAV.exe")) && !existe(filepath.Join(p, "GTA5_Enhanced.exe")) {
			return
		}
		vistos[lower] = true
		pastas = append(pastas, p)
	}
	for _, chave := range []string{
		`SOFTWARE\WOW6432Node\Rockstar Games\Grand Theft Auto V`,
		`SOFTWARE\Rockstar Games\Grand Theft Auto V`,
		`SOFTWARE\WOW6432Node\Rockstar Games\GTAV`,
	} {
		if v, ok := lerString(registry.LOCAL_MACHINE, chave, "InstallFolder"); ok {
			adiciona(v)
		}
	}
	for _, unidade := range unidadesFixas() {
		for _, sub := range []string{
			`Program Files\Rockstar Games\Grand Theft Auto V`,
			`Program Files (x86)\Steam\steamapps\common\Grand Theft Auto V`,
			`SteamLibrary\steamapps\common\Grand Theft Auto V`,
			`Games\Grand Theft Auto V`,
			`Grand Theft Auto V`,
			`Epic Games\GTAV`,
		} {
			adiciona(filepath.Join(unidade, sub))
		}
	}
	for _, p := range c.Perfis {
		adiciona(filepath.Join(p.Pasta, "Desktop", "Grand Theft Auto V"))
	}
	return pastas
}

func detectarVirtualizacao() []SinalDeVirtualizacao {
	var achados []SinalDeVirtualizacao
	testar := func(fonte, valor string) {
		if valor == "" {
			return
		}
		if m := contemAlgum(valor, marcasDeVM); m != "" {
			achados = append(achados, SinalDeVirtualizacao{Fonte: fonte, Valor: valor, Marca: m})
		}
	}
	const bios = `HARDWARE\DESCRIPTION\System\BIOS`
	for _, campo := range []string{"SystemManufacturer", "SystemProductName", "BIOSVendor", "BaseBoardManufacturer", "BaseBoardProduct"} {
		if v, ok := lerString(registry.LOCAL_MACHINE, bios, campo); ok {
			testar("BIOS/"+campo, v)
		}
	}
	if v, ok := lerString(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System`, "SystemBiosVersion"); ok {
		testar("BIOS", v)
	}
	for _, servico := range []string{"VBoxGuest", "VBoxService", "vmhgfs", "vmmouse", "vmtools", "vmrawdsk", "qemu-ga", "prl_tools", "prl_fs"} {
		if _, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+servico, registry.READ); err == nil {
			achados = append(achados, SinalDeVirtualizacao{Fonte: "servico do Windows", Valor: servico, Marca: strings.ToLower(servico)})
		}
	}
	if processos, err := listarProcessos(); err == nil {
		for _, p := range processos {
			nome := strings.ToLower(p.Nome)
			for _, alvo := range []string{"vmtoolsd.exe", "vboxservice.exe", "vboxtray.exe", "vmwaretray.exe", "vmwareuser.exe", "prl_cc.exe", "qemu-ga.exe", "vmusrvc.exe", "vmsrvc.exe"} {
				if nome == alvo {
					achados = append(achados, SinalDeVirtualizacao{Fonte: "processo rodando", Valor: p.Nome, Marca: strings.TrimSuffix(alvo, ".exe")})
				}
			}
		}
	}
	return achados
}

func checarJogo(c *Contexto) {
	r := c.R
	r.Secao("INTEGRIDADE DO JOGO (FiveM e GTA V)")

	vms := detectarVirtualizacao()
	for _, s := range avaliarVirtualizacaoForte(vms) {
		r.Add(s.Severidade, s.Titulo, s.Detalhe)
	}
	if len(avaliarVirtualizacaoForte(vms)) == 0 {
		r.Ok("Windows rodando direto no hardware, nao em maquina virtual")
	}

	instalacoes := 0
	for _, p := range c.Perfis {
		candidatos := []string{
			filepath.Join(p.Pasta, "AppData", "Local", "FiveM", "FiveM.app"),
			filepath.Join(p.Pasta, "Downloads", "FiveM.app"),
			filepath.Join(p.Pasta, "Desktop", "FiveM.app"),
		}
		for _, unidade := range unidadesFixas() {
			candidatos = append(candidatos, filepath.Join(unidade, "FiveM", "FiveM.app"), filepath.Join(unidade, "FiveM.app"))
		}
		for _, app := range candidatos {
			if !existe(filepath.Join(app, "FiveM.exe")) && !existe(filepath.Join(app, "CitizenFX.ini")) {
				continue
			}
			instalacoes++
			r.Linha("FiveM de %s em %s", p.Usuario, app)
			for _, s := range avaliarLocalDaInstalacao(app) {
				r.Add(s.Severidade, s.Titulo, s.Detalhe)
			}
			inicio := time.Now()
			arquivos := preencherAssinaturas(coletarArquivosDoJogo(app, 4000), r, "arquivos do FiveM")
			r.Linha("%d arquivos do FiveM conferidos em %s", len(arquivos), time.Since(inicio).Round(time.Second))
			sinais := avaliarIntegridadeDoJogo(app, arquivos, c.A)
			for _, s := range sinais {
				r.Add(s.Severidade, s.Titulo, s.Detalhe)
			}
			if len(sinais) == 0 {
				r.Ok("Arquivos do FiveM com assinatura digital do fabricante, nenhum trocado")
			}
		}
	}
	if instalacoes == 0 {
		r.Add(Info, "Nenhuma instalacao do FiveM encontrada para conferir", "Sem a pasta FiveM.app nao da para checar se algum arquivo do jogo foi trocado por versao modificada")
	}

	pastas := pastasDoGTA(c)
	if len(pastas) == 0 {
		r.Linha("Pasta do GTA V nao encontrada nos locais conhecidos")
		return
	}
	for _, pasta := range pastas {
		r.Linha("GTA V em %s", pasta)
		inicio := time.Now()
		arquivos := preencherAssinaturas(coletarArquivosDoJogo(pasta, 4000), r, "arquivos do GTA V")
		r.Linha("%d arquivos do GTA V conferidos em %s", len(arquivos), time.Since(inicio).Round(time.Second))
		sinais := avaliarPastaDoGTA(pasta, arquivos, c.A)
		for _, s := range sinais {
			r.Add(s.Severidade, s.Titulo, s.Detalhe)
		}
		if len(sinais) == 0 {
			r.Ok("Nenhum plugin .asi nem dll de carregamento de mod na pasta do GTA V")
		}
	}
}
