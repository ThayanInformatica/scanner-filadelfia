//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

type execucao struct {
	Caminho string
	Hora    time.Time
	Fonte   string
	Usuario string
}

func checarRegistro(c *Contexto) {
	r := c.R
	r.Secao("HISTORICO DE EXECUCAO (registro do Windows)")

	var execucoes []execucao
	execucoes = append(execucoes, lerBAM(c)...)

	for _, p := range c.Perfis {
		if !p.Hive {
			continue
		}
		execucoes = append(execucoes, lerUserAssist(p)...)
		execucoes = append(execucoes, lerCompatStore(p)...)
		execucoes = append(execucoes, lerMuiCache(p)...)
		execucoes = append(execucoes, lerRecentDocs(p)...)
	}

	sort.Slice(execucoes, func(i, j int) bool { return execucoes[i].Hora.After(execucoes[j].Hora) })
	for _, e := range execucoes {
		if e.Fonte == "BAM" || e.Fonte == "UserAssist" {
			c.RegistraExecucao(e.Caminho, e.Hora, e.Fonte)
		}
	}

	porFonte := map[string]int{}
	for _, e := range execucoes {
		porFonte[e.Fonte]++
	}
	var resumoFontes []string
	for _, f := range []string{"BAM", "UserAssist", "PcaSvc Store", "MuiCache", "RecentDocs"} {
		resumoFontes = append(resumoFontes, fmt.Sprintf("%s=%d", f, porFonte[f]))
	}
	r.Linha("Entradas encontradas: %s", strings.Join(resumoFontes, "  "))

	c.Rastros.BAMLido = true
	c.Rastros.BAMQuantidade = porFonte["BAM"]
	c.Rastros.UserAssistQuantidade = porFonte["UserAssist"]
	if porFonte["BAM"] == 0 {
		r.Add(Critico, "BAM VAZIO", "O BAM sempre tem dezenas de entradas em um Windows em uso. Vazio = limpo ou servico desligado")
	} else if porFonte["BAM"] < 15 && !c.Instalacao.IsZero() && time.Since(c.Instalacao) > 7*24*time.Hour {
		r.Add(Alerta, fmt.Sprintf("BAM com poucas entradas (%d)", porFonte["BAM"]), "Pode ter sido limpo recentemente")
	}
	if porFonte["UserAssist"] == 0 {
		r.Add(Alerta, "UserAssist vazio", "Historico de programas abertos pelo Explorer foi limpo ou desativado")
	}
	if porFonte["PcaSvc Store"] == 0 {
		r.Add(Alerta, "Compatibility Assistant Store vazio", "Historico do PcaSvc limpo (ou servico parado ha muito tempo)")
	}

	vistos := map[string]bool{}
	var recentes, acessoRemoto []string
	for _, e := range execucoes {
		chave := strings.ToLower(e.Caminho)
		if t := c.A.ControleRemotoAtivo(filepath.Base(e.Caminho)); t != "" && !e.Hora.IsZero() && time.Since(e.Hora) < 7*24*time.Hour && !vistos["a"+chave] {
			vistos["a"+chave] = true
			acessoRemoto = append(acessoRemoto, fmt.Sprintf("%s  %s  (%s, %s)", formataHora(e.Hora), e.Caminho, t, e.Fonte))
		}
		if classe, t := c.A.Classificar(e.Caminho); classe != SemMatch && !vistos["m"+chave] {
			vistos["m"+chave] = true
			r.Add(classe.Severidade(), fmt.Sprintf("Executado (%s) bate com assinatura '%s': %s", e.Fonte, t, filepath.Base(e.Caminho)), fmt.Sprintf("%s  usuario: %s\n%s", formataHora(e.Hora), e.Usuario, e.Caminho))
			continue
		}
		if motivo := caminhoSuspeito(e.Caminho); motivo != "" && !vistos["s"+chave] && (e.Fonte == "BAM" || e.Fonte == "PcaSvc Store") {
			vistos["s"+chave] = true
			r.Add(Alerta, fmt.Sprintf("Executavel %s (%s)", motivo, e.Fonte), fmt.Sprintf("%s  usuario: %s\n%s", formataHora(e.Hora), e.Usuario, e.Caminho))
			continue
		}
		if !e.Hora.IsZero() && time.Since(e.Hora) < 7*24*time.Hour && e.Fonte == "BAM" && !vistos["r"+chave] {
			vistos["r"+chave] = true
			recentes = append(recentes, fmt.Sprintf("%s  %s", formataHora(e.Hora), e.Caminho))
		}
	}
	if len(recentes) > 0 {
		r.Add(Info, fmt.Sprintf("Ultimos executaveis registrados no BAM (7 dias): %d", len(recentes)), strings.Join(limita(recentes, 240), "\n"))
	}
	if len(acessoRemoto) > 0 {
		r.Add(Alerta, fmt.Sprintf("Ferramenta de acesso remoto executada nos ultimos 7 dias: %d", len(acessoRemoto)), strings.Join(limita(acessoRemoto, 20), "\n")+"\nAnyDesk, RustDesk e afins sao normais para suporte, mas tambem sao o jeito padrao de vendedor de cheat instalar e configurar no PC do cliente. Pergunte ao jogador quem acessou o PC e por que")
	}

	for _, p := range c.Perfis {
		if !p.Hive {
			continue
		}
		checarMRUs(c, p)
		checarAutoInicio(c, p)
	}
	checarAutoInicioMaquina(c)
	for _, p := range c.Perfis {
		checarHistoricoPowerShell(c, p)
	}
}

func lerBAM(c *Contexto) []execucao {
	var lista []execucao
	for _, raiz := range []string{`SYSTEM\CurrentControlSet\Services\bam\State\UserSettings`, `SYSTEM\CurrentControlSet\Services\bam\UserSettings`} {
		for _, sid := range subchaves(registry.LOCAL_MACHINE, raiz) {
			usuario := sid
			for _, p := range c.Perfis {
				if strings.EqualFold(p.SID, sid) {
					usuario = p.Usuario
				}
			}
			for _, v := range valoresDaChave(registry.LOCAL_MACHINE, raiz+`\`+sid) {
				if v.Nome == "Version" || v.Nome == "SequenceNumber" || len(v.Bytes) < 8 {
					continue
				}
				lista = append(lista, execucao{Caminho: normalizaDevice(v.Nome), Hora: filetimeDeBytes(v.Bytes), Fonte: "BAM", Usuario: usuario})
			}
		}
		if len(lista) > 0 {
			break
		}
	}
	return lista
}

func normalizaDevice(caminho string) string {
	if strings.HasPrefix(caminho, `\Device\HarddiskVolume`) {
		resto := caminho[len(`\Device\HarddiskVolume`):]
		if i := strings.Index(resto, `\`); i >= 0 {
			return "[Volume" + resto[:i] + "]" + resto[i:]
		}
	}
	return caminho
}

func lerUserAssist(p Perfil) []execucao {
	var lista []execucao
	raiz := p.SID + `\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`
	for _, guid := range subchaves(registry.USERS, raiz) {
		for _, v := range valoresDaChave(registry.USERS, raiz+`\`+guid+`\Count`) {
			nome := rot13(v.Nome)
			if strings.HasPrefix(nome, "UEME_") || nome == "" {
				continue
			}
			e := execucao{Caminho: nome, Fonte: "UserAssist", Usuario: p.Usuario}
			if len(v.Bytes) >= 68 {
				e.Hora = filetimeDeBytes(v.Bytes[60:68])
			}
			lista = append(lista, e)
		}
	}
	return lista
}

func lerCompatStore(p Perfil) []execucao {
	var lista []execucao
	for _, nome := range nomesDeValores(registry.USERS, p.SID+`\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store`) {
		lista = append(lista, execucao{Caminho: nome, Fonte: "PcaSvc Store", Usuario: p.Usuario})
	}
	return lista
}

func lerMuiCache(p Perfil) []execucao {
	var lista []execucao
	for _, nome := range nomesDeValores(registry.USERS, p.SID+`_Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache`) {
		if strings.HasPrefix(nome, "@") || strings.HasSuffix(nome, ".ApplicationCompany") {
			continue
		}
		nome = strings.TrimSuffix(nome, ".FriendlyAppName")
		lista = append(lista, execucao{Caminho: nome, Fonte: "MuiCache", Usuario: p.Usuario})
	}
	return lista
}

func lerRecentDocs(p Perfil) []execucao {
	var lista []execucao
	raiz := p.SID + `\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`
	for _, v := range valoresDaChave(registry.USERS, raiz) {
		if v.Nome == "MRUListEx" {
			continue
		}
		if nome := utf16DeBytes(v.Bytes); nome != "" {
			lista = append(lista, execucao{Caminho: nome, Fonte: "RecentDocs", Usuario: p.Usuario})
		}
	}
	for _, ext := range subchaves(registry.USERS, raiz) {
		for _, v := range valoresDaChave(registry.USERS, raiz+`\`+ext) {
			if v.Nome == "MRUListEx" {
				continue
			}
			if nome := utf16DeBytes(v.Bytes); nome != "" {
				lista = append(lista, execucao{Caminho: nome, Fonte: "RecentDocs", Usuario: p.Usuario})
			}
		}
	}
	return lista
}

func checarMRUs(c *Contexto, p Perfil) {
	r := c.R
	base := p.SID + `\Software\Microsoft\Windows\CurrentVersion\Explorer\`

	var comandos []string
	for _, v := range valoresDaChave(registry.USERS, base+"RunMRU") {
		if v.Nome == "MRUList" || v.Texto == "" {
			continue
		}
		cmd := strings.TrimSuffix(v.Texto, `\1`)
		comandos = append(comandos, cmd)
		if strings.EqualFold(strings.TrimSpace(cmd), "prefetch") || strings.Contains(strings.ToLower(cmd), `\prefetch`) {
			r.Add(Alerta, "Abriu a pasta Prefetch pela caixa Executar ("+p.Usuario+")", cmd+"\nQuem abre essa pasta normalmente e para apagar os .pf. Cruzar com a checagem de Prefetch")
		} else if motivo := comandoDeOcultacao(cmd); motivo != "" {
			r.Add(Critico, "Comando de ocultacao na caixa Executar ("+p.Usuario+"): "+motivo, cmd)
		} else if classe, t := c.A.Classificar(cmd); classe != SemMatch {
			r.Add(classe.Severidade(), "Caixa Executar ("+p.Usuario+") bate com assinatura '"+t+"'", cmd)
		}
	}
	if len(comandos) > 0 {
		r.Add(Info, fmt.Sprintf("Historico da caixa Executar de %s (%d)", p.Usuario, len(comandos)), strings.Join(limita(comandos, 120), "\n"))
	}

	var caminhos []string
	for _, v := range valoresDaChave(registry.USERS, base+"TypedPaths") {
		if v.Texto == "" {
			continue
		}
		caminhos = append(caminhos, v.Texto)
		if classe, t := c.A.Classificar(v.Texto); classe != SemMatch {
			r.Add(classe.Severidade(), "Caminho digitado no Explorer ("+p.Usuario+") bate com '"+t+"'", v.Texto)
		}
	}
	if len(caminhos) > 0 {
		r.Add(Info, fmt.Sprintf("Caminhos digitados no Explorer por %s", p.Usuario), strings.Join(limita(caminhos, 100), "\n"))
	}

	var buscas []string
	for _, v := range valoresDaChave(registry.USERS, base+"WordWheelQuery") {
		if v.Nome == "MRUListEx" {
			continue
		}
		termo := utf16DeBytes(v.Bytes)
		if termo == "" {
			continue
		}
		buscas = append(buscas, termo)
		if classe, t := c.A.Classificar(termo); classe != SemMatch {
			r.Add(classe.Severidade(), "Busca no Explorer ("+p.Usuario+") bate com '"+t+"'", termo)
		}
	}
	if len(buscas) > 0 {
		r.Add(Info, fmt.Sprintf("Buscas feitas no Explorer por %s", p.Usuario), strings.Join(limita(buscas, 100), "\n"))
	}
}

func checarAutoInicio(c *Contexto, p Perfil) {
	for _, chave := range []string{`Software\Microsoft\Windows\CurrentVersion\Run`, `Software\Microsoft\Windows\CurrentVersion\RunOnce`} {
		for _, v := range valoresDaChave(registry.USERS, p.SID+`\`+chave) {
			avaliaAutoInicio(c, "HKU\\"+p.Usuario+"\\...\\"+filepath.Base(chave), v.Nome, v.Texto)
		}
	}
}

func checarAutoInicioMaquina(c *Contexto) {
	for _, chave := range []string{`SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`} {
		for _, v := range valoresDaChave(registry.LOCAL_MACHINE, chave) {
			avaliaAutoInicio(c, "HKLM\\...\\"+filepath.Base(chave), v.Nome, v.Texto)
		}
	}
}

func avaliaAutoInicio(c *Contexto, origem, nome, comando string) {
	texto := nome + " " + comando
	if classe, t := c.A.Classificar(texto); classe != SemMatch {
		c.R.Add(classe.Severidade(), "Inicializacao automatica bate com '"+t+"' ("+origem+")", nome+" = "+comando)
		return
	}
	if motivo := caminhoSuspeito(comando); motivo != "" {
		c.R.Add(Alerta, "Inicializacao automatica "+motivo+" ("+origem+")", nome+" = "+comando)
	}
}

func checarHistoricoPowerShell(c *Contexto, p Perfil) {
	caminho := filepath.Join(p.Pasta, `AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`)
	conteudo, err := os.ReadFile(caminho)
	if err != nil {
		return
	}
	var suspeitos []string
	linhas := strings.Split(string(conteudo), "\n")
	for _, l := range linhas {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if motivo := comandoDeOcultacao(l); motivo != "" {
			suspeitos = append(suspeitos, "["+motivo+"] "+resume(l, 150))
		} else if classe, t := c.A.Classificar(l); classe != SemMatch {
			suspeitos = append(suspeitos, "[assinatura "+t+"] "+resume(l, 150))
		}
	}
	c.R.Linha("Historico PowerShell de %s: %d linhas", p.Usuario, len(linhas))
	if len(suspeitos) > 0 {
		c.R.Add(Critico, fmt.Sprintf("Historico PowerShell de %s tem %d comando(s) de ocultacao/cheat", p.Usuario, len(suspeitos)), strings.Join(limita(suspeitos, 100), "\n"))
	}
}
