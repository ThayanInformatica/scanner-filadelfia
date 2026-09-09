//go:build windows

package main

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

func checarSistema(c *Contexto) {
	r := c.R
	r.Secao("SISTEMA")

	c.Instalacao = dataInstalacaoWindows()
	ligado := tempoLigado()
	c.Boot = time.Now().Add(-ligado)

	r.Sistema_("Windows", versaoWindows())
	r.Sistema_("Usuario atual", r.Usuario)
	r.Sistema_("Instalacao do Windows", formataHora(c.Instalacao))
	r.Sistema_("Ultimo boot", fmt.Sprintf("%s (ligado ha %s)", formataHora(c.Boot), ligado.Round(time.Minute)))
	r.Sistema_("Hora do sistema", formataHora(time.Now()))

	if idade := time.Since(c.Instalacao); !c.Instalacao.IsZero() && idade < 24*time.Hour {
		r.Add(Critico, fmt.Sprintf("Windows FORMATADO HOJE, %s antes desta checagem", idade.Round(time.Minute)), "Instalado em "+formataHora(c.Instalacao)+"\nFormatar no mesmo dia da telagem zera Prefetch, BAM, logs, historico e journal. E a forma mais completa de apagar rastro, e o proprio ato ja e o indicio: quase nada do que este relatorio mede sobreviveu a isso")
	} else if !c.Instalacao.IsZero() && idade < 72*time.Hour {
		r.Add(Alerta, fmt.Sprintf("Windows instalado ha %s", idade.Round(time.Hour)), "Formatacao recente apaga todo o historico. Instalado em "+formataHora(c.Instalacao))
	}
	if ligado < 30*time.Minute {
		r.Add(Info, "PC reiniciado ha menos de 30 minutos", "Reiniciar antes da checagem limpa processos, modulos injetados e o cache DNS")
	}

	c.Perfis = perfisDeUsuario()
	var nomes []string
	for _, p := range c.Perfis {
		estado := "hive carregada"
		if !p.Hive {
			estado = "sem sessao aberta, registro do usuario nao analisado"
		}
		nomes = append(nomes, fmt.Sprintf("%s (%s)", p.Usuario, estado))
	}
	r.Sistema_("Perfis de usuario", strings.Join(nomes, "; "))

	opcoes, err := integridadeDeCodigo()
	if err != nil {
		r.Erro("integridade de codigo: %v", err)
	} else {
		if opcoes&ciTestSign != 0 {
			r.Add(Critico, "Modo TESTSIGNING ativo", "Permite carregar drivers de kernel sem assinatura. Usado por cheats de kernel e spoofers")
		}
		if opcoes&ciDebugMode != 0 {
			r.Add(Alerta, "Kernel em modo DEBUG", "Depuracao de kernel habilitada (bcdedit /debug on). Desabilita protecoes do PatchGuard")
		}
		if opcoes&ciEnabled == 0 {
			r.Add(Critico, "Verificacao de assinatura de driver DESLIGADA", "nointegritychecks ativo. Qualquer driver pode ser carregado")
		}
		if opcoes&(ciTestSign|ciDebugMode) == 0 && opcoes&ciEnabled != 0 {
			r.Ok("Integridade de codigo normal (drivers precisam de assinatura)")
		}
	}

	if v, ok := lerDword(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\SecureBoot\State`, "UEFISecureBootEnabled"); ok {
		if v == 1 {
			r.Ok("Secure Boot ligado")
		} else {
			r.Add(Info, "Secure Boot desligado", "Nao e prova de nada, mas facilita drivers nao assinados e spoofers de BIOS")
		}
	}
	if v, ok := lerDword(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity`, "Enabled"); ok {
		if v == 1 {
			r.Ok("HVCI (integridade de memoria) ligado")
		} else {
			r.Add(Info, "HVCI (integridade de memoria) desligado", "Comum em PC gamer, mas cheats de kernel exigem isso desligado")
		}
	}
	if v, ok := lerDword(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\CI\Config`, "VulnerableDriverBlocklistEnable"); ok && v == 0 {
		r.Add(Critico, "Lista de bloqueio de drivers vulneraveis DESATIVADA", "Ninguem desliga isso sem querer. Necessario para carregar drivers vulneraveis (BYOVD) usados por mapeadores de cheat")
	}

	if v, ok := lerDword(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters`, "EnablePrefetcher"); ok {
		if v == 0 {
			c.Rastros.PrefetchDesligadoNoRegistro = true
			r.Add(Critico, "Prefetch DESATIVADO no registro", "EnablePrefetcher=0. Impede o Windows de registrar programas executados")
		} else {
			r.Ok("Prefetch habilitado (EnablePrefetcher=%d)", v)
		}
	}

	for _, p := range c.Perfis {
		if !p.Hive {
			continue
		}
		chave := p.SID + `\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced`
		oculto, _ := lerDword(registry.USERS, chave, "Hidden")
		superOculto, _ := lerDword(registry.USERS, chave, "ShowSuperHidden")
		if oculto == 1 && superOculto == 1 {
			r.Add(Info, "Usuario "+p.Usuario+" exibe arquivos ocultos e de sistema", "Configuracao de usuario avancado, comum em quem mexe com pastas protegidas")
		}
	}
}
