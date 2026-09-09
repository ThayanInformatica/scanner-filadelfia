package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type Evidencia struct {
	ID         int      `json:"id"`
	Descricao  string   `json:"descricao"`
	Tipo       string   `json:"tipo"`
	Precisa    []string `json:"precisa"`
	Severidade string   `json:"severidade"`
}

type Plantio struct {
	Termo      string      `json:"termo"`
	Evidencias []Evidencia `json:"evidencias"`
}

type Achado struct {
	Severidade string `json:"severidade"`
	Categoria  string `json:"categoria"`
	Titulo     string `json:"titulo"`
	Detalhe    string `json:"detalhe"`
}

type Processo struct {
	Nome     string `json:"nome"`
	Caminho  string `json:"caminho"`
	Situacao string `json:"situacao"`
}

type Relatorio struct {
	Achados     []Achado   `json:"achados"`
	Processos   []Processo `json:"processos"`
	Incompletas []string   `json:"etapas_incompletas"`
	Erros       []string   `json:"erros"`
}

var peso = map[string]int{"INFO": 1, "ALERTA": 2, "CRITICO": 3}

func contemTodos(texto string, partes []string) bool {
	for _, p := range partes {
		if !strings.Contains(texto, strings.ToLower(p)) {
			return false
		}
	}
	return true
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("uso: verificar plantio.json relatorio.json")
		os.Exit(2)
	}
	var plantio Plantio
	var rel Relatorio
	if err := lerJSON(os.Args[1], &plantio); err != nil {
		fmt.Println("plantio:", err)
		os.Exit(2)
	}
	if err := lerJSON(os.Args[2], &rel); err != nil {
		fmt.Println("relatorio:", err)
		os.Exit(2)
	}

	falhas := 0
	fmt.Printf("Termo plantado: %s\n\n", plantio.Termo)
	for _, e := range plantio.Evidencias {
		ok := false
		switch e.Tipo {
		case "processo":
			for _, p := range rel.Processos {
				if contemTodos(strings.ToLower(p.Nome+" "+p.Caminho+" "+p.Situacao), e.Precisa) {
					ok = true
					break
				}
			}
		default:
			minimo := peso[strings.ToUpper(e.Severidade)]
			for _, a := range rel.Achados {
				if peso[a.Severidade] < minimo {
					continue
				}
				if contemTodos(strings.ToLower(a.Titulo+"\n"+a.Detalhe+"\n"+a.Categoria), e.Precisa) {
					ok = true
					break
				}
			}
		}
		marca := "PASS"
		if !ok {
			marca = "FAIL"
			falhas++
		}
		fmt.Printf("[%s] %2d. %s\n", marca, e.ID, e.Descricao)
		if !ok {
			fmt.Printf("       esperava achar: %s\n", strings.Join(e.Precisa, " + "))
		}
	}
	fmt.Println()
	if len(rel.Incompletas) > 0 {
		fmt.Printf("Etapas incompletas no relatorio: %s\n", strings.Join(rel.Incompletas, ", "))
	}
	if len(rel.Erros) > 0 {
		fmt.Printf("Erros de checagem: %d\n", len(rel.Erros))
		for _, er := range rel.Erros {
			fmt.Println("  - " + er)
		}
	}
	fmt.Printf("%d de %d evidencias encontradas\n", len(plantio.Evidencias)-falhas, len(plantio.Evidencias))
	if falhas > 0 {
		os.Exit(1)
	}
}

func lerJSON(caminho string, destino any) error {
	dados, err := os.ReadFile(caminho)
	if err != nil {
		return err
	}
	return json.Unmarshal(dados, destino)
}
