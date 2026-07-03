package main

import (
	"fmt"
	"os"

	"github.com/redlens/redlens/internal/api"
	"github.com/redlens/redlens/internal/scanner"
	"github.com/redlens/redlens/internal/scanner/plugins/host"
	"github.com/redlens/redlens/internal/scanner/plugins/network"
	"github.com/redlens/redlens/internal/scanner/plugins/web"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: redlens <command>")
		fmt.Println("Commands: scan, report, serve")
		os.Exit(1)
	}

	engine := scanner.NewEngine()
	engine.Register(web.New())
	engine.Register(network.New())
	engine.Register(host.New())

	switch os.Args[1] {
	case "serve":
		server := api.NewServer(engine)
		if err := server.Start(":8080"); err != nil {
			fmt.Printf("Server error: %v\n", err)
			os.Exit(1)
		}
	case "scan":
		fmt.Println("CLI scan - use 'serve' mode with UI")
	case "report":
		fmt.Println("CLI report - use 'serve' mode with UI")
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}
