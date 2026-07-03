package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: redlens <command>")
		fmt.Println("Commands: scan, report, serve")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "scan":
		fmt.Println("Scan command - TODO")
	case "report":
		fmt.Println("Report command - TODO")
	case "serve":
		fmt.Println("Serve command - TODO")
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}