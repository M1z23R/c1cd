package main

import (
	"fmt"
	"os"

	"c1cd/internal/auth"
	"c1cd/internal/config"
	"c1cd/internal/service"
	"c1cd/internal/wizard"
)

func main() {
	args := os.Args[1:]

	if len(args) >= 1 && args[0] == "--service" {
		cfg, err := config.Load()
		if err != nil {
			fmt.Println("Failed to load config:", err)
			os.Exit(1)
		}
		if len(cfg.Jobs) == 0 {
			fmt.Println("No pipeline jobs configured. Please run wizard first.")
			os.Exit(1)
		}
		service.Run()
		return
	}

	// Handle auth commands: --pat, --login, --auth
	if len(args) >= 1 && (args[0] == "--pat" || args[0] == "--login" || args[0] == "--auth") {
		err := auth.HandleAuthCommand()
		if err != nil {
			fmt.Println("Authentication error:", err)
			os.Exit(1)
		}
		return
	}

	// Main wizard - prompt for provider and token selection
	err := wizard.RunMainWizard()
	if err != nil {
		fmt.Println("Wizard error:", err)
		os.Exit(1)
	}
}