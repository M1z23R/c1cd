package main

import (
	"fmt"
	"os"
	"strconv"

	"c1cd/internal/auth"
	"c1cd/internal/config"
	"c1cd/internal/providers"
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

	// Handle pipeline list command
	if len(args) >= 1 && args[0] == "ls" {
		err := listPipelines()
		if err != nil {
			fmt.Println("Error listing pipelines:", err)
			os.Exit(1)
		}
		return
	}

	// Handle pipeline remove command
	if len(args) >= 2 && args[0] == "rm" {
		err := removePipeline(args[1])
		if err != nil {
			fmt.Println("Error removing pipeline:", err)
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

func listPipelines() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	if len(cfg.Jobs) == 0 {
		fmt.Println("No pipelines configured.")
		return nil
	}

	fmt.Printf("%-3s %-10s %-30s %-15s %-10s\n", "ID", "Provider", "Project", "Event", "Workspace")
	fmt.Println("------------------------------------------------------------------------------------")
	
	for i, job := range cfg.Jobs {
		fmt.Printf("%-3d %-10s %-30s %-15s %-10s\n", 
			i, 
			job.Provider, 
			job.ProjectName, 
			job.Event, 
			job.Workspace)
	}
	return nil
}

func removePipeline(idStr string) error {
	id, err := strconv.Atoi(idStr)
	if err != nil {
		return fmt.Errorf("invalid pipeline ID: %s", idStr)
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	if id < 0 || id >= len(cfg.Jobs) {
		return fmt.Errorf("pipeline ID %d not found", id)
	}

	removedJob := cfg.Jobs[id]
	
	// Try to remove webhook if webhook ID is available
	if removedJob.WebhookID != 0 {
		// Find the appropriate token for this provider
		if tokens, exists := cfg.Tokens[removedJob.Provider]; exists && len(tokens) > 0 {
			token := tokens[0].Token // Use first available token
			if err := providers.RemoveWebhook(token, removedJob); err != nil {
				fmt.Printf("Warning: Failed to remove webhook: %v\n", err)
			}
		} else {
			fmt.Printf("Warning: No token found for provider '%s', webhook not removed\n", removedJob.Provider)
		}
	}
	
	cfg.Jobs = append(cfg.Jobs[:id], cfg.Jobs[id+1:]...)

	err = config.Save(cfg)
	if err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("Removed pipeline: %s (%s)\n", removedJob.ProjectName, removedJob.Provider)
	return nil
}