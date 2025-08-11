package service

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"c1cd/internal/webhook"
)

var PORT string

func init() {
	PORT = os.Getenv("C1CD_PORT")
	if PORT == "" {
		PORT = "9091"
		log.Println("⚠️  C1CD_PORT not set, using default 9091")
	}
}

func Run() {
	addr := fmt.Sprintf(":%s", PORT)

	http.HandleFunc("/gitlab/webhook", webhook.HandleGitLabWebhook)
	http.HandleFunc("/github/webhook", webhook.HandleGitHubWebhook)

	fmt.Println("Starting webhook listener on", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		fmt.Println("Server error:", err)
	}
}