package service

import (
	"fmt"
	"net/http"
	"os"

	"c1cd/internal/logs"
	"c1cd/internal/webhook"
)

var PORT string
var logger *logs.Logger

func init() {
	logger = logs.GetLogger()
	PORT = os.Getenv("C1CD_PORT")
	if PORT == "" {
		PORT = "9091"
		logger.Println("C1CD_PORT not set, using default 9091")
	}
}

func Run() {
	addr := fmt.Sprintf(":%s", PORT)

	http.HandleFunc("/gitlab/webhook", webhook.HandleGitLabWebhook)
	http.HandleFunc("/github/webhook", webhook.HandleGitHubWebhook)
	http.HandleFunc("/logs/", handleLogs)

	logger.Println("Starting webhook listener on", addr)
	if logPath := logger.LogPath(); logPath != "" {
		logger.Println("Application logs:", logPath)
	}
	if err := http.ListenAndServe(addr, nil); err != nil {
		logger.Println("Server error:", err)
	}
}

// handleLogs serves job logs via HTTP
func handleLogs(w http.ResponseWriter, r *http.Request) {
	// Extract job ID from URL path: /logs/{jobID}
	jobID := r.URL.Path[len("/logs/"):]
	if jobID == "" {
		http.Error(w, "Job ID required", http.StatusBadRequest)
		return
	}

	store := logs.GetStore()
	job, content, err := store.GetJobLog(jobID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Log not found: %v", err), http.StatusNotFound)
		return
	}

	// Set headers for plain text display
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// Write job metadata header
	fmt.Fprintf(w, "Project: %s\n", job.ProjectName)
	fmt.Fprintf(w, "Commit: %s\n", job.CommitSHA)
	fmt.Fprintf(w, "Status: %s\n", job.Status)
	fmt.Fprintf(w, "Started: %s\n", job.StartTime.Format("2006-01-02 15:04:05"))
	if job.EndTime != nil {
		duration := job.EndTime.Sub(job.StartTime)
		fmt.Fprintf(w, "Completed: %s (duration: %s)\n", job.EndTime.Format("2006-01-02 15:04:05"), duration.Round(100*1000000))
	}
	fmt.Fprintf(w, "\n%s\n\n", "─────────────────────────────────────────────────────────────")

	// Write log content
	w.Write(content)
}