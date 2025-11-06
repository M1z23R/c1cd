package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"c1cd/internal/config"
)

var allowedEvents = map[string]string{
	"on_push":               "push_events",
	"on_merge_request":      "merge_requests_events",
	"on_tag":                "tag_push_events",
	"on_issue":              "issues_events",
	"on_note":               "note_events",
	"on_job":                "job_events",
	"on_pipeline":           "pipeline_events",
	"on_wiki_page":          "wiki_page_events",
	"on_release":            "release_events",
	"on_confidential_issue": "confidential_issues_events",
	"on_confidential_note":  "confidential_note_events",
}

var gitlabEventMap = map[string]string{
	"Push Hook":               "push_events",
	"Merge Request Hook":      "merge_requests_events",
	"Tag Push Hook":           "tag_push_events",
	"Issue Hook":              "issues_events",
	"Note Hook":               "note_events",
	"Job Hook":                "job_events",
	"Pipeline Hook":           "pipeline_events",
	"Wiki Page Hook":          "wiki_page_events",
	"Release Hook":            "release_events",
	"Confidential Issue Hook": "confidential_issues_events",
	"Confidential Note Hook":  "confidential_note_events",
}

var githubAllowedEvents = map[string]string{
	"on_push":         "push",
	"on_pull_request": "pull_request",
	"on_release":      "release",
	"on_issue":        "issues",
	"on_tag":          "create",
}

func HandleGitLabWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintln(w, "Only POST method is allowed")
		return
	}

	cfg, err := config.Load()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Failed to load config")
		fmt.Println("Error loading config:", err)
		return
	}

	if len(cfg.Jobs) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "No pipeline jobs configured. Please run wizard first.")
		return
	}

	token := r.Header.Get("X-Gitlab-Token")
	if token == "" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, "Missing X-Gitlab-Token header")
		return
	}

	var job *config.PipelineJob
	for i, j := range cfg.Jobs {
		if j.Secret == token && j.Provider == "gitlab" {
			job = &cfg.Jobs[i]
			break
		}
	}

	if job == nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, "Invalid X-Gitlab-Token")
		return
	}

	eventType := r.Header.Get("X-Gitlab-Event")
	expectedEventKey, ok := allowedEvents[job.Event]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Configured job has unsupported event: %s\n", job.Event)
		return
	}

	if gitlabEventMap[eventType] != expectedEventKey {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, "Event type '%s' does not match job configuration '%s'\n", eventType, job.Event)
		return
	}

	// Check branch filtering for GitLab webhooks
	if len(job.Branches) > 0 {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, "Failed to read request body")
			return
		}
		
		branch := extractBranchFromGitLabPayload(body)
		if branch != "" && !isBranchAllowed(branch, job.Branches) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "Branch '%s' not in allowed branches, skipping pipeline", branch)
			return
		}
	}

	go func(j *config.PipelineJob) {
		fmt.Printf("Running pipeline commands for project %s...\n", j.ProjectName)
		if err := runCommands(j.Workspace, j.Commands); err != nil {
			fmt.Printf("Error running commands for %s: %v\n", j.ProjectName, err)
		} else {
			fmt.Printf("Commands finished successfully for %s\n", j.ProjectName)
		}
	}(job)

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "Webhook received, running pipeline.")
}

func HandleGitHubWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintln(w, "Only POST method is allowed")
		return
	}

	cfg, err := config.Load()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Failed to load config")
		fmt.Println("Error loading config:", err)
		return
	}

	if len(cfg.Jobs) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "No pipeline jobs configured. Please run wizard first.")
		return
	}

	// Read the payload
	payload, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "Failed to read request body")
		return
	}

	// Get the signature from headers
	signature := r.Header.Get("X-Hub-Signature-256")
	if signature == "" {
		signature = r.Header.Get("X-Hub-Signature")
	}
	if signature == "" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, "Missing webhook signature")
		return
	}

	// Get event type
	eventType := r.Header.Get("X-GitHub-Event")
	if eventType == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "Missing X-GitHub-Event header")
		return
	}

	// Find matching job by validating signature
	var job *config.PipelineJob
	for i, j := range cfg.Jobs {
		if j.Provider == "github" && validateGitHubSignature(payload, signature, j.Secret) {
			// Also check if event type matches
			expectedEventType, ok := githubAllowedEvents[j.Event]
			if ok && eventType == expectedEventType {
				job = &cfg.Jobs[i]
				break
			}
		}
	}

	if job == nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, "Invalid webhook signature or event type")
		return
	}

	// Check branch filtering for GitHub webhooks
	if len(job.Branches) > 0 {
		branch := extractBranchFromGitHubPayload(payload)
		if branch != "" && !isBranchAllowed(branch, job.Branches) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "Branch '%s' not in allowed branches, skipping pipeline", branch)
			return
		}
	}

	go func(j *config.PipelineJob) {
		fmt.Printf("Running pipeline commands for project %s...\n", j.ProjectName)
		if err := runCommands(j.Workspace, j.Commands); err != nil {
			fmt.Printf("Error running commands for %s: %v\n", j.ProjectName, err)
		} else {
			fmt.Printf("Commands finished successfully for %s\n", j.ProjectName)
		}
	}(job)

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "Webhook received, running pipeline.")
}

func validateGitHubSignature(payload []byte, signature, secret string) bool {
	// Remove the algorithm prefix if present (sha1= or sha256=)
	if strings.HasPrefix(signature, "sha256=") {
		signature = strings.TrimPrefix(signature, "sha256=")
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(payload)
		expected := hex.EncodeToString(mac.Sum(nil))
		return hmac.Equal([]byte(signature), []byte(expected))
	} else if strings.HasPrefix(signature, "sha1=") {
		// Handle legacy SHA1 signatures if needed
		signature = strings.TrimPrefix(signature, "sha1=")
		// For now, we'll skip SHA1 validation as it's deprecated
		return false
	}
	return false
}

func runCommands(workspace string, commands []string) error {
	if len(commands) == 0 {
		return nil
	}

	for _, c := range commands {
		fmt.Printf("Executing in %s: %s\n", workspace, c)

		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.Command("cmd", "/C", c) // Windows cmd
		} else {
			cmd = exec.Command("bash", "-c", c) // Unix shell
		}

		cmd.Dir = workspace
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Env = os.Environ()

		if err := cmd.Run(); err != nil {
			return fmt.Errorf("command failed: %s, error: %w", c, err)
		}
	}

	return nil
}


func extractBranchFromGitLabPayload(payload []byte) string {
	var gitlabPayload struct {
		Ref string `json:"ref"`
	}
	
	if err := json.Unmarshal(payload, &gitlabPayload); err != nil {
		return ""
	}
	
	// GitLab ref format: refs/heads/branch-name
	if strings.HasPrefix(gitlabPayload.Ref, "refs/heads/") {
		return strings.TrimPrefix(gitlabPayload.Ref, "refs/heads/")
	}
	
	return ""
}

func extractBranchFromGitHubPayload(payload []byte) string {
	var githubPayload struct {
		Ref string `json:"ref"`
	}
	
	if err := json.Unmarshal(payload, &githubPayload); err != nil {
		return ""
	}
	
	// GitHub ref format: refs/heads/branch-name
	if strings.HasPrefix(githubPayload.Ref, "refs/heads/") {
		return strings.TrimPrefix(githubPayload.Ref, "refs/heads/")
	}
	
	return ""
}

func isBranchAllowed(branch string, allowedBranches []string) bool {
	for _, allowed := range allowedBranches {
		if branch == allowed {
			return true
		}
	}
	return false
}