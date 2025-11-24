package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"c1cd/internal/config"
	"c1cd/internal/logs"
	"c1cd/internal/providers"
)

var logger = logs.GetLogger()

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
		logger.Println("Error loading config:", err)
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

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "Failed to read request body")
		return
	}

	// Extract commit SHA from payload
	commitSHA := extractCommitSHAFromGitLabPayload(body)

	// Extract ref (branch) from payload
	ref := extractRefFromGitLabPayload(body)

	// Check branch filtering for GitLab webhooks
	if len(job.Branches) > 0 {
		branch := extractBranchFromGitLabPayload(body)
		if branch != "" && !isBranchAllowed(branch, job.Branches) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "Branch '%s' not in allowed branches, skipping pipeline", branch)
			return
		}
	}

	go func(j *config.PipelineJob, sha, gitRef string) {
		logger.Printf("Running pipeline commands for project %s...\n", j.ProjectName)

		// Create job log
		logStore := logs.GetStore()
		jobID, err := logStore.CreateJob(j.ProjectName, sha)
		if err != nil {
			logger.Printf("Warning: failed to create job log: %v\n", err)
		}

		// Get log writer
		var logWriter io.Writer
		if jobID != "" {
			var writerErr error
			logWriter, writerErr = logStore.GetJobWriter(jobID)
			if writerErr != nil {
				logger.Printf("Warning: failed to get job writer: %v\n", writerErr)
			}
		}

		// Get token for this job
		cfg, err := config.Load()
		if err != nil {
			logger.Printf("Error loading config for status update: %v\n", err)
		} else {
			// Find the token and serverURL for this provider
			token, serverURL := findTokenForJob(cfg, j)

			// Build target URL for logs from webhook URL
			targetURL := ""
			if jobID != "" {
				targetURL = buildTargetURLFromWebhook(j.WebhookURL, jobID)
			}

			// Send "running" status if we have commit SHA
			if sha != "" && token != "" {
				if err := providers.UpdateCommitStatusWithURL(token, serverURL, j, sha, "running", targetURL, gitRef); err != nil {
					logger.Printf("Warning: failed to update commit status to running: %v\n", err)
				} else {
					logger.Printf("Commit status updated to 'running' for SHA %s\n", sha)
					logger.Printf("Target URL: %s\n", targetURL)
				}
			}
		}

		// Run the commands with log capture
		lastLog, cmdErr := runCommandsWithWriter(j.Workspace, j.Commands, logWriter)

		// Complete the job log
		if jobID != "" {
			if cmdErr != nil {
				logStore.CompleteJob(jobID, "failed")
			} else {
				logStore.CompleteJob(jobID, "success")
			}
		}

		if cmdErr != nil {
			logger.Printf("Error running commands for %s: %v\n", j.ProjectName, cmdErr)

			// Update status to failed
			if sha != "" {
				cfg, err := config.Load()
				if err == nil {
					token, serverURL := findTokenForJob(cfg, j)
					targetURL := ""
					if jobID != "" {
						targetURL = buildTargetURLFromWebhook(j.WebhookURL, jobID)
					}
					if token != "" {
						if err := providers.UpdateCommitStatusWithURLAndDesc(token, serverURL, j, sha, "failed", targetURL, gitRef, lastLog); err != nil {
							logger.Printf("Warning: failed to update commit status to failed: %v\n", err)
						} else {
							logger.Printf("Commit status updated to 'failed' for SHA %s\n", sha)
							logger.Printf("Target URL: %s\n", targetURL)
						}
					}
				}
			}
		} else {
			logger.Printf("Commands finished successfully for %s\n", j.ProjectName)

			// Update status to success
			if sha != "" {
				cfg, err := config.Load()
				if err == nil {
					token, serverURL := findTokenForJob(cfg, j)
					targetURL := ""
					if jobID != "" {
						targetURL = buildTargetURLFromWebhook(j.WebhookURL, jobID)
					}
					if token != "" {
						if err := providers.UpdateCommitStatusWithURLAndDesc(token, serverURL, j, sha, "success", targetURL, gitRef, lastLog); err != nil {
							logger.Printf("Warning: failed to update commit status to success: %v\n", err)
						} else {
							logger.Printf("Commit status updated to 'success' for SHA %s\n", sha)
							logger.Printf("Target URL: %s\n", targetURL)
						}
					}
				}
			}
		}
	}(job, commitSHA, ref)

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
		logger.Println("Error loading config:", err)
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

	// Extract commit SHA from payload
	commitSHA := extractCommitSHAFromGitHubPayload(payload)

	// Check branch filtering for GitHub webhooks
	if len(job.Branches) > 0 {
		branch := extractBranchFromGitHubPayload(payload)
		if branch != "" && !isBranchAllowed(branch, job.Branches) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "Branch '%s' not in allowed branches, skipping pipeline", branch)
			return
		}
	}

	go func(j *config.PipelineJob, sha string) {
		logger.Printf("Running pipeline commands for project %s...\n", j.ProjectName)

		// Create job log
		logStore := logs.GetStore()
		jobID, err := logStore.CreateJob(j.ProjectName, sha)
		if err != nil {
			logger.Printf("Warning: failed to create job log: %v\n", err)
		}

		// Get log writer
		var logWriter io.Writer
		if jobID != "" {
			var writerErr error
			logWriter, writerErr = logStore.GetJobWriter(jobID)
			if writerErr != nil {
				logger.Printf("Warning: failed to get job writer: %v\n", writerErr)
			}
		}

		// Get token for this job
		cfg, err := config.Load()
		if err != nil {
			logger.Printf("Error loading config for status update: %v\n", err)
		} else {
			// Find the token for this provider
			token, serverURL := findTokenForJob(cfg, j)

			// Build target URL for logs from webhook URL
			targetURL := ""
			if jobID != "" {
				targetURL = buildTargetURLFromWebhook(j.WebhookURL, jobID)
			}

			// Send "pending" status if we have commit SHA (GitHub uses "pending" instead of "running")
			if sha != "" && token != "" {
				if err := providers.UpdateCommitStatusWithURLAndDesc(token, serverURL, j, sha, "pending", targetURL, "", ""); err != nil {
					logger.Printf("Warning: failed to update commit status to pending: %v\n", err)
				} else {
					logger.Printf("Commit status updated to 'pending' for SHA %s\n", sha)
					logger.Printf("Target URL: %s\n", targetURL)
				}
			}
		}

		// Run the commands and capture last 140 chars of output
		lastLog, cmdErr := runCommandsWithWriter(j.Workspace, j.Commands, logWriter)

		// Complete the job log
		if jobID != "" {
			if cmdErr != nil {
				logStore.CompleteJob(jobID, "failed")
			} else {
				logStore.CompleteJob(jobID, "success")
			}
		}

		if cmdErr != nil {
			logger.Printf("Error running commands for %s: %v\n", j.ProjectName, cmdErr)

			// Update status to failure
			if sha != "" {
				cfg, err := config.Load()
				if err == nil {
					token, serverURL := findTokenForJob(cfg, j)
					targetURL := ""
					if jobID != "" {
						targetURL = buildTargetURLFromWebhook(j.WebhookURL, jobID)
					}
					if token != "" {
						if err := providers.UpdateCommitStatusWithURLAndDesc(token, serverURL, j, sha, "failure", targetURL, "", lastLog); err != nil {
							logger.Printf("Warning: failed to update commit status to failure: %v\n", err)
						} else {
							logger.Printf("Commit status updated to 'failure' for SHA %s\n", sha)
							logger.Printf("Target URL: %s\n", targetURL)
						}
					}
				}
			}
		} else {
			logger.Printf("Commands finished successfully for %s\n", j.ProjectName)

			// Update status to success
			if sha != "" {
				cfg, err := config.Load()
				if err == nil {
					token, serverURL := findTokenForJob(cfg, j)
					targetURL := ""
					if jobID != "" {
						targetURL = buildTargetURLFromWebhook(j.WebhookURL, jobID)
					}
					if token != "" {
						if err := providers.UpdateCommitStatusWithURLAndDesc(token, serverURL, j, sha, "success", targetURL, "", lastLog); err != nil {
							logger.Printf("Warning: failed to update commit status to success: %v\n", err)
						} else {
							logger.Printf("Commit status updated to 'success' for SHA %s\n", sha)
							logger.Printf("Target URL: %s\n", targetURL)
						}
					}
				}
			}
		}
	}(job, commitSHA)

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

// lastNCharsWriter captures the last N characters written to it
type lastNCharsWriter struct {
	maxSize int
	buf     []byte
}

func newLastNCharsWriter(n int) *lastNCharsWriter {
	return &lastNCharsWriter{
		maxSize: n,
		buf:     make([]byte, 0, n),
	}
}

func (w *lastNCharsWriter) Write(p []byte) (n int, err error) {
	n = len(p)

	// Append new data to buffer
	w.buf = append(w.buf, p...)

	// Keep only the last maxSize characters
	if len(w.buf) > w.maxSize {
		w.buf = w.buf[len(w.buf)-w.maxSize:]
	}

	return n, nil
}

func (w *lastNCharsWriter) String() string {
	return string(w.buf)
}

func runCommands(workspace string, commands []string) error {
	_, err := runCommandsWithWriter(workspace, commands, nil)
	return err
}

func runCommandsWithWriter(workspace string, commands []string, logWriter io.Writer) (string, error) {
	if len(commands) == 0 {
		return "", nil
	}

	separator := " && "
	if runtime.GOOS == "windows" {
		separator = "; "
	}
	joinedCommand := strings.Join(commands, separator)

	logger.Printf("Executing in %s:\n", workspace)
	for _, c := range commands {
		logger.Printf("  %s\n", c)
	}

	if logWriter != nil {
		fmt.Fprintf(logWriter, "Executing in %s:\n", workspace)
		for _, c := range commands {
			fmt.Fprintf(logWriter, "  %s\n", c)
		}
		fmt.Fprintln(logWriter, "\n--- Command Output ---")
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		// Use cmd.exe for more predictable behavior
		cmd = exec.Command("cmd.exe", "/C", joinedCommand)
	} else {
		cmd = exec.Command("bash", "-c", joinedCommand)
	}

	cmd.Dir = workspace
	cmd.Env = os.Environ()
	cmd.Stdin = nil // Prevent hanging on interactive prompts

	lastCharsWriter := newLastNCharsWriter(140)

	if logWriter != nil {
		multiWriter := io.MultiWriter(logWriter, lastCharsWriter)
		cmd.Stdout = multiWriter
		cmd.Stderr = multiWriter
	} else {
		cmd.Stdout = lastCharsWriter
		cmd.Stderr = lastCharsWriter
	}

	if err := cmd.Run(); err != nil {
		errorMsg := fmt.Sprintf("Command failed: %v", err)
		if exitErr, ok := err.(*exec.ExitError); ok {
			errorMsg = fmt.Sprintf("Command failed with exit code %d", exitErr.ExitCode())
		}

		if logWriter != nil {
			fmt.Fprintf(logWriter, "\n--- Error ---\n%s\n", errorMsg)
			fmt.Fprintf(logWriter, "Last output:\n%s\n", lastCharsWriter.String())
		}

		logger.Printf("Error: %s", errorMsg)
		return lastCharsWriter.String(), fmt.Errorf("%s: %w", errorMsg, err)
	}

	if logWriter != nil {
		fmt.Fprintln(logWriter, "\n--- Completed Successfully ---")
	}

	return lastCharsWriter.String(), nil
}

func extractCommitSHAFromGitLabPayload(payload []byte) string {
	// GitLab webhook payloads have different structures for different events
	// For push events, the commit SHA is in checkout_sha or after field
	var gitlabPayload struct {
		CheckoutSHA string `json:"checkout_sha"` // Push events
		After       string `json:"after"`        // Push events (commit SHA after push)
		Commit      struct {
			ID string `json:"id"` // Other events like merge request
		} `json:"commit"`
		ObjectAttributes struct {
			LastCommit struct {
				ID string `json:"id"`
			} `json:"last_commit"`
		} `json:"object_attributes"`
	}

	if err := json.Unmarshal(payload, &gitlabPayload); err != nil {
		return ""
	}

	// Try different fields in order of preference
	if gitlabPayload.CheckoutSHA != "" && gitlabPayload.CheckoutSHA != "0000000000000000000000000000000000000000" {
		return gitlabPayload.CheckoutSHA
	}
	if gitlabPayload.After != "" && gitlabPayload.After != "0000000000000000000000000000000000000000" {
		return gitlabPayload.After
	}
	if gitlabPayload.Commit.ID != "" {
		return gitlabPayload.Commit.ID
	}
	if gitlabPayload.ObjectAttributes.LastCommit.ID != "" {
		return gitlabPayload.ObjectAttributes.LastCommit.ID
	}

	return ""
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

func extractRefFromGitLabPayload(payload []byte) string {
	var gitlabPayload struct {
		Ref string `json:"ref"`
	}

	if err := json.Unmarshal(payload, &gitlabPayload); err != nil {
		return ""
	}

	return gitlabPayload.Ref
}

func extractCommitSHAFromGitHubPayload(payload []byte) string {
	// GitHub webhook payloads have different structures for different events
	var githubPayload struct {
		After      string `json:"after"` // Push events
		HeadCommit struct {
			ID string `json:"id"`
		} `json:"head_commit"` // Push events
		PullRequest struct {
			Head struct {
				SHA string `json:"sha"`
			} `json:"head"`
		} `json:"pull_request"` // Pull request events
	}

	if err := json.Unmarshal(payload, &githubPayload); err != nil {
		return ""
	}

	// Try different fields in order of preference
	if githubPayload.After != "" && githubPayload.After != "0000000000000000000000000000000000000000" {
		return githubPayload.After
	}
	if githubPayload.HeadCommit.ID != "" {
		return githubPayload.HeadCommit.ID
	}
	if githubPayload.PullRequest.Head.SHA != "" {
		return githubPayload.PullRequest.Head.SHA
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

// findTokenForJob finds the appropriate token and serverURL for a job
func findTokenForJob(cfg *config.Config, job *config.PipelineJob) (token string, serverURL string) {
	// Look for tokens for this provider
	tokens, ok := cfg.Tokens[job.Provider]
	if !ok || len(tokens) == 0 {
		return "", ""
	}

	// For GitLab, we need to match by project ID if there are multiple tokens
	// For simplicity, we'll use the first token of the matching provider
	// In the future, this could be enhanced to match by project ID or user
	tokenInfo := tokens[0]
	return tokenInfo.Token, tokenInfo.ServerURL
}

// buildTargetURLFromWebhook extracts the base URL from webhook URL and builds the target URL for logs
// Example: https://example.com:9091/gitlab/webhook -> https://example.com:9091/logs/{jobID}
func buildTargetURLFromWebhook(webhookURL, jobID string) string {
	u, err := url.Parse(webhookURL)
	if err != nil {
		return ""
	}

	// Build base URL (scheme + host)
	baseURL := fmt.Sprintf("%s://%s", u.Scheme, u.Host)

	// Append /logs/{jobID}
	return fmt.Sprintf("%s/logs/%s", baseURL, jobID)
}
