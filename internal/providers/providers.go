package providers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"c1cd/internal/config"
)

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
}

type Project struct {
	ID                int    `json:"id"`
	PathWithNamespace string `json:"path_with_namespace"`
}

func GetUser(token, provider, serverURL string) (*User, error) {
	switch provider {
	case "gitlab":
		return getGitLabUser(token, serverURL)
	case "github":
		return getGitHubUser(token)
	default:
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}
}

func getGitLabUser(token, serverURL string) (*User, error) {
	baseURL := getGitLabBaseURL(serverURL)
	apiURL := baseURL + "/api/v4/user"

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("PRIVATE-TOKEN", token)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user, status %d: %s", resp.StatusCode, string(body))
	}
	var user User
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&user); err != nil {
		return nil, err
	}
	return &user, nil
}

// getGitLabBaseURL returns the base URL for GitLab API calls
// If serverURL is empty, defaults to gitlab.com
func getGitLabBaseURL(serverURL string) string {
	if serverURL == "" {
		return "https://gitlab.com"
	}
	return serverURL
}

func getGitHubUser(token string) (*User, error) {
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "token "+token)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user, status %d: %s", resp.StatusCode, string(body))
	}
	var ghUser struct {
		ID    int    `json:"id"`
		Login string `json:"login"`
	}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&ghUser); err != nil {
		return nil, err
	}
	return &User{ID: ghUser.ID, Username: ghUser.Login}, nil
}

func SearchProjects(token, search, provider, serverURL string) ([]Project, error) {
	switch provider {
	case "gitlab":
		return searchGitLabProjects(token, search, serverURL)
	case "github":
		return searchGitHubRepos(token, search)
	default:
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}
}

func searchGitLabProjects(token, search, serverURL string) ([]Project, error) {
	baseURL := getGitLabBaseURL(serverURL)
	apiURL := baseURL + "/api/v4/projects?membership=true&per_page=20&search=" + url.QueryEscape(search)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("PRIVATE-TOKEN", token)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to search projects, status %d: %s", resp.StatusCode, string(body))
	}
	var projects []Project
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&projects)
	if err != nil {
		return nil, err
	}
	return projects, nil
}

func searchGitHubRepos(token, search string) ([]Project, error) {
	apiURL := "https://api.github.com/search/repositories?q=" + url.QueryEscape(search+" user:@me")
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "token "+token)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to search repositories, status %d: %s", resp.StatusCode, string(body))
	}
	var result struct {
		Items []struct {
			ID       int    `json:"id"`
			FullName string `json:"full_name"`
		} `json:"items"`
	}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&result); err != nil {
		return nil, err
	}
	var projects []Project
	for _, repo := range result.Items {
		projects = append(projects, Project{
			ID:                repo.ID,
			PathWithNamespace: repo.FullName,
		})
	}
	return projects, nil
}

func CreateWebhook(token, serverURL string, job *config.PipelineJob) error {
	switch job.Provider {
	case "gitlab":
		return createGitLabWebhook(token, serverURL, job)
	case "github":
		return createGitHubWebhook(token, job)
	default:
		return fmt.Errorf("unsupported provider: %s", job.Provider)
	}
}

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

var githubAllowedEvents = map[string]string{
	"on_push":         "push",
	"on_pull_request": "pull_request",
	"on_release":      "release",
	"on_issue":        "issues",
	"on_tag":          "create",
}

func createGitLabWebhook(token, serverURL string, job *config.PipelineJob) error {
	baseURL := getGitLabBaseURL(serverURL)
	apiURL := fmt.Sprintf("%s/api/v4/projects/%d/hooks", baseURL, job.ProjectID)

	eventKey, ok := allowedEvents[job.Event]
	if !ok {
		return fmt.Errorf("unsupported event type: %s", job.Event)
	}

	payload := map[string]any{
		"url":                     job.WebhookURL,
		"enable_ssl_verification": job.EnableSSLVerification,
		"token":                   job.Secret,
		eventKey:                  true,
	}

	jsonBody, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", apiURL, bytes.NewReader(jsonBody))
	if err != nil {
		return err
	}
	req.Header.Set("PRIVATE-TOKEN", token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	switch resp.StatusCode {
	case 201:
		var webhookResponse struct {
			ID int `json:"id"`
		}
		if err := json.Unmarshal(body, &webhookResponse); err == nil {
			job.WebhookID = webhookResponse.ID
		}
		fmt.Println("Webhook created successfully!")
		return nil
	case 409:
		return fmt.Errorf("webhook already exists: %s", string(body))
	default:
		return fmt.Errorf("failed to create webhook, status %d: %s", resp.StatusCode, string(body))
	}
}

func createGitHubWebhook(token string, job *config.PipelineJob) error {
	parts := strings.SplitN(job.ProjectName, "/", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid GitHub repository format: %s, expected owner/repo", job.ProjectName)
	}
	owner, repo := parts[0], parts[1]

	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/hooks", owner, repo)

	eventType, ok := githubAllowedEvents[job.Event]
	if !ok {
		return fmt.Errorf("unsupported event type: %s", job.Event)
	}

	payload := map[string]any{
		"name":   "web",
		"active": true,
		"events": []string{eventType},
		"config": map[string]any{
			"url":          job.WebhookURL,
			"content_type": "json",
			"secret":       job.Secret,
			"insecure_ssl": !job.EnableSSLVerification,
		},
	}

	jsonBody, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", apiURL, bytes.NewReader(jsonBody))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	switch resp.StatusCode {
	case 201:
		var webhookResponse struct {
			ID int `json:"id"`
		}
		if err := json.Unmarshal(body, &webhookResponse); err == nil {
			job.WebhookID = webhookResponse.ID
		}
		fmt.Println("Webhook created successfully!")
		return nil
	case 422:
		return fmt.Errorf("webhook validation failed or already exists: %s", string(body))
	default:
		return fmt.Errorf("failed to create webhook, status %d: %s", resp.StatusCode, string(body))
	}
}

func RemoveWebhook(token, serverURL string, job config.PipelineJob) error {
	switch job.Provider {
	case "gitlab":
		return removeGitLabWebhook(token, serverURL, job)
	case "github":
		return removeGitHubWebhook(token, job)
	default:
		return fmt.Errorf("unsupported provider: %s", job.Provider)
	}
}

func removeGitLabWebhook(token, serverURL string, job config.PipelineJob) error {
	if job.WebhookID == 0 {
		return fmt.Errorf("no webhook ID stored for this job")
	}

	baseURL := getGitLabBaseURL(serverURL)
	apiURL := fmt.Sprintf("%s/api/v4/projects/%d/hooks/%d", baseURL, job.ProjectID, job.WebhookID)
	
	req, err := http.NewRequest("DELETE", apiURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("PRIVATE-TOKEN", token)
	
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == 204 {
		fmt.Println("GitLab webhook removed successfully!")
		return nil
	}
	
	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("failed to remove GitLab webhook, status %d: %s", resp.StatusCode, string(body))
}

func removeGitHubWebhook(token string, job config.PipelineJob) error {
	if job.WebhookID == 0 {
		return fmt.Errorf("no webhook ID stored for this job")
	}
	
	parts := strings.SplitN(job.ProjectName, "/", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid GitHub repository format: %s, expected owner/repo", job.ProjectName)
	}
	owner, repo := parts[0], parts[1]
	
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/hooks/%d", owner, repo, job.WebhookID)
	
	req, err := http.NewRequest("DELETE", apiURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "token "+token)
	
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == 204 {
		fmt.Println("GitHub webhook removed successfully!")
		return nil
	}
	
	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("failed to remove GitHub webhook, status %d: %s", resp.StatusCode, string(body))
}

func GetAllowedEventKeys(provider string) []string {
	var eventMap map[string]string
	switch provider {
	case "gitlab":
		eventMap = allowedEvents
	case "github":
		eventMap = githubAllowedEvents
	default:
		eventMap = allowedEvents
	}
	keys := make([]string, 0, len(eventMap))
	for k := range eventMap {
		keys = append(keys, k)
	}
	return keys
}

// UpdateCommitStatus updates the commit status on GitHub or GitLab
func UpdateCommitStatus(token, serverURL string, job *config.PipelineJob, commitSHA, state string) error {
	return UpdateCommitStatusWithURL(token, serverURL, job, commitSHA, state, "", "")
}

// UpdateCommitStatusWithURL updates commit status with optional target URL and ref
func UpdateCommitStatusWithURL(token, serverURL string, job *config.PipelineJob, commitSHA, state, targetURL, ref string) error {
	return UpdateCommitStatusWithURLAndDesc(token, serverURL, job, commitSHA, state, targetURL, ref, "")
}

// UpdateCommitStatusWithURLAndDesc updates commit status with optional target URL, ref, and custom description
func UpdateCommitStatusWithURLAndDesc(token, serverURL string, job *config.PipelineJob, commitSHA, state, targetURL, ref, customDesc string) error {
	switch job.Provider {
	case "gitlab":
		return updateGitLabCommitStatusWithURLAndDesc(token, serverURL, job, commitSHA, state, targetURL, ref, customDesc)
	case "github":
		return updateGitHubCommitStatusWithURLAndDesc(token, job, commitSHA, state, targetURL, customDesc)
	default:
		return fmt.Errorf("unsupported provider: %s", job.Provider)
	}
}

// updateGitLabCommitStatus updates commit status via GitLab API
// States: running, pending, success, failed, canceled
func updateGitLabCommitStatus(token, serverURL string, job *config.PipelineJob, commitSHA, state string) error {
	return updateGitLabCommitStatusWithURL(token, serverURL, job, commitSHA, state, "", "")
}

// updateGitLabCommitStatusWithURL updates commit status via GitLab API with optional target URL and ref
// States: running, pending, success, failed, canceled
func updateGitLabCommitStatusWithURL(token, serverURL string, job *config.PipelineJob, commitSHA, state, targetURL, ref string) error {
	return updateGitLabCommitStatusWithURLAndDesc(token, serverURL, job, commitSHA, state, targetURL, ref, "")
}

// updateGitLabCommitStatusWithURLAndDesc updates commit status via GitLab API with optional target URL, ref, and custom description
// States: running, pending, success, failed, canceled
func updateGitLabCommitStatusWithURLAndDesc(token, serverURL string, job *config.PipelineJob, commitSHA, state, targetURL, ref, customDesc string) error {
	baseURL := getGitLabBaseURL(serverURL)
	apiURL := fmt.Sprintf("%s/api/v4/projects/%d/statuses/%s", baseURL, job.ProjectID, commitSHA)

	// Use custom pipeline name if set, otherwise default to "Build & Deploy"
	pipelineName := job.PipelineName
	if pipelineName == "" {
		pipelineName = "Build & Deploy"
	}

	// Use custom description if provided, otherwise use default
	description := customDesc
	if description == "" {
		description = getStatusDescription(state)
	}

	payload := map[string]any{
		"state":       state,
		"name":        pipelineName,
		"description": description,
	}

	// Add target_url if provided
	if targetURL != "" {
		payload["target_url"] = targetURL
	}

	// Add ref if provided
	if ref != "" {
		payload["ref"] = ref
	}

	jsonBody, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", apiURL, bytes.NewReader(jsonBody))
	if err != nil {
		return err
	}
	req.Header.Set("PRIVATE-TOKEN", token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("failed to update GitLab commit status, status %d: %s", resp.StatusCode, string(body))
}

// updateGitHubCommitStatus updates commit status via GitHub API
// States: pending, success, error, failure
func updateGitHubCommitStatus(token string, job *config.PipelineJob, commitSHA, state string) error {
	return updateGitHubCommitStatusWithURL(token, job, commitSHA, state, "")
}

// updateGitHubCommitStatusWithURL updates commit status via GitHub API with optional target URL
// States: pending, success, error, failure
func updateGitHubCommitStatusWithURL(token string, job *config.PipelineJob, commitSHA, state, targetURL string) error {
	return updateGitHubCommitStatusWithURLAndDesc(token, job, commitSHA, state, targetURL, "")
}

// updateGitHubCommitStatusWithURLAndDesc updates commit status via GitHub API with optional target URL and custom description
// States: pending, success, error, failure
func updateGitHubCommitStatusWithURLAndDesc(token string, job *config.PipelineJob, commitSHA, state, targetURL, customDesc string) error {
	parts := strings.SplitN(job.ProjectName, "/", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid GitHub repository format: %s, expected owner/repo", job.ProjectName)
	}
	owner, repo := parts[0], parts[1]

	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/statuses/%s", owner, repo, commitSHA)

	// Use custom pipeline name if set, otherwise default to "Build"
	pipelineName := job.PipelineName
	if pipelineName == "" {
		pipelineName = "Build"
	}

	// Use custom description if provided, otherwise use default
	description := customDesc
	if description == "" {
		description = getStatusDescription(state)
	}

	payload := map[string]any{
		"state":       state,
		"context":     pipelineName,
		"description": description,
	}

	// Add target_url if provided
	if targetURL != "" {
		payload["target_url"] = targetURL
	}

	jsonBody, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", apiURL, bytes.NewReader(jsonBody))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("failed to update GitHub commit status, status %d: %s", resp.StatusCode, string(body))
}

// getStatusDescription returns a human-readable description for each status state
func getStatusDescription(state string) string {
	descriptions := map[string]string{
		"pending": "Build is pending",
		"running": "Build is running",
		"success": "Build succeeded",
		"failed":  "Build failed",
		"failure": "Build failed",
		"error":   "Build error",
	}
	if desc, ok := descriptions[state]; ok {
		return desc
	}
	return "Build status: " + state
}
