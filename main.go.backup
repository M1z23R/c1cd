package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/AlecAivazis/survey/v2"
)

const configPath = ".config/c1cd/config.json"

var (
	PORT string
)

type Config struct {
	Tokens map[string][]TokenInfo `json:"tokens"` // provider -> []tokens
	Jobs   []PipelineJob         `json:"jobs"`
}

type TokenInfo struct {
	Token    string `json:"token"`
	Username string `json:"username"`
	UserID   int    `json:"user_id"`
}

type PipelineJob struct {
	Provider              string   `json:"provider"`              // "gitlab" or "github"
	ProjectID             int      `json:"project_id"`
	ProjectName           string   `json:"project_name"`
	Workspace             string   `json:"workspace"`
	Event                 string   `json:"event"`
	Branches              []string `json:"branches"`
	Commands              []string `json:"commands"`
	WebhookURL            string   `json:"webhook_url"`
	EnableSSLVerification bool     `json:"enable_ssl_verification"`
	Secret                string   `json:"secret"` // For webhook token header
}

func main() {
	args := os.Args[1:]

	if len(args) >= 1 && args[0] == "--service" {
		cfg, err := loadConfig()
		if err != nil {
			fmt.Println("Failed to load config:", err)
			os.Exit(1)
		}
		if len(cfg.Jobs) == 0 {
			fmt.Println("No pipeline jobs configured. Please run wizard first.")
			os.Exit(1)
		}
		runService()
		return
	}

	// Handle auth commands: --pat, --login, --auth
	if len(args) >= 1 && (args[0] == "--pat" || args[0] == "--login" || args[0] == "--auth") {
		err := handleAuthCommand()
		if err != nil {
			fmt.Println("Authentication error:", err)
			os.Exit(1)
		}
		return
	}

	// Main wizard - prompt for provider and token selection
	err := runMainWizard()
	if err != nil {
		fmt.Println("Wizard error:", err)
		os.Exit(1)
	}
}

func handleAuthCommand() error {
	// Select provider
	provider, err := selectProvider()
	if err != nil {
		return err
	}

	// Prompt for token
	token := ""
	tokenPrompt := &survey.Password{
		Message: fmt.Sprintf("Enter your %s Personal Access Token:", strings.Title(provider)),
		Help:    fmt.Sprintf("Get your token from: %s", getTokenURL(provider)),
	}
	err = survey.AskOne(tokenPrompt, &token, survey.WithValidator(survey.Required))
	if err != nil {
		return err
	}

	return saveTokenAndValidate(token, provider)
}

func selectProvider() (string, error) {
	provider := ""
	providerPrompt := &survey.Select{
		Message: "Select provider:",
		Options: []string{"gitlab", "github"},
	}
	err := survey.AskOne(providerPrompt, &provider)
	return provider, err
}

func saveTokenAndValidate(token, provider string) error {
	user, err := getUser(token, provider)
	if err != nil {
		return err
	}
	fmt.Printf("Authenticated as: %s (id: %d)\n", user.Username, user.ID)

	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	// Add or update token
	tokenInfo := TokenInfo{
		Token:    token,
		Username: user.Username,
		UserID:   user.ID,
	}

	// Check if token already exists for this provider
	if tokens, exists := cfg.Tokens[provider]; exists {
		// Check if this user already has a token stored
		for i, existing := range tokens {
			if existing.UserID == user.ID {
				// Update existing token
				cfg.Tokens[provider][i] = tokenInfo
				fmt.Printf("Updated existing token for %s\n", user.Username)
				return saveConfig(cfg)
			}
		}
		// Add new token for this provider
		cfg.Tokens[provider] = append(cfg.Tokens[provider], tokenInfo)
	} else {
		// First token for this provider
		cfg.Tokens[provider] = []TokenInfo{tokenInfo}
	}

	fmt.Printf("Added token for %s\n", user.Username)
	return saveConfig(cfg)
}

func loadConfig() (*Config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(home, configPath)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{
				Tokens: make(map[string][]TokenInfo),
				Jobs:   []PipelineJob{},
			}, nil
		}
		return nil, err
	}
	defer f.Close()
	var cfg Config
	dec := json.NewDecoder(f)
	if err := dec.Decode(&cfg); err != nil {
		return nil, err
	}
	// Ensure tokens map is initialized
	if cfg.Tokens == nil {
		cfg.Tokens = make(map[string][]TokenInfo)
	}
	return &cfg, nil
}

func saveConfig(cfg *Config) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	path := filepath.Join(home, configPath)
	os.MkdirAll(filepath.Dir(path), 0700)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(cfg)
}

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
}

func getUser(token, provider string) (*User, error) {
	switch provider {
	case "gitlab":
		return getGitLabUser(token)
	case "github":
		return getGitHubUser(token)
	default:
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}
}

func getGitLabUser(token string) (*User, error) {
	req, err := http.NewRequest("GET", "https://gitlab.com/api/v4/user", nil)
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

type Project struct {
	ID                int    `json:"id"`
	PathWithNamespace string `json:"path_with_namespace"`
}

func runMainWizard() error {
	// Load config to check available tokens
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Check if any tokens exist
	if len(cfg.Tokens) == 0 {
		fmt.Println("No authentication tokens found. Please run with --pat, --login, or --auth first.")
		return errors.New("no tokens configured")
	}

	// Select provider
	provider, err := selectProviderFromConfig(cfg)
	if err != nil {
		return err
	}

	// Select token for the provider
	tokenInfo, err := selectTokenForProvider(cfg, provider)
	if err != nil {
		return err
	}

	// Start wizard
	job, err := wizard(tokenInfo.Token, provider)
	if err != nil {
		return fmt.Errorf("wizard error: %w", err)
	}

	cfg.Jobs = append(cfg.Jobs, job)
	err = saveConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}
	fmt.Println("Pipeline job added and config saved!")
	return nil
}

func selectProviderFromConfig(cfg *Config) (string, error) {
	availableProviders := make([]string, 0, len(cfg.Tokens))
	for provider := range cfg.Tokens {
		availableProviders = append(availableProviders, provider)
	}

	if len(availableProviders) == 1 {
		return availableProviders[0], nil
	}

	provider := ""
	providerPrompt := &survey.Select{
		Message: "Select provider:",
		Options: availableProviders,
	}
	err := survey.AskOne(providerPrompt, &provider)
	return provider, err
}

func selectTokenForProvider(cfg *Config, provider string) (*TokenInfo, error) {
	tokens := cfg.Tokens[provider]
	if len(tokens) == 0 {
		return nil, fmt.Errorf("no tokens found for %s", provider)
	}

	if len(tokens) == 1 {
		return &tokens[0], nil
	}

	// Multiple tokens - let user choose
	options := make([]string, len(tokens))
	for i, token := range tokens {
		options[i] = fmt.Sprintf("%s (ID: %d)", token.Username, token.UserID)
	}

	var selected string
	selectPrompt := &survey.Select{
		Message: fmt.Sprintf("Select %s account:", provider),
		Options: options,
	}
	err := survey.AskOne(selectPrompt, &selected)
	if err != nil {
		return nil, err
	}

	// Find the selected token
	for i, option := range options {
		if option == selected {
			return &tokens[i], nil
		}
	}

	return nil, errors.New("token selection failed")
}

func wizard(token, provider string) (PipelineJob, error) {
	var job PipelineJob
	job.Provider = provider

	// 1. Project search + selection
	projectName := ""
	prompt := &survey.Input{Message: "Enter part of your project name for search:"}
	err := survey.AskOne(prompt, &projectName, survey.WithValidator(survey.Required))
	if err != nil {
		return job, err
	}

	projects, err := searchProjects(token, projectName, provider)
	if err != nil {
		return job, err
	}
	if len(projects) == 0 {
		return job, errors.New("no projects found with that name")
	}

	options := make([]string, len(projects))
	for i, p := range projects {
		options[i] = fmt.Sprintf("%d: %s", p.ID, p.PathWithNamespace)
	}
	var selected string
	selectPrompt := &survey.Select{
		Message: "Select your project:",
		Options: options,
	}
	err = survey.AskOne(selectPrompt, &selected)
	if err != nil {
		return job, err
	}
	var projectID int
	var projectNameFull string
	for _, p := range projects {
		opt := fmt.Sprintf("%d: %s", p.ID, p.PathWithNamespace)
		if opt == selected {
			projectID = p.ID
			projectNameFull = p.PathWithNamespace
			break
		}
	}
	job.ProjectID = projectID
	job.ProjectName = projectNameFull

	// 2. Workspace path
	workspace := ""
	wsPrompt := &survey.Input{Message: "Enter your workspace path (where commands will run):"}
	err = survey.AskOne(wsPrompt, &workspace, survey.WithValidator(func(val any) error {
		s, ok := val.(string)
		if !ok || s == "" {
			return errors.New("workspace path cannot be empty")
		}
		info, err := os.Stat(s)
		if err != nil {
			return fmt.Errorf("path error: %v", err)
		}
		if !info.IsDir() {
			return errors.New("path is not a directory")
		}
		return nil
	}))
	if err != nil {
		return job, err
	}
	job.Workspace = workspace

	// 3. Webhook URL
	webhookRaw := ""
	urlPrompt := &survey.Input{
		Message: "Enter your webhook base URL (include scheme, e.g. https://webhooks.example.com or http://192.168.1.1:9091):",
		Help:    "No path needed; /gitlab/webhook will be appended automatically.",
	}
	err = survey.AskOne(urlPrompt, &webhookRaw, survey.WithValidator(func(val any) error {
		s, ok := val.(string)
		if !ok || s == "" {
			return errors.New("webhook URL cannot be empty")
		}
		u, err := url.ParseRequestURI(s)
		if err != nil {
			return fmt.Errorf("invalid URL: %v", err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return errors.New("URL scheme must be http or https")
		}
		return nil
	}))
	if err != nil {
		return job, err
	}

	// Build full webhook URL and determine SSL verification flag
	fullURL, sslVerify, err := buildWebhookURLAndSSLValidation(webhookRaw, provider)
	if err != nil {
		return job, err
	}
	job.WebhookURL = fullURL
	job.EnableSSLVerification = sslVerify

	// 4. Event to listen to
	event := ""
	eventPrompt := &survey.Select{
		Message: "Select event to listen for:",
		Options: getAllowedEventKeys(provider),
		Default: "on_push",
	}
	err = survey.AskOne(eventPrompt, &event)
	if err != nil {
		return job, err
	}
	job.Event = event

	// 5. Branches to listen on (comma separated, empty = all)
	branchesRaw := ""
	branchesPrompt := &survey.Input{
		Message: "Enter branches to listen on (comma separated, leave empty for all):",
	}
	err = survey.AskOne(branchesPrompt, &branchesRaw)
	if err != nil {
		return job, err
	}
	branches := []string{}
	for b := range strings.SplitSeq(branchesRaw, ",") {
		if trimmed := strings.TrimSpace(b); trimmed != "" {
			branches = append(branches, trimmed)
		}
	}
	job.Branches = branches

	// 6. Commands: choose file or interactive
	cmdMode := ""
	cmdModePrompt := &survey.Select{
		Message: "Add commands from:",
		Options: []string{"File (.txt)", "Interactive input"},
	}
	err = survey.AskOne(cmdModePrompt, &cmdMode)
	if err != nil {
		return job, err
	}

	if cmdMode == "File (.txt)" {
		filename := ""
		filePrompt := &survey.Input{
			Message: "Enter commands file path:",
			Help:    "One command per line",
		}
		err = survey.AskOne(filePrompt, &filename, survey.WithValidator(func(val any) error {
			s, ok := val.(string)
			if !ok || s == "" {
				return errors.New("filename cannot be empty")
			}
			info, err := os.Stat(s)
			if err != nil {
				return fmt.Errorf("file error: %v", err)
			}
			if info.IsDir() {
				return errors.New("path is a directory, not file")
			}
			return nil
		}))
		if err != nil {
			return job, err
		}
		cmds, err := readCommandsFromFile(filename)
		if err != nil {
			return job, err
		}
		job.Commands = cmds
	} else {
		fmt.Println("Enter commands one by one. Press ENTER twice to finish.")
		cmds, err := readCommandsInteractive(os.Stdin)
		if err != nil {
			return job, err
		}
		job.Commands = cmds
	}

	// 7. Generate a simple secret for webhook validation
	job.Secret = generateSecret(20)

	err = createWebhook(token, job)
	if err != nil {
		return job, fmt.Errorf("failed to create webhook: %w", err)
	}

	return job, nil
}

func readCommandsFromFile(filename string) ([]string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var cmds []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			cmds = append(cmds, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return cmds, nil
}

func readCommandsInteractive(r io.Reader) ([]string, error) {
	scanner := bufio.NewScanner(r)
	var cmds []string
	emptyCount := 0
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			emptyCount++
			if emptyCount >= 2 {
				break
			}
			continue
		}
		emptyCount = 0
		cmds = append(cmds, line)
	}
	return cmds, scanner.Err()
}

func generateSecret(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[randInt(len(letters))]
	}
	return string(b)
}

func randInt(max int) int {
	f, err := os.Open("/dev/urandom")
	if err != nil {
		return 0
	}
	defer f.Close()
	var b [1]byte
	_, err = f.Read(b[:])
	if err != nil {
		return 0
	}
	return int(b[0]) % max
}

func searchProjects(token, search, provider string) ([]Project, error) {
	switch provider {
	case "gitlab":
		return searchGitLabProjects(token, search)
	case "github":
		return searchGitHubRepos(token, search)
	default:
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}
}

func searchGitLabProjects(token, search string) ([]Project, error) {
	apiURL := "https://gitlab.com/api/v4/projects?membership=true&per_page=20&search=" + url.QueryEscape(search)
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

func createWebhook(token string, job PipelineJob) error {
	switch job.Provider {
	case "gitlab":
		return createGitLabWebhook(token, job)
	case "github":
		return createGitHubWebhook(token, job)
	default:
		return fmt.Errorf("unsupported provider: %s", job.Provider)
	}
}

func createGitLabWebhook(token string, job PipelineJob) error {
	apiURL := fmt.Sprintf("https://gitlab.com/api/v4/projects/%d/hooks", job.ProjectID)

	eventKey, ok := allowedEvents[job.Event]
	if !ok {
		return fmt.Errorf("unsupported event type: %s", job.Event)
	}

	payload := map[string]any{
		"url":                     job.WebhookURL,
		"enable_ssl_verification": job.EnableSSLVerification,
		"token":                   job.Secret,
		eventKey:                  true, // dynamically set event flag
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
		fmt.Println("Webhook created successfully!")
		return nil
	case 409:
		return fmt.Errorf("webhook already exists: %s", string(body))
	default:
		return fmt.Errorf("failed to create webhook, status %d: %s", resp.StatusCode, string(body))
	}
}

func createGitHubWebhook(token string, job PipelineJob) error {
	// Extract owner/repo from project name (format: owner/repo)
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
		fmt.Println("Webhook created successfully!")
		return nil
	case 422:
		return fmt.Errorf("webhook validation failed or already exists: %s", string(body))
	default:
		return fmt.Errorf("failed to create webhook, status %d: %s", resp.StatusCode, string(body))
	}
}

func buildWebhookURLAndSSLValidation(rawURL, provider string) (string, bool, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", false, fmt.Errorf("invalid URL: %w", err)
	}
	// Append path based on provider
	u.Path = filepath.Join(u.Path, provider, "webhook")
	enableSSL := false
	if u.Scheme == "https" {
		enableSSL = true
	}
	return u.String(), enableSSL, nil
}

func runService() {
	addr := fmt.Sprintf(":%s", PORT)

	http.HandleFunc("/gitlab/webhook", handleGitLabWebhook)
	http.HandleFunc("/github/webhook", handleGitHubWebhook)

	fmt.Println("Starting webhook listener on", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		fmt.Println("Server error:", err)
	}
}

func handleGitLabWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintln(w, "Only POST method is allowed")
		return
	}

	// Always reload config for each request
	cfg, err := loadConfig()
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

	// Validate token
	token := r.Header.Get("X-Gitlab-Token")
	if token == "" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, "Missing X-Gitlab-Token header")
		return
	}

	var job *PipelineJob
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

	// Check if event type matches what is configured
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

	// Run the job in the background
	go func(j *PipelineJob) {
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

func handleGitHubWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintln(w, "Only POST method is allowed")
		return
	}

	// Always reload config for each request
	cfg, err := loadConfig()
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

	// GitHub uses X-Hub-Signature-256 for webhook validation
	// For simplicity, we'll use a custom header like GitLab for now
	token := r.Header.Get("X-Hub-Signature")
	if token == "" {
		// Fallback to custom header for backward compatibility
		token = r.Header.Get("X-GitHub-Token")
	}
	if token == "" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, "Missing webhook signature or token")
		return
	}

	var job *PipelineJob
	for i, j := range cfg.Jobs {
		if j.Secret == token && j.Provider == "github" {
			job = &cfg.Jobs[i]
			break
		}
	}

	if job == nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, "Invalid webhook token")
		return
	}

	// Check if event type matches what is configured
	eventType := r.Header.Get("X-GitHub-Event")
	expectedEventType, ok := githubAllowedEvents[job.Event]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Configured job has unsupported event: %s\n", job.Event)
		return
	}

	if eventType != expectedEventType {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, "Event type '%s' does not match job configuration '%s'\n", eventType, job.Event)
		return
	}

	// Run the job in the background
	go func(j *PipelineJob) {
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

func runCommands(workspace string, commands []string) error {
	for _, cmdline := range commands {
		fmt.Printf("Executing: %s\n", cmdline)

		// Split command and args (simple split by space, you may improve parsing)
		parts := strings.Fields(cmdline)
		if len(parts) == 0 {
			continue
		}
		cmd := exec.Command(parts[0], parts[1:]...)
		cmd.Dir = workspace
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		err := cmd.Run()
		if err != nil {
			return fmt.Errorf("command failed: %s, error: %w", cmdline, err)
		}
	}
	return nil
}

func init() {
	PORT = os.Getenv("C1CD_PORT")
	if PORT == "" {
		PORT = "9091"
		log.Println("⚠️  C1CD_PORT not set, using default 9091")
	}
}

func getAllowedEventKeys(provider string) []string {
	var eventMap map[string]string
	switch provider {
	case "gitlab":
		eventMap = allowedEvents
	case "github":
		eventMap = githubAllowedEvents
	default:
		eventMap = allowedEvents // fallback
	}
	keys := make([]string, 0, len(eventMap))
	for k := range eventMap {
		keys = append(keys, k)
	}
	return keys
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
	"on_tag":          "create", // for tags
}

var githubEventMap = map[string]string{
	"push":         "push",
	"pull_request": "pull_request", 
	"release":      "release",
	"issues":       "issues",
	"create":       "create",
}

func getTokenURL(provider string) string {
	switch provider {
	case "gitlab":
		return "https://gitlab.com/-/profile/personal_access_tokens"
	case "github":
		return "https://github.com/settings/tokens"
	default:
		return "unknown provider"
	}
}
