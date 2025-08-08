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
	Token string        `json:"token"`
	Jobs  []PipelineJob `json:"jobs"`
}

type PipelineJob struct {
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

	if len(args) >= 2 && args[0] == "--pat" {
		pat := args[1]
		err := saveTokenAndValidate(pat)
		if err != nil {
			fmt.Println("Failed to save or validate PAT:", err)
			os.Exit(1)
		}
		fmt.Println("PAT saved and validated successfully.")
		return
	}

	cfg, err := loadConfig()
	if err != nil {
		fmt.Println("Failed to load config:", err)
		os.Exit(1)
	}
	if cfg.Token == "" {
		fmt.Println("No PAT token found. Please run with --pat <token> first.")
		os.Exit(1)
	}

	// Start wizard
	job, err := wizard(cfg.Token)
	if err != nil {
		fmt.Println("Wizard error:", err)
		os.Exit(1)
	}

	cfg.Jobs = append(cfg.Jobs, job)
	err = saveConfig(cfg)
	if err != nil {
		fmt.Println("Failed to save config:", err)
		os.Exit(1)
	}
	fmt.Println("Pipeline job added and config saved!")
}

func saveTokenAndValidate(token string) error {
	user, err := getUser(token)
	if err != nil {
		return err
	}
	fmt.Printf("Authenticated as: %s (id: %d)\n", user.Username, user.ID)

	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	cfg.Token = token
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
			return &Config{}, nil
		}
		return nil, err
	}
	defer f.Close()
	var cfg Config
	dec := json.NewDecoder(f)
	if err := dec.Decode(&cfg); err != nil {
		return nil, err
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

func getUser(token string) (*User, error) {
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

type Project struct {
	ID                int    `json:"id"`
	PathWithNamespace string `json:"path_with_namespace"`
}

func wizard(token string) (PipelineJob, error) {
	var job PipelineJob

	// 1. Project search + selection
	projectName := ""
	prompt := &survey.Input{Message: "Enter part of your project name for search:"}
	err := survey.AskOne(prompt, &projectName, survey.WithValidator(survey.Required))
	if err != nil {
		return job, err
	}

	projects, err := searchProjects(token, projectName)
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
	fullURL, sslVerify, err := buildWebhookURLAndSSLValidation(webhookRaw)
	if err != nil {
		return job, err
	}
	job.WebhookURL = fullURL
	job.EnableSSLVerification = sslVerify

	// 4. Event to listen to (for now, just on_push)
	event := ""
	eventPrompt := &survey.Select{
		Message: "Select event to listen for:",
		Options: getAllowedEventKeys(),
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

func searchProjects(token, search string) ([]Project, error) {
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
	apiURL := fmt.Sprintf("https://gitlab.com/api/v4/projects/%d/hooks", job.ProjectID)

	allowedEvents := map[string]string{
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

func buildWebhookURLAndSSLValidation(rawURL string) (string, bool, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", false, fmt.Errorf("invalid URL: %w", err)
	}
	// Append path /gitlab/webhook
	u.Path = filepath.Join(u.Path, "gitlab", "webhook")
	enableSSL := false
	if u.Scheme == "https" {
		enableSSL = true
	}
	return u.String(), enableSSL, nil
}

func runService() {
	addr := fmt.Sprintf(":%s", PORT)

	http.HandleFunc("/gitlab/webhook", func(w http.ResponseWriter, r *http.Request) {
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
			if j.Secret == token {
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

		// Map from GitLab header event names to our keys

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
	})

	fmt.Println("Starting webhook listener on", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		fmt.Println("Server error:", err)
	}
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

func getAllowedEventKeys() []string {
	keys := make([]string, 0, len(allowedEvents))
	for k := range allowedEvents {
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
