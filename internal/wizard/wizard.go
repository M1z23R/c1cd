package wizard

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"c1cd/internal/config"
	"c1cd/internal/providers"

	"github.com/AlecAivazis/survey/v2"
)

func RunMainWizard() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if len(cfg.Tokens) == 0 {
		fmt.Println("No authentication tokens found. Please run with --pat, --login, or --auth first.")
		return errors.New("no tokens configured")
	}

	provider, err := selectProviderFromConfig(cfg)
	if err != nil {
		return err
	}

	tokenInfo, err := selectTokenForProvider(cfg, provider)
	if err != nil {
		return err
	}

	job, err := runWizard(tokenInfo.Token, provider)
	if err != nil {
		return fmt.Errorf("wizard error: %w", err)
	}

	cfg.Jobs = append(cfg.Jobs, job)
	err = config.Save(cfg)
	if err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}
	fmt.Println("Pipeline job added and config saved!")
	return nil
}

func selectProviderFromConfig(cfg *config.Config) (string, error) {
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

func selectTokenForProvider(cfg *config.Config, provider string) (*config.TokenInfo, error) {
	tokens := cfg.Tokens[provider]
	if len(tokens) == 0 {
		return nil, fmt.Errorf("no tokens found for %s", provider)
	}

	if len(tokens) == 1 {
		return &tokens[0], nil
	}

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

	for i, option := range options {
		if option == selected {
			return &tokens[i], nil
		}
	}

	return nil, errors.New("token selection failed")
}

func runWizard(token, provider string) (config.PipelineJob, error) {
	var job config.PipelineJob
	job.Provider = provider

	projectName := ""
	prompt := &survey.Input{Message: "Enter part of your project name for search:"}
	err := survey.AskOne(prompt, &projectName, survey.WithValidator(survey.Required))
	if err != nil {
		return job, err
	}

	projects, err := providers.SearchProjects(token, projectName, provider)
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

	fullURL, sslVerify, err := buildWebhookURLAndSSLValidation(webhookRaw, provider)
	if err != nil {
		return job, err
	}
	job.WebhookURL = fullURL
	job.EnableSSLVerification = sslVerify

	event := ""
	eventPrompt := &survey.Select{
		Message: "Select event to listen for:",
		Options: providers.GetAllowedEventKeys(provider),
		Default: "on_push",
	}
	err = survey.AskOne(eventPrompt, &event)
	if err != nil {
		return job, err
	}
	job.Event = event

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

	job.Secret = generateSecret(20)

	err = providers.CreateWebhook(token, job)
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

func buildWebhookURLAndSSLValidation(rawURL, provider string) (string, bool, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", false, fmt.Errorf("invalid URL: %w", err)
	}
	u.Path = filepath.Join(u.Path, provider, "webhook")
	enableSSL := false
	if u.Scheme == "https" {
		enableSSL = true
	}
	return u.String(), enableSSL, nil
}