package auth

import (
	"fmt"
	"net/url"
	"strings"

	"c1cd/internal/config"
	"c1cd/internal/providers"

	"github.com/AlecAivazis/survey/v2"
)

func HandleAuthCommand() error {
	provider, serverURL, err := selectProvider()
	if err != nil {
		return err
	}

	token := ""
	tokenPrompt := &survey.Password{
		Message: fmt.Sprintf("Enter your %s Personal Access Token:", strings.Title(provider)),
		Help:    fmt.Sprintf("Get your token from: %s", getTokenURL(provider, serverURL)),
	}
	err = survey.AskOne(tokenPrompt, &token, survey.WithValidator(survey.Required))
	if err != nil {
		return err
	}

	return saveTokenAndValidate(token, provider, serverURL)
}

func selectProvider() (string, string, error) {
	provider := ""
	providerPrompt := &survey.Select{
		Message: "Select provider:",
		Options: []string{"gitlab", "gitlab-custom", "github"},
	}
	err := survey.AskOne(providerPrompt, &provider)
	if err != nil {
		return "", "", err
	}

	var serverURL string
	if provider == "gitlab-custom" {
		serverURL, err = promptForCustomGitLabURL()
		if err != nil {
			return "", "", err
		}
		provider = "gitlab" // Use gitlab as the actual provider
	}

	return provider, serverURL, nil
}

func promptForCustomGitLabURL() (string, error) {
	var serverURL string
	urlPrompt := &survey.Input{
		Message: "Enter your custom GitLab server URL (e.g., https://gitlab.yourcompany.com):",
		Help:    "Include the scheme (https://) but no path",
	}
	err := survey.AskOne(urlPrompt, &serverURL, survey.WithValidator(func(val any) error {
		s, ok := val.(string)
		if !ok || s == "" {
			return fmt.Errorf("server URL cannot be empty")
		}
		u, err := url.Parse(s)
		if err != nil {
			return fmt.Errorf("invalid URL: %v", err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("URL scheme must be http or https")
		}
		if u.Host == "" {
			return fmt.Errorf("URL must include a host")
		}
		return nil
	}))
	if err != nil {
		return "", err
	}

	// Ensure no trailing slash
	serverURL = strings.TrimRight(serverURL, "/")
	return serverURL, nil
}

func saveTokenAndValidate(token, provider, serverURL string) error {
	user, err := providers.GetUser(token, provider, serverURL)
	if err != nil {
		return err
	}

	displayURL := serverURL
	if displayURL == "" {
		displayURL = "gitlab.com"
	}
	fmt.Printf("Authenticated as: %s (id: %d) on %s\n", user.Username, user.ID, displayURL)

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	tokenInfo := config.TokenInfo{
		Token:     token,
		Username:  user.Username,
		UserID:    user.ID,
		ServerURL: serverURL,
	}

	if tokens, exists := cfg.Tokens[provider]; exists {
		for i, existing := range tokens {
			if existing.UserID == user.ID && existing.ServerURL == serverURL {
				cfg.Tokens[provider][i] = tokenInfo
				fmt.Printf("Updated existing token for %s\n", user.Username)
				return config.Save(cfg)
			}
		}
		cfg.Tokens[provider] = append(cfg.Tokens[provider], tokenInfo)
	} else {
		cfg.Tokens[provider] = []config.TokenInfo{tokenInfo}
	}

	fmt.Printf("Added token for %s\n", user.Username)
	return config.Save(cfg)
}

func getTokenURL(provider, serverURL string) string {
	switch provider {
	case "gitlab":
		if serverURL != "" {
			return serverURL + "/-/profile/personal_access_tokens"
		}
		return "https://gitlab.com/-/profile/personal_access_tokens"
	case "github":
		return "https://github.com/settings/tokens"
	default:
		return "unknown provider"
	}
}