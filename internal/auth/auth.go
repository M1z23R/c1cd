package auth

import (
	"fmt"
	"strings"

	"c1cd/internal/config"
	"c1cd/internal/providers"

	"github.com/AlecAivazis/survey/v2"
)

func HandleAuthCommand() error {
	provider, err := selectProvider()
	if err != nil {
		return err
	}

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
	user, err := providers.GetUser(token, provider)
	if err != nil {
		return err
	}
	fmt.Printf("Authenticated as: %s (id: %d)\n", user.Username, user.ID)

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	tokenInfo := config.TokenInfo{
		Token:    token,
		Username: user.Username,
		UserID:   user.ID,
	}

	if tokens, exists := cfg.Tokens[provider]; exists {
		for i, existing := range tokens {
			if existing.UserID == user.ID {
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