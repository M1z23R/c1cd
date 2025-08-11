package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

const configPath = ".config/c1cd/config.json"

type Config struct {
	Tokens map[string][]TokenInfo `json:"tokens"`
	Jobs   []PipelineJob          `json:"jobs"`
}

type TokenInfo struct {
	Token    string `json:"token"`
	Username string `json:"username"`
	UserID   int    `json:"user_id"`
}

type PipelineJob struct {
	Provider              string   `json:"provider"`
	ProjectID             int      `json:"project_id"`
	ProjectName           string   `json:"project_name"`
	Workspace             string   `json:"workspace"`
	Event                 string   `json:"event"`
	Branches              []string `json:"branches"`
	Commands              []string `json:"commands"`
	WebhookURL            string   `json:"webhook_url"`
	EnableSSLVerification bool     `json:"enable_ssl_verification"`
	Secret                string   `json:"secret"`
}

func Load() (*Config, error) {
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
	if cfg.Tokens == nil {
		cfg.Tokens = make(map[string][]TokenInfo)
	}
	return &cfg, nil
}

func Save(cfg *Config) error {
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