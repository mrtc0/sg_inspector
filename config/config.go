package config

import (
	"github.com/BurntSushi/toml"
	"os"
	"path/filepath"
)

type Config struct {
	DryRun                        bool
	Rules                         []Rule
	Username                      string `toml:"username"`
	IconEmoji                     string `toml:"icon_emoji"`
	CheckInterval                 string `toml:"check_interval"`
	ResetInterval                 string `toml:"reset_interval"`
	Include                       string
	SlackChannel                  string
	SlackToken                    string
	TemporaryAllowdSecurityGroups []string
	FinishMessage                 string `toml:"finish_message"`
	OpenStack                     OpenStack
}

type OpenStack struct {
	AuthURL     string
	Username    string
	Password    string
	RegionName  string
	ProjectName string
	Cert        string
	Key         string
}

type Rule struct {
	Tenant   string
	TenantID string
	SG       string
	Port     []string
}

func includeConfigFile(cfg *Config, include string) error {

	files, err := filepath.Glob(include)
	if err != nil {
		return err
	}

	for _, file := range files {
		tmpCfg := Config{}
		_, err = toml.DecodeFile(file, &tmpCfg)
		if err != nil {
			return err
		}
		for _, r := range tmpCfg.Rules {
			cfg.Rules = append(cfg.Rules, r)
		}
	}
	return nil
}

func ReadConfigFile(cfgPath string) (Config, error) {
	var cfg Config
	_, err := toml.DecodeFile(cfgPath, &cfg)
	if err != nil {
		return cfg, err
	}
	if cfg.Include != "" {
		if err := includeConfigFile(&cfg, cfg.Include); err != nil {
			return cfg, err
		}
	}
	return cfg, err
}

func ReadConfig(cfgPath string, dryRun bool) (Config, error) {
	cfg, err := ReadConfigFile(cfgPath)
	if err != nil {
		return cfg, err
	}

	cfg.DryRun = dryRun
	cfg.SlackChannel = os.Getenv("SLACK_CHANNEL_NAME")
	cfg.SlackToken = os.Getenv("SLACK_TOKEN")

	cfg.OpenStack.AuthURL = os.Getenv("OS_AUTH_URL")
	cfg.OpenStack.Username = os.Getenv("OS_USERNAME")
	cfg.OpenStack.Password = os.Getenv("OS_PASSWORD")
	cfg.OpenStack.RegionName = os.Getenv("OS_REGION_NAME")
	cfg.OpenStack.ProjectName = os.Getenv("OS_PROJECT_NAME")
	cfg.OpenStack.Cert = os.Getenv("OS_CERT")
	cfg.OpenStack.Key = os.Getenv("OS_KEY")

	return cfg, nil
}
