package main

import (
	"github.com/BurntSushi/toml"
	"github.com/go-playground/validator/v10"
	"os"
	"path/filepath"
)

var Version string

type Config struct {
	DryRun                        bool
	Rules                         []Rule
	Username                      string `toml:"username" validate:"required"`
	IconEmoji                     string `toml:"icon_emoji" validate:"required"`
	CheckInterval                 string `toml:"check_interval" validate:"required"`
	ResetInterval                 string `toml:"reset_interval" validate:"required"`
	Include                       string
	SlackChannel                  string
	SlackToken                    string
	TemporaryAllowdSecurityGroups []string
	PrefixMessage                 string `toml:"prefix_message" validate:"required"`
	SuffixMessage                 string `toml:"suffix_message" validate:"required"`
	OpenStack                     OpenStack
	Policies                      []Policy
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

type Policy struct {
	Policy        string `toml:"policy" validate:"required"`
	Data          string `toml:"data"`
	PrefixMessage string `toml:"prefix_message" validate:"required"`
	SuffixMessage string `toml:"suffix_message" validate:"required"`
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

	validate := validator.New()
	if err := validate.Struct(cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}
