package config

import (
	"github.com/BurntSushi/toml"
	"path/filepath"
)

type Config struct {
	DryRun       bool
	Rules        []Rule
	Username     string `toml:"username"`
	IconEmoji    string `toml:"icon_emoji"`
	CheckInterval string `toml:"check_interval"`
	Include      string
	SlackChannel string
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
