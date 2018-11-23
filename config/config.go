package config

type Config struct {
	Rules     []Rule
	Username  string `toml:"username"`
	IconEmoji string `toml:"icon_emoji"`
	Include   string
}

type Rule struct {
	Tenant   string
	TenantID string
	SG       string
	Port     []string
}
