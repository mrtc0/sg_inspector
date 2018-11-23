package config

type Config struct {
	Rules []Rule
}

type Rule struct {
	Tenant   string
	TenantID string
	SG       string
	Port     []string
}
