package config

type Config struct {
	Rules []Rule
}

type Rule struct {
	Tenant string
	SG     string
	Port   []string
}
