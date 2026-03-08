package config

import (
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Server    ServerConfig    `mapstructure:"server"`
	Database  DatabaseConfig  `mapstructure:"database"`
	RabbitMQ  RabbitMQConfig  `mapstructure:"rabbitmq"`
	Redis     RedisConfig     `mapstructure:"redis"`
	Worker    WorkerConfig    `mapstructure:"worker"`
	RateLimit RateLimitConfig `mapstructure:"rate_limit"`
	Notify    NotifyConfig    `mapstructure:"notify"`
	Tools     ToolsConfig     `mapstructure:"tools"`
}

type ServerConfig struct {
	Port int    `mapstructure:"port"`
	Host string `mapstructure:"host"`
}

type DatabaseConfig struct {
	URL            string `mapstructure:"url"`
	MigrationsPath string `mapstructure:"migrations_path"`
	MaxConns       int    `mapstructure:"max_conns"`
}

type RabbitMQConfig struct {
	URL string `mapstructure:"url"`
}

type RedisConfig struct {
	URL string `mapstructure:"url"`
}

type WorkerConfig struct {
	Concurrency int `mapstructure:"concurrency"`
}

type RateLimitConfig struct {
	Global    int            `mapstructure:"global"`     // requests per second globally
	PerTool   map[string]int `mapstructure:"per_tool"`   // per-tool rps limits
	PerTarget int            `mapstructure:"per_target"` // rps per target domain
}

type NotifyConfig struct {
	DiscordWebhookURL string `mapstructure:"discord_webhook_url"`
	SlackWebhookURL   string `mapstructure:"slack_webhook_url"`
	MinSeverity       string `mapstructure:"min_severity"` // minimum severity to notify
}

type ToolsConfig struct {
	Subfinder  string `mapstructure:"subfinder"`
	Amass      string `mapstructure:"amass"`
	ShuffleDNS string `mapstructure:"shuffledns"`
	Naabu      string `mapstructure:"naabu"`
	Httpx      string `mapstructure:"httpx"`
	Katana     string `mapstructure:"katana"`
	Nuclei     string `mapstructure:"nuclei"`
}

func Load(configPath string) (*Config, error) {
	v := viper.New()

	// Defaults
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("database.url", "postgres://scanner:changeme@localhost:5432/bugscanner?sslmode=disable")
	v.SetDefault("database.migrations_path", "/etc/bugscanner/migrations")
	v.SetDefault("database.max_conns", 20)
	v.SetDefault("rabbitmq.url", "amqp://scanner:changeme@localhost:5672/")
	v.SetDefault("redis.url", "redis://localhost:6379/0")
	v.SetDefault("worker.concurrency", 3)
	v.SetDefault("rate_limit.global", 100)
	v.SetDefault("rate_limit.per_target", 30)
	v.SetDefault("rate_limit.per_tool", map[string]int{
		"subfinder":  50,
		"amass":      20,
		"shuffledns": 100,
		"naabu":      200,
		"httpx":      100,
		"katana":     50,
		"nuclei":     50,
	})
	v.SetDefault("notify.min_severity", "medium")
	v.SetDefault("tools.subfinder", "subfinder")
	v.SetDefault("tools.amass", "amass")
	v.SetDefault("tools.shuffledns", "shuffledns")
	v.SetDefault("tools.naabu", "naabu")
	v.SetDefault("tools.httpx", "httpx")
	v.SetDefault("tools.katana", "katana")
	v.SetDefault("tools.nuclei", "nuclei")

	// Config file
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath("/etc/bugscanner")
		v.AddConfigPath("./configs")
		v.AddConfigPath(".")
	}

	// Environment variables
	v.SetEnvPrefix("")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Direct env var bindings for Docker/deployment
	v.BindEnv("database.url", "DATABASE_URL")
	v.BindEnv("database.migrations_path", "DATABASE_MIGRATIONS_PATH")
	v.BindEnv("rabbitmq.url", "RABBITMQ_URL")
	v.BindEnv("redis.url", "REDIS_URL")
	v.BindEnv("notify.discord_webhook_url", "DISCORD_WEBHOOK_URL")
	v.BindEnv("notify.slack_webhook_url", "SLACK_WEBHOOK_URL")
	v.BindEnv("worker.concurrency", "WORKER_CONCURRENCY")

	// Read config file (optional - not an error if missing)
	_ = v.ReadInConfig()

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
