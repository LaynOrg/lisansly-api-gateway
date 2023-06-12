package config

import (
	"os"
)

type Config struct {
	ServerPort string
}

func ReadConfig() (*Config, error) {
	serverPort := os.Getenv(ServerPort)
	if serverPort == "" {
		return nil, EnvironmentVariablesNotDefined
	}

	return &Config{
		ServerPort: serverPort,
	}, nil
}
