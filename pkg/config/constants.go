package config

import "github.com/pkg/errors"

var (
	EnvironmentVariablesNotDefined = errors.New("environment variables is not defined")
)

// #nosec
const (
	IsAtRemote = "IS_AT_REMOTE"

	ServerPort      = "SERVER_PORT"
	PactBrokerURL   = "PACT_BROKER_URL"
	PactBrokerToken = "PACT_BROKER_TOKEN"
)
