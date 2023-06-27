package config

import (
	"fmt"
	"os"
	"strings"
)

type Config struct {
	ServerPort string
	UserApiUrl string
	Jwt        *JwtConfig
}

func ReadConfig() (*Config, error) {
	var err error

	serverPort := os.Getenv(ServerPort)
	if serverPort == "" {
		return nil, fmt.Errorf(EnvironmentVariableNotDefined, ServerPort)
	}

	userApiUrl := os.Getenv(UserApiUrl)
	if userApiUrl == "" {
		return nil, fmt.Errorf(EnvironmentVariableNotDefined, UserApiUrl)
	}

	var jwtConfig *JwtConfig
	jwtConfig, err = ReadJwtConfig()
	if err != nil {
		return nil, err
	}

	return &Config{
		ServerPort: serverPort,
		UserApiUrl: userApiUrl,
		Jwt:        jwtConfig,
	}, nil
}

func ReadJwtConfig() (*JwtConfig, error) {
	privateKey := os.Getenv(JwtPrivateKey)
	if privateKey == "" {
		return nil, fmt.Errorf(EnvironmentVariableNotDefined, JwtPrivateKey)
	}
	privateKey = strings.ReplaceAll(privateKey, `\n`, "\n")

	publicKey := os.Getenv(JwtPublicKey)
	if publicKey == "" {
		return nil, fmt.Errorf(EnvironmentVariableNotDefined, JwtPublicKey)
	}
	publicKey = strings.ReplaceAll(publicKey, `\n`, "\n")

	return &JwtConfig{
		PrivateKey: []byte(privateKey),
		PublicKey:  []byte(publicKey),
	}, nil
}
