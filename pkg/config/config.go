package config

import (
	"fmt"
	"os"
	"strings"
)

type Config struct {
	FunctionNames *FunctionNames
	Jwt           *JwtConfig
}

func ReadConfig() (*Config, error) {
	var err error

	var userApiCfg map[UserApiFunctionNames]string
	userApiCfg, err = ReadUserApiConfig()
	if err != nil {
		return nil, err
	}

	var jwtConfig *JwtConfig
	jwtConfig, err = ReadJwtConfig()
	if err != nil {
		return nil, err
	}

	return &Config{
		FunctionNames: &FunctionNames{
			UserAPI: userApiCfg,
		},
		Jwt: jwtConfig,
	}, nil
}

func ReadUserApiConfig() (map[UserApiFunctionNames]string, error) {
	getUserByIdFunctionName := os.Getenv(EnvironmentVariableGetUserByIdFunctionName)
	if getUserByIdFunctionName == "" {
		return nil, fmt.Errorf(EnvironmentVariableNotDefined, EnvironmentVariableGetUserByIdFunctionName)
	}

	registerFunctionName := os.Getenv(EnvironmentVariableRegisterFunctionName)
	if registerFunctionName == "" {
		return nil, fmt.Errorf(EnvironmentVariableNotDefined, EnvironmentVariableRegisterFunctionName)
	}

	loginFunctionName := os.Getenv(EnvironmentVariableLoginFunctionName)
	if loginFunctionName == "" {
		return nil, fmt.Errorf(EnvironmentVariableNotDefined, EnvironmentVariableLoginFunctionName)
	}

	getAccessTokenViaRefreshTokenFunctionName := os.Getenv(EnvironmentVariableGetAccessTokenByRefreshTokenFunctionName)
	if getAccessTokenViaRefreshTokenFunctionName == "" {
		return nil, fmt.Errorf(EnvironmentVariableNotDefined, EnvironmentVariableGetAccessTokenByRefreshTokenFunctionName)
	}

	updateUserByIdFunctionName := os.Getenv(EnvironmentVariableUpdateUserByIdFunctionName)
	if updateUserByIdFunctionName == "" {
		return nil, fmt.Errorf(EnvironmentVariableNotDefined, EnvironmentVariableUpdateUserByIdFunctionName)
	}

	return map[UserApiFunctionNames]string{
		GetUserById:                   getUserByIdFunctionName,
		Register:                      registerFunctionName,
		Login:                         loginFunctionName,
		GetAccessTokenViaRefreshToken: getAccessTokenViaRefreshTokenFunctionName,
		UpdateUserById:                updateUserByIdFunctionName,
	}, nil
}

func ReadJwtConfig() (*JwtConfig, error) {
	privateKey := os.Getenv(EnvironmentVariableJwtPrivateKey)
	if privateKey == "" {
		return nil, fmt.Errorf(EnvironmentVariableNotDefined, EnvironmentVariableJwtPrivateKey)
	}
	privateKey = strings.ReplaceAll(privateKey, `\n`, "\n")

	publicKey := os.Getenv(EnvironmentVariableJwtPublicKey)
	if publicKey == "" {
		return nil, fmt.Errorf(EnvironmentVariableNotDefined, EnvironmentVariableJwtPublicKey)
	}
	publicKey = strings.ReplaceAll(publicKey, `\n`, "\n")

	return &JwtConfig{
		PrivateKey: []byte(privateKey),
		PublicKey:  []byte(publicKey),
	}, nil
}
