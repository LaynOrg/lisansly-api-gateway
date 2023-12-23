//go:build unit

package config

import (
	"os"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadConfig(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		var err error

		err = os.Setenv(
			EnvironmentVariableGetUserByIdFunctionName,
			"getUserById",
		)
		require.NoError(t, err)

		err = os.Setenv(
			EnvironmentVariableRegisterFunctionName,
			"register",
		)
		require.NoError(t, err)

		err = os.Setenv(
			EnvironmentVariableLoginFunctionName,
			"login",
		)
		require.NoError(t, err)

		err = os.Setenv(
			EnvironmentVariableGetAccessTokenByRefreshTokenFunctionName,
			"GetAccessTokenByRefreshToken",
		)
		require.NoError(t, err)

		err = os.Setenv(
			EnvironmentVariableUpdateUserByIdFunctionName,
			"updateUser",
		)
		require.NoError(t, err)

		err = os.Setenv(EnvironmentVariableJwtPrivateKey, "privateKey")
		require.NoError(t, err)

		err = os.Setenv(EnvironmentVariableJwtPublicKey, "publicKey")
		require.NoError(t, err)

		cfg, err := ReadConfig()
		defer os.Clearenv()

		assert.NoError(t, err)
		assert.Equal(t, &Config{
			FunctionNames: &FunctionNames{
				UserAPI: map[UserApiFunctionNames]string{
					GetAccessTokenByRefreshToken: "GetAccessTokenByRefreshToken",
					Login:                        "login",
					Register:                     "register",
					UpdateUserById:               "updateUser",
					GetUserById:                  "getUserById",
				},
			},
			Jwt: &JwtConfig{
				PrivateKey: []byte("privateKey"),
				PublicKey:  []byte("publicKey"),
			},
		}, cfg)
	})

	t.Run("when user api config return error should return it", func(t *testing.T) {
		var err error

		err = os.Setenv(EnvironmentVariableJwtPrivateKey, "privateKey")
		require.NoError(t, err)

		err = os.Setenv(EnvironmentVariableJwtPublicKey, "publicKey")
		require.NoError(t, err)

		cfg, err := ReadConfig()
		defer os.Clearenv()

		assert.Error(t, err)
		assert.Nil(t, cfg)
	})

	t.Run("when jwt config return error should return it", func(t *testing.T) {
		var err error

		err = os.Setenv(EnvironmentVariableJwtPrivateKey, "privateKey")
		require.NoError(t, err)

		err = os.Setenv(EnvironmentVariableJwtPublicKey, "publicKey")
		require.NoError(t, err)

		cfg, err := ReadConfig()
		defer os.Clearenv()

		assert.Error(t, err)
		assert.Nil(t, cfg)
	})
}

func TestReadUserApiConfig(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		var err error

		err = os.Setenv(
			EnvironmentVariableGetUserByIdFunctionName,
			"getUserById",
		)
		require.NoError(t, err)

		err = os.Setenv(
			EnvironmentVariableRegisterFunctionName,
			"register",
		)
		require.NoError(t, err)

		err = os.Setenv(
			EnvironmentVariableLoginFunctionName,
			"login",
		)
		require.NoError(t, err)

		err = os.Setenv(
			EnvironmentVariableGetAccessTokenByRefreshTokenFunctionName,
			"GetAccessTokenByRefreshToken",
		)
		require.NoError(t, err)

		err = os.Setenv(
			EnvironmentVariableUpdateUserByIdFunctionName,
			"updateUser",
		)
		require.NoError(t, err)

		cfg, err := ReadUserApiConfig()
		defer os.Clearenv()

		assert.NoError(t, err)
		assert.Equal(t, map[UserApiFunctionNames]string{
			GetAccessTokenByRefreshToken: "GetAccessTokenByRefreshToken",
			Login:                        "login",
			Register:                     "register",
			UpdateUserById:               "updateUser",
			GetUserById:                  "getUserById",
		}, cfg)
	})

	t.Run("when getUserById function name is empty should return error", func(t *testing.T) {
		cfg, err := ReadUserApiConfig()

		assert.Equal(t,
			errors.Errorf(
				EnvironmentVariableNotDefined,
				EnvironmentVariableGetUserByIdFunctionName,
			).Error(),
			err.Error(),
		)
		assert.Empty(t, cfg)
	})

	t.Run("when register function name is empty should return error", func(t *testing.T) {
		var err error

		err = os.Setenv(
			EnvironmentVariableGetUserByIdFunctionName,
			"getUserById",
		)
		require.NoError(t, err)

		cfg, err := ReadUserApiConfig()
		defer os.Clearenv()

		assert.Equal(t,
			errors.Errorf(
				EnvironmentVariableNotDefined,
				EnvironmentVariableRegisterFunctionName,
			).Error(),
			err.Error(),
		)
		assert.Empty(t, cfg)
	})

	t.Run("when login function name is empty should return error", func(t *testing.T) {
		var err error

		err = os.Setenv(
			EnvironmentVariableGetUserByIdFunctionName,
			"getUserById",
		)
		require.NoError(t, err)

		err = os.Setenv(
			EnvironmentVariableRegisterFunctionName,
			"register",
		)
		require.NoError(t, err)

		cfg, err := ReadUserApiConfig()
		defer os.Clearenv()

		assert.Equal(t,
			errors.Errorf(
				EnvironmentVariableNotDefined,
				EnvironmentVariableLoginFunctionName,
			).Error(),
			err.Error(),
		)
		assert.Empty(t, cfg)
	})

	t.Run("when GetAccessTokenByRefreshToken function name is empty should return error", func(t *testing.T) {
		var err error

		err = os.Setenv(
			EnvironmentVariableGetUserByIdFunctionName,
			"getUserById",
		)
		require.NoError(t, err)

		err = os.Setenv(
			EnvironmentVariableRegisterFunctionName,
			"register",
		)
		require.NoError(t, err)

		err = os.Setenv(
			EnvironmentVariableLoginFunctionName,
			"login",
		)
		require.NoError(t, err)

		cfg, err := ReadUserApiConfig()
		defer os.Clearenv()

		assert.Equal(t,
			errors.Errorf(
				EnvironmentVariableNotDefined,
				EnvironmentVariableGetAccessTokenByRefreshTokenFunctionName,
			).Error(),
			err.Error(),
		)
		assert.Empty(t, cfg)
	})

	t.Run("when updateUser function name is empty should return error", func(t *testing.T) {
		var err error

		err = os.Setenv(
			EnvironmentVariableGetUserByIdFunctionName,
			"getUserById",
		)
		require.NoError(t, err)

		err = os.Setenv(
			EnvironmentVariableRegisterFunctionName,
			"register",
		)
		require.NoError(t, err)

		err = os.Setenv(
			EnvironmentVariableLoginFunctionName,
			"login",
		)
		require.NoError(t, err)

		err = os.Setenv(
			EnvironmentVariableGetAccessTokenByRefreshTokenFunctionName,
			"GetAccessTokenByRefreshToken",
		)
		require.NoError(t, err)

		cfg, err := ReadUserApiConfig()
		defer os.Clearenv()

		assert.Equal(t,
			errors.Errorf(
				EnvironmentVariableNotDefined,
				EnvironmentVariableUpdateUserByIdFunctionName,
			).Error(),
			err.Error(),
		)
		assert.Empty(t, cfg)
	})
}

func TestReadJwtConfig(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		err := os.Setenv(EnvironmentVariableJwtPrivateKey, "privateKey")
		require.NoError(t, err)

		err = os.Setenv(EnvironmentVariableJwtPublicKey, "publicKey")
		require.NoError(t, err)

		cfg, err := ReadJwtConfig()
		defer os.Clearenv()

		assert.NoError(t, err)
		assert.Equal(t,
			&JwtConfig{
				PrivateKey: []byte("privateKey"),
				PublicKey:  []byte("publicKey"),
			},
			cfg,
		)
	})

	t.Run("empty jwt private key", func(t *testing.T) {
		cfg, err := ReadJwtConfig()
		defer os.Clearenv()

		assert.Empty(t, cfg)
		assert.Equal(t,
			errors.Errorf(
				EnvironmentVariableNotDefined,
				EnvironmentVariableJwtPrivateKey,
			).Error(),
			err.Error(),
		)
	})

	t.Run("empty jwt public key", func(t *testing.T) {
		err := os.Setenv(EnvironmentVariableJwtPrivateKey, "privateKey")
		require.NoError(t, err)

		cfg, err := ReadJwtConfig()
		defer os.Clearenv()

		assert.Empty(t, cfg)
		assert.Equal(t,
			errors.Errorf(
				EnvironmentVariableNotDefined,
				EnvironmentVariableJwtPublicKey,
			).Error(),
			err.Error(),
		)
	})
}
