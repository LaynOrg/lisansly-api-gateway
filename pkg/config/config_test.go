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
		err := os.Setenv(ServerPort, "8080")
		require.NoError(t, err)

		err = os.Setenv(UserApiUrl, "http://localhost:8081")
		require.NoError(t, err)

		err = os.Setenv(JwtPrivateKey, "privateKey")
		require.NoError(t, err)

		err = os.Setenv(JwtPublicKey, "publicKey")
		require.NoError(t, err)

		cfg, err := ReadConfig()
		defer os.Clearenv()

		assert.NoError(t, err)
		assert.IsType(t, &Config{}, cfg)
	})

	t.Run("empty server port", func(t *testing.T) {
		cfg, err := ReadConfig()

		assert.Empty(t, cfg)
		assert.Equal(t, err.Error(), errors.Errorf(EnvironmentVariableNotDefined, ServerPort).Error())
	})

	t.Run("empty user api url", func(t *testing.T) {
		err := os.Setenv(ServerPort, "8080")
		require.NoError(t, err)

		cfg, err := ReadConfig()
		defer os.Clearenv()

		assert.Empty(t, cfg)
		assert.Equal(t, err.Error(), errors.Errorf(EnvironmentVariableNotDefined, UserApiUrl).Error())
	})
}

func TestReadJwtConfig(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		err := os.Setenv(JwtPrivateKey, "privateKey")
		require.NoError(t, err)

		err = os.Setenv(JwtPublicKey, "publicKey")
		require.NoError(t, err)

		cfg, err := ReadJwtConfig()
		defer os.Clearenv()

		assert.NoError(t, err)
		assert.IsType(t, &JwtConfig{}, cfg)
	})

	t.Run("empty jwt private key", func(t *testing.T) {
		cfg, err := ReadJwtConfig()
		defer os.Clearenv()

		assert.Empty(t, cfg)
		assert.Equal(t, err.Error(), errors.Errorf(EnvironmentVariableNotDefined, JwtPrivateKey).Error())
	})

	t.Run("empty jwt public key", func(t *testing.T) {
		err := os.Setenv(JwtPrivateKey, "privateKey")
		require.NoError(t, err)

		cfg, err := ReadJwtConfig()
		defer os.Clearenv()

		assert.Empty(t, cfg)
		assert.Equal(t, err.Error(), errors.Errorf(EnvironmentVariableNotDefined, JwtPublicKey).Error())
	})
}
