//go:build unit

package server

import (
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestNewServer(t *testing.T) {
	logProd, err := zap.NewProduction()
	require.NoError(t, err)

	log := logProd.Sugar()
	defer log.Sync()

	srv := NewServer(log)

	assert.IsType(t, &fiber.App{}, srv)
}
