package cerror

import (
	"github.com/gofiber/fiber/v2"
	"go.uber.org/zap/zapcore"
)

var (
	ErrorBadRequest = &CustomError{
		HttpStatusCode: fiber.StatusBadRequest,
		LogMessage:     "malformed request body or query parameter",
		LogSeverity:    zapcore.WarnLevel,
	}
)
