package cerror

import (
	"fmt"

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

func ErrorApiReturnError(apiName string, statusCode int) *CustomError {
	return &CustomError{
		HttpStatusCode: statusCode,

		LogMessage:  fmt.Sprintf("error occurred while calling %s", apiName),
		LogSeverity: zapcore.ErrorLevel,
	}
}
