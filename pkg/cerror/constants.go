package cerror

import (
	"github.com/gofiber/fiber/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	ErrorBadRequest = &CustomError{
		HttpStatusCode: fiber.StatusBadRequest,
		LogMessage:     "malformed request body or query parameter",
		LogSeverity:    zapcore.WarnLevel,
	}

	ErrorMarshalling = &CustomError{
		HttpStatusCode: fiber.StatusInternalServerError,
		LogMessage:     "error occurred while marshalling request body",
		LogSeverity:    zap.ErrorLevel,
	}

	ErrorUnmarshalling = &CustomError{
		HttpStatusCode: fiber.StatusInternalServerError,
		LogMessage:     "error occurred while unmarshalling response body",
		LogSeverity:    zap.ErrorLevel,
	}

	ErrorFunctionInvoke = &CustomError{
		HttpStatusCode: fiber.StatusInternalServerError,
		LogMessage:     "error occurred while invoke %s function",
		LogSeverity:    zap.ErrorLevel,
	}
)
