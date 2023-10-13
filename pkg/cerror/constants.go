package cerror

import (
	"net/http"

	"go.uber.org/zap/zapcore"
)

var (
	ErrorBadRequest = &CustomError{
		HttpStatusCode: http.StatusBadRequest,
		LogMessage:     "malformed request body or query parameter",
		LogSeverity:    zapcore.WarnLevel,
	}

	ErrorMarshalling = &CustomError{
		HttpStatusCode: http.StatusInternalServerError,
		LogMessage:     "error occurred while marshalling request body",
		LogSeverity:    zapcore.ErrorLevel,
	}

	ErrorUnmarshalling = &CustomError{
		HttpStatusCode: http.StatusInternalServerError,
		LogMessage:     "error occurred while unmarshalling response body",
		LogSeverity:    zapcore.ErrorLevel,
	}

	ErrorFunctionInvoke = &CustomError{
		HttpStatusCode: http.StatusInternalServerError,
		LogMessage:     "error occurred while invoke %s function",
		LogSeverity:    zapcore.ErrorLevel,
	}
)
