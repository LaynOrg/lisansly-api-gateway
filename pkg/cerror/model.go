package cerror

import "go.uber.org/zap/zapcore"

type CustomError struct {
	error          `json:"-"`
	HttpStatusCode int             `json:"httpStatus"`
	LogMessage     string          `json:"-"`
	LogSeverity    zapcore.Level   `json:"-"`
	LogFields      []zapcore.Field `json:"-"`
}

const (
	ErrorTypeUnhandled string = "Unhandled"
)

type LambdaFunctionErrorPayload struct {
	ErrorMessage string `json:"errorMessage"`
	ErrorType    string `json:"errorType"`
}
