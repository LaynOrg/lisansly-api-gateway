package cerror

import (
	"errors"

	"github.com/gofiber/fiber/v2"
	"go.uber.org/zap"

	"api-gateway/pkg/logger"
)

const StackSkipAmount = 7

func Middleware(ctx *fiber.Ctx, err error) error {
	var cerr *CustomError
	ok := errors.As(err, &cerr)
	if !ok {
		var fiberError *fiber.Error
		errors.As(err, &fiberError)
		return ctx.SendStatus(fiberError.Code)
	}

	log := logger.FromContext(ctx.Context()).Desugar()
	if len(cerr.LogFields) > 0 {
		for _, field := range cerr.LogFields {
			log = log.With(field)
		}
	}
	log.WithOptions(
		zap.WithCaller(false),
		zap.AddCallerSkip(StackSkipAmount),
	).Log(cerr.LogSeverity, cerr.LogMessage)

	return ctx.SendStatus(cerr.HttpStatusCode)
}
