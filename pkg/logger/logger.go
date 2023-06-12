package logger

import (
	"go.uber.org/zap"
)

type Logger interface {
	Desugar() *zap.Logger
	With(args ...any) *zap.SugaredLogger
	WithOptions(opts ...zap.Option) *zap.SugaredLogger

	Error(args ...any)
	Info(args ...any)
	Warn(args ...any)
	Fatal(args ...any)
}

type logger struct {
	*zap.SugaredLogger
}

func NewLogger() Logger {
	log, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}
	_ = log.Sync()

	return &logger{
		log.Sugar(),
	}
}
