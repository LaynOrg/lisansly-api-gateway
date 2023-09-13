package server

import (
	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"go.uber.org/zap"

	"api-gateway/pkg/cerror"
	"api-gateway/pkg/logger"
)

func NewServer(log *zap.SugaredLogger) *fiber.App {
	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
		JSONEncoder:           json.Marshal,
		JSONDecoder:           json.Unmarshal,
		ErrorHandler:          cerror.Middleware,
	})
	app.Use(cors.New())
	app.Use(logger.Middleware(log))

	return app
}
