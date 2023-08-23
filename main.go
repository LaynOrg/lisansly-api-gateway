package main

import (
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/joho/godotenv"
	"go.uber.org/zap"

	"api-gateway/internal/user"
	"api-gateway/pkg/config"
	"api-gateway/pkg/jwt_generator"
	"api-gateway/pkg/logger"
	"api-gateway/pkg/server"
)

func main() {
	var err error

	logWithProductionConfig, _ := zap.NewProduction()
	log := logWithProductionConfig.Sugar()
	defer func(l *zap.Logger) {
		err := l.Sync()
		if err != nil {
			panic(err)
		}
	}(logWithProductionConfig)

	isAtRemote := os.Getenv(config.IsAtRemote)
	if isAtRemote == "" {
		err = godotenv.Load()
		if err != nil {
			panic(err)
		}
	}

	var cfg *config.Config
	cfg, err = config.ReadConfig()
	if err != nil {
		panic(err)
	}
	cfg.Print()

	var handlers []server.Handler

	var jwtGenerator jwt_generator.JwtGenerator
	jwtGenerator, err = jwt_generator.NewJwtGenerator(cfg.Jwt)
	if err != nil {
		panic(err)
	}

	userRepository := user.NewRepository(cfg)
	userService := user.NewService(jwtGenerator, userRepository)
	userHandler := user.NewHandler(userService, userRepository)

	handlers = append(handlers, userHandler)

	srv := server.NewServer(cfg, handlers)

	app := srv.GetFiberInstance()
	app.Use(cors.New())
	app.Use(logger.Middleware(log))
	app.Get("/health", func(ctx *fiber.Ctx) error {
		return ctx.Status(fiber.StatusOK).SendString("OK")
	})

	srv.RegisterRoutes()

	if isAtRemote == "" {
		err = srv.Start()
		if err != nil {
			panic(err)
		}
	} else {
		lambda.Start(srv.LambdaProxyHandler)
	}
}
