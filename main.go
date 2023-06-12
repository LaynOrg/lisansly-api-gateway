package main

import (
	"os"
	"path/filepath"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/joho/godotenv"

	"api-gateway/pkg/config"
	"api-gateway/pkg/logger"
	"api-gateway/pkg/path"
	"api-gateway/pkg/server"
)

func main() {
	var err error
	log := logger.NewLogger()

	isAtRemote := os.Getenv(config.IsAtRemote)
	if isAtRemote == "" {
		rootDirectory := path.GetRootDirectory()
		dotenvPath := filepath.Join(rootDirectory, ".env")
		err = godotenv.Load(dotenvPath)
		if err != nil {
			log.Fatal(err)
		}
	}

	var cfg *config.Config
	cfg, err = config.ReadConfig()
	if err != nil {
		log.Fatal(err)
	}

	var handlers []server.Handler
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
			log.Fatal(err)
		}
	} else {
		lambda.Start(srv.LambdaProxyHandler)
	}
}
