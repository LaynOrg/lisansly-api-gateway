package server

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/aws/aws-lambda-go/events"
	fiberadapter "github.com/awslabs/aws-lambda-go-api-proxy/fiber"
	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"

	"api-gateway/pkg/cerror"
	"api-gateway/pkg/config"
)

type Handler interface {
	RegisterRoutes(app *fiber.App)
}

type Server interface {
	GetFiberInstance() *fiber.App
	Start() error
	Shutdown() error
	RegisterRoutes()
	LambdaProxyHandler(
		ctx context.Context,
		req events.APIGatewayProxyRequest,
	) (events.APIGatewayProxyResponse, error)
}

type server struct {
	serverPort         string
	fiber              *fiber.App
	handlers           []Handler
	fiberLambdaAdapter *fiberadapter.FiberLambda
}

func NewServer(config *config.Config, handlers []Handler) Server {
	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
		JSONEncoder:           json.Marshal,
		JSONDecoder:           json.Unmarshal,
		ErrorHandler:          cerror.Middleware,
	})
	serverPort := config.ServerPort
	fiberLambdaAdapter := fiberadapter.New(app)

	return &server{
		serverPort:         serverPort,
		fiber:              app,
		handlers:           handlers,
		fiberLambdaAdapter: fiberLambdaAdapter,
	}
}

func (server *server) Start() error {
	shutdownChannel := make(chan os.Signal, 1)
	signal.Notify(shutdownChannel, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-shutdownChannel
		_ = server.fiber.Shutdown()
	}()

	serverAddress := fmt.Sprintf(":%s", server.serverPort)
	return server.fiber.Listen(serverAddress)
}

func (server *server) Shutdown() error {
	return server.fiber.Shutdown()
}

func (server *server) GetFiberInstance() *fiber.App {
	return server.fiber
}

func (server *server) RegisterRoutes() {
	handlersLength := len(server.handlers)
	if handlersLength > 0 {
		for _, handler := range server.handlers {
			handler.RegisterRoutes(server.fiber)
		}
	} else {
		panic("no handlers is registered")
	}
}

func (server *server) LambdaProxyHandler(
	ctx context.Context,
	req events.APIGatewayProxyRequest,
) (events.APIGatewayProxyResponse, error) {
	return server.fiberLambdaAdapter.ProxyWithContext(ctx, req)
}
