package server

import (
	"testing"

	fiberadapter "github.com/awslabs/aws-lambda-go-api-proxy/fiber"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
)

func TestLambdaProxyHandler(t *testing.T) {
	app := fiber.New()
	lambdaAdapter := fiberadapter.New(app)
	out := LambdaProxyHandler(lambdaAdapter)

	assert.NotNil(t, out)
	assert.IsType(t, (lambdaProxyHandler)(nil), out)
}
