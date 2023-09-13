package server

import (
	"context"

	"github.com/aws/aws-lambda-go/events"
	fiberadapter "github.com/awslabs/aws-lambda-go-api-proxy/fiber"
)

type lambdaProxyHandler func(
	ctx context.Context,
	req events.APIGatewayProxyRequest,
) (
	events.APIGatewayProxyResponse,
	error,
)

func LambdaProxyHandler(lambdaAdapter *fiberadapter.FiberLambda) lambdaProxyHandler {
	return func(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
		return lambdaAdapter.ProxyWithContext(ctx, req)
	}
}
