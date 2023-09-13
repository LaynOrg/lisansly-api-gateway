package main

import (
	"context"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	lambdaClient "github.com/aws/aws-sdk-go-v2/service/lambda"
	fiberadapter "github.com/awslabs/aws-lambda-go-api-proxy/fiber"
	"go.uber.org/zap"

	"api-gateway/internal/user"
	"api-gateway/pkg/config"
	"api-gateway/pkg/jwt_generator"
	"api-gateway/pkg/server"
)

func main() {
	var err error

	logProd, err := zap.NewProduction()
	log := logProd.Sugar()
	defer func(log *zap.SugaredLogger) {
		err := log.Sync()
		if err != nil {
			panic(err)
		}
	}(log)

	var awsSdkConfig aws.Config
	awsSdkConfig, err = awsConfig.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Panic(err)
	}

	var cfg *config.Config
	cfg, err = config.ReadConfig()
	if err != nil {
		log.Panic(err)
	}

	lClient := lambdaClient.NewFromConfig(awsSdkConfig)
	userRepository := user.NewRepository(lClient, cfg)

	var jwtGenerator jwt_generator.JwtGenerator
	jwtGenerator, err = jwt_generator.NewJwtGenerator(cfg.Jwt)
	if err != nil {
		log.Panic(err)
	}

	service := user.NewService(jwtGenerator, userRepository)
	handler := user.NewHandler(service, userRepository)

	srv := server.NewServer(log)
	srv.Get(
		"/user/refreshToken/:refreshToken",
		handler.AuthenticationMiddleware,
		handler.GetAccessTokenViaRefreshToken,
	)

	lambdaAdapter := fiberadapter.New(srv)
	lambda.Start(server.LambdaProxyHandler(lambdaAdapter))
}
