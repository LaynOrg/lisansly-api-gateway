package user

import (
	"context"
	"fmt"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"api-gateway/pkg/aws_wrapper"
	"api-gateway/pkg/cerror"
	"api-gateway/pkg/config"
	"api-gateway/pkg/jwt_generator"
)

type Repository interface {
	Register(ctx context.Context, user *RegisterPayload) (*jwt_generator.Tokens, error)
	Login(ctx context.Context, user *LoginPayload) (*jwt_generator.Tokens, error)
	GetUserById(ctx context.Context, userId string) (*Document, error)
	GetAccessTokenViaRefreshToken(ctx context.Context, userId, refreshToken string) (string, error)
	UpdateUserById(ctx context.Context, userId string, user *UpdateUserPayload) (*jwt_generator.Tokens, error)
}

type repository struct {
	lambdaClient aws_wrapper.LambdaClient
	config       *config.Config
}

func NewRepository(lambdaClient aws_wrapper.LambdaClient, config *config.Config) Repository {
	return &repository{
		lambdaClient: lambdaClient,
		config:       config,
	}
}

func (r *repository) GetUserById(ctx context.Context, userId string) (*Document, error) {
	var err error

	var marshalledPayload []byte
	marshalledPayload, err = json.Marshal(map[string]string{
		"userId": userId,
	})

	var requestPayload []byte
	requestPayload, err = json.Marshal(events.APIGatewayProxyRequest{
		Body:            string(marshalledPayload),
		IsBase64Encoded: false,
	})
	if err != nil {
		cerr := cerror.ErrorMarshalling
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, cerr
	}

	lambdaFunctionName := r.config.FunctionNames.UserAPI[config.GetUserById]

	var response *lambda.InvokeOutput
	response, err = r.lambdaClient.Invoke(ctx, &lambda.InvokeInput{
		FunctionName:   aws.String(lambdaFunctionName),
		InvocationType: types.InvocationTypeRequestResponse,
		Payload:        requestPayload,
	})
	if err != nil {
		cerr := cerror.ErrorFunctionInvoke
		cerr.LogMessage = fmt.Sprintf(cerr.LogMessage, config.GetUserById)
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, cerr
	}

	statusCode := response.StatusCode
	if statusCode == fiber.StatusNotFound {
		return nil, &cerror.CustomError{
			HttpStatusCode: fiber.StatusNotFound,
			LogMessage:     "user not found",
			LogSeverity:    zapcore.ErrorLevel,
		}
	}

	if statusCode != fiber.StatusOK {
		return nil, &cerror.CustomError{
			HttpStatusCode: int(statusCode),
			LogMessage:     "user-api return error",
			LogSeverity:    zapcore.ErrorLevel,
		}
	}

	var user *Document
	err = json.Unmarshal(response.Payload, &user)
	if err != nil {
		cerr := cerror.ErrorUnmarshalling
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, cerr
	}

	return user, nil
}

func (r *repository) Register(ctx context.Context, user *RegisterPayload) (*jwt_generator.Tokens, error) {
	var err error

	var marshalledUser []byte
	marshalledUser, err = json.Marshal(user)
	if err != nil {
		cerr := cerror.ErrorMarshalling
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, cerr
	}

	var requestPayload []byte
	requestPayload, err = json.Marshal(events.APIGatewayProxyRequest{
		Body:            string(marshalledUser),
		IsBase64Encoded: false,
	})
	if err != nil {
		cerr := cerror.ErrorMarshalling
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, cerr
	}

	lambdaFunctionName := r.config.FunctionNames.UserAPI[config.Register]

	var response *lambda.InvokeOutput
	response, err = r.lambdaClient.Invoke(ctx, &lambda.InvokeInput{
		FunctionName:   aws.String(lambdaFunctionName),
		InvocationType: types.InvocationTypeRequestResponse,
		Payload:        requestPayload,
	})
	if err != nil {
		cerr := cerror.ErrorFunctionInvoke
		cerr.LogMessage = fmt.Sprintf(cerr.LogMessage, config.Register)
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, cerr
	}

	if response.StatusCode != fiber.StatusCreated {
		return nil, &cerror.CustomError{
			HttpStatusCode: int(response.StatusCode),
			LogMessage:     "user-api return error",
			LogSeverity:    zapcore.ErrorLevel,
		}
	}

	var tokens *jwt_generator.Tokens
	err = json.Unmarshal(response.Payload, &tokens)
	if err != nil {
		cerr := cerror.ErrorUnmarshalling
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, cerr
	}

	return tokens, nil
}

func (r *repository) Login(ctx context.Context, user *LoginPayload) (*jwt_generator.Tokens, error) {
	var err error

	var marshalledUser []byte
	marshalledUser, err = json.Marshal(user)
	if err != nil {
		cerr := cerror.ErrorMarshalling
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, cerr
	}

	var requestBody []byte
	requestBody, err = json.Marshal(events.APIGatewayProxyRequest{
		Body:            string(marshalledUser),
		IsBase64Encoded: false,
	})

	lambdaFunctionName := r.config.FunctionNames.UserAPI[config.Login]

	var response *lambda.InvokeOutput
	response, err = r.lambdaClient.Invoke(ctx, &lambda.InvokeInput{
		FunctionName:   aws.String(lambdaFunctionName),
		InvocationType: types.InvocationTypeRequestResponse,
		Payload:        requestBody,
	})
	if err != nil {
		cerr := cerror.ErrorFunctionInvoke
		cerr.LogMessage = fmt.Sprintf(cerr.LogMessage, config.Login)
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, cerr
	}

	if response.StatusCode != fiber.StatusOK {
		return nil, &cerror.CustomError{
			HttpStatusCode: int(response.StatusCode),
			LogMessage:     "user-api return error",
			LogSeverity:    zapcore.ErrorLevel,
		}
	}

	var tokens *jwt_generator.Tokens
	err = json.Unmarshal(response.Payload, &tokens)
	if err != nil {
		cerr := cerror.ErrorUnmarshalling
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, cerr
	}

	return tokens, nil
}

func (r *repository) GetAccessTokenViaRefreshToken(ctx context.Context, userId, refreshToken string) (string, error) {
	var err error

	var marshalledPayload []byte
	marshalledPayload, err = json.Marshal(map[string]string{
		"userId":       userId,
		"refreshToken": refreshToken,
	})
	if err != nil {
		cerr := cerror.ErrorUnmarshalling
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return "", cerr
	}

	var requestBody []byte
	requestBody, err = json.Marshal(events.APIGatewayProxyRequest{
		Body:            string(marshalledPayload),
		IsBase64Encoded: false,
	})
	if err != nil {
		cerr := cerror.ErrorUnmarshalling
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return "", cerr
	}

	lambdaFunctionName := r.config.FunctionNames.UserAPI[config.GetAccessTokenViaRefreshToken]

	var response *lambda.InvokeOutput
	response, err = r.lambdaClient.Invoke(ctx, &lambda.InvokeInput{
		FunctionName:   aws.String(lambdaFunctionName),
		InvocationType: types.InvocationTypeRequestResponse,
		Payload:        requestBody,
	})
	if err != nil {
		cerr := cerror.ErrorFunctionInvoke
		cerr.LogMessage = fmt.Sprintf(cerr.LogMessage, config.GetAccessTokenViaRefreshToken)
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return "", cerr
	}

	if response.StatusCode != fiber.StatusOK {
		return "", &cerror.CustomError{
			HttpStatusCode: int(response.StatusCode),
			LogMessage:     "user-api return error",
			LogSeverity:    zapcore.ErrorLevel,
		}
	}

	var tokens *jwt_generator.Tokens
	err = json.Unmarshal(response.Payload, &tokens)
	if err != nil {
		cerr := cerror.ErrorUnmarshalling
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return "", cerr
	}

	return tokens.AccessToken, nil
}

func (r *repository) UpdateUserById(
	ctx context.Context,
	userId string,
	user *UpdateUserPayload,
) (*jwt_generator.Tokens, error) {
	var err error

	var marshalledUpdateUserPayload []byte
	marshalledUpdateUserPayload, err = json.Marshal(map[string]any{
		"userId": userId,
		"user":   user,
	})
	if err != nil {
		cerr := cerror.ErrorMarshalling
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, cerr
	}

	var requestBody []byte
	requestBody, err = json.Marshal(events.APIGatewayProxyRequest{
		Body:            string(marshalledUpdateUserPayload),
		IsBase64Encoded: false,
	})
	if err != nil {
		cerr := cerror.ErrorMarshalling
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, cerr
	}

	lambdaFunctionName := r.config.FunctionNames.UserAPI[config.UpdateUserById]

	var response *lambda.InvokeOutput
	response, err = r.lambdaClient.Invoke(ctx, &lambda.InvokeInput{
		FunctionName:   aws.String(lambdaFunctionName),
		InvocationType: types.InvocationTypeRequestResponse,
		Payload:        requestBody,
	})
	if err != nil {
		cerr := cerror.ErrorFunctionInvoke
		cerr.LogMessage = fmt.Sprintf(cerr.LogMessage, config.UpdateUserById)
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, cerr
	}

	statusCode := response.StatusCode
	if statusCode == fiber.StatusConflict {
		return nil, &cerror.CustomError{
			HttpStatusCode: fiber.StatusConflict,
			LogMessage:     "user with this email already exists",
			LogSeverity:    zapcore.WarnLevel,
		}
	}

	if statusCode != fiber.StatusOK {
		return nil, &cerror.CustomError{
			HttpStatusCode: int(statusCode),
			LogMessage:     "user-api return error",
			LogSeverity:    zapcore.ErrorLevel,
		}
	}

	var tokens *jwt_generator.Tokens
	err = json.Unmarshal(response.Payload, &tokens)
	if err != nil {
		cerr := cerror.ErrorUnmarshalling
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, cerr
	}

	return tokens, nil
}
