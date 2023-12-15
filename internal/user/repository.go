package user

import (
	"context"
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/goccy/go-json"
	"go.uber.org/zap"

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
	UpdateUserById(ctx context.Context, user *UpdateUserByIdPayload) (*jwt_generator.Tokens, error)
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

	var requestPayload []byte
	requestPayload, err = json.Marshal(GetUserByIdPayloadToUserAPI{
		UserId: userId,
	})
	if err != nil {
		cerr := cerror.ErrorMarshalling
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, cerr
	}

	lambdaFunctionName := r.config.FunctionNames.UserAPI[config.GetUserById]
	var invokeOutput *lambda.InvokeOutput
	invokeOutput, err = r.lambdaClient.Invoke(ctx, &lambda.InvokeInput{
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

	cerrFromLambda := cerror.LambdaFunctionErrorToCerror(invokeOutput)
	if cerrFromLambda != nil {
		statusCode := cerrFromLambda.HttpStatusCode
		if statusCode == http.StatusNotFound {
			return nil, &cerror.CustomError{
				HttpStatusCode: http.StatusNotFound,
				LogMessage:     "user not found",
				LogSeverity:    zap.ErrorLevel,
			}
		}

		if statusCode != http.StatusOK {
			return nil, &cerror.CustomError{
				HttpStatusCode: cerrFromLambda.HttpStatusCode,
				LogMessage:     "user-service return error",
				LogSeverity:    zap.ErrorLevel,
			}
		}
	}

	var user *Document
	err = json.Unmarshal(invokeOutput.Payload, &user)
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

	var requestPayload []byte
	requestPayload, err = json.Marshal(user)
	if err != nil {
		cerr := cerror.ErrorMarshalling
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, cerr
	}

	lambdaFunctionName := r.config.FunctionNames.UserAPI[config.Register]
	var invokeOutput *lambda.InvokeOutput
	invokeOutput, err = r.lambdaClient.Invoke(ctx, &lambda.InvokeInput{
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

	cerrFromLambda := cerror.LambdaFunctionErrorToCerror(invokeOutput)
	if cerrFromLambda != nil {
		statusCode := cerrFromLambda.HttpStatusCode
		if statusCode == http.StatusConflict {
			return nil, &cerror.CustomError{
				HttpStatusCode: http.StatusConflict,
				LogMessage:     "user already exist",
				LogSeverity:    zap.WarnLevel,
			}
		}

		if statusCode != http.StatusCreated {
			return nil, &cerror.CustomError{
				HttpStatusCode: cerrFromLambda.HttpStatusCode,
				LogMessage:     "user-service return error",
				LogSeverity:    zap.ErrorLevel,
			}
		}
	}

	var tokens *jwt_generator.Tokens
	err = json.Unmarshal(invokeOutput.Payload, &tokens)
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

	var requestBody []byte
	requestBody, err = json.Marshal(user)
	if err != nil {
		cerr := cerror.ErrorMarshalling
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, cerr
	}

	lambdaFunctionName := r.config.FunctionNames.UserAPI[config.Login]
	var invokeOutput *lambda.InvokeOutput
	invokeOutput, err = r.lambdaClient.Invoke(ctx, &lambda.InvokeInput{
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

	cerrFromLambda := cerror.LambdaFunctionErrorToCerror(invokeOutput)
	if cerrFromLambda != nil {
		statusCode := cerrFromLambda.HttpStatusCode
		if statusCode == http.StatusUnauthorized {
			return nil, &cerror.CustomError{
				HttpStatusCode: http.StatusUnauthorized,
				LogMessage:     "credentials is invalid",
				LogSeverity:    zap.WarnLevel,
			}
		}

		if statusCode != http.StatusOK {
			return nil, &cerror.CustomError{
				HttpStatusCode: cerrFromLambda.HttpStatusCode,
				LogMessage:     "user-service return error",
				LogSeverity:    zap.ErrorLevel,
			}
		}
	}

	var tokens *jwt_generator.Tokens
	err = json.Unmarshal(invokeOutput.Payload, &tokens)
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

	var requestBody []byte
	requestBody, err = json.Marshal(map[string]string{
		"userId":       userId,
		"refreshToken": refreshToken,
	})
	if err != nil {
		cerr := cerror.ErrorMarshalling
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return "", cerr
	}

	lambdaFunctionName := r.config.FunctionNames.UserAPI[config.GetAccessTokenViaRefreshToken]
	var invokeOutput *lambda.InvokeOutput
	invokeOutput, err = r.lambdaClient.Invoke(ctx, &lambda.InvokeInput{
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

	cerrFromLambda := cerror.LambdaFunctionErrorToCerror(invokeOutput)
	if cerrFromLambda != nil {
		statusCode := cerrFromLambda.HttpStatusCode
		if statusCode == http.StatusForbidden {
			return "", &cerror.CustomError{
				HttpStatusCode: http.StatusForbidden,
				LogMessage:     "refresh token expired",
				LogSeverity:    zap.WarnLevel,
			}
		}

		if statusCode != http.StatusOK {
			return "", &cerror.CustomError{
				HttpStatusCode: cerrFromLambda.HttpStatusCode,
				LogMessage:     "user-service return error",
				LogSeverity:    zap.ErrorLevel,
			}
		}
	}

	var tokens *jwt_generator.Tokens
	err = json.Unmarshal(invokeOutput.Payload, &tokens)
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
	user *UpdateUserByIdPayload,
) (*jwt_generator.Tokens, error) {
	var err error

	var requestBody []byte
	requestBody, err = json.Marshal(user)
	if err != nil {
		cerr := cerror.ErrorMarshalling
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, cerr
	}

	lambdaFunctionName := r.config.FunctionNames.UserAPI[config.UpdateUserById]
	var invokeOutput *lambda.InvokeOutput
	invokeOutput, err = r.lambdaClient.Invoke(ctx, &lambda.InvokeInput{
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

	cerrFromLambda := cerror.LambdaFunctionErrorToCerror(invokeOutput)
	if cerrFromLambda != nil {
		statusCode := cerrFromLambda.HttpStatusCode
		if statusCode == http.StatusConflict {
			return nil, &cerror.CustomError{
				HttpStatusCode: http.StatusConflict,
				LogMessage:     "user with this email already exists",
				LogSeverity:    zap.WarnLevel,
			}
		}

		if statusCode != http.StatusOK {
			return nil, &cerror.CustomError{
				HttpStatusCode: cerrFromLambda.HttpStatusCode,
				LogMessage:     "user-service return error",
				LogSeverity:    zap.ErrorLevel,
			}
		}
	}

	var tokens *jwt_generator.Tokens
	err = json.Unmarshal(invokeOutput.Payload, &tokens)
	if err != nil {
		cerr := cerror.ErrorUnmarshalling
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, cerr
	}

	return tokens, nil
}
