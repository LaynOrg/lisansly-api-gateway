//go:build unit

package user

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"api-gateway/pkg/aws_wrapper"
	"api-gateway/pkg/cerror"
	"api-gateway/pkg/config"
	"api-gateway/pkg/jwt_generator"
)

const (
	TestUserName                                  = "lynicis"
	TestUserEmail                                 = "test@test.com"
	TestUserPassword                              = "Asdf12345_"
	TestToken                                     = "abcd.abcd.abcd"
	TestRegisterFunctionName                      = "register-func-name"
	TestLoginFunctionName                         = "login-func-name"
	TestGetUserByIdFunctionName                   = "get-user-by-id-func-name"
	TestGetAccessTokenViaRefreshTokenFunctionName = "get-access-token-via-refresh-token"
	TestUpdateUserByIdFunctionName                = "update-user-by-id-func-name"
)

var (
	TestTokensPayload = &jwt_generator.Tokens{
		AccessToken:  TestToken,
		RefreshToken: TestToken,
	}
)

func TestNewRepository(t *testing.T) {
	userRepository := NewRepository(nil, nil)
	assert.Implements(t, (*Repository)(nil), userRepository)
}

func TestRepository_Register(t *testing.T) {
	testRegisterPayload := &RegisterPayload{
		Name:     TestUserName,
		Email:    TestUserEmail,
		Password: TestUserPassword,
	}

	mockController := gomock.NewController(t)
	defer mockController.Finish()

	t.Run("happy path", func(t *testing.T) {
		ctx := context.Background()

		requestBody, err := json.Marshal(testRegisterPayload)
		require.NoError(t, err)

		responseBody, err := json.Marshal(TestTokensPayload)
		require.NoError(t, err)

		mockLambdaClient := aws_wrapper.NewMockLambdaClient(mockController)
		mockLambdaClient.
			EXPECT().
			Invoke(ctx, &lambda.InvokeInput{
				FunctionName:   aws.String(TestRegisterFunctionName),
				InvocationType: types.InvocationTypeRequestResponse,
				Payload:        requestBody,
			}).
			Return(
				&lambda.InvokeOutput{
					Payload:    responseBody,
					StatusCode: http.StatusCreated,
				},
				nil,
			)

		repository := NewRepository(mockLambdaClient, &config.Config{
			FunctionNames: &config.FunctionNames{
				UserAPI: map[config.UserApiFunctionNames]string{
					config.Register: TestRegisterFunctionName,
				},
			},
		})

		tokens, cerr := repository.Register(ctx, testRegisterPayload)

		assert.NoError(t, cerr)
		assert.Equal(t, TestTokensPayload, tokens)
	})

	t.Run("when user api return error should return it", func(t *testing.T) {
		ctx := context.Background()

		requestBody, err := json.Marshal(testRegisterPayload)
		require.NoError(t, err)

		mockLambdaClient := aws_wrapper.NewMockLambdaClient(mockController)
		mockLambdaClient.
			EXPECT().
			Invoke(ctx, &lambda.InvokeInput{
				FunctionName:   aws.String(TestRegisterFunctionName),
				InvocationType: types.InvocationTypeRequestResponse,
				Payload:        requestBody,
			}).
			Return(
				nil,
				errors.New("test error"),
			)

		repository := NewRepository(mockLambdaClient, &config.Config{
			FunctionNames: &config.FunctionNames{
				UserAPI: map[config.UserApiFunctionNames]string{
					config.Register: TestRegisterFunctionName,
				},
			},
		})

		tokens, cerr := repository.Register(ctx, testRegisterPayload)

		assert.Error(t, cerr)
		assert.Equal(t, http.StatusInternalServerError, cerr.(*cerror.CustomError).HttpStatusCode)
		assert.Empty(t, tokens)
	})

	t.Run("when user api can't handle requests should return it", func(t *testing.T) {
		ctx := context.Background()

		requestBody, err := json.Marshal(testRegisterPayload)
		require.NoError(t, err)

		mockLambdaClient := aws_wrapper.NewMockLambdaClient(mockController)
		mockLambdaClient.
			EXPECT().
			Invoke(ctx, &lambda.InvokeInput{
				FunctionName:   aws.String(TestRegisterFunctionName),
				InvocationType: types.InvocationTypeRequestResponse,
				Payload:        requestBody,
			}).
			Return(
				nil,
				errors.New("test error"),
			)

		repository := NewRepository(mockLambdaClient, &config.Config{
			FunctionNames: &config.FunctionNames{
				UserAPI: map[config.UserApiFunctionNames]string{
					config.Register: TestRegisterFunctionName,
				},
			},
		})

		tokens, cerr := repository.Register(ctx, testRegisterPayload)

		assert.Error(t, cerr)
		assert.Equal(t,
			http.StatusInternalServerError,
			cerr.(*cerror.CustomError).HttpStatusCode,
		)
		assert.Nil(t, tokens)
	})

	t.Run("when user api return ambiguous status code should return error", func(t *testing.T) {
		ctx := context.Background()

		requestBody, err := json.Marshal(testRegisterPayload)
		require.NoError(t, err)

		mockLambdaClient := aws_wrapper.NewMockLambdaClient(mockController)
		mockLambdaClient.
			EXPECT().
			Invoke(ctx, &lambda.InvokeInput{
				FunctionName:   aws.String(TestRegisterFunctionName),
				InvocationType: types.InvocationTypeRequestResponse,
				Payload:        requestBody,
			}).
			Return(
				&lambda.InvokeOutput{
					StatusCode: http.StatusNotFound,
				},
				nil,
			)

		repository := NewRepository(mockLambdaClient, &config.Config{
			FunctionNames: &config.FunctionNames{
				UserAPI: map[config.UserApiFunctionNames]string{
					config.Register: TestRegisterFunctionName,
				},
			},
		})

		tokens, cerr := repository.Register(ctx, testRegisterPayload)

		assert.Error(t, cerr)
		assert.Equal(t,
			&cerror.CustomError{
				HttpStatusCode: http.StatusNotFound,
				LogMessage:     "user-api return error",
				LogSeverity:    zapcore.ErrorLevel,
			},
			cerr,
		)
		assert.Empty(t, tokens)
	})

	t.Run("when user api return ambiguous response payload should return error", func(t *testing.T) {
		ctx := context.Background()

		requestBody, err := json.Marshal(testRegisterPayload)
		require.NoError(t, err)

		mockLambdaClient := aws_wrapper.NewMockLambdaClient(mockController)
		mockLambdaClient.
			EXPECT().
			Invoke(ctx, &lambda.InvokeInput{
				FunctionName:   aws.String(TestRegisterFunctionName),
				InvocationType: types.InvocationTypeRequestResponse,
				Payload:        requestBody,
			}).
			Return(
				&lambda.InvokeOutput{
					Payload:    []byte("{'key':"),
					StatusCode: http.StatusCreated,
				},
				nil,
			)

		repository := NewRepository(mockLambdaClient, &config.Config{
			FunctionNames: &config.FunctionNames{
				UserAPI: map[config.UserApiFunctionNames]string{
					config.Register: TestRegisterFunctionName,
				},
			},
		})

		tokens, cerr := repository.Register(ctx, testRegisterPayload)

		assert.Error(t, cerr)
		assert.Equal(t,
			http.StatusInternalServerError,
			cerr.(*cerror.CustomError).HttpStatusCode,
		)
		assert.Nil(t, tokens)
	})
}

func TestRepository_Login(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()

	t.Run("happy path", func(t *testing.T) {
		requestPayload, err := json.Marshal(&LoginPayload{
			Email:    TestUserEmail,
			Password: TestUserPassword,
		})
		require.NoError(t, err)

		responsePayload, err := json.Marshal(&jwt_generator.Tokens{
			AccessToken:  TestToken,
			RefreshToken: TestToken,
		})
		require.NoError(t, err)

		ctx := context.Background()
		mockLambdaClient := aws_wrapper.NewMockLambdaClient(mockController)
		mockLambdaClient.
			EXPECT().
			Invoke(
				ctx, &lambda.InvokeInput{
					FunctionName:   aws.String(TestLoginFunctionName),
					InvocationType: types.InvocationTypeRequestResponse,
					Payload:        requestPayload,
				},
			).
			Return(
				&lambda.InvokeOutput{
					Payload:    responsePayload,
					StatusCode: http.StatusOK,
				},
				nil,
			)

		repository := NewRepository(mockLambdaClient, &config.Config{
			FunctionNames: &config.FunctionNames{
				UserAPI: map[config.UserApiFunctionNames]string{
					config.Login: TestLoginFunctionName,
				},
			},
		})

		tokens, cerr := repository.Login(ctx, &LoginPayload{
			Email:    TestUserEmail,
			Password: TestUserPassword,
		})

		assert.Equal(t, TestTokensPayload, tokens)
		assert.NoError(t, cerr)
	})

	t.Run("when user api can't handle requests return it", func(t *testing.T) {
		requestPayload, err := json.Marshal(&LoginPayload{
			Email:    TestUserEmail,
			Password: TestUserPassword,
		})
		require.NoError(t, err)

		ctx := context.Background()
		mockLambdaClient := aws_wrapper.NewMockLambdaClient(mockController)
		mockLambdaClient.
			EXPECT().
			Invoke(
				ctx, &lambda.InvokeInput{
					FunctionName:   aws.String(TestLoginFunctionName),
					InvocationType: types.InvocationTypeRequestResponse,
					Payload:        requestPayload,
				},
			).
			Return(
				nil,
				errors.New("test error"),
			)

		repository := NewRepository(mockLambdaClient, &config.Config{
			FunctionNames: &config.FunctionNames{
				UserAPI: map[config.UserApiFunctionNames]string{
					config.Login: TestLoginFunctionName,
				},
			},
		})

		tokens, cerr := repository.Login(ctx, &LoginPayload{
			Email:    TestUserEmail,
			Password: TestUserPassword,
		})

		assert.Error(t, cerr)
		assert.Equal(t,
			http.StatusInternalServerError,
			cerr.(*cerror.CustomError).HttpStatusCode,
		)
		assert.Nil(t, tokens)
	})

	t.Run("when user api return ambiguous status should return error", func(t *testing.T) {
		requestPayload, err := json.Marshal(&LoginPayload{
			Email:    TestUserEmail,
			Password: TestUserPassword,
		})
		require.NoError(t, err)

		ctx := context.Background()
		mockLambdaClient := aws_wrapper.NewMockLambdaClient(mockController)
		mockLambdaClient.
			EXPECT().
			Invoke(
				ctx, &lambda.InvokeInput{
					FunctionName:   aws.String(TestLoginFunctionName),
					InvocationType: types.InvocationTypeRequestResponse,
					Payload:        requestPayload,
				},
			).
			Return(
				&lambda.InvokeOutput{
					StatusCode: http.StatusUnauthorized,
				},
				nil,
			)

		repository := NewRepository(mockLambdaClient, &config.Config{
			FunctionNames: &config.FunctionNames{
				UserAPI: map[config.UserApiFunctionNames]string{
					config.Login: TestLoginFunctionName,
				},
			},
		})

		tokens, cerr := repository.Login(ctx, &LoginPayload{
			Email:    TestUserEmail,
			Password: TestUserPassword,
		})

		assert.Error(t, cerr)
		assert.Equal(t,
			http.StatusUnauthorized,
			cerr.(*cerror.CustomError).HttpStatusCode,
		)
		assert.Nil(t, tokens)
	})

	t.Run("when user api return ambiguous response payload should return error", func(t *testing.T) {
		requestPayload, err := json.Marshal(&LoginPayload{
			Email:    TestUserEmail,
			Password: TestUserPassword,
		})
		require.NoError(t, err)

		ctx := context.Background()
		mockLambdaClient := aws_wrapper.NewMockLambdaClient(mockController)
		mockLambdaClient.
			EXPECT().
			Invoke(
				ctx, &lambda.InvokeInput{
					FunctionName:   aws.String(TestLoginFunctionName),
					InvocationType: types.InvocationTypeRequestResponse,
					Payload:        requestPayload,
				},
			).
			Return(
				&lambda.InvokeOutput{
					Payload:    []byte(`{"key":`),
					StatusCode: http.StatusOK,
				},
				nil,
			)

		repository := NewRepository(mockLambdaClient, &config.Config{
			FunctionNames: &config.FunctionNames{
				UserAPI: map[config.UserApiFunctionNames]string{
					config.Login: TestLoginFunctionName,
				},
			},
		})

		tokens, cerr := repository.Login(ctx, &LoginPayload{
			Email:    TestUserEmail,
			Password: TestUserPassword,
		})

		assert.Error(t, cerr)
		assert.Equal(t,
			http.StatusInternalServerError,
			cerr.(*cerror.CustomError).HttpStatusCode,
		)
		assert.Nil(t, tokens)
	})
}

func TestRepository_GetUserById(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()

	t.Run("happy path", func(t *testing.T) {
		requestBody, err := json.Marshal(map[string]any{
			"userId": TestUserId,
		})
		require.NoError(t, err)

		now := time.Now().UTC()
		response, err := json.Marshal(&Document{
			Id:        TestUserId,
			Name:      TestUserName,
			Email:     TestUserEmail,
			Password:  TestUserPassword,
			Role:      RoleUser,
			CreatedAt: now,
		})
		require.NoError(t, err)

		ctx := context.Background()
		mockLambdaClient := aws_wrapper.NewMockLambdaClient(mockController)
		mockLambdaClient.
			EXPECT().
			Invoke(ctx, &lambda.InvokeInput{
				FunctionName:   aws.String(TestGetUserByIdFunctionName),
				InvocationType: types.InvocationTypeRequestResponse,
				Payload:        requestBody,
			}).
			Return(
				&lambda.InvokeOutput{
					Payload:    response,
					StatusCode: http.StatusOK,
				},
				nil,
			)

		repository := NewRepository(mockLambdaClient, &config.Config{
			FunctionNames: &config.FunctionNames{
				UserAPI: map[config.UserApiFunctionNames]string{
					config.GetUserById: TestGetUserByIdFunctionName,
				},
			},
		})
		user, cerr := repository.GetUserById(ctx, TestUserId)

		assert.NoError(t, cerr)
		assert.Equal(t,
			&Document{
				Id:        TestUserId,
				Name:      TestUserName,
				Email:     TestUserEmail,
				Password:  TestUserPassword,
				Role:      RoleUser,
				CreatedAt: now,
			},
			user,
		)
	})

	t.Run("when user api can't handle request should return error", func(t *testing.T) {
		requestBody, err := json.Marshal(map[string]any{
			"userId": TestUserId,
		})
		require.NoError(t, err)

		ctx := context.Background()
		mockLambdaClient := aws_wrapper.NewMockLambdaClient(mockController)
		mockLambdaClient.
			EXPECT().
			Invoke(ctx, &lambda.InvokeInput{
				FunctionName:   aws.String(TestGetUserByIdFunctionName),
				InvocationType: types.InvocationTypeRequestResponse,
				Payload:        requestBody,
			}).
			Return(
				nil,
				errors.New("test error"),
			)

		repository := NewRepository(mockLambdaClient, &config.Config{
			FunctionNames: &config.FunctionNames{
				UserAPI: map[config.UserApiFunctionNames]string{
					config.GetUserById: TestGetUserByIdFunctionName,
				},
			},
		})
		user, cerr := repository.GetUserById(ctx, TestUserId)

		assert.Error(t, cerr)
		assert.Equal(t,
			http.StatusInternalServerError,
			cerr.(*cerror.CustomError).HttpStatusCode,
		)
		assert.Nil(t, user)
	})

	t.Run("when user api return user not found should return error", func(t *testing.T) {
		requestBody, err := json.Marshal(map[string]any{
			"userId": TestUserId,
		})
		require.NoError(t, err)

		ctx := context.Background()
		mockLambdaClient := aws_wrapper.NewMockLambdaClient(mockController)
		mockLambdaClient.
			EXPECT().
			Invoke(ctx, &lambda.InvokeInput{
				FunctionName:   aws.String(TestGetUserByIdFunctionName),
				InvocationType: types.InvocationTypeRequestResponse,
				Payload:        requestBody,
			}).
			Return(
				&lambda.InvokeOutput{
					StatusCode: http.StatusNotFound,
				},
				nil,
			)

		repository := NewRepository(mockLambdaClient, &config.Config{
			FunctionNames: &config.FunctionNames{
				UserAPI: map[config.UserApiFunctionNames]string{
					config.GetUserById: TestGetUserByIdFunctionName,
				},
			},
		})
		user, cerr := repository.GetUserById(ctx, TestUserId)

		assert.Error(t, cerr)
		assert.Equal(t, &cerror.CustomError{
			HttpStatusCode: http.StatusNotFound,
			LogMessage:     "user not found",
			LogSeverity:    zap.ErrorLevel,
		}, cerr)
		assert.Nil(t, user)
	})

	t.Run("when user api return ambiguous status code should return it", func(t *testing.T) {
		requestBody, err := json.Marshal(map[string]any{
			"userId": TestUserId,
		})
		require.NoError(t, err)

		ctx := context.Background()
		mockLambdaClient := aws_wrapper.NewMockLambdaClient(mockController)
		mockLambdaClient.
			EXPECT().
			Invoke(ctx, &lambda.InvokeInput{
				FunctionName:   aws.String(TestGetUserByIdFunctionName),
				InvocationType: types.InvocationTypeRequestResponse,
				Payload:        requestBody,
			}).
			Return(
				&lambda.InvokeOutput{
					StatusCode: http.StatusUnauthorized,
				},
				nil,
			)

		repository := NewRepository(mockLambdaClient, &config.Config{
			FunctionNames: &config.FunctionNames{
				UserAPI: map[config.UserApiFunctionNames]string{
					config.GetUserById: TestGetUserByIdFunctionName,
				},
			},
		})
		user, cerr := repository.GetUserById(ctx, TestUserId)

		assert.Error(t, cerr)
		assert.Equal(t,
			http.StatusUnauthorized,
			cerr.(*cerror.CustomError).HttpStatusCode,
		)
		assert.Nil(t, user)
	})

	t.Run("when user api return ambiguous response body should return error", func(t *testing.T) {
		requestBody, err := json.Marshal(map[string]any{
			"userId": TestUserId,
		})
		require.NoError(t, err)

		ctx := context.Background()
		mockLambdaClient := aws_wrapper.NewMockLambdaClient(mockController)
		mockLambdaClient.
			EXPECT().
			Invoke(ctx, &lambda.InvokeInput{
				FunctionName:   aws.String(TestGetUserByIdFunctionName),
				InvocationType: types.InvocationTypeRequestResponse,
				Payload:        requestBody,
			}).
			Return(
				&lambda.InvokeOutput{
					Payload:    []byte(`{"key":}`),
					StatusCode: http.StatusOK,
				},
				nil,
			)

		repository := NewRepository(mockLambdaClient, &config.Config{
			FunctionNames: &config.FunctionNames{
				UserAPI: map[config.UserApiFunctionNames]string{
					config.GetUserById: TestGetUserByIdFunctionName,
				},
			},
		})
		user, cerr := repository.GetUserById(ctx, TestUserId)

		assert.Error(t, cerr)
		assert.Equal(t,
			http.StatusInternalServerError,
			cerr.(*cerror.CustomError).HttpStatusCode,
		)
		assert.Nil(t, user)
	})
}

func TestRepository_GetAccessTokenViaRefreshToken(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()

	t.Run("happy path", func(t *testing.T) {
		requestBody, err := json.Marshal(map[string]any{
			"userId":       TestUserId,
			"refreshToken": TestToken,
		})
		require.NoError(t, err)

		responseBody, err := json.Marshal(&jwt_generator.Tokens{
			AccessToken: TestToken,
		})
		require.NoError(t, err)

		ctx := context.Background()
		mockLambdaClient := aws_wrapper.NewMockLambdaClient(mockController)
		mockLambdaClient.
			EXPECT().
			Invoke(ctx, &lambda.InvokeInput{
				FunctionName:   aws.String(TestGetAccessTokenViaRefreshTokenFunctionName),
				InvocationType: types.InvocationTypeRequestResponse,
				Payload:        requestBody,
			}).
			Return(
				&lambda.InvokeOutput{
					Payload:    responseBody,
					StatusCode: http.StatusOK,
				},
				nil,
			)

		repository := NewRepository(mockLambdaClient, &config.Config{
			FunctionNames: &config.FunctionNames{
				UserAPI: map[config.UserApiFunctionNames]string{
					config.GetAccessTokenViaRefreshToken: TestGetAccessTokenViaRefreshTokenFunctionName,
				},
			},
		})
		accessToken, cerr := repository.GetAccessTokenViaRefreshToken(ctx, TestUserId, TestToken)

		assert.NoError(t, cerr)
		assert.Equal(t, TestToken, accessToken)
	})

	t.Run("when user api can't handle request should return error", func(t *testing.T) {
		requestBody, err := json.Marshal(map[string]any{
			"userId":       TestUserId,
			"refreshToken": TestToken,
		})
		require.NoError(t, err)

		ctx := context.Background()
		mockLambdaClient := aws_wrapper.NewMockLambdaClient(mockController)
		mockLambdaClient.
			EXPECT().
			Invoke(ctx, &lambda.InvokeInput{
				FunctionName:   aws.String(TestGetAccessTokenViaRefreshTokenFunctionName),
				InvocationType: types.InvocationTypeRequestResponse,
				Payload:        requestBody,
			}).
			Return(
				nil,
				errors.New("test error"),
			)

		repository := NewRepository(mockLambdaClient, &config.Config{
			FunctionNames: &config.FunctionNames{
				UserAPI: map[config.UserApiFunctionNames]string{
					config.GetAccessTokenViaRefreshToken: TestGetAccessTokenViaRefreshTokenFunctionName,
				},
			},
		})
		accessToken, cerr := repository.GetAccessTokenViaRefreshToken(ctx, TestUserId, TestToken)

		assert.Error(t, cerr)
		assert.Equal(t,
			http.StatusInternalServerError,
			cerr.(*cerror.CustomError).HttpStatusCode,
		)
		assert.Empty(t, accessToken)
	})

	t.Run("when user api return ambiguous status should return error", func(t *testing.T) {
		requestBody, err := json.Marshal(map[string]any{
			"userId":       TestUserId,
			"refreshToken": TestToken,
		})
		require.NoError(t, err)

		ctx := context.Background()
		mockLambdaClient := aws_wrapper.NewMockLambdaClient(mockController)
		mockLambdaClient.
			EXPECT().
			Invoke(ctx, &lambda.InvokeInput{
				FunctionName:   aws.String(TestGetAccessTokenViaRefreshTokenFunctionName),
				InvocationType: types.InvocationTypeRequestResponse,
				Payload:        requestBody,
			}).
			Return(
				&lambda.InvokeOutput{
					StatusCode: http.StatusUnauthorized,
				},
				nil,
			)

		repository := NewRepository(mockLambdaClient, &config.Config{
			FunctionNames: &config.FunctionNames{
				UserAPI: map[config.UserApiFunctionNames]string{
					config.GetAccessTokenViaRefreshToken: TestGetAccessTokenViaRefreshTokenFunctionName,
				},
			},
		})
		accessToken, cerr := repository.GetAccessTokenViaRefreshToken(ctx, TestUserId, TestToken)

		assert.Error(t, cerr)
		assert.Equal(t,
			http.StatusUnauthorized,
			cerr.(*cerror.CustomError).HttpStatusCode,
		)
		assert.Empty(t, accessToken)
	})

	t.Run("when user api return ambiguous response body should return error", func(t *testing.T) {
		requestBody, err := json.Marshal(map[string]any{
			"userId":       TestUserId,
			"refreshToken": TestToken,
		})
		require.NoError(t, err)

		ctx := context.Background()
		mockLambdaClient := aws_wrapper.NewMockLambdaClient(mockController)
		mockLambdaClient.
			EXPECT().
			Invoke(ctx, &lambda.InvokeInput{
				FunctionName:   aws.String(TestGetAccessTokenViaRefreshTokenFunctionName),
				InvocationType: types.InvocationTypeRequestResponse,
				Payload:        requestBody,
			}).
			Return(
				&lambda.InvokeOutput{
					Payload:    []byte(`{"key":}`),
					StatusCode: http.StatusOK,
				},
				nil,
			)

		repository := NewRepository(mockLambdaClient, &config.Config{
			FunctionNames: &config.FunctionNames{
				UserAPI: map[config.UserApiFunctionNames]string{
					config.GetAccessTokenViaRefreshToken: TestGetAccessTokenViaRefreshTokenFunctionName,
				},
			},
		})
		accessToken, cerr := repository.GetAccessTokenViaRefreshToken(ctx, TestUserId, TestToken)

		assert.Error(t, cerr)
		assert.Equal(t,
			http.StatusInternalServerError,
			cerr.(*cerror.CustomError).HttpStatusCode,
		)
		assert.Empty(t, accessToken)
	})
}

func TestRepository_UpdateUserById(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()

	t.Run("happy path", func(t *testing.T) {
		requestBody, err := json.Marshal(map[string]any{
			"userId": TestUserId,
			"user": &UpdateUserPayload{
				Name:     TestUserId,
				Email:    TestUserEmail,
				Password: TestUserPassword,
			},
		})
		require.NoError(t, err)

		responseBody, err := json.Marshal(&jwt_generator.Tokens{
			AccessToken:  TestToken,
			RefreshToken: TestToken,
		})
		require.NoError(t, err)

		ctx := context.Background()
		mockLambdaClient := aws_wrapper.NewMockLambdaClient(mockController)
		mockLambdaClient.
			EXPECT().
			Invoke(ctx, &lambda.InvokeInput{
				FunctionName:   aws.String(TestUpdateUserByIdFunctionName),
				InvocationType: types.InvocationTypeRequestResponse,
				Payload:        requestBody,
			}).
			Return(
				&lambda.InvokeOutput{
					Payload:    responseBody,
					StatusCode: http.StatusOK,
				},
				nil,
			)

		repository := NewRepository(mockLambdaClient, &config.Config{
			FunctionNames: &config.FunctionNames{
				UserAPI: map[config.UserApiFunctionNames]string{
					config.UpdateUserById: TestUpdateUserByIdFunctionName,
				},
			},
		})

		tokens, cerr := repository.UpdateUserById(
			ctx,
			TestUserId,
			&UpdateUserPayload{
				Name:     TestUserId,
				Email:    TestUserEmail,
				Password: TestUserPassword,
			},
		)

		assert.NoError(t, cerr)
		assert.Equal(t,
			&jwt_generator.Tokens{
				AccessToken:  TestToken,
				RefreshToken: TestToken,
			},
			tokens,
		)
	})

	t.Run("when user api return error should return it", func(t *testing.T) {
		requestBody, err := json.Marshal(map[string]any{
			"userId": TestUserId,
			"user": &UpdateUserPayload{
				Name:     TestUserId,
				Email:    TestUserEmail,
				Password: TestUserPassword,
			},
		})
		require.NoError(t, err)

		ctx := context.Background()
		mockLambdaClient := aws_wrapper.NewMockLambdaClient(mockController)
		mockLambdaClient.
			EXPECT().
			Invoke(ctx, &lambda.InvokeInput{
				FunctionName:   aws.String(TestUpdateUserByIdFunctionName),
				InvocationType: types.InvocationTypeRequestResponse,
				Payload:        requestBody,
			}).
			Return(
				nil,
				errors.New("test error"),
			)

		repository := NewRepository(mockLambdaClient, &config.Config{
			FunctionNames: &config.FunctionNames{
				UserAPI: map[config.UserApiFunctionNames]string{
					config.UpdateUserById: TestUpdateUserByIdFunctionName,
				},
			},
		})

		tokens, err := repository.UpdateUserById(
			ctx,
			TestUserId,
			&UpdateUserPayload{
				Name:     TestUserId,
				Email:    TestUserEmail,
				Password: TestUserPassword,
			},
		)

		assert.Error(t, err)
		assert.Equal(t,
			http.StatusInternalServerError,
			err.(*cerror.CustomError).HttpStatusCode,
		)
		assert.Nil(t, tokens)
	})

	t.Run("when user api return conflict status code should return error", func(t *testing.T) {
		requestBody, err := json.Marshal(map[string]any{
			"userId": TestUserId,
			"user": &UpdateUserPayload{
				Name:     TestUserId,
				Email:    TestUserEmail,
				Password: TestUserPassword,
			},
		})
		require.NoError(t, err)

		ctx := context.Background()
		mockLambdaClient := aws_wrapper.NewMockLambdaClient(mockController)
		mockLambdaClient.
			EXPECT().
			Invoke(ctx, &lambda.InvokeInput{
				FunctionName:   aws.String(TestUpdateUserByIdFunctionName),
				InvocationType: types.InvocationTypeRequestResponse,
				Payload:        requestBody,
			}).
			Return(
				&lambda.InvokeOutput{
					StatusCode: http.StatusConflict,
				},
				nil,
			)

		repository := NewRepository(mockLambdaClient, &config.Config{
			FunctionNames: &config.FunctionNames{
				UserAPI: map[config.UserApiFunctionNames]string{
					config.UpdateUserById: TestUpdateUserByIdFunctionName,
				},
			},
		})

		tokens, cerr := repository.UpdateUserById(
			ctx,
			TestUserId,
			&UpdateUserPayload{
				Name:     TestUserId,
				Email:    TestUserEmail,
				Password: TestUserPassword,
			},
		)

		assert.Error(t, cerr)
		assert.Equal(t,
			http.StatusConflict,
			cerr.(*cerror.CustomError).HttpStatusCode,
		)
		assert.Nil(t, tokens)
	})

	t.Run("when user api return ambiguous status code should return error", func(t *testing.T) {
		requestBody, err := json.Marshal(map[string]any{
			"userId": TestUserId,
			"user": &UpdateUserPayload{
				Name:     TestUserId,
				Email:    TestUserEmail,
				Password: TestUserPassword,
			},
		})
		require.NoError(t, err)

		ctx := context.Background()
		mockLambdaClient := aws_wrapper.NewMockLambdaClient(mockController)
		mockLambdaClient.
			EXPECT().
			Invoke(ctx, &lambda.InvokeInput{
				FunctionName:   aws.String(TestUpdateUserByIdFunctionName),
				InvocationType: types.InvocationTypeRequestResponse,
				Payload:        requestBody,
			}).
			Return(
				&lambda.InvokeOutput{
					StatusCode: http.StatusUnauthorized,
				},
				nil,
			)

		repository := NewRepository(mockLambdaClient, &config.Config{
			FunctionNames: &config.FunctionNames{
				UserAPI: map[config.UserApiFunctionNames]string{
					config.UpdateUserById: TestUpdateUserByIdFunctionName,
				},
			},
		})

		tokens, cerr := repository.UpdateUserById(
			ctx,
			TestUserId,
			&UpdateUserPayload{
				Name:     TestUserId,
				Email:    TestUserEmail,
				Password: TestUserPassword,
			},
		)

		assert.Error(t, cerr)
		assert.Equal(t,
			http.StatusUnauthorized,
			cerr.(*cerror.CustomError).HttpStatusCode,
		)
		assert.Nil(t, tokens)
	})

	t.Run("when user api return ambiguous response body should return error", func(t *testing.T) {
		requestBody, err := json.Marshal(map[string]any{
			"userId": TestUserId,
			"user": &UpdateUserPayload{
				Name:     TestUserId,
				Email:    TestUserEmail,
				Password: TestUserPassword,
			},
		})
		require.NoError(t, err)

		ctx := context.Background()
		mockLambdaClient := aws_wrapper.NewMockLambdaClient(mockController)
		mockLambdaClient.
			EXPECT().
			Invoke(ctx, &lambda.InvokeInput{
				FunctionName:   aws.String(TestUpdateUserByIdFunctionName),
				InvocationType: types.InvocationTypeRequestResponse,
				Payload:        requestBody,
			}).
			Return(
				&lambda.InvokeOutput{
					Payload:    []byte(`{"key":}`),
					StatusCode: http.StatusOK,
				},
				nil,
			)

		repository := NewRepository(mockLambdaClient, &config.Config{
			FunctionNames: &config.FunctionNames{
				UserAPI: map[config.UserApiFunctionNames]string{
					config.UpdateUserById: TestUpdateUserByIdFunctionName,
				},
			},
		})

		tokens, cerr := repository.UpdateUserById(
			ctx,
			TestUserId,
			&UpdateUserPayload{
				Name:     TestUserId,
				Email:    TestUserEmail,
				Password: TestUserPassword,
			},
		)

		assert.Error(t, cerr)
		assert.Equal(t,
			http.StatusInternalServerError,
			cerr.(*cerror.CustomError).HttpStatusCode,
		)
		assert.Nil(t, tokens)
	})
}
