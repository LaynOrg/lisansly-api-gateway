package user

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"

	"api-gateway/pkg/cerror"
	"api-gateway/pkg/config"
	"api-gateway/pkg/jwt_generator"
	"api-gateway/pkg/server"
)

const (
	TestUserId = "abcd-abcd-abcd-abcd"
)

func TestNewHandler(t *testing.T) {
	h := NewHandler(nil, nil)
	assert.Implements(t, (*Handler)(nil), h)
}

func TestHandler_RegisterRoutes(t *testing.T) {
	h := NewHandler(nil, nil)

	app := fiber.New()
	h.RegisterRoutes(app)
}

func TestHandler_AuthenticationMiddleware(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()

	t.Run("happy path", func(t *testing.T) {
		mockUserRepository := NewMockService(mockController)
		mockUserRepository.
			EXPECT().
			VerifyAccessToken(TestToken).
			Return(&jwt_generator.Claims{
				Name:  TestUserName,
				Email: TestUserEmail,
				Role:  RoleUser,
				RegisteredClaims: jwt.RegisteredClaims{
					ID:        uuid.New().String(),
					Issuer:    jwt_generator.IssuerDefault,
					Subject:   "abcd-abcd-abcd-abcd",
					ExpiresAt: nil,
					NotBefore: nil,
					IssuedAt:  nil,
				},
			}, nil)

		userHandler := NewHandler(mockUserRepository, nil)
		srv := server.NewServer(&config.Config{}, nil)
		app := srv.GetFiberInstance()
		app.Get("/test", userHandler.AuthenticationMiddleware, func(ctx *fiber.Ctx) error {
			return ctx.SendStatus(fiber.StatusOK)
		})

		go srv.Start()
		defer srv.Shutdown()

		req := httptest.NewRequest(fiber.MethodGet, "/test", nil)
		req.Header.Set(fiber.HeaderAuthorization, fmt.Sprintf("Bearer %s", TestToken))
		resp, err := app.Test(req)
		require.NoError(t, err)

		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("when authorization is empty should return error", func(t *testing.T) {
		userHandler := NewHandler(nil, nil)
		srv := server.NewServer(&config.Config{}, nil)
		app := srv.GetFiberInstance()
		app.Get("/test", userHandler.AuthenticationMiddleware, func(ctx *fiber.Ctx) error {
			return ctx.SendStatus(fiber.StatusOK)
		})

		go srv.Start()
		defer srv.Shutdown()

		req := httptest.NewRequest(fiber.MethodGet, "/test", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)

		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("when authorization is invalid should return error", func(t *testing.T) {
		mockUserService := NewMockService(mockController)
		mockUserService.
			EXPECT().
			VerifyAccessToken(TestToken).
			Return(nil, &cerror.CustomError{
				HttpStatusCode: fiber.StatusUnauthorized,
				LogMessage:     "invalid token",
				LogSeverity:    zapcore.ErrorLevel,
			})

		userHandler := NewHandler(mockUserService, nil)
		srv := server.NewServer(&config.Config{}, nil)
		app := srv.GetFiberInstance()
		app.Get("/test", userHandler.AuthenticationMiddleware, func(ctx *fiber.Ctx) error {
			return ctx.SendStatus(fiber.StatusOK)
		})

		go srv.Start()
		defer srv.Shutdown()

		req := httptest.NewRequest(fiber.MethodGet, "/test", nil)
		req.Header.Set(fiber.HeaderAuthorization, fmt.Sprintf("Bearer %s", TestToken))
		resp, err := app.Test(req)
		require.NoError(t, err)

		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})
}

func TestHandler_Register(t *testing.T) {
	TestUserModel := RegisterPayload{
		Name:     TestUserName,
		Email:    TestUserEmail,
		Password: TestUserPassword,
	}

	mockController := gomock.NewController(t)
	defer mockController.Finish()

	t.Run("happy path", func(t *testing.T) {
		app := fiber.New()

		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.EXPECT().Register(&TestUserModel).
			Return(&jwt_generator.Tokens{
				AccessToken:  TestToken,
				RefreshToken: TestToken,
			}, nil)

		userHandler := NewHandler(nil, mockUserRepository)
		userHandler.RegisterRoutes(app)

		reqBody, err := json.Marshal(&TestUserModel)
		require.NoError(t, err)

		req := httptest.NewRequest(fiber.MethodPost, "/register", bytes.NewReader(reqBody))
		req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
		req.Header.Set(fiber.HeaderAccept, fiber.MIMEApplicationJSON)

		resp, err := app.Test(req)
		require.NoError(t, err)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		var actualTokens *jwt_generator.Tokens
		err = json.Unmarshal(body, &actualTokens)

		assert.Equal(t, fiber.StatusCreated, resp.StatusCode)
		assert.Equal(t, &jwt_generator.Tokens{
			AccessToken:  TestToken,
			RefreshToken: TestToken,
		}, actualTokens)
	})

	t.Run("error occurred while parsing body", func(t *testing.T) {
		app := fiber.New(fiber.Config{
			ErrorHandler: cerror.Middleware,
		})

		userHandler := NewHandler(nil, nil)
		userHandler.RegisterRoutes(app)

		req := httptest.NewRequest(fiber.MethodPost, "/register", strings.NewReader(`"invalid":"body"`))
		req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
		req.Header.Set(fiber.HeaderAccept, fiber.MIMEApplicationJSON)

		resp, err := app.Test(req)
		require.NoError(t, err)

		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
	})

	t.Run("validation", func(t *testing.T) {
		t.Run("name", func(t *testing.T) {
			app := fiber.New(fiber.Config{
				ErrorHandler: cerror.Middleware,
			})

			userHandler := NewHandler(nil, nil)
			userHandler.RegisterRoutes(app)

			reqBody, err := json.Marshal(&RegisterPayload{
				Name:     "",
				Email:    TestUserEmail,
				Password: TestUserPassword,
			})
			require.NoError(t, err)

			req := httptest.NewRequest(fiber.MethodPost, "/register", bytes.NewReader(reqBody))
			req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
			req.Header.Set(fiber.HeaderAccept, fiber.MIMEApplicationJSON)

			resp, err := app.Test(req)
			require.NoError(t, err)

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			var actualTokens *jwt_generator.Tokens
			err = json.Unmarshal(body, &actualTokens)

			assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
			assert.Empty(t, actualTokens)
		})

		t.Run("email", func(t *testing.T) {
			app := fiber.New(fiber.Config{
				ErrorHandler: cerror.Middleware,
			})

			userHandler := NewHandler(nil, nil)
			userHandler.RegisterRoutes(app)

			reqBody, err := json.Marshal(&RegisterPayload{
				Name:     TestUserName,
				Email:    "invalid",
				Password: TestUserPassword,
			})
			require.NoError(t, err)

			req := httptest.NewRequest(fiber.MethodPost, "/register", bytes.NewReader(reqBody))
			req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
			req.Header.Set(fiber.HeaderAccept, fiber.MIMEApplicationJSON)

			resp, err := app.Test(req)
			require.NoError(t, err)

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			var actualTokens *jwt_generator.Tokens
			err = json.Unmarshal(body, &actualTokens)

			assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
			assert.Empty(t, actualTokens)
		})

		t.Run("password", func(t *testing.T) {
			app := fiber.New(fiber.Config{
				ErrorHandler: cerror.Middleware,
			})

			userHandler := NewHandler(nil, nil)
			userHandler.RegisterRoutes(app)

			reqBody, err := json.Marshal(&RegisterPayload{
				Name:     TestUserName,
				Email:    TestUserEmail,
				Password: "1234",
			})
			require.NoError(t, err)

			req := httptest.NewRequest(fiber.MethodPost, "/register", bytes.NewReader(reqBody))
			req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
			req.Header.Set(fiber.HeaderAccept, fiber.MIMEApplicationJSON)

			resp, err := app.Test(req)
			require.NoError(t, err)

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			var actualTokens *jwt_generator.Tokens
			err = json.Unmarshal(body, &actualTokens)

			assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
			assert.Empty(t, actualTokens)
		})
	})

	t.Run("error occurred while registering user", func(t *testing.T) {
		app := fiber.New(fiber.Config{
			ErrorHandler: cerror.Middleware,
		})

		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.EXPECT().Register(&TestUserModel).
			Return(nil, &cerror.CustomError{
				HttpStatusCode: http.StatusInternalServerError,
				LogMessage:     "error occurred while registering user",
				LogSeverity:    zapcore.ErrorLevel,
			})

		userHandler := NewHandler(nil, mockUserRepository)
		userHandler.RegisterRoutes(app)

		reqBody, err := json.Marshal(&TestUserModel)
		require.NoError(t, err)

		req := httptest.NewRequest(fiber.MethodPost, "/register", bytes.NewReader(reqBody))
		req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
		req.Header.Set(fiber.HeaderAccept, fiber.MIMEApplicationJSON)

		resp, err := app.Test(req)
		require.NoError(t, err)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		var actualTokens *jwt_generator.Tokens
		err = json.Unmarshal(body, &actualTokens)

		assert.Equal(t, fiber.StatusInternalServerError, resp.StatusCode)
		assert.Empty(t, actualTokens)
	})
}

func TestHandler_Login(t *testing.T) {
	TestUserModel := LoginPayload{
		Email:    TestUserEmail,
		Password: TestUserPassword,
	}

	mockController := gomock.NewController(t)
	defer mockController.Finish()

	t.Run("happy path", func(t *testing.T) {
		app := fiber.New()

		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.EXPECT().Login(&TestUserModel).Return(
			&jwt_generator.Tokens{
				AccessToken:  TestToken,
				RefreshToken: TestToken,
			}, nil)

		userHandler := NewHandler(nil, mockUserRepository)
		userHandler.RegisterRoutes(app)

		reqBody, err := json.Marshal(&TestUserModel)
		require.NoError(t, err)

		req := httptest.NewRequest(fiber.MethodPost, "/login", bytes.NewReader(reqBody))
		req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
		req.Header.Set(fiber.HeaderAccept, fiber.MIMEApplicationJSON)

		resp, err := app.Test(req)
		require.NoError(t, err)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		var actualTokens *jwt_generator.Tokens
		err = json.Unmarshal(body, &actualTokens)

		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		assert.Equal(t, &jwt_generator.Tokens{
			AccessToken:  TestToken,
			RefreshToken: TestToken,
		}, actualTokens)
	})

	t.Run("validation", func(t *testing.T) {
		t.Run("email", func(t *testing.T) {
			app := fiber.New(fiber.Config{
				ErrorHandler: cerror.Middleware,
			})

			userHandler := NewHandler(nil, nil)
			userHandler.RegisterRoutes(app)

			reqBody, err := json.Marshal(&LoginPayload{
				Email: "invalid-email",
			})
			require.NoError(t, err)

			req := httptest.NewRequest(fiber.MethodPost, "/login", bytes.NewReader(reqBody))
			req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
			req.Header.Set(fiber.HeaderAccept, fiber.MIMEApplicationJSON)

			resp, err := app.Test(req)
			require.NoError(t, err)

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			var actualTokens *jwt_generator.Tokens
			err = json.Unmarshal(body, &actualTokens)

			assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
			assert.Empty(t, actualTokens)
		})

		t.Run("password", func(t *testing.T) {
			app := fiber.New(fiber.Config{
				ErrorHandler: cerror.Middleware,
			})

			userHandler := NewHandler(nil, nil)
			userHandler.RegisterRoutes(app)

			reqBody, err := json.Marshal(&LoginPayload{
				Password: "123",
			})
			require.NoError(t, err)

			req := httptest.NewRequest(fiber.MethodPost, "/login", bytes.NewReader(reqBody))
			req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
			req.Header.Set(fiber.HeaderAccept, fiber.MIMEApplicationJSON)

			resp, err := app.Test(req)
			require.NoError(t, err)

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			var actualTokens *jwt_generator.Tokens
			err = json.Unmarshal(body, &actualTokens)

			assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
			assert.Empty(t, actualTokens)
		})
	})

	t.Run("when user repository return error should return it", func(t *testing.T) {
		app := fiber.New(fiber.Config{
			ErrorHandler: cerror.Middleware,
		})

		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.EXPECT().Login(&TestUserModel).Return(
			nil, &cerror.CustomError{
				HttpStatusCode: fiber.StatusUnauthorized,
				LogMessage:     "invalid credentials",
				LogSeverity:    zapcore.WarnLevel,
			})

		userHandler := NewHandler(nil, mockUserRepository)
		userHandler.RegisterRoutes(app)

		reqBody, err := json.Marshal(&TestUserModel)
		require.NoError(t, err)

		req := httptest.NewRequest(fiber.MethodPost, "/login", bytes.NewReader(reqBody))
		req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
		req.Header.Set(fiber.HeaderAccept, fiber.MIMEApplicationJSON)

		resp, err := app.Test(req)
		require.NoError(t, err)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		var actualTokens *jwt_generator.Tokens
		err = json.Unmarshal(body, &actualTokens)

		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
		assert.Empty(t, actualTokens)
	})
}

func TestHandler_GetAccessTokenByRefreshToken(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()

	t.Run("happy path", func(t *testing.T) {
		app := fiber.New()

		mockUserService := NewMockService(mockController)
		mockUserService.EXPECT().VerifyAccessToken(TestToken).Return(TestJwtClaims, nil)

		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.EXPECT().GetAccessTokenByRefreshToken(TestUserId, TestToken).Return(TestToken, nil)

		userHandler := NewHandler(mockUserService, mockUserRepository)
		userHandler.RegisterRoutes(app)

		reqUrl := fmt.Sprintf("/user/refreshToken/%s", TestToken)
		req := httptest.NewRequest(fiber.MethodGet, reqUrl, nil)
		req.Header.Set(fiber.HeaderAccept, fiber.MIMEApplicationJSON)
		req.Header.Set(fiber.HeaderAuthorization, fmt.Sprintf("Bearer %s", TestToken))

		resp, err := app.Test(req)
		require.NoError(t, err)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		var token map[string]string
		err = json.Unmarshal(body, &token)

		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		assert.Equal(t, TestToken, token["accessToken"])
	})

	t.Run("invalid refresh token", func(t *testing.T) {
		app := fiber.New(fiber.Config{
			ErrorHandler: cerror.Middleware,
		})

		mockUserService := NewMockService(mockController)
		mockUserService.EXPECT().VerifyAccessToken(TestToken).Return(TestJwtClaims, nil)

		userHandler := NewHandler(mockUserService, nil)
		userHandler.RegisterRoutes(app)

		reqUrl := fmt.Sprintf("/user/refreshToken/%s", "invalid-token")
		req := httptest.NewRequest(fiber.MethodGet, reqUrl, nil)
		req.Header.Set(fiber.HeaderAccept, fiber.MIMEApplicationJSON)
		req.Header.Set(fiber.HeaderAuthorization, fmt.Sprintf("Bearer %s", TestToken))

		resp, err := app.Test(req)
		require.NoError(t, err)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		var token map[string]string
		err = json.Unmarshal(body, &token)

		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
		assert.Empty(t, token)
	})

	t.Run("when user repository return error should return it", func(t *testing.T) {
		app := fiber.New(fiber.Config{
			ErrorHandler: cerror.Middleware,
		})

		mockUserService := NewMockService(mockController)
		mockUserService.EXPECT().VerifyAccessToken(TestToken).Return(TestJwtClaims, nil)

		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.EXPECT().GetAccessTokenByRefreshToken(TestUserId, TestToken).Return(
			"",
			&cerror.CustomError{
				HttpStatusCode: fiber.StatusUnauthorized,
				LogMessage:     "invalid refresh token",
				LogSeverity:    zapcore.WarnLevel,
			})

		userHandler := NewHandler(mockUserService, mockUserRepository)
		userHandler.RegisterRoutes(app)

		reqUrl := fmt.Sprintf("/user/refreshToken/%s", TestToken)
		req := httptest.NewRequest(fiber.MethodGet, reqUrl, nil)
		req.Header.Set(fiber.HeaderAccept, fiber.MIMEApplicationJSON)
		req.Header.Set(fiber.HeaderAuthorization, fmt.Sprintf("Bearer %s", TestToken))

		resp, err := app.Test(req)
		require.NoError(t, err)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		var token map[string]string
		err = json.Unmarshal(body, &token)

		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
		assert.Empty(t, token)
	})
}

func TestHandler_UpdateUserById(t *testing.T) {
	TestUserModel := &UpdateUserPayload{
		Name:     TestUserName,
		Email:    TestUserEmail,
		Password: TestUserPassword,
	}

	mockController := gomock.NewController(t)
	defer mockController.Finish()

	t.Run("happy path", func(t *testing.T) {
		app := fiber.New(fiber.Config{
			ErrorHandler: cerror.Middleware,
		})

		mockUserService := NewMockService(mockController)
		mockUserService.EXPECT().VerifyAccessToken(TestToken).Return(TestJwtClaims, nil)

		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.EXPECT().UpdateUserById(TestUserId, TestUserModel).Return(&jwt_generator.Tokens{
			AccessToken:  TestToken,
			RefreshToken: TestToken,
		}, nil)

		userHandler := NewHandler(mockUserService, mockUserRepository)
		userHandler.RegisterRoutes(app)

		reqBody, err := json.Marshal(&TestUserModel)
		require.NoError(t, err)

		req := httptest.NewRequest(fiber.MethodPatch, "/user", bytes.NewReader(reqBody))
		req.Header.Set(fiber.HeaderAuthorization, fmt.Sprintf("Bearer %s", TestToken))
		req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)

		resp, err := app.Test(req)
		require.NoError(t, err)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		var tokens *jwt_generator.Tokens
		err = json.Unmarshal(body, &tokens)

		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		assert.Equal(t, &jwt_generator.Tokens{
			AccessToken:  TestToken,
			RefreshToken: TestToken,
		}, tokens)
	})

	t.Run("parse request body error", func(t *testing.T) {
		app := fiber.New(fiber.Config{
			ErrorHandler: cerror.Middleware,
		})

		mockUserService := NewMockService(mockController)
		mockUserService.EXPECT().VerifyAccessToken(TestToken).Return(TestJwtClaims, nil)

		userHandler := NewHandler(mockUserService, nil)
		userHandler.RegisterRoutes(app)

		req := httptest.NewRequest(fiber.MethodPatch, "/user", strings.NewReader(`"name": "test"`))
		req.Header.Set(fiber.HeaderAuthorization, fmt.Sprintf("Bearer %s", TestToken))
		req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)

		resp, err := app.Test(req)
		require.NoError(t, err)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		var tokens *jwt_generator.Tokens
		err = json.Unmarshal(body, &tokens)

		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
		assert.Empty(t, tokens)
	})

	t.Run("validation", func(t *testing.T) {
		t.Run("empty values", func(t *testing.T) {
			app := fiber.New(fiber.Config{
				ErrorHandler: cerror.Middleware,
			})

			mockUserService := NewMockService(mockController)
			mockUserService.EXPECT().VerifyAccessToken(TestToken).Return(TestJwtClaims, nil)

			userHandler := NewHandler(mockUserService, nil)
			userHandler.RegisterRoutes(app)

			reqBody, err := json.Marshal(&UpdateUserPayload{
				Name:     "",
				Email:    "",
				Password: "",
			})

			req := httptest.NewRequest(fiber.MethodPatch, "/user", bytes.NewReader(reqBody))
			req.Header.Set(fiber.HeaderAuthorization, fmt.Sprintf("Bearer %s", TestToken))
			req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)

			resp, err := app.Test(req)
			require.NoError(t, err)

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			var tokens *jwt_generator.Tokens
			err = json.Unmarshal(body, &tokens)

			assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
			assert.Empty(t, tokens)
		})

		t.Run("invalid email", func(t *testing.T) {
			app := fiber.New(fiber.Config{
				ErrorHandler: cerror.Middleware,
			})

			mockUserService := NewMockService(mockController)
			mockUserService.EXPECT().VerifyAccessToken(TestToken).Return(TestJwtClaims, nil)

			userHandler := NewHandler(mockUserService, nil)
			userHandler.RegisterRoutes(app)

			reqBody, err := json.Marshal(&UpdateUserPayload{
				Email: "invalid",
			})
			require.NoError(t, err)

			req := httptest.NewRequest(fiber.MethodPatch, "/user", bytes.NewReader(reqBody))
			req.Header.Set(fiber.HeaderAuthorization, fmt.Sprintf("Bearer %s", TestToken))
			req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)

			resp, err := app.Test(req)
			require.NoError(t, err)

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			var tokens *jwt_generator.Tokens
			err = json.Unmarshal(body, &tokens)

			assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
			assert.Empty(t, tokens)
		})

		t.Run("invalid password", func(t *testing.T) {
			app := fiber.New(fiber.Config{
				ErrorHandler: cerror.Middleware,
			})

			mockUserService := NewMockService(mockController)
			mockUserService.EXPECT().VerifyAccessToken(TestToken).Return(TestJwtClaims, nil)

			userHandler := NewHandler(mockUserService, nil)
			userHandler.RegisterRoutes(app)

			reqBody, err := json.Marshal(&UpdateUserPayload{
				Password: "123",
			})
			require.NoError(t, err)

			req := httptest.NewRequest(fiber.MethodPatch, "/user", bytes.NewReader(reqBody))
			req.Header.Set(fiber.HeaderAuthorization, fmt.Sprintf("Bearer %s", TestToken))
			req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)

			resp, err := app.Test(req)
			require.NoError(t, err)

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			var tokens *jwt_generator.Tokens
			err = json.Unmarshal(body, &tokens)

			assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
			assert.Empty(t, tokens)
		})
	})

	t.Run("when user repository return error return it", func(t *testing.T) {
		app := fiber.New(fiber.Config{
			ErrorHandler: cerror.Middleware,
		})

		mockUserService := NewMockService(mockController)
		mockUserService.EXPECT().VerifyAccessToken(TestToken).Return(TestJwtClaims, nil)

		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.EXPECT().UpdateUserById(TestUserId, TestUserModel).Return(nil, &cerror.CustomError{
			HttpStatusCode: fiber.StatusConflict,
			LogMessage:     "already exists",
			LogSeverity:    zapcore.WarnLevel,
		})

		userHandler := NewHandler(mockUserService, mockUserRepository)
		userHandler.RegisterRoutes(app)

		reqBody, err := json.Marshal(&TestUserModel)
		require.NoError(t, err)

		req := httptest.NewRequest(fiber.MethodPatch, "/user", bytes.NewReader(reqBody))
		req.Header.Set(fiber.HeaderAuthorization, fmt.Sprintf("Bearer %s", TestToken))
		req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)

		resp, err := app.Test(req)
		require.NoError(t, err)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		var tokens *jwt_generator.Tokens
		err = json.Unmarshal(body, &tokens)

		assert.Equal(t, fiber.StatusConflict, resp.StatusCode)
		assert.Empty(t, tokens)
	})
}
