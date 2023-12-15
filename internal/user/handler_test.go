//go:build unit

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
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"go.uber.org/zap"

	"api-gateway/pkg/cerror"
	"api-gateway/pkg/jwt_generator"
)

const (
	TestUserId = "abcd-abcd-abcd-abcd"
)

func TestNewHandler(t *testing.T) {
	h := NewHandler(nil, nil)
	assert.Implements(t, (*Handler)(nil), h)
}

func TestHandler_AuthenticationMiddleware(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()

	t.Run("happy path", func(t *testing.T) {
		mockUserRepository := NewMockService(mockController)
		mockUserRepository.
			EXPECT().
			VerifyAccessToken(gomock.Any(), TestToken).
			Return(&jwt_generator.Claims{
				Name:  TestUserName,
				Email: TestUserEmail,
				Plan:  PlanDefault,
				RegisteredClaims: jwt.RegisteredClaims{
					ID:        uuid.New().String(),
					Issuer:    jwt_generator.IssuerDefault,
					Subject:   "abcd-abcd-abcd-abcd",
					ExpiresAt: nil,
					NotBefore: nil,
					IssuedAt:  nil,
				},
			}, nil)

		h := NewHandler(mockUserRepository, nil)

		app := fiber.New()
		app.Get("/test", h.AuthenticationMiddleware, func(ctx *fiber.Ctx) error {
			return ctx.SendStatus(fiber.StatusOK)
		})

		go app.Listen(":8080")
		defer app.Shutdown()

		req := httptest.NewRequest(fiber.MethodGet, "/test", nil)
		req.Header.Set(fiber.HeaderAuthorization, fmt.Sprintf("Bearer %s", TestToken))
		resp, err := app.Test(req)
		require.NoError(t, err)

		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("when authorization is empty should return error", func(t *testing.T) {
		h := NewHandler(nil, nil)

		app := fiber.New(fiber.Config{
			ErrorHandler: cerror.Middleware,
		})
		app.Get("/test", h.AuthenticationMiddleware, func(ctx *fiber.Ctx) error {
			return ctx.SendStatus(fiber.StatusOK)
		})

		go app.Listen(":8080")
		defer app.Shutdown()

		req := httptest.NewRequest(fiber.MethodGet, "/test", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)

		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("when authorization is invalid should return error", func(t *testing.T) {
		mockservice := NewMockService(mockController)
		mockservice.
			EXPECT().
			VerifyAccessToken(gomock.Any(), TestToken).
			Return(nil, &cerror.CustomError{
				HttpStatusCode: fiber.StatusUnauthorized,
				LogMessage:     "invalid token",
				LogSeverity:    zap.ErrorLevel,
			})

		h := NewHandler(mockservice, nil)

		app := fiber.New(fiber.Config{
			ErrorHandler: cerror.Middleware,
		})
		app.Get("/test", h.AuthenticationMiddleware, func(ctx *fiber.Ctx) error {
			return ctx.SendStatus(fiber.StatusOK)
		})

		go app.Listen(":8080")
		defer app.Shutdown()

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
		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.EXPECT().Register(gomock.Any(), &TestUserModel).
			Return(&jwt_generator.Tokens{
				AccessToken:  TestToken,
				RefreshToken: TestToken,
			}, nil)

		h := NewHandler(nil, mockUserRepository)

		app := fiber.New()
		app.Post("/register", h.Register)

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
		h := NewHandler(nil, nil)

		app := fiber.New(fiber.Config{
			ErrorHandler: cerror.Middleware,
		})
		app.Post("/register", h.Register)

		req := httptest.NewRequest(fiber.MethodPost, "/register", strings.NewReader(`"invalid":"body"`))
		req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
		req.Header.Set(fiber.HeaderAccept, fiber.MIMEApplicationJSON)

		resp, err := app.Test(req)
		require.NoError(t, err)

		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
	})

	t.Run("validation", func(t *testing.T) {
		t.Run("name", func(t *testing.T) {
			h := NewHandler(nil, nil)

			app := fiber.New(fiber.Config{
				ErrorHandler: cerror.Middleware,
			})
			app.Post("/register", h.Register)

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
			h := NewHandler(nil, nil)

			app := fiber.New(fiber.Config{
				ErrorHandler: cerror.Middleware,
			})
			app.Post("/register", h.Register)

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
			h := NewHandler(nil, nil)

			app := fiber.New(fiber.Config{
				ErrorHandler: cerror.Middleware,
			})
			app.Post("/register", h.Register)

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
		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.EXPECT().Register(gomock.Any(), &TestUserModel).
			Return(nil, &cerror.CustomError{
				HttpStatusCode: http.StatusInternalServerError,
				LogMessage:     "error occurred while registering user",
				LogSeverity:    zap.ErrorLevel,
			})

		h := NewHandler(nil, mockUserRepository)

		app := fiber.New(fiber.Config{
			ErrorHandler: cerror.Middleware,
		})
		app.Post("/register", h.Register)

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
		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.EXPECT().Login(gomock.Any(), &TestUserModel).Return(
			&jwt_generator.Tokens{
				AccessToken:  TestToken,
				RefreshToken: TestToken,
			}, nil)

		h := NewHandler(nil, mockUserRepository)

		app := fiber.New()
		app.Post("/login", h.Login)

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
			h := NewHandler(nil, nil)

			app := fiber.New(fiber.Config{
				ErrorHandler: cerror.Middleware,
			})
			app.Post("/login", h.Login)

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
			h := NewHandler(nil, nil)

			app := fiber.New(fiber.Config{
				ErrorHandler: cerror.Middleware,
			})
			app.Post("/login", h.Login)

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
		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.EXPECT().Login(gomock.Any(), &TestUserModel).Return(
			nil, &cerror.CustomError{
				HttpStatusCode: fiber.StatusUnauthorized,
				LogMessage:     "invalid credentials",
				LogSeverity:    zap.WarnLevel,
			})

		h := NewHandler(nil, mockUserRepository)

		app := fiber.New(fiber.Config{
			ErrorHandler: cerror.Middleware,
		})
		app.Post("/login", h.Login)

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
		mockservice := NewMockService(mockController)
		mockservice.EXPECT().VerifyAccessToken(gomock.Any(), TestToken).Return(TestJwtClaims, nil)

		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.EXPECT().GetAccessTokenViaRefreshToken(gomock.Any(), TestUserId, TestToken).Return(TestToken, nil)

		h := NewHandler(mockservice, mockUserRepository)

		app := fiber.New()
		app.Get(
			"/user/refreshToken/:refreshToken",
			h.AuthenticationMiddleware,
			h.GetAccessTokenViaRefreshToken,
		)

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
		mockservice := NewMockService(mockController)
		mockservice.EXPECT().VerifyAccessToken(gomock.Any(), TestToken).Return(TestJwtClaims, nil)

		h := NewHandler(mockservice, nil)

		app := fiber.New(fiber.Config{
			ErrorHandler: cerror.Middleware,
		})
		app.Get(
			"/user/refreshToken/:refreshToken",
			h.AuthenticationMiddleware,
			h.GetAccessTokenViaRefreshToken,
		)

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
		mockservice := NewMockService(mockController)
		mockservice.EXPECT().VerifyAccessToken(gomock.Any(), TestToken).Return(TestJwtClaims, nil)

		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.EXPECT().GetAccessTokenViaRefreshToken(gomock.Any(), TestUserId, TestToken).Return(
			"",
			&cerror.CustomError{
				HttpStatusCode: fiber.StatusUnauthorized,
				LogMessage:     "invalid refresh token",
				LogSeverity:    zap.WarnLevel,
			})

		h := NewHandler(mockservice, mockUserRepository)

		app := fiber.New(fiber.Config{
			ErrorHandler: cerror.Middleware,
		})
		app.Get(
			"/user/refreshToken/:refreshToken",
			h.AuthenticationMiddleware,
			h.GetAccessTokenViaRefreshToken,
		)

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
	TestUserModel := &UpdateUserByIdPayload{
		Id:       TestUserId,
		Name:     TestUserName,
		Email:    TestUserEmail,
		Password: TestUserPassword,
	}

	mockController := gomock.NewController(t)
	defer mockController.Finish()

	t.Run("happy path", func(t *testing.T) {
		mockservice := NewMockService(mockController)
		mockservice.EXPECT().VerifyAccessToken(gomock.Any(), TestToken).Return(TestJwtClaims, nil)

		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.EXPECT().UpdateUserById(gomock.Any(), TestUserModel).Return(&jwt_generator.Tokens{
			AccessToken:  TestToken,
			RefreshToken: TestToken,
		}, nil)

		h := NewHandler(mockservice, mockUserRepository)

		app := fiber.New()
		app.Patch("/user", h.AuthenticationMiddleware, h.UpdateUserById)

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
		mockservice := NewMockService(mockController)
		mockservice.EXPECT().VerifyAccessToken(gomock.Any(), TestToken).Return(TestJwtClaims, nil)

		h := NewHandler(mockservice, nil)

		app := fiber.New(fiber.Config{
			ErrorHandler: cerror.Middleware,
		})
		app.Patch("/user", h.AuthenticationMiddleware, h.UpdateUserById)

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
			mockservice := NewMockService(mockController)
			mockservice.EXPECT().VerifyAccessToken(gomock.Any(), TestToken).Return(TestJwtClaims, nil)

			h := NewHandler(mockservice, nil)

			app := fiber.New(fiber.Config{
				ErrorHandler: cerror.Middleware,
			})
			app.Patch("/user", h.AuthenticationMiddleware, h.UpdateUserById)

			reqBody, err := json.Marshal(&UpdateUserByIdPayload{
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
			mockservice := NewMockService(mockController)
			mockservice.EXPECT().VerifyAccessToken(gomock.Any(), TestToken).Return(TestJwtClaims, nil)

			h := NewHandler(mockservice, nil)

			app := fiber.New(fiber.Config{
				ErrorHandler: cerror.Middleware,
			})
			app.Patch("/user", h.AuthenticationMiddleware, h.UpdateUserById)

			reqBody, err := json.Marshal(&UpdateUserByIdPayload{
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
			mockservice := NewMockService(mockController)
			mockservice.EXPECT().VerifyAccessToken(gomock.Any(), TestToken).Return(TestJwtClaims, nil)

			h := NewHandler(mockservice, nil)

			app := fiber.New(fiber.Config{
				ErrorHandler: cerror.Middleware,
			})
			app.Patch("/user", h.AuthenticationMiddleware, h.UpdateUserById)

			reqBody, err := json.Marshal(&UpdateUserByIdPayload{
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

		t.Run("at least one of user fields is full except for the userId", func(t *testing.T) {
			TestJwtTokens := &jwt_generator.Tokens{
				AccessToken:  "abcd.abcd.abcd",
				RefreshToken: "abcd.abcd.abcd",
			}

			mockService := NewMockService(mockController)
			mockService.
				EXPECT().
				VerifyAccessToken(gomock.Any(), TestToken).
				Return(TestJwtClaims, nil)

			mockRepository := NewMockRepository(mockController)
			mockRepository.
				EXPECT().
				UpdateUserById(gomock.Any(), gomock.Any()).
				Return(TestJwtTokens, nil)

			h := NewHandler(mockService, mockRepository)

			app := fiber.New()
			app.Patch("/user", h.AuthenticationMiddleware, h.UpdateUserById)

			reqBody, err := json.Marshal(&UpdateUserByIdPayload{
				Name:     TestUserName,
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
			require.NoError(t, err)

			assert.Equal(t, fiber.StatusOK, resp.StatusCode)
			assert.Equal(t, TestJwtTokens, tokens)
		})
	})

	t.Run("when user repository return error return it", func(t *testing.T) {
		mockservice := NewMockService(mockController)
		mockservice.EXPECT().VerifyAccessToken(gomock.Any(), TestToken).Return(TestJwtClaims, nil)

		mockUserRepository := NewMockRepository(mockController)
		mockUserRepository.EXPECT().UpdateUserById(gomock.Any(), TestUserModel).Return(nil, &cerror.CustomError{
			HttpStatusCode: fiber.StatusConflict,
			LogMessage:     "already exists",
			LogSeverity:    zap.WarnLevel,
		})

		h := NewHandler(mockservice, mockUserRepository)

		app := fiber.New(fiber.Config{
			ErrorHandler: cerror.Middleware,
		})
		app.Patch("/user", h.AuthenticationMiddleware, h.UpdateUserById)

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
