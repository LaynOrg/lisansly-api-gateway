//go:build unit

package user

import (
	"errors"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zapcore"

	"api-gateway/pkg/cerror"
	"api-gateway/pkg/jwt_generator"
)

var (
	TestJwtClaims = &jwt_generator.Claims{
		Name:  TestUserName,
		Email: TestUserPassword,
		Role:  RoleUser,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			Issuer:    jwt_generator.IssuerDefault,
			Subject:   TestUserId,
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(10 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		},
	}
)

func TestNewService(t *testing.T) {
	userService := NewService(nil, nil)
	assert.Implements(t, (*Service)(nil), userService)
}

func TestService_VerifyAccessToken(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()

	t.Run("happy path", func(t *testing.T) {
		mockJwtGenerator := jwt_generator.NewMockJwtGenerator(mockController)
		mockUserRepository := NewMockRepository(mockController)
		mockJwtGenerator.
			EXPECT().
			VerifyAccessToken(TestToken).
			Return(TestJwtClaims, nil)
		mockUserRepository.
			EXPECT().
			GetUserById(TestUserId).
			Return(&Document{
				Id:        TestUserId,
				Name:      TestUserName,
				Email:     TestUserEmail,
				Password:  TestUserPassword,
				Role:      RoleUser,
				CreatedAt: time.Now().UTC(),
			}, nil)

		userService := NewService(mockJwtGenerator, mockUserRepository)
		jwtClaims, err := userService.VerifyAccessToken(TestToken)

		assert.NoError(t, err)
		assert.Equal(t, TestJwtClaims, jwtClaims)
	})

	t.Run("when token is invalid should return error", func(t *testing.T) {
		mockJwtGenerator := jwt_generator.NewMockJwtGenerator(mockController)
		mockJwtGenerator.
			EXPECT().
			VerifyAccessToken(TestToken).
			Return(nil, errors.New("invalid token"))

		userService := NewService(mockJwtGenerator, nil)
		jwtClaims, err := userService.VerifyAccessToken(TestToken)

		assert.Error(t, err)
		assert.Empty(t, jwtClaims)
	})

	t.Run("when user is not found should return error", func(t *testing.T) {
		mockJwtGenerator := jwt_generator.NewMockJwtGenerator(mockController)
		mockUserRepository := NewMockRepository(mockController)
		mockJwtGenerator.
			EXPECT().
			VerifyAccessToken(TestToken).
			Return(TestJwtClaims, nil)
		mockUserRepository.
			EXPECT().
			GetUserById(TestUserId).
			Return(nil, &cerror.CustomError{
				HttpStatusCode: fiber.StatusNotFound,
				LogMessage:     "user not found",
				LogSeverity:    zapcore.WarnLevel,
			})

		userService := NewService(mockJwtGenerator, mockUserRepository)
		jwtClaims, err := userService.VerifyAccessToken(TestToken)

		assert.Error(t, err)
		assert.Empty(t, jwtClaims)
	})

	t.Run("when user repository method return error should return it", func(t *testing.T) {
		mockJwtGenerator := jwt_generator.NewMockJwtGenerator(mockController)
		mockUserRepository := NewMockRepository(mockController)
		mockJwtGenerator.
			EXPECT().
			VerifyAccessToken(TestToken).
			Return(TestJwtClaims, nil)
		mockUserRepository.
			EXPECT().
			GetUserById(TestUserId).
			Return(nil, &cerror.CustomError{
				HttpStatusCode: fiber.StatusInternalServerError,
				LogMessage:     "user-api error",
				LogSeverity:    zapcore.ErrorLevel,
			})

		userService := NewService(mockJwtGenerator, mockUserRepository)
		jwtClaims, err := userService.VerifyAccessToken(TestToken)

		assert.Error(t, err)
		assert.Empty(t, jwtClaims)
	})
}
