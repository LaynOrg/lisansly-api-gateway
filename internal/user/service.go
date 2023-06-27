package user

import (
	"github.com/gofiber/fiber/v2"
	"go.uber.org/zap/zapcore"

	"api-gateway/pkg/cerror"
	"api-gateway/pkg/jwt_generator"
)

type service struct {
	jwtGenerator   jwt_generator.JwtGenerator
	userRepository Repository
}

type Service interface {
	VerifyAccessToken(accessToken string) (*jwt_generator.Claims, error)
}

func NewService(jwtGenerator jwt_generator.JwtGenerator, userRepository Repository) Service {
	return &service{
		jwtGenerator:   jwtGenerator,
		userRepository: userRepository,
	}
}

func (s *service) VerifyAccessToken(
	accessToken string,
) (*jwt_generator.Claims, error) {
	var err error

	var jwtClaims *jwt_generator.Claims
	jwtClaims, err = s.jwtGenerator.VerifyAccessToken(accessToken)
	if err != nil {
		return nil, &cerror.CustomError{
			HttpStatusCode: fiber.StatusUnauthorized,
			LogMessage:     err.Error(),
			LogSeverity:    zapcore.WarnLevel,
		}
	}

	userId := jwtClaims.Subject
	_, err = s.userRepository.GetUserById(userId)
	if err != nil {
		statusCode := err.(*cerror.CustomError).HttpStatusCode
		if statusCode == fiber.StatusNotFound {
			return nil, &cerror.CustomError{
				HttpStatusCode: fiber.StatusUnauthorized,
				LogMessage:     "user not found email in jwt claims",
				LogSeverity:    zapcore.WarnLevel,
			}
		}

		return nil, err
	}

	return jwtClaims, nil
}
