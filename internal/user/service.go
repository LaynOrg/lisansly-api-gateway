package user

import (
	"context"
	"errors"
	"net/http"

	"go.uber.org/zap/zapcore"

	"api-gateway/pkg/cerror"
	"api-gateway/pkg/jwt_generator"
)

type Service interface {
	VerifyAccessToken(ctx context.Context, accessToken string) (*jwt_generator.Claims, error)
}

type service struct {
	jwtGenerator   jwt_generator.JwtGenerator
	userRepository Repository
}

func NewService(jwtGenerator jwt_generator.JwtGenerator, userRepository Repository) Service {
	return &service{
		jwtGenerator:   jwtGenerator,
		userRepository: userRepository,
	}
}

func (s *service) VerifyAccessToken(
	ctx context.Context,
	accessToken string,
) (*jwt_generator.Claims, error) {
	var err error

	var jwtClaims *jwt_generator.Claims
	jwtClaims, err = s.jwtGenerator.VerifyAccessToken(accessToken)
	if err != nil {
		return nil, &cerror.CustomError{
			HttpStatusCode: http.StatusUnauthorized,
			LogMessage:     err.Error(),
			LogSeverity:    zapcore.WarnLevel,
		}
	}

	userId := jwtClaims.Subject
	_, err = s.userRepository.GetUserById(ctx, userId)
	if err != nil {
		var cerr *cerror.CustomError
		errors.As(err, &cerr)

		if cerr.HttpStatusCode == http.StatusNotFound {
			return nil, &cerror.CustomError{
				HttpStatusCode: http.StatusUnauthorized,
				LogMessage:     "user not found email in jwt claims",
				LogSeverity:    zapcore.WarnLevel,
			}
		}

		return nil, err
	}

	return jwtClaims, nil
}
