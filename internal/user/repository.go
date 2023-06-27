package user

import (
	"fmt"
	"time"

	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"api-gateway/pkg/cerror"
	"api-gateway/pkg/config"
	"api-gateway/pkg/jwt_generator"
)

type repository struct {
	config *config.Config
}

type Repository interface {
	GetUserById(userId string) (*Document, error)
	Register(user *RegisterPayload) (*jwt_generator.Tokens, error)
	Login(user *LoginPayload) (*jwt_generator.Tokens, error)
	GetAccessTokenByRefreshToken(userId, refreshToken string) (string, error)
	UpdateUserById(userId string, user *UpdateUserPayload) (*jwt_generator.Tokens, error)
}

func NewRepository(config *config.Config) Repository {
	return &repository{
		config: config,
	}
}

func (r *repository) GetUserById(userId string) (*Document, error) {
	var err error

	agent := fiber.AcquireAgent()
	agent.Timeout(10 * time.Second)
	req := agent.Request()
	req.Header.SetMethod(fiber.MethodGet)
	req.Header.Set(fiber.HeaderAccept, fiber.MIMEApplicationJSON)
	req.Header.SetUserAgent("API-Gateway")

	url := fmt.Sprintf("%s/user/%s", r.config.UserApiUrl, userId)
	req.SetRequestURI(url)

	err = agent.Parse()
	if err != nil {
		return nil, &cerror.CustomError{
			HttpStatusCode: fiber.StatusInternalServerError,
			LogMessage:     "error occurred while parse request",
			LogSeverity:    zapcore.ErrorLevel,
		}
	}

	statusCode, body, errs := agent.Bytes()
	if len(errs) > 0 {
		return nil, &cerror.CustomError{
			HttpStatusCode: fiber.StatusInternalServerError,
			LogMessage:     "error occurred while make request",
			LogSeverity:    zapcore.ErrorLevel,
			LogFields: []zap.Field{
				zap.Errors("errors", errs),
			},
		}
	}

	if statusCode == fiber.StatusNotFound {
		return nil, &cerror.CustomError{
			HttpStatusCode: fiber.StatusNotFound,
			LogMessage:     "user not found",
			LogSeverity:    zapcore.ErrorLevel,
		}
	}

	if statusCode != fiber.StatusOK {
		return nil, &cerror.CustomError{
			HttpStatusCode: statusCode,
			LogMessage:     "user-api return error",
			LogSeverity:    zapcore.ErrorLevel,
		}
	}

	var user *Document
	err = json.Unmarshal(body, &user)
	if err != nil {
		return nil, &cerror.CustomError{
			HttpStatusCode: fiber.StatusInternalServerError,
			LogMessage:     "error occurred while unmarshal body",
			LogSeverity:    zapcore.ErrorLevel,
			LogFields: []zap.Field{
				zap.Error(err),
			},
		}
	}

	return user, nil
}

func (r *repository) Register(user *RegisterPayload) (*jwt_generator.Tokens, error) {
	var err error

	agent := fiber.AcquireAgent()
	agent.Timeout(10 * time.Second)
	req := agent.Request()
	req.Header.SetMethod(fiber.MethodPost)
	req.Header.SetContentType(fiber.MIMEApplicationJSON)
	req.Header.Set(fiber.HeaderAccept, fiber.MIMEApplicationJSON)
	req.Header.SetUserAgent("API-Gateway")

	var requestBody []byte
	requestBody, err = json.Marshal(user)
	req.SetBody(requestBody)

	url := fmt.Sprintf("%s/user", r.config.UserApiUrl)
	req.SetRequestURI(url)

	err = agent.Parse()
	if err != nil {
		return nil, &cerror.CustomError{
			HttpStatusCode: fiber.StatusInternalServerError,
			LogMessage:     "error occurred while parse request",
			LogSeverity:    zapcore.ErrorLevel,
		}
	}

	statusCode, body, errs := agent.Bytes()
	if len(errs) > 0 {
		return nil, &cerror.CustomError{
			HttpStatusCode: fiber.StatusInternalServerError,
			LogMessage:     "error occurred while make request",
			LogSeverity:    zapcore.ErrorLevel,
			LogFields: []zap.Field{
				zap.Errors("errors", errs),
			},
		}
	}

	if statusCode != fiber.StatusCreated {
		return nil, &cerror.CustomError{
			HttpStatusCode: statusCode,
			LogMessage:     "user-api return error",
			LogSeverity:    zapcore.ErrorLevel,
		}
	}

	var tokens *jwt_generator.Tokens
	err = json.Unmarshal(body, &tokens)
	if err != nil {
		return nil, &cerror.CustomError{
			HttpStatusCode: fiber.StatusInternalServerError,
			LogMessage:     "error occurred while unmarshal body",
			LogSeverity:    zapcore.ErrorLevel,
		}
	}

	return tokens, nil
}

func (r *repository) Login(user *LoginPayload) (*jwt_generator.Tokens, error) {
	var err error

	agent := fiber.AcquireAgent()
	agent.Timeout(10 * time.Second)
	req := agent.Request()
	req.Header.SetMethod(fiber.MethodPost)
	req.Header.Set(fiber.HeaderAccept, fiber.MIMEApplicationJSON)
	req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	req.Header.SetUserAgent("API-Gateway")

	requestUrl := fmt.Sprintf(
		"%s/login",
		r.config.UserApiUrl,
	)
	req.SetRequestURI(requestUrl)

	var requestBody []byte
	requestBody, err = json.Marshal(user)
	req.SetBody(requestBody)

	err = agent.Parse()
	if err != nil {
		return nil, &cerror.CustomError{
			HttpStatusCode: fiber.StatusInternalServerError,
			LogMessage:     "error occurred while parse request",
			LogSeverity:    zapcore.ErrorLevel,
		}
	}

	statusCode, body, errs := agent.Bytes()
	if len(errs) > 0 {
		return nil, &cerror.CustomError{
			HttpStatusCode: fiber.StatusInternalServerError,
			LogMessage:     "error occurred while make request",
			LogSeverity:    zapcore.ErrorLevel,
		}
	}

	if statusCode != fiber.StatusOK {
		return nil, &cerror.CustomError{
			HttpStatusCode: statusCode,
			LogMessage:     "user-api return error",
			LogSeverity:    zapcore.ErrorLevel,
		}
	}

	var tokens *jwt_generator.Tokens
	err = json.Unmarshal(body, &tokens)
	if err != nil {
		return nil, &cerror.CustomError{
			HttpStatusCode: fiber.StatusInternalServerError,
			LogMessage:     "error occurred while unmarshal body",
			LogSeverity:    zapcore.ErrorLevel,
		}
	}

	return tokens, nil
}

func (r *repository) GetAccessTokenByRefreshToken(userId, refreshToken string) (string, error) {
	var err error

	agent := fiber.AcquireAgent()
	agent.Timeout(10 * time.Second)
	req := agent.Request()
	req.Header.SetMethod(fiber.MethodGet)
	req.Header.Set(fiber.HeaderAccept, fiber.MIMEApplicationJSON)
	req.Header.SetUserAgent("API-Gateway")

	url := fmt.Sprintf(
		"%s/user/%s/refreshToken/%s",
		r.config.UserApiUrl,
		userId,
		refreshToken,
	)
	req.SetRequestURI(url)

	err = agent.Parse()
	if err != nil {
		return "", &cerror.CustomError{
			HttpStatusCode: fiber.StatusInternalServerError,
			LogMessage:     "error occurred while parse request",
			LogSeverity:    zapcore.ErrorLevel,
		}
	}

	statusCode, body, errs := agent.Bytes()
	if len(errs) > 0 {
		return "", &cerror.CustomError{
			HttpStatusCode: fiber.StatusInternalServerError,
			LogMessage:     "error occurred while make request",
			LogSeverity:    zapcore.ErrorLevel,
			LogFields: []zap.Field{
				zap.Any("errors", errs),
			},
		}
	}

	if statusCode != fiber.StatusOK {
		return "", &cerror.CustomError{
			HttpStatusCode: statusCode,
			LogMessage:     "user-api return error",
			LogSeverity:    zapcore.ErrorLevel,
		}
	}

	var tokens *jwt_generator.Tokens
	err = json.Unmarshal(body, &tokens)
	if err != nil {
		return "", &cerror.CustomError{
			HttpStatusCode: fiber.StatusInternalServerError,
			LogMessage:     "error occurred while unmarshal body",
			LogSeverity:    zapcore.ErrorLevel,
		}
	}

	return tokens.AccessToken, nil
}

func (r *repository) UpdateUserById(userId string, user *UpdateUserPayload) (*jwt_generator.Tokens, error) {
	var err error

	agent := fiber.AcquireAgent()
	agent.Timeout(10 * time.Second)
	req := agent.Request()
	req.Header.SetMethod(fiber.MethodPatch)
	req.Header.SetContentType(fiber.MIMEApplicationJSON)
	req.Header.Set(fiber.HeaderAccept, fiber.MIMEApplicationJSON)
	req.Header.SetUserAgent("API-Gateway")

	var requestBody []byte
	requestBody, err = json.Marshal(user)
	req.SetBody(requestBody)

	url := fmt.Sprintf("%s/user/%s", r.config.UserApiUrl, userId)
	req.SetRequestURI(url)

	err = agent.Parse()
	if err != nil {
		return nil, &cerror.CustomError{
			HttpStatusCode: fiber.StatusInternalServerError,
			LogMessage:     "error occurred while parse request",
			LogSeverity:    zapcore.ErrorLevel,
		}
	}

	statusCode, body, errs := agent.Bytes()
	if len(errs) > 0 {
		return nil, &cerror.CustomError{
			HttpStatusCode: fiber.StatusInternalServerError,
			LogMessage:     "error occurred while make request",
			LogSeverity:    zapcore.ErrorLevel,
			LogFields: []zap.Field{
				zap.Any("errors", errs),
			},
		}
	}

	if statusCode != fiber.StatusOK {
		return nil, &cerror.CustomError{
			HttpStatusCode: statusCode,
			LogMessage:     "user-api return error",
			LogSeverity:    zapcore.ErrorLevel,
		}
	}

	var tokens *jwt_generator.Tokens
	err = json.Unmarshal(body, &tokens)
	if err != nil {
		return nil, &cerror.CustomError{
			HttpStatusCode: fiber.StatusInternalServerError,
			LogMessage:     "error occurred while unmarshal body",
			LogSeverity:    zapcore.ErrorLevel,
		}
	}

	return tokens, nil
}
