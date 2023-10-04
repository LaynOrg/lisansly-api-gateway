package user

import (
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"api-gateway/pkg/cerror"
	"api-gateway/pkg/jwt_generator"
	"api-gateway/pkg/logger"
)

type Handler interface {
	AuthenticationMiddleware(ctx *fiber.Ctx) error
	Register(ctx *fiber.Ctx) error
	Login(ctx *fiber.Ctx) error
	GetAccessTokenViaRefreshToken(ctx *fiber.Ctx) error
	UpdateUserById(ctx *fiber.Ctx) error
}

type handler struct {
	service        Service
	userRepository Repository
	validate       *validator.Validate
}

func NewHandler(service Service, userRepository Repository) Handler {
	validate := validator.New()
	return &handler{
		service:        service,
		userRepository: userRepository,
		validate:       validate,
	}
}

func (h *handler) AuthenticationMiddleware(ctx *fiber.Ctx) error {
	var err error

	log := logger.FromContext(ctx.Context()).
		With(zap.String("eventName", "authenticationMiddleware"))
	logger.InjectContext(ctx.Context(), log)

	requestHeaders := ctx.GetReqHeaders()
	authorizationHeader := requestHeaders[fiber.HeaderAuthorization]
	authorizationHeaderLength := len([]rune(authorizationHeader))
	if authorizationHeaderLength == 0 {
		return &cerror.CustomError{
			HttpStatusCode: fiber.StatusUnauthorized,
			LogMessage:     "access token not found in authorization header",
			LogSeverity:    zapcore.WarnLevel,
		}
	}

	accessToken := authorizationHeader[7:authorizationHeaderLength]
	var jwtClaims *jwt_generator.Claims
	jwtClaims, err = h.service.VerifyAccessToken(ctx.Context(), accessToken)
	if err != nil {
		return err
	}

	userId := jwtClaims.Subject
	ctx.Locals(ContextKeyUserId, userId)

	log.With(
		zap.String("authorizationHeader", authorizationHeader),
	).Info("authenticated")
	return ctx.Next()
}

func (h *handler) Register(ctx *fiber.Ctx) error {
	var err error

	var user *RegisterPayload
	err = ctx.BodyParser(&user)
	if err != nil {
		cerr := cerror.ErrorBadRequest
		cerr.LogFields = []zapcore.Field{
			zap.Any("body", ctx.Body()),
		}
		return cerr
	}

	err = h.validate.Struct(user)
	if err != nil {
		cerr := cerror.ErrorBadRequest
		cerr.LogFields = []zapcore.Field{
			zap.Any("body", ctx.Body()),
		}
		return cerr
	}

	var tokens *jwt_generator.Tokens
	tokens, err = h.userRepository.Register(ctx.Context(), user)
	if err != nil {
		return err
	}

	log := logger.FromContext(ctx.Context())
	log.Info(logger.EventFinishedSuccessfully)
	return ctx.Status(fiber.StatusCreated).JSON(tokens)
}

func (h *handler) Login(ctx *fiber.Ctx) error {
	var err error

	var user *LoginPayload
	err = ctx.BodyParser(&user)
	if err != nil {
		cerr := cerror.ErrorBadRequest
		cerr.LogFields = []zapcore.Field{
			zap.Any("body", ctx.Body()),
		}
		return cerr
	}

	err = h.validate.Struct(user)
	if err != nil {
		cerr := cerror.ErrorBadRequest
		cerr.LogFields = []zapcore.Field{
			zap.Any("credentials", user),
		}
		return cerr
	}

	var tokens *jwt_generator.Tokens
	tokens, err = h.userRepository.Login(ctx.Context(), user)
	if err != nil {
		return err
	}

	log := logger.FromContext(ctx.Context())
	log.Info(logger.EventFinishedSuccessfully)
	return ctx.Status(fiber.StatusOK).JSON(tokens)
}

func (h *handler) GetAccessTokenViaRefreshToken(ctx *fiber.Ctx) error {
	var err error

	refreshToken := ctx.Params("refreshToken")
	userId, isOk := ctx.Locals(ContextKeyUserId).(string)
	if !isOk || userId == "" {
		return &cerror.CustomError{
			HttpStatusCode: fiber.StatusInternalServerError,
			LogMessage:     "userId not found in context",
			LogSeverity:    zapcore.ErrorLevel,
		}
	}

	err = h.validate.Struct(&GetAccessTokenViaRefreshTokenPayload{
		RefreshToken: refreshToken,
	})
	if err != nil {
		cerr := cerror.ErrorBadRequest
		cerr.LogFields = []zapcore.Field{
			zap.String("userId", userId),
			zap.String("refreshToken", refreshToken),
		}
		return cerr
	}

	var accessToken string
	accessToken, err = h.userRepository.GetAccessTokenViaRefreshToken(ctx.Context(), userId, refreshToken)
	if err != nil {
		return err
	}

	log := logger.FromContext(ctx.Context())
	log.Info(logger.EventFinishedSuccessfully)
	return ctx.
		Status(fiber.StatusOK).
		JSON(fiber.Map{
			"accessToken": accessToken,
		})
}

func (h *handler) UpdateUserById(ctx *fiber.Ctx) error {
	var err error

	var user *UpdateUserPayload
	err = ctx.BodyParser(&user)
	if err != nil {
		cerr := cerror.ErrorBadRequest
		cerr.LogFields = []zap.Field{
			zap.Any("body", ctx.Body()),
		}
		return cerr
	}

	err = h.validate.Struct(user)
	if err != nil {
		cerr := cerror.ErrorBadRequest
		cerr.LogFields = []zapcore.Field{
			zap.Any("body", ctx.Body()),
		}
		return cerr
	}

	userId, isOk := ctx.Locals(ContextKeyUserId).(string)
	if !isOk || userId == "" {
		return &cerror.CustomError{
			HttpStatusCode: fiber.StatusInternalServerError,
			LogMessage:     "empty user id",
			LogSeverity:    zapcore.ErrorLevel,
		}
	}

	var tokens *jwt_generator.Tokens
	tokens, err = h.userRepository.UpdateUserById(ctx.Context(), userId, user)
	if err != nil {
		return err
	}

	log := logger.FromContext(ctx.Context())
	log.Info(logger.EventFinishedSuccessfully)
	return ctx.Status(fiber.StatusOK).JSON(tokens)
}
