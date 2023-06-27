package user

import (
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"api-gateway/pkg/cerror"
	"api-gateway/pkg/jwt_generator"
	"api-gateway/pkg/logger"
	"api-gateway/pkg/server"
)

type handler struct {
	userService    Service
	userRepository Repository
	validate       *validator.Validate
}

type Handler interface {
	server.Handler
	AuthenticationMiddleware(ctx *fiber.Ctx) error
	Register(ctx *fiber.Ctx) error
	Login(ctx *fiber.Ctx) error
	GetAccessTokenByRefreshToken(ctx *fiber.Ctx) error
	UpdateUserById(ctx *fiber.Ctx) error
}

func NewHandler(userService Service, userRepository Repository) Handler {
	validate := validator.New()
	return &handler{
		userService:    userService,
		userRepository: userRepository,
		validate:       validate,
	}
}

func (h *handler) RegisterRoutes(app *fiber.App) {
	app.Post("/register", h.Register)
	app.Post("/login", h.Login)
	app.Get("/user/refreshToken/:refreshToken", h.AuthenticationMiddleware, h.GetAccessTokenByRefreshToken)
	app.Patch("/user", h.AuthenticationMiddleware, h.UpdateUserById)
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
	jwtClaims, err = h.userService.VerifyAccessToken(accessToken)
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

	log := logger.FromContext(ctx.Context()).
		With(zap.String("eventName", "register"))
	logger.InjectContext(ctx.Context(), log)

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
	tokens, err = h.userRepository.Register(user)
	if err != nil {
		return err
	}

	log.Info(logger.EventFinishedSuccessfully)
	return ctx.Status(fiber.StatusCreated).JSON(tokens)
}

func (h *handler) Login(ctx *fiber.Ctx) error {
	var err error

	log := logger.FromContext(ctx.Context()).
		With(zap.String("eventName", "login"))
	logger.InjectContext(ctx.Context(), log)

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
	tokens, err = h.userRepository.Login(user)
	if err != nil {
		return err
	}

	log.Info(logger.EventFinishedSuccessfully)
	return ctx.Status(fiber.StatusOK).JSON(tokens)
}

func (h *handler) GetAccessTokenByRefreshToken(ctx *fiber.Ctx) error {
	var err error

	log := logger.FromContext(ctx.Context()).
		With(zap.String("eventName", "getAccessTokenByRefreshToken"))
	logger.InjectContext(ctx.Context(), log)

	refreshToken := ctx.Params("refreshToken")
	userId, isOk := ctx.Locals(ContextKeyUserId).(string)
	if !isOk || userId == "" {
		return &cerror.CustomError{
			HttpStatusCode: fiber.StatusInternalServerError,
			LogMessage:     "userId not found in context",
			LogSeverity:    zapcore.ErrorLevel,
		}
	}

	err = h.validate.Struct(&GetAccessTokenByRefreshTokenPayload{
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
	accessToken, err = h.userRepository.GetAccessTokenByRefreshToken(userId, refreshToken)
	if err != nil {
		return err
	}

	log.Info(logger.EventFinishedSuccessfully)
	return ctx.
		Status(fiber.StatusOK).
		JSON(fiber.Map{
			"accessToken": accessToken,
		})
}

func (h *handler) UpdateUserById(ctx *fiber.Ctx) error {
	var err error

	log := logger.FromContext(ctx.Context()).
		With(zap.String("eventName", "updateUserById"))
	logger.InjectContext(ctx.Context(), log)

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
	tokens, err = h.userRepository.UpdateUserById(userId, user)
	if err != nil {
		return err
	}

	log.Info(logger.EventFinishedSuccessfully)
	return ctx.Status(fiber.StatusOK).JSON(tokens)
}
