package user

import (
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"go.uber.org/zap"

	"api-gateway/pkg/cerror"
	"api-gateway/pkg/jwt_generator"
	"api-gateway/pkg/logger"
)

type Handler interface {
	AuthenticationMiddleware(ctx *fiber.Ctx) error
	Register(ctx *fiber.Ctx) error
	Login(ctx *fiber.Ctx) error
	GetAccessTokenByRefreshToken(ctx *fiber.Ctx) error
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

	authorizationHeader := ctx.Get(fiber.HeaderAuthorization)
	authorizationHeaderLength := len(authorizationHeader)
	if authorizationHeaderLength == 0 {
		return &cerror.CustomError{
			HttpStatusCode: fiber.StatusUnauthorized,
			LogMessage:     "access token not found in authorization header",
			LogSeverity:    zap.WarnLevel,
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

func (h *handler) Register(fiberCtx *fiber.Ctx) error {
	var err error

	var user *RegisterPayload
	err = fiberCtx.BodyParser(&user)
	if err != nil {
		cerr := cerror.ErrorBadRequest
		cerr.LogFields = []zap.Field{
			zap.Any("body", fiberCtx.Body()),
		}
		return cerr
	}

	err = h.validate.Struct(user)
	if err != nil {
		cerr := cerror.ErrorBadRequest
		cerr.LogFields = []zap.Field{
			zap.Any("body", fiberCtx.Body()),
		}
		return cerr
	}

	requestCtx := fiberCtx.Context()
	var tokens *jwt_generator.Tokens
	tokens, err = h.userRepository.Register(requestCtx, user)
	if err != nil {
		return err
	}

	log := logger.FromContext(requestCtx)
	log.Info(logger.EventFinished)
	return fiberCtx.Status(fiber.StatusCreated).JSON(tokens)
}

func (h *handler) Login(fiberCtx *fiber.Ctx) error {
	var err error

	var user *LoginPayload
	err = fiberCtx.BodyParser(&user)
	if err != nil {
		cerr := cerror.ErrorBadRequest
		cerr.LogFields = []zap.Field{
			zap.Any("body", fiberCtx.Body()),
		}
		return cerr
	}

	err = h.validate.Struct(user)
	if err != nil {
		cerr := cerror.ErrorBadRequest
		cerr.LogFields = []zap.Field{
			zap.Any("credentials", user),
		}
		return cerr
	}

	requestCtx := fiberCtx.Context()
	var tokens *jwt_generator.Tokens
	tokens, err = h.userRepository.Login(requestCtx, user)
	if err != nil {
		return err
	}

	log := logger.FromContext(requestCtx)
	log.Info(logger.EventFinished)
	return fiberCtx.Status(fiber.StatusOK).JSON(tokens)
}

func (h *handler) GetAccessTokenByRefreshToken(fiberCtx *fiber.Ctx) error {
	var err error

	refreshToken := fiberCtx.Params("refreshToken")
	userId, isOk := fiberCtx.Locals(ContextKeyUserId).(string)
	if !isOk || userId == "" {
		return &cerror.CustomError{
			HttpStatusCode: fiber.StatusInternalServerError,
			LogMessage:     "userId not found in context",
			LogSeverity:    zap.ErrorLevel,
		}
	}

	err = h.validate.Struct(&GetAccessTokenByRefreshTokenPayload{
		RefreshToken: refreshToken,
	})
	if err != nil {
		cerr := cerror.ErrorBadRequest
		cerr.LogFields = []zap.Field{
			zap.String("userId", userId),
			zap.String("refreshToken", refreshToken),
		}
		return cerr
	}

	requestCtx := fiberCtx.Context()
	var accessToken string
	accessToken, err = h.userRepository.getAccessTokenByRefreshToken(requestCtx, userId, refreshToken)
	if err != nil {
		return err
	}

	log := logger.FromContext(requestCtx)
	log.Info(logger.EventFinished)
	return fiberCtx.
		Status(fiber.StatusOK).
		JSON(fiber.Map{
			"accessToken": accessToken,
		})
}

func (h *handler) UpdateUserById(fiberCtx *fiber.Ctx) error {
	var err error

	var user *UpdateUserByIdPayload
	err = fiberCtx.BodyParser(&user)
	if err != nil {
		cerr := cerror.ErrorBadRequest
		cerr.LogFields = []zap.Field{
			zap.Any("body", fiberCtx.Body()),
			zap.Error(err),
		}
		return cerr
	}

	err = h.validate.Struct(user)
	if err != nil {
		cerr := cerror.ErrorBadRequest
		cerr.LogFields = []zap.Field{
			zap.Any("body", fiberCtx.Body()),
			zap.Error(err),
		}
		return cerr
	}

	userId, isOk := fiberCtx.Locals(ContextKeyUserId).(string)
	if !isOk || userId == "" {
		return &cerror.CustomError{
			HttpStatusCode: fiber.StatusInternalServerError,
			LogMessage:     "empty user id",
			LogSeverity:    zap.ErrorLevel,
		}
	}

	user = &UpdateUserByIdPayload{
		Id:       userId,
		Name:     user.Name,
		Email:    user.Email,
		Password: user.Password,
	}

	requestCtx := fiberCtx.Context()
	var tokens *jwt_generator.Tokens
	tokens, err = h.userRepository.UpdateUserById(requestCtx, user)
	if err != nil {
		return err
	}

	log := logger.FromContext(requestCtx)
	log.Info(logger.EventFinished)
	return fiberCtx.Status(fiber.StatusOK).JSON(tokens)
}
