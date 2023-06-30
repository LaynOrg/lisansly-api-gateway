//go:build unit

package user

import (
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"

	"api-gateway/pkg/cerror"
	"api-gateway/pkg/config"
	"api-gateway/pkg/jwt_generator"
	"api-gateway/pkg/server"
)

const (
	TestUserName     = "lynicis"
	TestUserEmail    = "test@test.com"
	TestUserPassword = "Asdf12345_"

	TestToken = "abcd.abcd.abcd"
)

func TestNewRepository(t *testing.T) {
	userRepository := NewRepository(nil)
	assert.Implements(t, (*Repository)(nil), userRepository)
}

func TestRepository_GetUserById(t *testing.T) {
	TestUserDocument := &Document{
		Id:        "123",
		Name:      TestUserName,
		Email:     TestUserEmail,
		Password:  TestUserPassword,
		Role:      RoleUser,
		CreatedAt: time.Now().UTC(),
	}

	t.Run("happy path", func(t *testing.T) {
		port := getFreePort()
		srv := server.NewServer(&config.Config{
			ServerPort: port,
		}, nil)
		app := srv.GetFiberInstance()
		app.Get("/user/:id", func(ctx *fiber.Ctx) error {
			return ctx.Status(fiber.StatusOK).JSON(TestUserDocument)
		})

		go srv.Start()
		defer srv.Shutdown()
		time.Sleep(1 * time.Second)

		userRepository := NewRepository(&config.Config{
			UserApiUrl: fmt.Sprintf("http://localhost:%s", port),
		})
		user, err := userRepository.GetUserById(TestUserId)

		assert.NoError(t, err)
		assert.Equal(t, TestUserDocument, user)
	})

	t.Run("request parse error", func(t *testing.T) {
		userRepository := NewRepository(&config.Config{
			UserApiUrl: "protocol://localhost:8080",
		})
		user, err := userRepository.GetUserById(TestUserId)
		cerr := err.(*cerror.CustomError)

		assert.Error(t, err)
		assert.Equal(t, fiber.StatusInternalServerError, cerr.HttpStatusCode)
		assert.Equal(t, "error occurred while parse request", cerr.LogMessage)
		assert.Empty(t, user)
	})

	t.Run("make request error", func(t *testing.T) {
		userRepository := NewRepository(&config.Config{
			UserApiUrl: "ambiguous-url",
		})
		user, err := userRepository.GetUserById(TestUserId)
		cerr := err.(*cerror.CustomError)

		assert.Error(t, err)
		assert.Empty(t, user)
		assert.Equal(t, "error occurred while make request", cerr.LogMessage)
		assert.Equal(t, fiber.StatusInternalServerError, cerr.HttpStatusCode)
	})

	t.Run("user not found", func(t *testing.T) {
		port := getFreePort()
		srv := server.NewServer(&config.Config{
			ServerPort: port,
		}, nil)
		app := srv.GetFiberInstance()
		app.Get("/user/:id", func(ctx *fiber.Ctx) error {
			return ctx.SendStatus(fiber.StatusNotFound)
		})

		go srv.Start()
		defer srv.Shutdown()
		time.Sleep(1 * time.Second)

		userRepository := NewRepository(&config.Config{
			UserApiUrl: fmt.Sprintf("http://localhost:%s", port),
		})
		user, err := userRepository.GetUserById(TestUserId)

		assert.Error(t, err)
		assert.Empty(t, user)
		assert.Equal(t, "user not found", err.(*cerror.CustomError).LogMessage)
		assert.Equal(t, fiber.StatusNotFound, err.(*cerror.CustomError).HttpStatusCode)
	})

	t.Run("user-api returns unexpected status code", func(t *testing.T) {
		port := getFreePort()
		srv := server.NewServer(&config.Config{
			ServerPort: port,
		}, nil)
		app := srv.GetFiberInstance()
		app.Get("/user/:id", func(ctx *fiber.Ctx) error {
			return ctx.SendStatus(fiber.StatusInternalServerError)
		})

		go srv.Start()
		defer srv.Shutdown()
		time.Sleep(1 * time.Second)

		userRepository := NewRepository(&config.Config{
			UserApiUrl: fmt.Sprintf("http://localhost:%s", port),
		})
		user, err := userRepository.GetUserById(TestUserId)

		assert.Error(t, err)
		assert.Empty(t, user)
		assert.Equal(t, "user-api return error", err.(*cerror.CustomError).LogMessage)
		assert.Equal(t, fiber.StatusInternalServerError, err.(*cerror.CustomError).HttpStatusCode)
	})

	t.Run("user-api returns invalid body", func(t *testing.T) {
		port := getFreePort()
		srv := server.NewServer(&config.Config{
			ServerPort: port,
		}, nil)
		app := srv.GetFiberInstance()
		app.Get("/user/:id", func(ctx *fiber.Ctx) error {
			return ctx.Status(fiber.StatusOK).SendString("invalid body")
		})

		go srv.Start()
		defer srv.Shutdown()
		time.Sleep(1 * time.Second)

		userRepository := NewRepository(&config.Config{
			UserApiUrl: fmt.Sprintf("http://localhost:%s", port),
		})
		user, err := userRepository.GetUserById(TestUserId)
		cerr := err.(*cerror.CustomError)

		assert.Error(t, err)
		assert.Equal(t, "error occurred while unmarshal response body", cerr.LogMessage)
		assert.Equal(t, fiber.StatusInternalServerError, cerr.HttpStatusCode)
		assert.Empty(t, user)
	})
}

func TestRepository_Register(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		port := getFreePort()
		srv := server.NewServer(&config.Config{
			ServerPort: port,
		}, nil)
		app := srv.GetFiberInstance()
		app.Post("/user", func(ctx *fiber.Ctx) error {
			return ctx.Status(fiber.StatusCreated).JSON(&jwt_generator.Tokens{
				AccessToken:  TestToken,
				RefreshToken: TestToken,
			})
		})

		go srv.Start()
		defer srv.Shutdown()
		time.Sleep(1 * time.Second)

		userRepository := NewRepository(&config.Config{
			UserApiUrl: fmt.Sprintf("http://localhost:%s", port),
		})
		tokens, err := userRepository.Register(&RegisterPayload{
			Name:     TestUserName,
			Email:    TestUserEmail,
			Password: TestUserPassword,
		})

		assert.NoError(t, err)
		assert.Equal(t, &jwt_generator.Tokens{
			AccessToken:  TestToken,
			RefreshToken: TestToken,
		}, tokens)
	})

	t.Run("request parse error", func(t *testing.T) {
		userRepository := NewRepository(&config.Config{
			UserApiUrl: "protocol://localhost:8080",
		})
		tokens, err := userRepository.Register(&RegisterPayload{
			Name:     TestUserName,
			Email:    TestUserEmail,
			Password: TestUserPassword,
		})
		cerr := err.(*cerror.CustomError)

		assert.Error(t, err)
		assert.Equal(t, "error occurred while parse request", cerr.LogMessage)
		assert.Equal(t, fiber.StatusInternalServerError, cerr.HttpStatusCode)
		assert.Empty(t, tokens)
	})

	t.Run("make request error", func(t *testing.T) {
		userRepository := NewRepository(&config.Config{
			UserApiUrl: "http://localhost",
		})
		tokens, err := userRepository.Register(&RegisterPayload{
			Name:     TestUserName,
			Email:    TestUserEmail,
			Password: TestUserPassword,
		})

		assert.Error(t, err)
		assert.Equal(t, "error occurred while make request", err.(*cerror.CustomError).LogMessage)
		assert.Equal(t, fiber.StatusInternalServerError, err.(*cerror.CustomError).HttpStatusCode)
		assert.Empty(t, tokens)
	})

	t.Run("user-api returns unexpected status code", func(t *testing.T) {
		port := getFreePort()
		srv := server.NewServer(&config.Config{
			ServerPort: port,
		}, nil)
		app := srv.GetFiberInstance()
		app.Post("/user", func(ctx *fiber.Ctx) error {
			return ctx.SendStatus(fiber.StatusInternalServerError)
		})

		go srv.Start()
		defer srv.Shutdown()
		time.Sleep(1 * time.Second)

		userRepository := NewRepository(&config.Config{
			UserApiUrl: fmt.Sprintf("http://localhost:%s", port),
		})
		tokens, err := userRepository.Register(&RegisterPayload{
			Name:     TestUserName,
			Email:    TestUserEmail,
			Password: TestUserPassword,
		})
		cerr := err.(*cerror.CustomError)

		assert.Error(t, err)
		assert.Equal(t, "user-api return error", cerr.LogMessage)
		assert.Equal(t, fiber.StatusInternalServerError, cerr.HttpStatusCode)
		assert.Empty(t, tokens)
	})

	t.Run("user-api returns invalid body", func(t *testing.T) {
		port := getFreePort()
		srv := server.NewServer(&config.Config{
			ServerPort: port,
		}, nil)
		app := srv.GetFiberInstance()
		app.Post("/user", func(ctx *fiber.Ctx) error {
			return ctx.Status(fiber.StatusCreated).SendString("invalid body")
		})

		go srv.Start()
		defer srv.Shutdown()
		time.Sleep(1 * time.Second)

		userRepository := NewRepository(&config.Config{
			UserApiUrl: fmt.Sprintf("http://localhost:%s", port),
		})
		tokens, err := userRepository.Register(&RegisterPayload{
			Name:     TestUserName,
			Email:    TestUserEmail,
			Password: TestUserPassword,
		})
		cerr := err.(*cerror.CustomError)

		assert.Error(t, err)
		assert.Equal(t, "error occurred while unmarshal response body", cerr.LogMessage)
		assert.Equal(t, fiber.StatusInternalServerError, cerr.HttpStatusCode)
		assert.Empty(t, tokens)
	})
}

func TestRepository_Login(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		port := getFreePort()
		srv := server.NewServer(&config.Config{
			ServerPort: port,
		}, nil)
		app := srv.GetFiberInstance()
		app.Post("/login", func(ctx *fiber.Ctx) error {
			return ctx.Status(fiber.StatusOK).JSON(&jwt_generator.Tokens{
				AccessToken:  TestToken,
				RefreshToken: TestToken,
			})
		})

		go srv.Start()
		defer srv.Shutdown()
		time.Sleep(1 * time.Second)

		userRepository := NewRepository(&config.Config{
			UserApiUrl: fmt.Sprintf("http://localhost:%s", port),
		})
		tokens, err := userRepository.Login(&LoginPayload{
			Email:    TestUserEmail,
			Password: TestUserPassword,
		})

		assert.NoError(t, err)
		assert.Equal(t, tokens, &jwt_generator.Tokens{
			AccessToken:  TestToken,
			RefreshToken: TestToken,
		})
	})

	t.Run("request parse error", func(t *testing.T) {
		userRepository := NewRepository(&config.Config{
			UserApiUrl: "protocol://localhost:8080",
		})
		tokens, err := userRepository.Login(&LoginPayload{
			Email:    TestUserEmail,
			Password: TestUserPassword,
		})
		cerr := err.(*cerror.CustomError)

		assert.Error(t, err)
		assert.Equal(t, "error occurred while parse request", cerr.LogMessage)
		assert.Equal(t, fiber.StatusInternalServerError, cerr.HttpStatusCode)
		assert.Empty(t, tokens)
	})

	t.Run("make request error", func(t *testing.T) {
		userRepository := NewRepository(&config.Config{
			UserApiUrl: "http://localhost",
		})
		tokens, err := userRepository.Login(&LoginPayload{
			Email:    TestUserEmail,
			Password: TestUserPassword,
		})
		cerr := err.(*cerror.CustomError)

		assert.Error(t, err)
		assert.Equal(t, "error occurred while make request", cerr.LogMessage)
		assert.Equal(t, fiber.StatusInternalServerError, cerr.HttpStatusCode)
		assert.Empty(t, tokens)
	})

	t.Run("user-api returns unexpected status code", func(t *testing.T) {
		port := getFreePort()
		srv := server.NewServer(&config.Config{
			ServerPort: port,
		}, nil)
		app := srv.GetFiberInstance()
		app.Post("/login", func(ctx *fiber.Ctx) error {
			return ctx.SendStatus(fiber.StatusInternalServerError)
		})

		go srv.Start()
		defer srv.Shutdown()
		time.Sleep(1 * time.Second)

		userRepository := NewRepository(&config.Config{
			UserApiUrl: fmt.Sprintf("http://localhost:%s", port),
		})
		tokens, err := userRepository.Login(&LoginPayload{
			Email:    TestUserEmail,
			Password: TestUserPassword,
		})
		cerr := err.(*cerror.CustomError)

		assert.Error(t, err)
		assert.Equal(t, "user-api return error", cerr.LogMessage)
		assert.Equal(t, fiber.StatusInternalServerError, cerr.HttpStatusCode)
		assert.Empty(t, tokens)
	})

	t.Run("user-api returns invalid body", func(t *testing.T) {
		port := getFreePort()
		srv := server.NewServer(&config.Config{
			ServerPort: port,
		}, nil)
		app := srv.GetFiberInstance()
		app.Post("/login", func(ctx *fiber.Ctx) error {
			return ctx.Status(fiber.StatusOK).Send([]byte("{'invalid':'body'}"))
		})

		go srv.Start()
		defer srv.Shutdown()
		time.Sleep(1 * time.Second)

		userRepository := NewRepository(&config.Config{
			UserApiUrl: fmt.Sprintf("http://localhost:%s", port),
		})
		tokens, err := userRepository.Login(&LoginPayload{
			Email:    TestUserEmail,
			Password: TestUserPassword,
		})
		cerr := err.(*cerror.CustomError)

		assert.Error(t, err)
		assert.Equal(t, "error occurred while unmarshal response body", cerr.LogMessage)
		assert.Equal(t, fiber.StatusInternalServerError, cerr.HttpStatusCode)
		assert.Empty(t, tokens)
	})
}

func TestRepository_GetAccessTokenByRefreshToken(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		port := getFreePort()
		srv := server.NewServer(&config.Config{
			ServerPort: port,
		}, nil)
		app := srv.GetFiberInstance()
		app.Get("/user/:userId/refreshToken/:refreshToken", func(ctx *fiber.Ctx) error {
			return ctx.Status(fiber.StatusOK).JSON(&jwt_generator.Tokens{
				AccessToken: TestToken,
			})
		})

		go srv.Start()
		defer srv.Shutdown()
		time.Sleep(1 * time.Second)

		userRepository := NewRepository(&config.Config{
			UserApiUrl: fmt.Sprintf("http://localhost:%s", port),
		})
		accessToken, err := userRepository.GetAccessTokenByRefreshToken(TestUserId, TestToken)

		assert.NoError(t, err)
		assert.Equal(t, accessToken, TestToken)
	})

	t.Run("request parse error", func(t *testing.T) {
		userRepository := NewRepository(&config.Config{
			UserApiUrl: "protocol://localhost",
		})
		accessToken, err := userRepository.GetAccessTokenByRefreshToken(TestUserId, TestToken)
		cerr := err.(*cerror.CustomError)

		assert.Error(t, err)
		assert.Equal(t, "error occurred while parse request", cerr.LogMessage)
		assert.Equal(t, fiber.StatusInternalServerError, cerr.HttpStatusCode)
		assert.Empty(t, accessToken)
	})

	t.Run("make request error", func(t *testing.T) {
		userRepository := NewRepository(&config.Config{
			UserApiUrl: "http://localhost",
		})
		accessToken, err := userRepository.GetAccessTokenByRefreshToken(TestUserId, TestToken)
		cerr := err.(*cerror.CustomError)

		assert.Error(t, err)
		assert.Equal(t, "error occurred while make request", cerr.LogMessage)
		assert.Equal(t, fiber.StatusInternalServerError, cerr.HttpStatusCode)
		assert.Empty(t, accessToken)
	})

	t.Run("user-api returns unexpected status code", func(t *testing.T) {
		port := getFreePort()
		srv := server.NewServer(&config.Config{
			ServerPort: port,
		}, nil)
		app := srv.GetFiberInstance()
		app.Get("/user/:userId/refreshToken/:refreshToken", func(ctx *fiber.Ctx) error {
			return ctx.SendStatus(fiber.StatusInternalServerError)
		})

		go srv.Start()
		defer srv.Shutdown()
		time.Sleep(1 * time.Second)

		userRepository := NewRepository(&config.Config{
			UserApiUrl: fmt.Sprintf("http://localhost:%s", port),
		})
		accessToken, err := userRepository.GetAccessTokenByRefreshToken(TestUserId, TestToken)
		cerr := err.(*cerror.CustomError)

		assert.Error(t, err)
		assert.Equal(t, "user-api return error", cerr.LogMessage)
		assert.Equal(t, fiber.StatusInternalServerError, cerr.HttpStatusCode)
		assert.Empty(t, accessToken)
	})

	t.Run("user-api returns ambiguous body", func(t *testing.T) {
		port := getFreePort()
		srv := server.NewServer(&config.Config{
			ServerPort: port,
		}, nil)
		app := srv.GetFiberInstance()
		app.Get("/user/:userId/refreshToken/:refreshToken", func(ctx *fiber.Ctx) error {
			return ctx.Status(fiber.StatusOK).SendString("invalid body")
		})

		go srv.Start()
		defer srv.Shutdown()
		time.Sleep(1 * time.Second)

		userRepository := NewRepository(&config.Config{
			UserApiUrl: fmt.Sprintf("http://localhost:%s", port),
		})
		accessToken, err := userRepository.GetAccessTokenByRefreshToken(TestUserId, TestToken)
		cerr := err.(*cerror.CustomError)

		assert.Error(t, err)
		assert.Equal(t, "error occurred while unmarshal response body", cerr.LogMessage)
		assert.Equal(t, fiber.StatusInternalServerError, cerr.HttpStatusCode)
		assert.Empty(t, accessToken)
	})
}

func TestRepository_UpdateUserById(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		port := getFreePort()
		srv := server.NewServer(&config.Config{
			ServerPort: port,
		}, nil)
		app := srv.GetFiberInstance()
		app.Patch("/user/:userId", func(ctx *fiber.Ctx) error {
			return ctx.Status(fiber.StatusOK).JSON(&jwt_generator.Tokens{
				AccessToken:  TestToken,
				RefreshToken: TestToken,
			})
		})

		go srv.Start()
		defer srv.Shutdown()
		time.Sleep(1 * time.Second)

		userRepository := NewRepository(&config.Config{
			UserApiUrl: fmt.Sprintf("http://localhost:%s", port),
		})
		tokens, err := userRepository.UpdateUserById(TestUserId, &UpdateUserPayload{
			Name:     TestUserName,
			Email:    TestUserEmail,
			Password: TestUserPassword,
		})

		assert.NoError(t, err)
		assert.Equal(t, &jwt_generator.Tokens{
			AccessToken:  TestToken,
			RefreshToken: TestToken,
		}, tokens)
	})

	t.Run("request parse error", func(t *testing.T) {
		userRepository := NewRepository(&config.Config{
			UserApiUrl: "protocol://localhost",
		})
		tokens, err := userRepository.UpdateUserById(TestUserId, &UpdateUserPayload{
			Name:     TestUserName,
			Email:    TestUserEmail,
			Password: TestUserPassword,
		})
		cerr := err.(*cerror.CustomError)

		assert.Error(t, err)
		assert.Equal(t, "error occurred while parse request", cerr.LogMessage)
		assert.Equal(t, fiber.StatusInternalServerError, cerr.HttpStatusCode)
		assert.Empty(t, tokens)
	})

	t.Run("make request error", func(t *testing.T) {
		userRepository := NewRepository(&config.Config{
			UserApiUrl: "http://localhost",
		})
		tokens, err := userRepository.UpdateUserById(TestUserId, &UpdateUserPayload{
			Name:     TestUserName,
			Email:    TestUserEmail,
			Password: TestUserPassword,
		})
		cerr := err.(*cerror.CustomError)

		assert.Error(t, err)
		assert.Equal(t, "error occurred while make request", cerr.LogMessage)
		assert.Equal(t, fiber.StatusInternalServerError, cerr.HttpStatusCode)
		assert.Empty(t, tokens)
	})

	t.Run("user-api returns unexpected status code", func(t *testing.T) {
		port := getFreePort()
		srv := server.NewServer(&config.Config{
			ServerPort: port,
		}, nil)
		app := srv.GetFiberInstance()
		app.Patch("/user/:userId", func(ctx *fiber.Ctx) error {
			return ctx.SendStatus(fiber.StatusInternalServerError)
		})

		go srv.Start()
		defer srv.Shutdown()
		time.Sleep(1 * time.Second)

		userRepository := NewRepository(&config.Config{
			UserApiUrl: fmt.Sprintf("http://localhost:%s", port),
		})
		tokens, err := userRepository.UpdateUserById(TestUserId, &UpdateUserPayload{
			Name:     TestUserName,
			Email:    TestUserEmail,
			Password: TestUserPassword,
		})

		assert.Error(t, err)
		assert.Equal(t, "user-api return error", err.(*cerror.CustomError).LogMessage)
		assert.Equal(t, fiber.StatusInternalServerError, err.(*cerror.CustomError).HttpStatusCode)
		assert.Empty(t, tokens)
	})

	t.Run("user-api return ambiguous body", func(t *testing.T) {
		port := getFreePort()
		srv := server.NewServer(&config.Config{
			ServerPort: port,
		}, nil)
		app := srv.GetFiberInstance()
		app.Patch("/user/:userId", func(ctx *fiber.Ctx) error {
			return ctx.Status(fiber.StatusOK).SendString("invalid body")
		})

		go srv.Start()
		defer srv.Shutdown()
		time.Sleep(1 * time.Second)

		userRepository := NewRepository(&config.Config{
			UserApiUrl: fmt.Sprintf("http://localhost:%s", port),
		})
		tokens, err := userRepository.UpdateUserById(TestUserId, &UpdateUserPayload{
			Name:     TestUserName,
			Email:    TestUserEmail,
			Password: TestUserPassword,
		})

		assert.Error(t, err)
		assert.Equal(t, "error occurred while unmarshal response body", err.(*cerror.CustomError).LogMessage)
		assert.Equal(t, fiber.StatusInternalServerError, err.(*cerror.CustomError).HttpStatusCode)
		assert.Empty(t, tokens)
	})
}

func getFreePort() string {
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		panic(err)
	}
	defer l.Close()

	port := l.Addr().(*net.TCPAddr).Port
	return strconv.Itoa(port)
}
