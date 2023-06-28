//go:build contract

package user

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/pact-foundation/pact-go/dsl"

	"api-gateway/pkg/cerror"
	"api-gateway/pkg/config"
	"api-gateway/pkg/jwt_generator"
)

func TestConsumerTest_APIGatewayToUserAPI(t *testing.T) {
	pact := &dsl.Pact{
		Consumer:          "APIGateway",
		Provider:          "UserAPI",
		PactFileWriteMode: "overwrite",
		LogLevel:          "INFO",
		PactDir:           filepath.Join("../../", "pacts"),
		LogDir:            filepath.Join("../../", "pacts/logs"),
	}
	defer pact.Teardown()

	t.Run("POST /user", func(t *testing.T) {
		TestUser := &RegisterPayload{
			Name:     TestUserName,
			Email:    TestUserEmail,
			Password: TestUserPassword,
		}

		t.Run("happy path", func(t *testing.T) {
			pact.
				AddInteraction().
				Given("Create user").
				UponReceiving("a request to create user").
				WithRequest(dsl.Request{
					Method: fiber.MethodPost,
					Path:   dsl.String("/user"),
					Headers: dsl.MapMatcher{
						fiber.HeaderContentType: dsl.String(fiber.MIMEApplicationJSON),
						fiber.HeaderAccept:      dsl.String(fiber.MIMEApplicationJSON),
					},
					Body: dsl.Match(TestUser),
				}).
				WillRespondWith(dsl.Response{
					Status: fiber.StatusCreated,
					Headers: dsl.MapMatcher{
						fiber.HeaderContentType: dsl.String(fiber.MIMEApplicationJSON),
					},
					Body: dsl.Match(&jwt_generator.Tokens{
						AccessToken:  TestToken,
						RefreshToken: TestToken,
					}),
				})

			var test = func() error {
				userRepository := NewRepository(&config.Config{
					UserApiUrl: fmt.Sprintf("http://localhost:%d", pact.Server.Port),
				})

				_, err := userRepository.Register(TestUser)
				if err != nil {
					return err
				}

				return nil
			}

			err := pact.Verify(test)
			if err != nil {
				t.Fatal(err)
			}
		})

		t.Run("when user already exists", func(t *testing.T) {
			pact.
				AddInteraction().
				Given("Create user but user already exists").
				UponReceiving("a request to create user").
				WithRequest(dsl.Request{
					Method: fiber.MethodPost,
					Path:   dsl.String("/user"),
					Headers: dsl.MapMatcher{
						fiber.HeaderContentType: dsl.String(fiber.MIMEApplicationJSON),
						fiber.HeaderAccept:      dsl.String(fiber.MIMEApplicationJSON),
					},
					Body: dsl.Match(TestUser),
				}).
				WillRespondWith(dsl.Response{
					Status: fiber.StatusConflict,
				})

			var test = func() error {
				userRepository := NewRepository(&config.Config{
					UserApiUrl: fmt.Sprintf("http://localhost:%d", pact.Server.Port),
				})

				_, err := userRepository.Register(TestUser)
				if err != nil {
					if err.(*cerror.CustomError).HttpStatusCode == fiber.StatusConflict {
						return nil
					}
					return err
				}

				return nil
			}

			err := pact.Verify(test)
			if err != nil {
				t.Fatal(err)
			}
		})
	})

	t.Run("POST /login", func(t *testing.T) {
		TestUser := &LoginPayload{
			Email:    TestUserEmail,
			Password: TestUserPassword,
		}

		t.Run("happy path", func(t *testing.T) {
			pact.
				AddInteraction().
				Given(fmt.Sprintf("Login user with %s id", TestUserId)).
				UponReceiving("a request to login").
				WithRequest(dsl.Request{
					Method: fiber.MethodPost,
					Path:   dsl.String("/login"),
					Headers: dsl.MapMatcher{
						fiber.HeaderAccept:      dsl.String(fiber.MIMEApplicationJSON),
						fiber.HeaderContentType: dsl.String(fiber.MIMEApplicationJSON),
					},
					Body: dsl.Match(TestUser),
				}).
				WillRespondWith(dsl.Response{
					Status: fiber.StatusOK,
					Headers: dsl.MapMatcher{
						fiber.HeaderContentType: dsl.String(fiber.MIMEApplicationJSON),
					},
					Body: dsl.Match(&jwt_generator.Tokens{
						AccessToken:  TestToken,
						RefreshToken: TestToken,
					}),
				})

			var test = func() error {
				userRepository := NewRepository(&config.Config{
					UserApiUrl: fmt.Sprintf("http://localhost:%d", pact.Server.Port),
				})

				_, err := userRepository.Login(TestUser)
				if err != nil {
					return err
				}

				return nil
			}

			err := pact.Verify(test)
			if err != nil {
				t.Fatal(err)
			}
		})
	})

	t.Run("GET /user/:userId", func(t *testing.T) {
		t.Run("happy path", func(t *testing.T) {
			pact.
				AddInteraction().
				Given(fmt.Sprintf("User with %s id exits", TestUserId)).
				UponReceiving("a request to get user by id").
				WithRequest(dsl.Request{
					Method: fiber.MethodGet,
					Path:   dsl.String(fmt.Sprintf("/user/%s", TestUserId)),
					Headers: dsl.MapMatcher{
						fiber.HeaderAccept: dsl.String(fiber.MIMEApplicationJSON),
					},
				}).
				WillRespondWith(dsl.Response{
					Status: fiber.StatusOK,
					Headers: dsl.MapMatcher{
						fiber.HeaderContentType: dsl.String(fiber.MIMEApplicationJSON),
					},
					Body: dsl.MapMatcher{
						"_id":       dsl.Like(TestUserId),
						"name":      dsl.Like(TestUserName),
						"email":     dsl.Like(TestUserEmail),
						"password":  dsl.Like(TestUserPassword),
						"role":      dsl.Like(RoleUser),
						"createdAt": dsl.Like(time.Now().UTC()),
					},
				})

			var test = func() error {
				userRepository := NewRepository(&config.Config{
					UserApiUrl: fmt.Sprintf("http://localhost:%d", pact.Server.Port),
				})

				_, err := userRepository.GetUserById(TestUserId)
				if err != nil {
					return err
				}

				return nil
			}

			err := pact.Verify(test)
			if err != nil {
				t.Fatal(err)
			}
		})

		t.Run("when user not found", func(t *testing.T) {
			pact.
				AddInteraction().
				Given(fmt.Sprintf("User with %s id not exists", TestUserId)).
				UponReceiving("a request to get user by id").
				WithRequest(dsl.Request{
					Method: fiber.MethodGet,
					Path:   dsl.String(fmt.Sprintf("/user/%s", TestUserId)),
					Headers: dsl.MapMatcher{
						fiber.HeaderAccept: dsl.String(fiber.MIMEApplicationJSON),
					},
				}).
				WillRespondWith(dsl.Response{
					Status: fiber.StatusNotFound,
				})

			var test = func() error {
				userRepository := NewRepository(&config.Config{
					UserApiUrl: fmt.Sprintf("http://localhost:%d", pact.Server.Port),
				})

				_, err := userRepository.GetUserById(TestUserId)
				if err != nil {
					if err.(*cerror.CustomError).HttpStatusCode == fiber.StatusNotFound {
						return nil
					}
					return err
				}

				return nil
			}

			err := pact.Verify(test)
			if err != nil {
				t.Fatal(err)
			}
		})
	})

	t.Run("PATCH /user/:userId", func(t *testing.T) {
		TestUser := &UpdateUserPayload{
			Name:     TestUserName,
			Email:    TestUserEmail,
			Password: TestUserPassword,
		}

		t.Run("happy path", func(t *testing.T) {
			pact.
				AddInteraction().
				Given(fmt.Sprintf("Update user with %s id", TestUserId)).
				UponReceiving("a request to update user info").
				WithRequest(dsl.Request{
					Method: fiber.MethodPatch,
					Path:   dsl.String(fmt.Sprintf("/user/%s", TestUserId)),
					Headers: dsl.MapMatcher{
						fiber.HeaderAccept: dsl.String(fiber.MIMEApplicationJSON),
					},
					Body: dsl.Match(TestUser),
				}).
				WillRespondWith(dsl.Response{
					Status: fiber.StatusOK,
					Headers: dsl.MapMatcher{
						fiber.HeaderContentType: dsl.String(fiber.MIMEApplicationJSON),
					},
					Body: dsl.Match(&jwt_generator.Tokens{
						AccessToken:  TestToken,
						RefreshToken: TestToken,
					}),
				})

			var test = func() error {
				userRepository := NewRepository(&config.Config{
					UserApiUrl: fmt.Sprintf("http://localhost:%d", pact.Server.Port),
				})

				_, err := userRepository.UpdateUserById(TestUserId, TestUser)
				if err != nil {
					return err
				}

				return nil
			}

			err := pact.Verify(test)
			if err != nil {
				t.Fatal(err)
			}
		})
	})
}
