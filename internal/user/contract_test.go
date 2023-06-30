//go:build contract

package user

import (
	"fmt"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/pact-foundation/pact-go/dsl"

	"api-gateway/pkg/cerror"
	"api-gateway/pkg/config"
	"api-gateway/pkg/jwt_generator"
)

const (
	ContractTestUserId       = "abcd-abcd-abcd-abcd"
	ContractTestUserName     = "lynicis"
	ContractTestUserEmail    = "test@test.com"
	ContractTestUserPassword = "Asdf12345_"
	ContractTestToken        = "abcd.abcd.abcd"
)

func TestConsumerContract_APIGatewayToUserAPI(t *testing.T) {
	pact := &dsl.Pact{
		Consumer:                 "API-Gateway",
		Provider:                 "User-API",
		PactFileWriteMode:        "overwrite",
		LogLevel:                 "INFO",
		LogDir:                   filepath.Join("../../", "pacts/logs"),
		PactDir:                  filepath.Join("../../", "pacts"),
		DisableToolValidityCheck: true,
	}
	defer pact.Teardown()

	t.Run("POST /user", func(t *testing.T) {
		TestUser := &RegisterPayload{
			Name:     ContractTestUserName,
			Email:    ContractTestUserEmail,
			Password: ContractTestUserPassword,
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
					Body: dsl.Like(TestUser),
				}).
				WillRespondWith(dsl.Response{
					Status: fiber.StatusCreated,
					Headers: dsl.MapMatcher{
						fiber.HeaderContentType: dsl.String(fiber.MIMEApplicationJSON),
					},
					Body: dsl.Like(&jwt_generator.Tokens{
						AccessToken:  ContractTestToken,
						RefreshToken: ContractTestToken,
					}),
				})

			var test = func() error {
				userRepository := NewRepository(&config.Config{
					UserApiUrl: &url.URL{
						Scheme: "http",
						Host:   fmt.Sprintf("localhost:%d", pact.Server.Port),
					},
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
					Body: dsl.Like(TestUser),
				}).
				WillRespondWith(dsl.Response{
					Status: fiber.StatusConflict,
				})

			var test = func() error {
				userRepository := NewRepository(&config.Config{
					UserApiUrl: &url.URL{
						Scheme: "http",
						Host:   fmt.Sprintf("localhost:%d", pact.Server.Port),
					},
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
			Email:    ContractTestUserEmail,
			Password: ContractTestUserPassword,
		}

		t.Run("happy path", func(t *testing.T) {
			pact.
				AddInteraction().
				Given(fmt.Sprintf("Login user with %s id", ContractTestUserId)).
				UponReceiving("a request to get access token and refresh token via login").
				WithRequest(dsl.Request{
					Method: fiber.MethodPost,
					Path:   dsl.String("/login"),
					Headers: dsl.MapMatcher{
						fiber.HeaderAccept:      dsl.String(fiber.MIMEApplicationJSON),
						fiber.HeaderContentType: dsl.String(fiber.MIMEApplicationJSON),
					},
					Body: dsl.Like(TestUser),
				}).
				WillRespondWith(dsl.Response{
					Status: fiber.StatusOK,
					Headers: dsl.MapMatcher{
						fiber.HeaderContentType: dsl.String(fiber.MIMEApplicationJSON),
					},
					Body: dsl.Like(&jwt_generator.Tokens{
						AccessToken:  ContractTestToken,
						RefreshToken: ContractTestToken,
					}),
				})

			var test = func() error {
				userRepository := NewRepository(&config.Config{
					UserApiUrl: &url.URL{
						Scheme: "http",
						Host:   fmt.Sprintf("localhost:%d", pact.Server.Port),
					},
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

		t.Run("invalid credentials", func(t *testing.T) {
			pact.
				AddInteraction().
				Given(fmt.Sprintf("Login user with %s id credentials is not valid", ContractTestUserId)).
				UponReceiving("a request to get access token and refresh token via login").
				WithRequest(dsl.Request{
					Method: fiber.MethodPost,
					Path:   dsl.String("/login"),
					Headers: dsl.MapMatcher{
						fiber.HeaderAccept:      dsl.String(fiber.MIMEApplicationJSON),
						fiber.HeaderContentType: dsl.String(fiber.MIMEApplicationJSON),
					},
					Body: dsl.Like(TestUser),
				}).
				WillRespondWith(dsl.Response{
					Status: fiber.StatusOK,
					Headers: dsl.MapMatcher{
						fiber.HeaderContentType: dsl.String(fiber.MIMEApplicationJSON),
					},
					Body: dsl.Like(&jwt_generator.Tokens{
						AccessToken:  ContractTestToken,
						RefreshToken: ContractTestToken,
					}),
				})

			var test = func() error {
				userRepository := NewRepository(&config.Config{
					UserApiUrl: &url.URL{
						Scheme: "http",
						Host:   fmt.Sprintf("localhost:%d", pact.Server.Port),
					},
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
				Given(fmt.Sprintf("User with %s id exits", ContractTestUserId)).
				UponReceiving("a request to get user by id").
				WithRequest(dsl.Request{
					Method: fiber.MethodGet,
					Path:   dsl.String(fmt.Sprintf("/user/%s", ContractTestUserId)),
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
						"_id":       dsl.Like(ContractTestUserId),
						"name":      dsl.Like(ContractTestUserName),
						"email":     dsl.Like(ContractTestUserEmail),
						"password":  dsl.Like(ContractTestUserPassword),
						"role":      dsl.Like(RoleUser),
						"createdAt": dsl.Like(time.Now().UTC()),
					},
				})

			var test = func() error {
				userRepository := NewRepository(&config.Config{
					UserApiUrl: &url.URL{
						Scheme: "http",
						Host:   fmt.Sprintf("localhost:%d", pact.Server.Port),
					},
				})

				_, err := userRepository.GetUserById(ContractTestUserId)
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
				Given(fmt.Sprintf("User with %s id not exists", ContractTestUserId)).
				UponReceiving("a request to get user by id").
				WithRequest(dsl.Request{
					Method: fiber.MethodGet,
					Path:   dsl.String(fmt.Sprintf("/user/%s", ContractTestUserId)),
					Headers: dsl.MapMatcher{
						fiber.HeaderAccept: dsl.String(fiber.MIMEApplicationJSON),
					},
				}).
				WillRespondWith(dsl.Response{
					Status: fiber.StatusNotFound,
				})

			var test = func() error {
				userRepository := NewRepository(&config.Config{
					UserApiUrl: &url.URL{
						Scheme: "http",
						Host:   fmt.Sprintf("localhost:%d", pact.Server.Port),
					},
				})

				_, err := userRepository.GetUserById(ContractTestUserId)
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
			Name:     ContractTestUserName,
			Email:    ContractTestUserEmail,
			Password: ContractTestUserPassword,
		}

		t.Run("happy path", func(t *testing.T) {
			pact.
				AddInteraction().
				Given(fmt.Sprintf("Update user with %s id", ContractTestUserId)).
				UponReceiving("a request to update user info and getting access token and refresh token").
				WithRequest(dsl.Request{
					Method: fiber.MethodPatch,
					Path:   dsl.String(fmt.Sprintf("/user/%s", ContractTestUserId)),
					Headers: dsl.MapMatcher{
						fiber.HeaderAccept:      dsl.String(fiber.MIMEApplicationJSON),
						fiber.HeaderContentType: dsl.String(fiber.MIMEApplicationJSON),
					},
					Body: dsl.Like(TestUser),
				}).
				WillRespondWith(dsl.Response{
					Status: fiber.StatusOK,
					Headers: dsl.MapMatcher{
						fiber.HeaderContentType: dsl.String(fiber.MIMEApplicationJSON),
					},
					Body: dsl.Like(&jwt_generator.Tokens{
						AccessToken:  ContractTestToken,
						RefreshToken: ContractTestToken,
					}),
				})

			var test = func() error {
				userRepository := NewRepository(&config.Config{
					UserApiUrl: &url.URL{
						Scheme: "http",
						Host:   fmt.Sprintf("localhost:%d", pact.Server.Port),
					},
				})

				_, err := userRepository.UpdateUserById(ContractTestUserId, TestUser)
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

		t.Run("email already exists", func(t *testing.T) {
			pact.
				AddInteraction().
				Given(fmt.Sprintf("Update user with %s id and %s email but email already exists", ContractTestUserId, ContractTestUserEmail)).
				UponReceiving("a request to update user info and getting access token and refresh token").
				WithRequest(dsl.Request{
					Method: fiber.MethodPatch,
					Path:   dsl.String(fmt.Sprintf("/user/%s", ContractTestUserId)),
					Headers: dsl.MapMatcher{
						fiber.HeaderAccept:      dsl.String(fiber.MIMEApplicationJSON),
						fiber.HeaderContentType: dsl.String(fiber.MIMEApplicationJSON),
					},
					Body: dsl.Like(TestUser),
				}).
				WillRespondWith(dsl.Response{
					Status: fiber.StatusConflict,
				})

			var test = func() error {
				userRepository := NewRepository(&config.Config{
					UserApiUrl: &url.URL{
						Scheme: "http",
						Host:   fmt.Sprintf("localhost:%d", pact.Server.Port),
					},
				})

				_, err := userRepository.UpdateUserById(ContractTestUserId, TestUser)
				if err == nil {
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
}
