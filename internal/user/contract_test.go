//go:build contract

package user

import (
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"
	"github.com/pact-foundation/pact-go/v2/consumer"
	"github.com/pact-foundation/pact-go/v2/matchers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	pact, err := consumer.NewV2Pact(consumer.MockHTTPProviderConfig{
		Consumer: "API-Gateway",
		Provider: "User-API",
		LogDir:   filepath.Join("../../", "pacts/logs"),
		PactDir:  filepath.Join("../../", "pacts"),
	})
	assert.NoError(t, err)

	t.Run("POST /user", func(t *testing.T) {
		TestUser := &RegisterPayload{
			Name:     ContractTestUserName,
			Email:    ContractTestUserEmail,
			Password: ContractTestUserPassword,
		}
		requestBody, err := json.Marshal(TestUser)
		require.NoError(t, err)

		t.Run("happy path", func(t *testing.T) {

			responseBody, err := json.Marshal(&jwt_generator.Tokens{
				AccessToken:  ContractTestToken,
				RefreshToken: ContractTestToken,
			})
			require.NoError(t, err)

			pact.
				AddInteraction().
				Given("Create user").
				UponReceiving("a request to create user").
				WithRequest(
					http.MethodPost,
					"/user",
					func(builder *consumer.V2RequestBuilder) {
						builder.
							Header(fiber.HeaderAccept, matchers.String(fiber.MIMEApplicationJSON)).
							Body(fiber.MIMEApplicationJSON, requestBody)
					}).
				WillRespondWith(
					fiber.StatusCreated,
					func(builder *consumer.V2ResponseBuilder) {
						builder.
							Body(fiber.MIMEApplicationJSON, responseBody)
					})

			err = pact.ExecuteTest(t, func(serverConfig consumer.MockServerConfig) error {
				userRepository := NewRepository(&config.Config{
					UserApiUrl: &url.URL{
						Scheme: "http",
						Host:   fmt.Sprintf("%s:%d", serverConfig.Host, serverConfig.Port),
					},
				})

				_, err := userRepository.Register(TestUser)
				if err != nil {
					return err
				}

				return nil
			})
			assert.NoError(t, err)
		})

		t.Run("when user already exists", func(t *testing.T) {
			pact.
				AddInteraction().
				Given("Create user but user already exists").
				UponReceiving("a request to create user").
				WithRequest(
					fiber.MethodPost,
					"/user",
					func(builder *consumer.V2RequestBuilder) {
						builder.
							Header(fiber.HeaderAccept, matchers.String(fiber.MIMEApplicationJSON)).
							Body(fiber.MIMEApplicationJSON, requestBody)
					}).
				WillRespondWith(fiber.StatusConflict)

			err := pact.ExecuteTest(t, func(serverConfig consumer.MockServerConfig) error {
				userRepository := NewRepository(&config.Config{
					UserApiUrl: &url.URL{
						Scheme: "http",
						Host:   fmt.Sprintf("%s:%d", serverConfig.Host, serverConfig.Port),
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
			})
			assert.NoError(t, err)
		})
	})

	t.Run("POST /login", func(t *testing.T) {
		TestUser := &LoginPayload{
			Email:    ContractTestUserEmail,
			Password: ContractTestUserPassword,
		}
		requestBody, err := json.Marshal(TestUser)
		require.NoError(t, err)

		t.Run("happy path", func(t *testing.T) {
			responseBody, err := json.Marshal(&jwt_generator.Tokens{
				AccessToken:  ContractTestToken,
				RefreshToken: ContractTestToken,
			})
			require.NoError(t, err)

			pact.
				AddInteraction().
				Given(fmt.Sprintf("Login user with %s id", ContractTestUserId)).
				UponReceiving("response return unauthorized").
				WithRequest(
					fiber.MethodPost,
					"/login",
					func(builder *consumer.V2RequestBuilder) {
						builder.
							Header(fiber.HeaderAccept, matchers.String(fiber.MIMEApplicationJSON)).
							Body(fiber.MIMEApplicationJSON, requestBody)
					}).
				WillRespondWith(
					fiber.StatusOK,
					func(builder *consumer.V2ResponseBuilder) {
						builder.
							Body(fiber.MIMEApplicationJSON, responseBody)
					})

			err = pact.ExecuteTest(t, func(serverConfig consumer.MockServerConfig) error {
				userRepository := NewRepository(&config.Config{
					UserApiUrl: &url.URL{
						Scheme: "http",
						Host:   fmt.Sprintf("%s:%d", serverConfig.Host, serverConfig.Port),
					},
				})

				_, err := userRepository.Login(TestUser)
				if err != nil {
					return err
				}

				return nil
			})
			assert.NoError(t, err)
		})

		t.Run("invalid credentials", func(t *testing.T) {
			pact.
				AddInteraction().
				Given(fmt.Sprintf("Login user with %s id credentials is not valid", ContractTestUserId)).
				UponReceiving("a request to get access token and refresh token via login").
				WithRequest(
					fiber.MethodPost,
					"/login",
					func(builder *consumer.V2RequestBuilder) {
						builder.
							Header(fiber.HeaderAccept, matchers.String(fiber.MIMEApplicationJSON)).
							Body(fiber.MIMEApplicationJSON, requestBody)
					}).
				WillRespondWith(fiber.StatusUnauthorized)

			err := pact.ExecuteTest(t, func(serverConfig consumer.MockServerConfig) error {
				userRepository := NewRepository(&config.Config{
					UserApiUrl: &url.URL{
						Scheme: "http",
						Host:   fmt.Sprintf("%s:%d", serverConfig.Host, serverConfig.Port),
					},
				})

				_, err := userRepository.Login(TestUser)
				if err != nil {
					if err.(*cerror.CustomError).HttpStatusCode == fiber.StatusUnauthorized {
						return nil
					}
					return err
				}

				return nil
			})
			assert.NoError(t, err)
		})
	})

	t.Run("GET /user/:userId", func(t *testing.T) {
		t.Run("happy path", func(t *testing.T) {
			user := Document{
				Id:        ContractTestUserId,
				Name:      ContractTestUserName,
				Email:     ContractTestUserEmail,
				Password:  ContractTestUserPassword,
				Role:      RoleUser,
				CreatedAt: time.Now().UTC(),
			}
			responseBody, err := json.Marshal(user)
			require.NoError(t, err)

			pact.
				AddInteraction().
				Given(fmt.Sprintf("User with %s id exits", ContractTestUserId)).
				UponReceiving("a request to get user by id").
				WithRequest(
					fiber.MethodGet,
					fmt.Sprintf("/user/%s", ContractTestUserId),
				).
				WillRespondWith(
					fiber.StatusOK,
					func(builder *consumer.V2ResponseBuilder) {
						builder.
							Body(fiber.MIMEApplicationJSON, responseBody)
					})

			err = pact.ExecuteTest(t, func(serverConfig consumer.MockServerConfig) error {
				userRepository := NewRepository(&config.Config{
					UserApiUrl: &url.URL{
						Scheme: "http",
						Host:   fmt.Sprintf("%s:%d", serverConfig.Host, serverConfig.Port),
					},
				})

				_, err := userRepository.GetUserById(ContractTestUserId)
				if err != nil {
					return err
				}

				return nil
			})
			assert.NoError(t, err)
		})

		t.Run("when user not found", func(t *testing.T) {
			pact.
				AddInteraction().
				Given(fmt.Sprintf("User with %s id not exists", ContractTestUserId)).
				UponReceiving("a request to get user by id").
				WithRequest(
					fiber.MethodGet,
					fmt.Sprintf("/user/%s", ContractTestUserId),
				).
				WillRespondWith(fiber.StatusNotFound)

			err := pact.ExecuteTest(t, func(serverConfig consumer.MockServerConfig) error {
				userRepository := NewRepository(&config.Config{
					UserApiUrl: &url.URL{
						Scheme: "http",
						Host:   fmt.Sprintf("%s:%d", serverConfig.Host, serverConfig.Port),
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
			})
			assert.NoError(t, err)
		})
	})

	t.Run("PATCH /user/:userId", func(t *testing.T) {
		TestUser := &UpdateUserPayload{
			Name:     ContractTestUserName,
			Email:    ContractTestUserEmail,
			Password: ContractTestUserPassword,
		}
		requestBody, err := json.Marshal(TestUser)
		require.NoError(t, err)

		t.Run("happy path", func(t *testing.T) {
			responseBody, err := json.Marshal(&jwt_generator.Tokens{
				AccessToken:  ContractTestToken,
				RefreshToken: ContractTestToken,
			})
			require.NoError(t, err)

			pact.
				AddInteraction().
				Given(fmt.Sprintf("Update user with %s id", ContractTestUserId)).
				UponReceiving("a request to update user info and getting access token and refresh token").
				WithRequest(
					fiber.MethodPatch,
					fmt.Sprintf("/user/%s", ContractTestUserId),
					func(builder *consumer.V2RequestBuilder) {
						builder.
							Header(fiber.HeaderAccept, matchers.String(fiber.MIMEApplicationJSON)).
							Body(fiber.MIMEApplicationJSON, requestBody)
					}).
				WillRespondWith(fiber.StatusOK,
					func(builder *consumer.V2ResponseBuilder) {
						builder.
							Body(fiber.MIMEApplicationJSON, responseBody)
					})

			err = pact.ExecuteTest(t, func(serverConfig consumer.MockServerConfig) error {
				userRepository := NewRepository(&config.Config{
					UserApiUrl: &url.URL{
						Scheme: "http",
						Host:   fmt.Sprintf("%s:%d", serverConfig.Host, serverConfig.Port),
					},
				})

				_, err := userRepository.UpdateUserById(ContractTestUserId, TestUser)
				if err != nil {
					return err
				}

				return nil
			})
			assert.NoError(t, err)
		})

		t.Run("email already exists", func(t *testing.T) {
			pact.
				AddInteraction().
				Given(fmt.Sprintf("Update user with %s id and %s email but email already exists", ContractTestUserId, ContractTestUserEmail)).
				UponReceiving("a request to update user info and getting access token and refresh token").
				WithRequest(
					fiber.MethodPatch,
					fmt.Sprintf("/user/%s", ContractTestUserId),
					func(builder *consumer.V2RequestBuilder) {
						builder.
							Header(fiber.HeaderAccept, matchers.String(fiber.MIMEApplicationJSON)).
							Body(fiber.MIMEApplicationJSON, requestBody)
					}).
				WillRespondWith(fiber.StatusConflict)

			err := pact.ExecuteTest(t, func(serverConfig consumer.MockServerConfig) error {
				userRepository := NewRepository(&config.Config{
					UserApiUrl: &url.URL{
						Scheme: "http",
						Host:   fmt.Sprintf("%s:%d", serverConfig.Host, serverConfig.Port),
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
			})
			assert.NoError(t, err)
		})
	})
}
