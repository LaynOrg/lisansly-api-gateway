get:
	go get ./...
	go mod tidy

.PHONY: build
build:
	env GOOS=linux GOARCH=arm64 go build -o build/getAccessTokenByRefreshToken/bootstrap internal/user/events/getAccessTokenByRefreshToken/main.go
	env GOOS=linux GOARCH=arm64 go build -o build/login/bootstrap internal/user/events/login/main.go
	env GOOS=linux GOARCH=arm64 go build -o build/register/bootstrap internal/user/events/register/main.go
	env GOOS=linux GOARCH=arm64 go build -o build/updateUserById/bootstrap internal/user/events/updateUserById/main.go

.PHONY: zip
zip:
	zip -j build/getAccessTokenByRefreshToken/getAccessTokenByRefreshToken.zip build/getAccessTokenByRefreshToken/bootstrap
	zip -j build/login/login.zip build/login/bootstrap
	zip -j build/register/register.zip build/register/bootstrap
	zip -j build/updateUserById/updateUserById.zip build/updateUserById/bootstrap

security-analysis:
	gosec ./...

lint:
	golangci-lint run -v -c .golangci.yml ./...

test:
	go clean -testcache
	go test -tags=unit ./...

contract-test:
	go clean -testcache
	go test -tags=contract ./...

coverage_report:
	go clean -testcache
	go test -tags=unit -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out
	go tool cover -html=coverage.out

generate-mock:
	mockgen --source=internal/user/service.go --destination=internal/user/service_mock.go --package=user
	mockgen --source=internal/user/repository.go --destination=internal/user/repository_mock.go --package=user
	mockgen --source=pkg/jwt_generator/jwt.go --destination=pkg/jwt_generator/jwt_mock.go --package=jwt_generator
	mockgen --source=pkg/aws_wrapper/lambda_client.go --destination=pkg/aws_wrapper/lambda_client_mock.go --package=aws_wrapper
