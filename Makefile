PROJECT_NAME = $(notdir $(CURDIR))

get:
	go get ./...
	go mod tidy

security-analysis:
	gosec ./...

lint:
	golangci-lint run -v -c .golangci.yml ./...

dev:
	air run

run:
	go run .

test:
	go clean -testcache
	go test -tags=unit ./...

dockerize:
	docker build -t $(PROJECT_NAME) .

coverage_report:
	go clean -testcache
	go test -tags=unit -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out
	go tool cover -html=coverage.out

generate-mock:
	mockgen --source=pkg/config/config.go --destination=pkg/config/mock/config_mock.go --package=configmock