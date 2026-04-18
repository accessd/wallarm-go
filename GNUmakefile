all: test

test:
	go test ./... -v -timeout=30s -parallel=4 -race

vet:
	go vet $(go list ./...)

lint:
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@golangci-lint run

cover:
	go test ./... -race -coverprofile=coverage.txt -covermode=atomic

.PHONY: test vet lint cover
