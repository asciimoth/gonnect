set shell := ["bash", "-euo", "pipefail", "-c"]
set dotenv-load := true

test:
	go test ./... --race -count=1

vet:
	go vet ./...

tidy:
	go mod tidy

lint:
  golangci-lint run ./...

fmt:
  golangci-lint fmt ./...

