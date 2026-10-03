set shell := ["bash", "-euo", "pipefail", "-c"]
set dotenv-load := true

typos:
  typos

check: tidy typos fmt lint vet test fuzz

# Fuzz all untrusted-input boundaries in parallel for one minute by default.
# Set FUZZ_TIME to use another Go duration or an iteration count.
fuzz:
	./scripts/fuzz.sh

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
