.PHONY: build run clean test test-ci test-cover test-race install fmt vet lint tidy all webui webui-install webui-dev

BINARY=xalgorix
BUILD_DIR=./build
VERSION=4.5.13
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION)"

webui/node_modules: webui/package.json
	@echo "Installing webui dependencies..."
	cd webui && npm install --no-audit --no-fund
	@touch webui/node_modules

webui-install: webui/node_modules

webui: webui/node_modules
	@echo "Building webui (React) → internal/web/static..."
	cd webui && npm run build

webui-dev: webui/node_modules
	cd webui && npm run dev

build: webui
	@echo "Building $(BINARY)..."
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) ./cmd/xalgorix/
	@echo "Built: $(BUILD_DIR)/$(BINARY)"

run:
	go run ./cmd/xalgorix/ $(ARGS)

clean:
	rm -rf $(BUILD_DIR)
	go clean

test:
	go test ./... -v

test-cover:
	go test ./... -cover

test-race:
	go test ./... -race

test-ci:
	go test ./...
	go test ./... -cover
	go test ./... -race
	go vet ./...
	@if command -v staticcheck >/dev/null 2>&1; then staticcheck ./...; else echo "staticcheck not installed; skipping"; fi
	go build ./cmd/xalgorix

install: build
	@echo "Installing $(BINARY) to /usr/local/bin..."
	sudo cp $(BUILD_DIR)/$(BINARY) /usr/local/bin/$(BINARY)
	sudo chmod +x /usr/local/bin/$(BINARY)
	@echo "Installed!"

fmt:
	go fmt ./...

vet:
	go vet ./...

lint: fmt vet
	@echo "Lint passed"

tidy:
	go mod tidy

all: tidy lint build
