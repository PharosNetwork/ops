BINARY_NAME=pharos-ops
BUILD_DIR=build
VERSION=v1.0.0

.PHONY: build clean test run build-all build-mac build-linux

build:
	go build -o $(BUILD_DIR)/$(BINARY_NAME) .

build-all: build-mac build-linux

build-mac:
	mkdir -p $(BUILD_DIR)
	GOOS=darwin GOARCH=amd64 go build -ldflags "-X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build -ldflags "-X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 .

build-linux:
	mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 go build -ldflags "-X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build -ldflags "-X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 .

clean:
	rm -rf $(BUILD_DIR)

test:
	go test ./...

run: build
	./$(BUILD_DIR)/$(BINARY_NAME)

install: build
	cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/

.DEFAULT_GOAL := build