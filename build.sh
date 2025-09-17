#!/bin/bash

set -e

VERSION=${VERSION:-v1.0.0}
BUILD_DIR="build"

echo "Building pharos-ops ${VERSION}..."

# Clean previous builds
rm -rf ${BUILD_DIR}
mkdir -p ${BUILD_DIR}

# Build for macOS
echo "Building for macOS..."
GOOS=darwin GOARCH=amd64 go build -ldflags "-X main.version=${VERSION}" -o ${BUILD_DIR}/pharos-ops-darwin-amd64 .
GOOS=darwin GOARCH=arm64 go build -ldflags "-X main.version=${VERSION}" -o ${BUILD_DIR}/pharos-ops-darwin-arm64 .

# Build for Linux
echo "Building for Linux..."
GOOS=linux GOARCH=amd64 go build -ldflags "-X main.version=${VERSION}" -o ${BUILD_DIR}/pharos-ops-linux-amd64 .
GOOS=linux GOARCH=arm64 go build -ldflags "-X main.version=${VERSION}" -o ${BUILD_DIR}/pharos-ops-linux-arm64 .

# Create checksums
echo "Creating checksums..."
cd ${BUILD_DIR}
sha256sum * > checksums.txt
cd ..

echo "Build completed! Binaries are in ${BUILD_DIR}/"
ls -la ${BUILD_DIR}/