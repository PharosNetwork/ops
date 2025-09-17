# Pharos Ops (Go Version)

A Go rewrite of the Pharos blockchain operations tool, providing simplified node management.

## Features

- **Simplified Architecture**: No separate deploy/distribution directories - current directory is the deployment directory
- **Idempotent Operations**: All operations are safe to run multiple times
- **Single Domain**: Focused on single domain.json management
- **Compatible**: Generates NODE_ID using the same SHA256 hash algorithm as Python version

## Installation

```bash
go mod tidy
go build -o pharos-ops
```

## Usage

### Configuration

```bash
# Generate domain.json from deploy.json
./pharos-ops generate deploy.json

# Set IP addresses in domain.json
./pharos-ops set-ip domain.json

# Bootstrap node configuration
./pharos-ops bootstrap domain.json
```

### Node Operations

```bash
# Start node
./pharos-ops start domain.json

# Stop node
./pharos-ops stop domain.json

# Restart node
./pharos-ops restart domain.json

# Check node status
./pharos-ops status domain.json
```

## Key Differences from Python Version

1. **No Deploy Step**: Eliminates the separate deployment phase - binaries are expected to be in place
2. **Current Directory Deployment**: Uses current directory structure instead of separate deploy/distribution directories
3. **Simplified Configuration**: Focuses on essential operations without complex deployment logic
4. **Better Error Handling**: Continues processing other domains even if one fails
5. **Idempotent Design**: All operations can be safely repeated

## Architecture

- `cmd/`: Command-line interface definitions
- `pkg/domain/`: Domain configuration types
- `pkg/composer/`: Core domain management logic  
- `pkg/utils/`: Utility functions and logging

## Supported Mode

- `light`: Light client mode for lightweight blockchain operations