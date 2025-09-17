# Pharos Ops (Go Version)

A Go rewrite of the Pharos blockchain operations tool, providing simplified and efficient management of Pharos networks.

## Features

- **Simplified Architecture**: No separate deploy/distribution directories - current directory is the deployment directory
- **Idempotent Operations**: All operations are safe to run multiple times
- **Light & Ultra Mode Support**: Automatic detection and handling of deployment modes
- **Service Management**: Start, stop, status, and clean operations for individual services or entire domains

## Installation

```bash
go mod tidy
go build -o pharos-ops
```

## Usage

### Basic Commands

```bash
# Check status
./pharos-ops status domain.json

# Start domain
./pharos-ops start domain.json

# Stop domain  
./pharos-ops stop domain.json

# Clean domain data
./pharos-ops clean domain.json

# Clean all data including config
./pharos-ops clean --all domain.json
```

### Service-Specific Operations

```bash
# Start specific service
./pharos-ops start -s etcd domain.json

# Stop specific service
./pharos-ops stop -s portal domain.json

# Check specific service status
./pharos-ops status -s light domain.json
```

### Multiple Domains

```bash
# Operate on multiple domains
./pharos-ops start domain1.json domain2.json domain3.json
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

## Supported Services

- `etcd`: Distributed key-value store
- `mygrid_service`: Storage service
- `portal`: API gateway
- `dog`: Domain service
- `txpool`: Transaction pool
- `controller`: Network controller
- `compute`: Computation service
- `light`: Light client mode