# Pharos Operations Tool

A simplified operations tool for Pharos blockchain deployment and management.

## Features

- **Simplified Architecture**: No domain.json dependency, flat directory structure
- **Key Management**: Generate and manage cryptographic keys
- **Node Operations**: Bootstrap, start, stop Pharos nodes
- **Validator Management**: Register and exit validators
- **Configuration**: Easy IP and configuration management

## Directory Structure

```
/deployment-root/
├── bin/
│   ├── pharos_cli
│   ├── pharos_light
│   └── libevmone.so
├── conf/
│   └── pharos.conf
├── log/
├── data/
├── keys/                    # Generated keys directory
│   ├── domain.key
│   ├── domain.pub
│   ├── stabilizing.key
│   └── stabilizing.pub
├── genesis.conf
└── pharos-ops              # This binary
```

## Installation

### Build from Source

```bash
# Clone repository
git clone https://github.com/PharosNetwork/ops.git
cd ops

# Checkout the flat-structure-ops branch
git checkout flat-structure-ops

# Build
GOOS=linux GOARCH=amd64 go build -o pharos-ops

# Copy to deployment directory
cp pharos-ops /path/to/deployment/
```

## Quick Start

### 1. Generate Keys

Generate cryptographic keys for your validator node:

```bash
./pharos-ops generate-keys --output-dir ./keys
```

This creates:
- `domain.key` - Prime256v1 encrypted private key (PEM format)
- `domain.pub` - Prime256v1 public key (hex with 1003 prefix)
- `stabilizing.key` - BLS12381 private key (hex with 0x prefix)
- `stabilizing.pub` - BLS12381 public key (hex with 0x prefix)

**Options:**
- `--output-dir` - Output directory (default: `./keys`)
- `--key-passwd` - Password for key encryption (default: `123abc`)

### 2. Encode Keys to Configuration

Encode keys and write them to `pharos.conf`:

```bash
# Encode domain key
./pharos-ops encode-key-to-conf ./keys/domain.key \
  --key-type domain \
  --pharos-conf ./conf/pharos.conf

# Encode stabilizing key
./pharos-ops encode-key-to-conf ./keys/stabilizing.key \
  --key-type stabilizing \
  --pharos-conf ./conf/pharos.conf
```

Or just encode to base64 without writing to config:

```bash
./pharos-ops encode-key ./keys/domain.key
```

### 3. Set Public IP

Update the host IP in `pharos.conf`:

```bash
./pharos-ops set-ip 47.84.7.245
```

This updates `aldaba.startup_config.init_config.host_ip` in `./conf/pharos.conf`.

### 4. Bootstrap Node

Initialize the genesis state:

```bash
./pharos-ops bootstrap
```

This runs `pharos_cli genesis` to initialize the blockchain state.

### 5. Start Node

Start the Pharos node:

```bash
./pharos-ops start
```

This starts `pharos_light` in daemon mode.

### 6. Stop Node

Stop the running node:

```bash
# Graceful stop
./pharos-ops stop

# Force stop
./pharos-ops stop --force
```

## Validator Management

### Register as Validator

Register your node as a validator on the network:

```bash
./pharos-ops add-validator \
  --key <PRIVATE_KEY> \
  --domain-label my-validator \
  --domain-endpoint http://47.84.7.245:19000 \
  --stake 1000000
```

**Required Parameters:**
- `--key` - Private key for transaction signing (hex format, no 0x prefix)
- `--domain-label` - Validator name/description
- `--domain-endpoint` - Your validator's public endpoint URL

**Optional Parameters:**
- `--rpc-endpoint` - RPC endpoint to send transaction (default: `http://127.0.0.1:18100`)
- `--stake` - Stake amount in tokens (default: `1000000`)
- `--domain-pubkey` - Path to domain public key (default: `./keys/domain.pub`)
- `--stabilizing-pubkey` - Path to stabilizing public key (default: `./keys/stabilizing.pub`)

**Example:**
```bash
./pharos-ops add-validator \
  --rpc-endpoint https://atlantic.dplabs-internal.com \
  --key fcfc69bd0056a2592e1f46cfba8264d8918fe98ecf5a2ef43aaa4ed1463725e1 \
  --domain-label golang-validator \
  --domain-endpoint http://127.0.0.1:19000 \
  --stake 10000000
```

**Output:**
```
Adding validator...
Account address: 0x1234567890abcdef...
Connected to endpoint
Stake amount: 10000000 tokens (10000000000000000000000000 wei)
Validator register tx: 0xabcdef1234567890...
Validator register success
```

### Exit Validator

Request to exit from the validator set:

```bash
./pharos-ops exit-validator \
  --key <PRIVATE_KEY>
```

**Required Parameters:**
- `--key` - Private key for transaction signing

**Optional Parameters:**
- `--rpc-endpoint` - RPC endpoint to send transaction (default: `http://127.0.0.1:18100`)
- `--domain-pubkey` - Path to domain public key (default: `./keys/domain.pub`)

**Example:**
```bash
./pharos-ops exit-validator \
  --rpc-endpoint https://atlantic.dplabs-internal.com \
  --key fcfc69bd0056a2592e1f46cfba8264d8918fe98ecf5a2ef43aaa4ed1463725e1
```

**Output:**
```
Exiting validator...
Account address: 0x1234567890abcdef...
Pool ID: abc123def456789...
Connected to endpoint
Validator exit tx: 0xfedcba0987654321...
Validator exit success
```

## Complete Deployment Flow

### New Node Deployment

```bash
# 1. Generate keys
./pharos-ops generate-keys

# 2. Encode keys to config
./pharos-ops encode-key-to-conf ./keys/domain.key --key-type domain
./pharos-ops encode-key-to-conf ./keys/stabilizing.key --key-type stabilizing

# 3. Set public IP
PUBLIC_IP=$(curl -s ifconfig.me)
./pharos-ops set-ip $PUBLIC_IP

# 4. Bootstrap
./pharos-ops bootstrap

# 5. Start node
./pharos-ops start

# 6. Register as validator (optional)
./pharos-ops add-validator \
  --rpc-endpoint https://network-rpc.example.com \
  --key <YOUR_PRIVATE_KEY> \
  --domain-label my-validator \
  --domain-endpoint http://$PUBLIC_IP:19000 \
  --stake 1000000
```

### Automated Deployment Script

```bash
#!/bin/bash
set -e

echo "=== Pulling latest code ==="
cd /path/to/ops/
git pull

echo "=== Building binary ==="
GOOS=linux GOARCH=amd64 go build -o pharos-ops

echo "=== Copying to deployment directory ==="
cp pharos-ops /data/deployment/

echo "=== Setting IP ==="
cd /data/deployment/
PUBLIC_IP=$(curl -s ifconfig.me)
echo "Public IP: $PUBLIC_IP"
./pharos-ops set-ip $PUBLIC_IP

echo "=== Bootstrapping ==="
./pharos-ops bootstrap

echo "=== Starting node ==="
./pharos-ops start

echo "=== Deployment complete ==="
```

## Command Reference

### Key Management

| Command | Description |
|---------|-------------|
| `generate-keys` | Generate domain and stabilizing keys |
| `encode-key <key_path>` | Encode key to base64 |
| `encode-key-to-conf <key_path>` | Encode key and write to pharos.conf |

### Node Operations

| Command | Description |
|---------|-------------|
| `set-ip <ip_address>` | Set public IP in pharos.conf |
| `bootstrap` | Initialize genesis state |
| `start` | Start pharos_light service |
| `stop` | Stop pharos_light service |

### Validator Operations

| Command | Description |
|---------|-------------|
| `add-validator` | Register as validator |
| `exit-validator` | Exit from validator set |

## Configuration Files

### pharos.conf Structure

```json
{
  "aldaba": {
    "startup_config": {
      "init_config": {
        "host_ip": "127.0.0.1",
        "http_port": "18100",
        "ws_port": "18200",
        "tcp_port": "19000",
        "rpc_port": "20000"
      }
    },
    "secret_config": {
      "domain_key": "<base64_encoded_key>",
      "stabilizing_key": "<base64_encoded_key>"
    }
  },
  "storage": {
    "mygrid_env": {
      "mygrid_env": {
        "project_data_path": "./data"
      }
    }
  }
}
```

### Key File Formats

**domain.key** (Prime256v1 encrypted private key):
```
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHsMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDA...
-----END ENCRYPTED PRIVATE KEY-----
```

**domain.pub** (Prime256v1 public key):
```
100304284fc6bccd20ada2e8a31525348b33a98b9e88ef7727c512b6bfad5caabc872248077d66fea399a17599e34aad72fa51ea189e2c21a2f70e5d05a2a45f8b892c
```

**stabilizing.key** (BLS12381 private key):
```
0x400238d28e50623cba45dfd569ac65d51905b2f6ffbe791ac086df191922ffcb588b
```

**stabilizing.pub** (BLS12381 public key):
```
0x400389d3bfe4256ace7d4db0d1a9ca5add712553490fc8298a3cd2c43e1b0004f21598df06655cdc514e73f21b01d9c23b82
```

## Troubleshooting

### pharos_cli not found

If `generate-keys` fails with "pharos_cli not found":
- Ensure `pharos_cli` is in `./bin/` directory
- Check file permissions: `chmod +x ./bin/pharos_cli`

### Config file not found

If commands fail with "config file not found":
- Ensure you're running commands from the deployment root directory
- Check that `./conf/pharos.conf` exists
- Verify directory structure matches the expected layout

### Connection refused

If validator commands fail with connection errors:
- Check that the RPC endpoint is accessible
- Verify firewall rules allow outbound connections
- Test with: `curl http://127.0.0.1:18100`

### Transaction failed

If validator registration fails:
- Ensure the account has sufficient balance for gas fees
- Check that the private key is correct (64 hex characters, no 0x prefix)
- Verify the network is accepting new validators

## Development

### Building

```bash
# Build for Linux
GOOS=linux GOARCH=amd64 go build -o pharos-ops

# Build for macOS
GOOS=darwin GOARCH=amd64 go build -o pharos-ops

# Build for current platform
go build -o pharos-ops
```

### Testing

```bash
# Run tests
go test ./...

# Test specific command
./pharos-ops generate-keys --output-dir ./test-keys
```

## License

Pharos Labs proprietary/confidential.

## Support

For issues and questions:
- GitHub Issues: https://github.com/PharosNetwork/ops/issues
- Documentation: https://docs.pharos.network
