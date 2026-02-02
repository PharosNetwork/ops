# Pharos Operations Tool

A simplified operations tool for Pharos blockchain deployment and management.

## Features

- **Simplified Architecture**: No domain.json dependency, flat directory structure
- **Password Management**: Secure password storage for key encryption
- **Key Management**: Generate and manage cryptographic keys
- **Node Operations**: Bootstrap, start, stop Pharos nodes
- **Validator Management**: Register and exit validators

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
├── .password               # Encrypted password file
└── ops                     # This binary
```

## Installation

### Download Pre-built Binary

```bash
# Download latest release
wget https://github.com/PharosNetwork/ops/releases/latest/download/ops-linux-amd64 -O ops
chmod +x ops
```

### Build from Source

```bash
# Clone repository
git clone https://github.com/PharosNetwork/ops.git
cd ops

# Build
GOOS=linux GOARCH=amd64 go build -o ops

# Copy to deployment directory
cp ops /path/to/deployment/
```

## Quick Start

### 1. Set Password

Set a password for key encryption:

```bash
./ops set-password YOUR_SECURE_PASSWORD
```

The password is stored in `./.password` file and used for key encryption/decryption.

### 2. Generate Keys

Generate cryptographic keys for your validator node:

```bash
./ops generate-keys
```

This creates:
- `domain.key` - Prime256v1 encrypted private key (PEM format)
- `domain.pub` - Prime256v1 public key (hex with 1003 prefix)
- `stabilizing.key` - BLS12381 private key (hex with 0x prefix)
- `stabilizing.pub` - BLS12381 public key (hex with 0x prefix)

**Options:**
- `--output-dir` - Output directory (default: `./keys`)

### 3. Get Node ID

Get the Node ID from your domain public key:

```bash
./ops get-nodeid
```

This calculates the SHA256 hash of the domain public key (with prefix stripped) and displays the Node ID.

**Options:**
- `--keys-dir` - Directory containing domain.pub (default: `./keys`)

**Output:**
```
Node ID: abc123def456789...
```

### 4. Bootstrap Node

Initialize the genesis state:

```bash
./ops bootstrap --config ./pharos.conf
```

This runs `pharos_cli genesis` to initialize the blockchain state.

### 5. Start Node

Start the Pharos node:

```bash
./ops start --config ./pharos.conf
```

This starts `pharos_light` in daemon mode.

### 6. Stop Node

Stop the running node:

```bash
# Graceful stop
./ops stop

# Force stop
./ops stop --force
```

## Validator Management

### Register as Validator

Register your node as a validator on the network:

```bash
# Set private key via environment variable (required)
export VALIDATOR_PRIVATE_KEY=YOUR_PRIVATE_KEY_HERE

./ops add-validator \
  --domain-label my-validator \
  --domain-endpoint tcp://47.84.7.245:19000 \
  --stake 1000000
```

**Environment Variable (Required):**
- `VALIDATOR_PRIVATE_KEY` - Private key for transaction signing (hex format, with or without 0x prefix)

**Required Parameters:**
- `--domain-label` - Validator name/description
- `--domain-endpoint` - Your validator's **public** endpoint URL (must be accessible from other nodes)
  - For IP:PORT format: must use `tcp://` prefix with your **public IP** (e.g., `tcp://47.84.7.245:19000`)
  - For domain names: can use any protocol (e.g., `https://pharos.validator.com`)
  - ⚠️ **Do NOT use `127.0.0.1` or `localhost`** - other nodes cannot connect to your validator

**Optional Parameters:**
- `--rpc-endpoint` - RPC endpoint to send transaction (default: `http://127.0.0.1:18100`)
- `--stake` - Stake amount in tokens (default: `1000000`)
- `--domain-pubkey` - Path to domain public key (default: `./keys/domain.pub`)
- `--stabilizing-pubkey` - Path to stabilizing public key (default: `./keys/stabilizing.pub`)

**Example:**
```bash
export VALIDATOR_PRIVATE_KEY=abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890

# Get your public IP
PUBLIC_IP=$(curl -s ifconfig.me)

./ops add-validator \
  --rpc-endpoint http://127.0.0.1:18100 \
  --domain-label golang-validator \
  --domain-endpoint tcp://$PUBLIC_IP:19000 \
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
# Set private key via environment variable (required)
export VALIDATOR_PRIVATE_KEY=YOUR_PRIVATE_KEY_HERE

./ops exit-validator
```

**Environment Variable (Required):**
- `VALIDATOR_PRIVATE_KEY` - Private key for transaction signing (hex format, with or without 0x prefix)

**Optional Parameters:**
- `--rpc-endpoint` - RPC endpoint to send transaction (default: `http://127.0.0.1:18100`)
- `--domain-pubkey` - Path to domain public key (default: `./keys/domain.pub`)

**Example:**
```bash
export VALIDATOR_PRIVATE_KEY=abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890

./ops exit-validator \
  --rpc-endpoint http://127.0.0.1:18100
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
# 1. Set password
./ops set-password YOUR_SECURE_PASSWORD

# 2. Generate keys
./ops generate-keys

# 3. Bootstrap
./ops bootstrap --config ./pharos.conf

# 4. Start node
./ops start --config ./pharos.conf

# 5. Register as validator (optional)
export VALIDATOR_PRIVATE_KEY=YOUR_PRIVATE_KEY_HERE
PUBLIC_IP=$(curl -s ifconfig.me)
./ops add-validator \
  --rpc-endpoint http://127.0.0.1:18100 \
  --domain-label my-validator \
  --domain-endpoint tcp://$PUBLIC_IP:19000 \
  --stake 1000000
```

## Command Reference

### Password Management

| Command | Description |
|---------|-------------|
| `set-password <password>` | Set password for key encryption |
| `get-password` | Display saved password |

### Key Management

| Command | Description |
|---------|-------------|
| `generate-keys` | Generate domain and stabilizing keys |
| `get-nodeid` | Get Node ID from domain public key |

### Node Operations

| Command | Description |
|---------|-------------|
| `bootstrap --config <path>` | Initialize genesis state |
| `start --config <path>` | Start pharos_light service |
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
...PEM format encrypted private key...
-----END ENCRYPTED PRIVATE KEY-----
```

**domain.pub** (Prime256v1 public key):
```
1003<64_hex_characters>
```

**stabilizing.key** (BLS12381 private key):
```
0x<hex_string>
```

**stabilizing.pub** (BLS12381 public key):
```
0x<hex_string>
```

## Troubleshooting

### Domain endpoint protocol

**Problem:** Validator registration fails or other nodes cannot connect to your validator.

**Solution:** Ensure `--domain-endpoint` uses your **public IP address**, not `127.0.0.1` or `localhost`:

**Correct examples (using public IP):**
- ✅ `tcp://47.84.7.245:19000`
- ✅ `tcp://203.0.113.50:19000`
- ✅ `https://pharos.validator.com`

**Wrong examples (using localhost):**
- ❌ `tcp://127.0.0.1:19000` - Other nodes cannot connect!
- ❌ `tcp://localhost:19000` - Other nodes cannot connect!
- ❌ `http://127.0.0.1:19000` - Wrong protocol and localhost

**Get your public IP:**
```bash
curl -s ifconfig.me
```

**Rule:** When using IP:PORT format, you must use `tcp://` prefix with your **public IP**.

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
- Check that the private key is correct (64 hex characters, with or without 0x prefix)
- Verify the `VALIDATOR_PRIVATE_KEY` environment variable is set
- Verify the network is accepting new validators

## Development

### Building

```bash
# Build for Linux
GOOS=linux GOARCH=amd64 go build -o ops

# Build for macOS
GOOS=darwin GOARCH=amd64 go build -o ops

# Build for current platform
go build -o ops
```

### Testing

```bash
# Run tests
go test ./...

# Test specific command
./ops generate-keys --output-dir ./test-keys
```

## License

Pharos Labs proprietary/confidential.

## Support

For issues and questions:
- GitHub Issues: https://github.com/PharosNetwork/ops/issues
- Documentation: https://docs.pharosnetwork.xyz
