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

### Get Node ID / Pool ID

Calculate the Node ID (also known as Pool ID) from your domain public key:

```bash
# Get Node ID without prefix (default)
./ops get-nodeid

# Get Node ID with 0x prefix (for contract calls)
./ops get-nodeid --format 0x
```

**Options:**
- `--keys-dir` - Directory containing domain.pub (default: `./keys`)
- `--format` - Output format: `hex` (no prefix, default) or `0x` (with 0x prefix)

**Output:**
```
Node ID: abc123def456789...
```

**Note:** Pool ID is the same as Node ID but with `0x` prefix for smart contract interactions.

### Register as Validator

Register your node as a validator on the network:

```bash
# Set private key via environment variable (required)
export VALIDATOR_PRIVATE_KEY=YOUR_PRIVATE_KEY_HERE

./ops add-validator \
  --domain-label my-validator \
  --domain-endpoint tcp://YOUR_PUBLIC_IP:19000 \
  --stake 1000000
```

**Environment Variable (Required):**
- `VALIDATOR_PRIVATE_KEY` - Private key for transaction signing (hex format, with or without 0x prefix)

**Required Parameters:**
- `--domain-label` - Validator name/description
- `--domain-endpoint` - Your validator's **public** endpoint URL (must be accessible from other nodes)
  - For IP:PORT format: must use `tcp://` prefix with your **public IP** (e.g., `tcp://YOUR_PUBLIC_IP:19000`)
  - For domain names: only TCP protocol is supported in the current version, and the domain port must be the consensus port (default: 19000), e.g., tcp://yourdomain:19000.
  - ⚠️ **Do NOT use `127.0.0.1` or `localhost`** - other nodes cannot connect to your validator

**Optional Parameters:**
- `--rpc-endpoint` - RPC endpoint to send transaction (default: `http://127.0.0.1:18100`)
- `--stake` - Stake amount in tokens (default: `1000000`)
- `--domain-pubkey` - Path to domain public key (default: `./keys/domain.pub`)
- `--stabilizing-pubkey` - Path to stabilizing public key (default: `./keys/stabilizing.pub`)
- `--unsigned` - Print the unsigned transaction (contract address, value in wei, method, calldata, function ABI) for a Safe multisig instead of signing and broadcasting. `VALIDATOR_PRIVATE_KEY` is not required in this mode. See [Using `--unsigned` with a Safe multisig](#using---unsigned-with-a-safe-multisig).

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
Account address: 0xYourAddress...
Connected to endpoint
Stake amount: 10000000 tokens (10000000000000000000000000 wei)
Validator register tx: 0xTransactionHash...
Validator register success
```

### Update Validator

Update your validator's description and endpoint:

```bash
# Set private key via environment variable (required)
export VALIDATOR_PRIVATE_KEY=YOUR_PRIVATE_KEY_HERE

./ops update-validator \
  --description "new-validator-name" \
  --endpoint "tcp://NEW_PUBLIC_IP:19000"
```

**Environment Variable (Required):**
- `VALIDATOR_PRIVATE_KEY` - Private key for transaction signing (hex format, with or without 0x prefix)

**Required Parameters:**
- `--description` - New validator description/label
- `--endpoint` - New validator endpoint URL

**Optional Parameters:**
- `--rpc-endpoint` - RPC endpoint to send transaction (default: `http://127.0.0.1:18100`)
- `--pool-id` - Pool ID (hex, 64 characters). If provided, `--domain-pubkey` is ignored
- `--domain-pubkey` - Path to domain public key (default: `./keys/domain.pub`, used only when `--pool-id` is empty)
- `--unsigned` - Print the unsigned transaction for a Safe multisig instead of signing and broadcasting. `VALIDATOR_PRIVATE_KEY` is not required in this mode. See [Using `--unsigned` with a Safe multisig](#using---unsigned-with-a-safe-multisig).

**Example:**
```bash
export VALIDATOR_PRIVATE_KEY=abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890

# Get your new public IP
NEW_PUBLIC_IP=$(curl -s ifconfig.me)

./ops update-validator \
  --rpc-endpoint http://127.0.0.1:18100 \
  --description "my-updated-validator" \
  --endpoint tcp://$NEW_PUBLIC_IP:19000
```

**Output:**
```
Updating validator...
Account address: 0xYourAddress...
Pool ID: YourPoolId...
Connected to endpoint
Validator update tx: 0xTransactionHash...
Validator update success
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
- `--unsigned` - Print the unsigned transaction for a Safe multisig instead of signing and broadcasting. `VALIDATOR_PRIVATE_KEY` is not required in this mode. See [Using `--unsigned` with a Safe multisig](#using---unsigned-with-a-safe-multisig).

**Example:**
```bash
export VALIDATOR_PRIVATE_KEY=abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890

./ops exit-validator \
  --rpc-endpoint http://127.0.0.1:18100
```

**Output:**
```
Exiting validator...
Account address: 0xYourAddress...
Pool ID: YourPoolId...
Connected to endpoint
Validator exit tx: 0xTransactionHash...
Validator exit success
```

## Staking Management

After registering as a validator, you can manage staking settings including delegation and commission rates.

### Enable/Disable Delegation

Allow or disallow delegators to stake to your validator pool:

```bash
# Set private key via environment variable (required)
export VALIDATOR_PRIVATE_KEY=YOUR_PRIVATE_KEY_HERE

# Enable delegation
./ops set-delegation --enabled=true

# Disable delegation
./ops set-delegation --enabled=false
```

**Environment Variable (Required):**
- `VALIDATOR_PRIVATE_KEY` - Private key for transaction signing (hex format, with or without 0x prefix)

**Optional Parameters:**
- `--rpc-endpoint` - RPC endpoint to send transaction (default: `http://127.0.0.1:18100`)
- `--pool-id` - Pool ID (hex, 64 characters). If empty, computed from `--domain-pubkey`
- `--domain-pubkey` - Path to domain public key (default: `./keys/domain.pub`)
- `--enabled` - Enable (true) or disable (false) delegation (default: `true`)
- `--unsigned` - Print the unsigned transaction for a Safe multisig instead of signing and broadcasting. `VALIDATOR_PRIVATE_KEY` is not required in this mode. See [Using `--unsigned` with a Safe multisig](#using---unsigned-with-a-safe-multisig).

**Example:**
```bash
export VALIDATOR_PRIVATE_KEY=abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890

./ops set-delegation \
  --rpc-endpoint http://127.0.0.1:18100 \
  --enabled=true
```

### Set Commission Rate

Set the commission rate for your validator (percentage of rewards taken from delegators):

```bash
# Set private key via environment variable (required)
export VALIDATOR_PRIVATE_KEY=YOUR_PRIVATE_KEY_HERE

# Set commission rate to 10% (1000 basis points)
./ops set-commission-rate --rate 1000
```

**Environment Variable (Required):**
- `VALIDATOR_PRIVATE_KEY` - Private key for transaction signing (hex format, with or without 0x prefix)

**Required Parameters:**
- `--rate` - Commission rate in basis points (0-10000, where 10000 = 100%)

**Optional Parameters:**
- `--rpc-endpoint` - RPC endpoint to send transaction (default: `http://127.0.0.1:18100`)
- `--pool-id` - Pool ID (hex, 64 characters). If empty, computed from `--domain-pubkey`
- `--domain-pubkey` - Path to domain public key (default: `./keys/domain.pub`)
- `--unsigned` - Print the unsigned transaction for a Safe multisig instead of signing and broadcasting. `VALIDATOR_PRIVATE_KEY` is not required in this mode. See [Using `--unsigned` with a Safe multisig](#using---unsigned-with-a-safe-multisig).

**Rate Examples:**
- `100` = 1%
- `500` = 5%
- `1000` = 10%
- `2500` = 25%
- `10000` = 100%

**Example:**
```bash
export VALIDATOR_PRIVATE_KEY=abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890

# Set 5% commission rate
./ops set-commission-rate \
  --rpc-endpoint http://127.0.0.1:18100 \
  --rate 500
```

### Set Delegation Approver

Set (or clear) the delegation approver address for your validator pool. When an approver is set, the contract accepts `delegateWithApproval` calls signed by that approver; passing the zero address clears the approver (which only the validator owner is authorized to do).

```bash
# Set private key via environment variable (required unless using --unsigned)
export VALIDATOR_PRIVATE_KEY=YOUR_PRIVATE_KEY_HERE

# Set an approver
./ops set-delegation-approver --approver 0xApproverAddress

# Clear the approver (owner only)
./ops set-delegation-approver --approver 0x0000000000000000000000000000000000000000
```

**Environment Variable (Required unless `--unsigned`):**
- `VALIDATOR_PRIVATE_KEY` - Private key for transaction signing (hex format, with or without 0x prefix)

**Required Parameters:**
- `--approver` - Approver address (`0x...`). Pass the zero address to clear the approver (owner only)

**Optional Parameters:**
- `--rpc-endpoint` - RPC endpoint to send transaction (default: `http://127.0.0.1:18100`)
- `--pool-id` - Pool ID (hex, 64 characters). If empty, computed from `--domain-pubkey`
- `--domain-pubkey` - Path to domain public key (default: `./keys/domain.pub`)
- `--unsigned` - Print the unsigned transaction for a Safe multisig instead of signing and broadcasting. See [Using `--unsigned` with a Safe multisig](#using---unsigned-with-a-safe-multisig).

### Withdraw Stake

Withdraw a portion of the validator owner's own stake. The withdrawn amount enters the unbonding window; use `claim-stake` later to collect it.

```bash
export VALIDATOR_PRIVATE_KEY=YOUR_PRIVATE_KEY_HERE

# Withdraw 500 tokens from your own stake
./ops withdraw-stake --amount 500
```

**Environment Variable (Required unless `--unsigned`):**
- `VALIDATOR_PRIVATE_KEY` - Private key for transaction signing (hex format, with or without 0x prefix)

**Required Parameters:**
- `--amount` - Amount to withdraw, in whole tokens (the tool multiplies by `1e18` to get wei)

**Optional Parameters:**
- `--rpc-endpoint` - RPC endpoint to send transaction (default: `http://127.0.0.1:18100`)
- `--pool-id` - Pool ID (hex, 64 characters). If empty, computed from `--domain-pubkey`
- `--domain-pubkey` - Path to domain public key (default: `./keys/domain.pub`)
- `--unsigned` - Print the unsigned transaction for a Safe multisig instead of signing and broadcasting. See [Using `--unsigned` with a Safe multisig](#using---unsigned-with-a-safe-multisig).

### Claim Stake

Claim stake that has already completed the withdrawal window (from a previous `withdraw-stake` or `exit-validator`). Transfers the unlocked amount back to the owner address.

```bash
export VALIDATOR_PRIVATE_KEY=YOUR_PRIVATE_KEY_HERE

./ops claim-stake
```

**Environment Variable (Required unless `--unsigned`):**
- `VALIDATOR_PRIVATE_KEY` - Private key for transaction signing (hex format, with or without 0x prefix)

**Optional Parameters:**
- `--rpc-endpoint` - RPC endpoint to send transaction (default: `http://127.0.0.1:18100`)
- `--pool-id` - Pool ID (hex, 64 characters). If empty, computed from `--domain-pubkey`
- `--domain-pubkey` - Path to domain public key (default: `./keys/domain.pub`)
- `--unsigned` - Print the unsigned transaction for a Safe multisig instead of signing and broadcasting. See [Using `--unsigned` with a Safe multisig](#using---unsigned-with-a-safe-multisig).

### Claim Reward

Claim accrued validator rewards to the owner address.

```bash
export VALIDATOR_PRIVATE_KEY=YOUR_PRIVATE_KEY_HERE

./ops claim-reward
```

**Environment Variable (Required unless `--unsigned`):**
- `VALIDATOR_PRIVATE_KEY` - Private key for transaction signing (hex format, with or without 0x prefix)

**Optional Parameters:**
- `--rpc-endpoint` - RPC endpoint to send transaction (default: `http://127.0.0.1:18100`)
- `--pool-id` - Pool ID (hex, 64 characters). If empty, computed from `--domain-pubkey`
- `--domain-pubkey` - Path to domain public key (default: `./keys/domain.pub`)
- `--unsigned` - Print the unsigned transaction for a Safe multisig instead of signing and broadcasting. See [Using `--unsigned` with a Safe multisig](#using---unsigned-with-a-safe-multisig).

**Tip:** If rewards look stale, run `settle-reward` first to settle pending reward accounting, then `claim-reward`.

### Compound Rewards

Compound accrued rewards back into the validator's stake instead of withdrawing them.

```bash
export VALIDATOR_PRIVATE_KEY=YOUR_PRIVATE_KEY_HERE

./ops compound-rewards
```

**Environment Variable (Required unless `--unsigned`):**
- `VALIDATOR_PRIVATE_KEY` - Private key for transaction signing (hex format, with or without 0x prefix)

**Optional Parameters:**
- `--rpc-endpoint` - RPC endpoint to send transaction (default: `http://127.0.0.1:18100`)
- `--pool-id` - Pool ID (hex, 64 characters). If empty, computed from `--domain-pubkey`
- `--domain-pubkey` - Path to domain public key (default: `./keys/domain.pub`)
- `--unsigned` - Print the unsigned transaction for a Safe multisig instead of signing and broadcasting. See [Using `--unsigned` with a Safe multisig](#using---unsigned-with-a-safe-multisig).

### Settle Reward

Settle pending reward accounting for your pool. Usually called before `claim-reward` or `compound-rewards` when the displayed reward amount looks stale.

```bash
export VALIDATOR_PRIVATE_KEY=YOUR_PRIVATE_KEY_HERE

./ops settle-reward
```

**Environment Variable (Required unless `--unsigned`):**
- `VALIDATOR_PRIVATE_KEY` - Private key for transaction signing (hex format, with or without 0x prefix)

**Optional Parameters:**
- `--rpc-endpoint` - RPC endpoint to send transaction (default: `http://127.0.0.1:18100`)
- `--pool-id` - Pool ID (hex, 64 characters). If empty, computed from `--domain-pubkey`
- `--domain-pubkey` - Path to domain public key (default: `./keys/domain.pub`)
- `--unsigned` - Print the unsigned transaction for a Safe multisig instead of signing and broadcasting. See [Using `--unsigned` with a Safe multisig](#using---unsigned-with-a-safe-multisig).

### Using `--unsigned` with a Safe multisig

If the validator owner is a Safe (Gnosis Safe) multisig, you cannot sign transactions locally with `VALIDATOR_PRIVATE_KEY`. Every write command in this tool (`add-validator`, `update-validator`, `exit-validator`, `set-delegation`, `set-commission-rate`, `set-delegation-approver`, `withdraw-stake`, `claim-stake`, `claim-reward`, `compound-rewards`, `settle-reward`) supports `--unsigned`, which skips signing/broadcasting and prints everything the Safe web UI needs to build the transaction manually:

- **Contract address** — the staking precompile
- **Value (wei)** — always `0` except for `add-validator`, which requires the registration stake
- **Method** — the contract function name
- **Calldata** — ABI-encoded `0x…` payload
- **Function ABI** — the single-function JSON fragment to paste into Safe's "Contract interaction" ABI field

`VALIDATOR_PRIVATE_KEY` is **not** required when using `--unsigned`.

**Example:**
```bash
./ops set-commission-rate \
  --pool-id 0x1111111111111111111111111111111111111111111111111111111111111111 \
  --rate 500 \
  --unsigned
```

**Output:**
```
Setting commission rate to 500 (5.00%) for pool 1111...1111
=== Unsigned transaction (for Safe web UI) ===
Contract address: 0x4100000000000000000000000000000000000000
Value (wei):      0
Method:           setCommissionRate
Calldata:         0x031e7f5d11111111...00000001f4

--- Function ABI (paste into Safe "Contract interaction" ABI field) ---
[
  {
    "inputs": [
      { "internalType": "bytes32", "name": "_poolId", "type": "bytes32" },
      { "internalType": "uint256", "name": "_newRate", "type": "uint256" }
    ],
    "name": "setCommissionRate",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  }
]
```

**Safe web UI flow:**
1. Open your Safe → **New transaction** → **Contract interaction**
2. **Contract address**: paste the printed value
3. **ABI**: paste the printed Function ABI fragment, then pick the matching **Method**
4. Fill in each parameter shown by the Safe UI. Either fill them from your original CLI arguments, or paste the raw **Calldata** into Safe's "custom data" field — both paths produce the same transaction
5. **Value**: paste the printed `Value (wei)` (non-zero only for `add-validator`)
6. Submit for signer review, then execute once the threshold is reached

**Notes:**
- `add-validator --unsigned` prints a non-zero `Value (wei)` equal to your `--stake` (tokens × 1e18). Make sure the Safe has that balance before executing.
- `setDelegationApprover` with the zero address is allowed only when the caller is the validator owner. The Safe must be the owner.
- Commands that read values (`get-validator-info`, `get-nodeid`, `health-check`, `network-test`) do not send transactions and therefore have no `--unsigned` flag.

### Get Validator Information

Query comprehensive validator information including staking details, commission rate, and delegation status:

```bash
./ops get-validator-info
```

**Optional Parameters:**
- `--rpc-endpoint` - RPC endpoint to query (default: `http://127.0.0.1:18100`)
- `--pool-id` - Pool ID (hex, 64 characters). If empty, computed from `--domain-pubkey`
- `--domain-pubkey` - Path to domain public key (default: `./keys/domain.pub`)

**Example:**
```bash
# Query using domain public key
./ops get-validator-info \
  --rpc-endpoint http://127.0.0.1:18100

# Query using specific pool ID
./ops get-validator-info \
  --pool-id YOUR_POOL_ID_HEX \
  --rpc-endpoint http://127.0.0.1:18100
```

**Output:**
```
=== Validator Information ===
Pool ID:              <your_pool_id_hex>
Description:          my-validator
Owner:                0xYourOwnerAddress
Endpoint:             tcp://YOUR_PUBLIC_IP:19000
Status:               1
Public Key:           0x1003...
BLS Public Key:       0x4003...

=== Staking Information ===
Total Stake:          1000000000000000000000000 wei
Stake Snapshot:       1000000000000000000000000 wei
Pending Withdraw:     0 wei
Withdraw Window:      0 epochs

=== Commission & Delegation ===
Commission Rate:      1000 basis points (10.00%)
Delegation Enabled:   true
```

## Diagnostics & Monitoring

### Health Check

Run a comprehensive self-check on your node. The output is split into two sections:

- **NODE INFO** — Informational items (network, CPU, memory, Node ID, validator status)
- **HEALTH CHECK** — Critical checks with ✅/❌ (ulimit, spec version, binary version, block production)

Network detection is based on chainID from local RPC (`0xa8231` = Atlantic, `0x688` = Mainnet).

```bash
./ops health-check
```

**Optional Parameters:**
- `--keys-dir` - Directory containing domain.pub (default: `./keys`)
- `--bin-dir` - Directory containing pharos_light and VERSION (default: `./bin`)
- `--rpc-endpoint` - Remote RPC endpoint for validator check (auto-detect if empty)

**Example Output:**
```
📋 NODE INFO
────────────────────────────────────────────────────────────
  Network      Atlantic
  CPU Cores    8
  Memory       31.2 GB
  Node ID      0xYourNodeId...
  Validator    ✅ (status=1)

🔍 HEALTH CHECK
────────────────────────────────────────────────────────────
  ✅ Ulimit (open files)   10000000
  ✅ Spec Version          matches remote
  ✅ Binary Version        a1b2c3d4e-dirty (commit: a1b2c3d4e)
  ✅ Block Production      block 1000000 → 1000003 (+3 in 3s)

✅ All checks passed.
```

**Check Details:**
- **Ulimit**: Must be ≥ 10,000,000 open files
- **Spec Version**: Compares local `./bin/VERSION` against remote GitHub version file
- **Binary Version**: Runs `pharos_light --version` to get commit ID
- **Block Production**: Calls `eth_blockNumber` twice (3s apart) to verify blocks are increasing

### Network Test

TCP latency test to all active validator endpoints. Fetches validator list from the staking contract via `getActiveValidators`, then measures TCP connection latency to each endpoint (pure Go, no external tools needed).

Results are sorted by AVG latency (ascending), with unreachable endpoints at the bottom. Validators without valid endpoints (no IP/hostname) are skipped.

```bash
./ops network-test
```

**Optional Parameters:**
- `--rpc-endpoint` - RPC endpoint to fetch validators (auto-detect based on chainID)
- `--port` - Default TCP port if endpoint has none (default: `18100`)
- `--count` - Number of TCP probes per endpoint (default: `3`)

**Example Output:**
```
Auto-detected network: Atlantic
🌐 Fetching validator endpoints...

Found 31 validators (5 with valid endpoints, 26 skipped), TCP latency test (3 probes each)...

VALIDATOR       ENDPOINT                        AVG       MIN       MAX       STATUS
---------       --------                        ---       ---       ---       ------
Validator-A     10.0.0.1:19000                  2.6ms     2.5ms     2.7ms     ✅
Validator-B     10.0.0.2:18100                  246.6ms   244.3ms   251.2ms   ✅
Validator-C     node.example.com:18100          496.3ms   494.2ms   497.5ms   ✅
```

## Complete Deployment Flow

### New Node Deployment

```bash
# 1. Set password
./ops set-password YOUR_SECURE_PASSWORD

# 2. Generate keys
./ops generate-keys

# 3. Get Node ID (optional, for reference)
./ops get-nodeid

# 4. Bootstrap
./ops bootstrap --config ./pharos.conf

# 5. Start node
./ops start --config ./pharos.conf

# 6. Register as validator (optional)
export VALIDATOR_PRIVATE_KEY=YOUR_PRIVATE_KEY_HERE
PUBLIC_IP=$(curl -s ifconfig.me)
./ops add-validator \
  --rpc-endpoint http://127.0.0.1:18100 \
  --domain-label my-validator \
  --domain-endpoint tcp://$PUBLIC_IP:19000 \
  --stake 1000000

# 7. Configure staking settings (optional)
# Enable delegation
./ops set-delegation --enabled=true

# Set commission rate to 10%
./ops set-commission-rate --rate 1000

# 8. Verify validator info
./ops get-validator-info

# 9. Run health check
./ops health-check

# 10. Test network connectivity to other validators
./ops network-test
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
| `get-nodeid` | Get Node ID / Pool ID from domain public key |

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
| `update-validator` | Update validator description and endpoint |
| `exit-validator` | Exit from validator set |

### Staking Operations

| Command | Description |
|---------|-------------|
| `set-delegation` | Enable or disable delegation for your validator |
| `set-commission-rate` | Set commission rate (0-10000 basis points) |
| `set-delegation-approver` | Set or clear the delegation approver address |
| `withdraw-stake` | Withdraw a portion of your own stake (enters unbonding) |
| `claim-stake` | Claim stake that has finished the withdrawal window |
| `claim-reward` | Claim accrued validator rewards |
| `compound-rewards` | Compound accrued rewards back into stake |
| `settle-reward` | Settle pending reward accounting |
| `get-validator-info` | Query validator information, staking details, and settings |

All write commands above (and every validator write command in the table above) accept `--unsigned` to emit a Safe-ready transaction payload instead of signing. See [Using `--unsigned` with a Safe multisig](#using---unsigned-with-a-safe-multisig).

### Diagnostics & Monitoring

| Command | Description |
|---------|-------------|
| `health-check` | Run node self-checks (system info, ulimit, spec version, binary version, block production, validator status) |
| `network-test` | TCP latency test to all active validator endpoints |

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
- ✅ `tcp://YOUR_PUBLIC_IP:19000`
- ✅ `tcp://203.0.113.50:19000` (example IP from RFC 5737)
- ✅ `https://pharos.your-domain.com`

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

If validator registration or staking commands fail:
- Ensure the account has sufficient balance for gas fees
- Check that the private key is correct (64 hex characters, with or without 0x prefix)
- Verify the `VALIDATOR_PRIVATE_KEY` environment variable is set (not needed when using `--unsigned`)
- Verify the network is accepting new validators
- For staking commands, ensure you are already registered as a validator
- If the validator owner is a Safe multisig, use `--unsigned` to produce a payload for the Safe web UI instead of signing locally. See [Using `--unsigned` with a Safe multisig](#using---unsigned-with-a-safe-multisig).

### Pool ID vs Node ID

**Pool ID** and **Node ID** are the same value, just with different formatting:
- **Node ID**: SHA256 hash of domain public key, displayed without prefix (e.g., `abc123...`)
- **Pool ID**: Same hash but with `0x` prefix for smart contract calls (e.g., `0xabc123...`)

Use `./ops get-nodeid --format 0x` to get the Pool ID format for contract interactions.

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

## Contribution

Contributors have to sign CLA.
Main branch is protected.