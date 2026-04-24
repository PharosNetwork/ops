package cmd

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/spf13/cobra"
)

const (
	stakingAddress = "0x4100000000000000000000000000000000000000"
	stakingABI     = `[{"inputs":[],"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"poolId","type":"bytes32"},{"indexed":false,"internalType":"string","name":"description","type":"string"},{"indexed":false,"internalType":"string","name":"publicKey","type":"string"},{"indexed":false,"internalType":"string","name":"blsPublicKey","type":"string"},{"indexed":false,"internalType":"string","name":"endpoint","type":"string"},{"indexed":false,"internalType":"uint64","name":"effectiveBlockNum","type":"uint64"},{"indexed":false,"internalType":"uint8","name":"status","type":"uint8"}],"name":"DomainUpdate","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"uint256","name":"epochNumber","type":"uint256"},{"indexed":true,"internalType":"uint256","name":"blockNumber","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"timestamp","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"totalStake","type":"uint256"},{"indexed":false,"internalType":"bytes32[]","name":"activeValidators","type":"bytes32[]"}],"name":"EpochChange","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"delegator","type":"address"},{"indexed":true,"internalType":"bytes32","name":"poolId","type":"bytes32"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"StakeAdded","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"poolId","type":"bytes32"}],"name":"ValidatorExitRequested","type":"event"},{"inputs":[{"internalType":"bytes32","name":"poolId","type":"bytes32"}],"name":"exitValidator","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"string","name":"description","type":"string"},{"internalType":"string","name":"publicKey","type":"string"},{"internalType":"string","name":"proofOfPossession","type":"string"},{"internalType":"string","name":"blsPublicKey","type":"string"},{"internalType":"string","name":"blsProofOfPossession","type":"string"},{"internalType":"string","name":"endpoint","type":"string"}],"name":"registerValidator","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"_poolId","type":"bytes32"},{"internalType":"string","name":"_description","type":"string"},{"internalType":"string","name":"_endpoint","type":"string"}],"name":"updateValidator","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"_poolId","type":"bytes32"},{"internalType":"bool","name":"_enabled","type":"bool"}],"name":"setDelegationEnabled","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"_poolId","type":"bytes32"},{"internalType":"uint256","name":"_newRate","type":"uint256"}],"name":"setCommissionRate","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"_poolId","type":"bytes32"}],"name":"delegate","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"_poolId","type":"bytes32"},{"internalType":"address","name":"_approver","type":"address"}],"name":"setDelegationApprover","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"_poolId","type":"bytes32"},{"internalType":"uint256","name":"_withdrawStake","type":"uint256"}],"name":"withdrawStake","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"_poolId","type":"bytes32"}],"name":"claimStake","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"_poolId","type":"bytes32"}],"name":"claimReward","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"_poolId","type":"bytes32"}],"name":"compoundRewards","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"_poolId","type":"bytes32"}],"name":"getDelegationApprover","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"_poolId","type":"bytes32"}],"name":"getValidator","outputs":[{"internalType":"struct IStaking.Validator","name":"validator","type":"tuple","components":[{"internalType":"string","name":"description","type":"string"},{"internalType":"string","name":"publicKey","type":"string"},{"internalType":"string","name":"publicKeyPop","type":"string"},{"internalType":"string","name":"blsPublicKey","type":"string"},{"internalType":"string","name":"blsPublicKeyPop","type":"string"},{"internalType":"string","name":"endpoint","type":"string"},{"internalType":"uint8","name":"status","type":"uint8"},{"internalType":"bytes32","name":"poolId","type":"bytes32"},{"internalType":"uint256","name":"totalStake","type":"uint256"},{"internalType":"address","name":"owner","type":"address"},{"internalType":"uint256","name":"stakeSnapshot","type":"uint256"},{"internalType":"uint256","name":"pendingWithdrawStake","type":"uint256"},{"internalType":"uint8","name":"pendingWithdrawWindow","type":"uint8"},{"internalType":"address","name":"pendingOwner","type":"address"}]}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"_poolId","type":"bytes32"}],"name":"getCommissionRate","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"poolId","type":"bytes32"}],"name":"delegationEnabledMapping","outputs":[{"internalType":"bool","name":"delegationEnabled","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"getActiveValidators","outputs":[{"internalType":"bytes32[]","name":"","type":"bytes32[]"}],"stateMutability":"view","type":"function"}]`
)

const (
	// Environment variable name for private key
	ValidatorPrivateKeyEnv = "VALIDATOR_PRIVATE_KEY"
)

var (
	validatorRPCEndpoint  string
	validatorStake        string
	domainLabel           string
	domainEndpoint        string
	domainPubKeyPath      string
	stabilizingPubKeyPath string
	addValidatorUnsigned  bool
)

var (
	exitValidatorRPCEndpoint string
	exitDomainPubKeyPath     string
	exitValidatorUnsigned    bool
)

var (
	updateValidatorRPCEndpoint string
	updateValidatorPoolID      string
	updateDomainPubKeyPath     string
	updateDescription          string
	updateEndpoint             string
	updateValidatorUnsigned    bool
)

var addValidatorCmd = &cobra.Command{
	Use:   "add-validator",
	Short: "Add validator to the network",
	Long:  "Register a validator node to the Pharos network by calling the staking contract",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Adding validator...")

		// Read domain public key (with prefix stripping)
		domainPubKey, err := readPublicKey(domainPubKeyPath)
		if err != nil {
			return fmt.Errorf("failed to read domain public key: %w", err)
		}

		// Read stabilizing public key (with prefix stripping)
		stabilizingPubKey, err := readPublicKey(stabilizingPubKeyPath)
		if err != nil {
			return fmt.Errorf("failed to read stabilizing public key: %w", err)
		}

		// Add 0x prefix if not present
		if len(domainPubKey) > 0 && !strings.HasPrefix(domainPubKey, "0x") {
			domainPubKey = "0x" + domainPubKey
		}
		if len(stabilizingPubKey) > 0 && !strings.HasPrefix(stabilizingPubKey, "0x") {
			stabilizingPubKey = "0x" + stabilizingPubKey
		}

		// Parse stake value (in tokens, will convert to wei)
		var stakeValue *big.Int
		if validatorStake != "" {
			stakeTokens, ok := new(big.Int).SetString(validatorStake, 10)
			if !ok {
				return fmt.Errorf("invalid stake value: %s", validatorStake)
			}
			// Convert tokens to wei (1 token = 10^18 wei)
			stakeValue = new(big.Int).Mul(stakeTokens, big.NewInt(1e18))
		} else {
			// Default: 1,000,000 tokens
			stakeValue = new(big.Int).Mul(big.NewInt(1000000), big.NewInt(1e18))
		}

		fmt.Printf("Stake amount: %s tokens (%s wei)\n", new(big.Int).Div(stakeValue, big.NewInt(1e18)).String(), stakeValue.String())

		// Parse ABI
		parsedABI, err := abi.JSON(strings.NewReader(stakingABI))
		if err != nil {
			return fmt.Errorf("failed to parse ABI: %w", err)
		}

		contractAddr := common.HexToAddress(stakingAddress)

		// Pack transaction data for registerValidator
		data, err := parsedABI.Pack("registerValidator",
			domainLabel,       // description
			domainPubKey,      // publicKey
			"0x00",            // proofOfPossession (placeholder)
			stabilizingPubKey, // blsPublicKey
			"0x00",            // blsProofOfPossession (placeholder)
			domainEndpoint,    // endpoint
		)
		if err != nil {
			return fmt.Errorf("failed to pack transaction data: %w", err)
		}

		if addValidatorUnsigned {
			printUnsignedTx("registerValidator", stakeValue, data)
			return nil
		}

		// Get private key from environment variable
		privateKeyHex := os.Getenv(ValidatorPrivateKeyEnv)
		if privateKeyHex == "" {
			return fmt.Errorf("private key not set. Please set environment variable %s", ValidatorPrivateKeyEnv)
		}
		// Remove 0x prefix if present
		privateKeyHex = strings.TrimPrefix(privateKeyHex, "0x")

		// Connect to Ethereum client
		client, err := ethclient.Dial(validatorRPCEndpoint)
		if err != nil {
			return fmt.Errorf("failed to connect to endpoint: %w", err)
		}
		defer client.Close()

		fmt.Println("Connected to endpoint")

		// Load private key
		privateKey, err := crypto.HexToECDSA(privateKeyHex)
		if err != nil {
			return fmt.Errorf("failed to load private key: %w", err)
		}

		// Get account address from private key
		publicKey := privateKey.Public()
		publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("failed to get public key")
		}
		accountAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
		fmt.Printf("Account address: %s\n", accountAddress.Hex())

		// Get chain ID
		chainID, err := client.ChainID(cmd.Context())
		if err != nil {
			return fmt.Errorf("failed to get chain ID: %w", err)
		}

		// Create transactor
		auth, err := bind.NewKeyedTransactorWithChainID(privateKey, chainID)
		if err != nil {
			return fmt.Errorf("failed to create transactor: %w", err)
		}

		// Set transaction parameters
		auth.Value = stakeValue
		auth.GasPrice = big.NewInt(1000000000) // 1 Gwei

		// Get nonce
		nonce, err := client.PendingNonceAt(cmd.Context(), auth.From)
		if err != nil {
			return fmt.Errorf("failed to get nonce: %w", err)
		}
		auth.Nonce = big.NewInt(int64(nonce))

		// Create transaction
		tx := types.NewTransaction(
			auth.Nonce.Uint64(),
			contractAddr,
			auth.Value,
			3000000, // gas limit
			auth.GasPrice,
			data,
		)

		// Sign transaction
		signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
		if err != nil {
			return fmt.Errorf("failed to sign transaction: %w", err)
		}

		// Send transaction
		err = client.SendTransaction(cmd.Context(), signedTx)
		if err != nil {
			return fmt.Errorf("failed to send transaction: %w", err)
		}

		fmt.Printf("Validator register tx: %s\n", signedTx.Hash().Hex())

		// Wait for receipt
		receipt, err := bind.WaitMined(cmd.Context(), client, signedTx)
		if err != nil {
			return fmt.Errorf("failed to wait for transaction: %w", err)
		}

		if receipt.Status == 1 {
			// Calculate and display Node ID
			pubKeyBytes, err := hex.DecodeString(domainPubKey[2:]) // Remove 0x prefix
			if err == nil {
				nodeID := sha256.Sum256(pubKeyBytes)
				fmt.Printf("Node ID: %s\n", hex.EncodeToString(nodeID[:]))
			}
			fmt.Println("Validator register success")
		} else {
			fmt.Println("Validator register failed")
		}

		return nil
	},
}

var exitValidatorCmd = &cobra.Command{
	Use:   "exit-validator",
	Short: "Exit validator from the network",
	Long:  "Request to exit a validator node from the Pharos network by calling the staking contract",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Exiting validator...")

		// Read domain public key
		domainPubKey, err := readPublicKey(exitDomainPubKeyPath)
		if err != nil {
			return fmt.Errorf("failed to read domain public key: %w", err)
		}

		// Calculate pool ID (SHA256 of public key)
		pubKeyBytes, err := hex.DecodeString(domainPubKey)
		if err != nil {
			return fmt.Errorf("failed to decode public key: %w", err)
		}

		poolID := sha256.Sum256(pubKeyBytes)
		fmt.Printf("Pool ID: %s\n", hex.EncodeToString(poolID[:]))

		// Prepare parameters for exitValidator
		var poolIDBytes32 [32]byte
		copy(poolIDBytes32[:], poolID[:])

		// Parse ABI
		parsedABI, err := abi.JSON(strings.NewReader(stakingABI))
		if err != nil {
			return fmt.Errorf("failed to parse ABI: %w", err)
		}

		contractAddr := common.HexToAddress(stakingAddress)

		// Pack transaction data
		data, err := parsedABI.Pack("exitValidator", poolIDBytes32)
		if err != nil {
			return fmt.Errorf("failed to pack transaction data: %w", err)
		}

		if exitValidatorUnsigned {
			printUnsignedTx("exitValidator", big.NewInt(0), data)
			return nil
		}

		// Get private key from environment variable
		privateKeyHex := os.Getenv(ValidatorPrivateKeyEnv)
		if privateKeyHex == "" {
			return fmt.Errorf("private key not set. Please set environment variable %s", ValidatorPrivateKeyEnv)
		}
		// Remove 0x prefix if present
		privateKeyHex = strings.TrimPrefix(privateKeyHex, "0x")

		// Load private key first to get account address
		privateKey, err := crypto.HexToECDSA(privateKeyHex)
		if err != nil {
			return fmt.Errorf("failed to load private key: %w", err)
		}

		// Get account address from private key
		publicKey := privateKey.Public()
		publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("failed to get public key")
		}
		accountAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
		fmt.Printf("Account address: %s\n", accountAddress.Hex())

		// Connect to Ethereum client
		client, err := ethclient.Dial(exitValidatorRPCEndpoint)
		if err != nil {
			return fmt.Errorf("failed to connect to endpoint: %w", err)
		}
		defer client.Close()

		fmt.Println("Connected to endpoint")

		// Get chain ID
		chainID, err := client.ChainID(cmd.Context())
		if err != nil {
			return fmt.Errorf("failed to get chain ID: %w", err)
		}

		// Create transactor
		auth, err := bind.NewKeyedTransactorWithChainID(privateKey, chainID)
		if err != nil {
			return fmt.Errorf("failed to create transactor: %w", err)
		}

		// Set transaction parameters
		auth.Value = big.NewInt(0)
		auth.GasPrice = big.NewInt(1000000000) // 1 Gwei
		auth.GasLimit = 2000000

		// Get nonce
		nonce, err := client.PendingNonceAt(cmd.Context(), auth.From)
		if err != nil {
			return fmt.Errorf("failed to get nonce: %w", err)
		}
		auth.Nonce = big.NewInt(int64(nonce))

		// Create transaction
		tx := types.NewTransaction(
			auth.Nonce.Uint64(),
			contractAddr,
			auth.Value,
			auth.GasLimit,
			auth.GasPrice,
			data,
		)

		// Sign transaction
		signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
		if err != nil {
			return fmt.Errorf("failed to sign transaction: %w", err)
		}

		// Send transaction
		err = client.SendTransaction(cmd.Context(), signedTx)
		if err != nil {
			return fmt.Errorf("failed to send transaction: %w", err)
		}

		fmt.Printf("Validator exit tx: %s\n", signedTx.Hash().Hex())

		// Wait for receipt
		receipt, err := bind.WaitMined(cmd.Context(), client, signedTx)
		if err != nil {
			return fmt.Errorf("failed to wait for transaction: %w", err)
		}

		if receipt.Status == 1 {
			fmt.Println("Validator exit success")
		} else {
			fmt.Println("Validator exit failed")
		}

		return nil
	},
}

var updateValidatorCmd = &cobra.Command{
	Use:   "update-validator",
	Short: "Update validator information",
	Long:  "Update validator description and endpoint by calling the staking contract",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Updating validator...")

		// Resolve pool ID
		var poolIDBytes32 [32]byte
		if updateValidatorPoolID != "" {
			// Use provided pool ID
			poolIDHex := strings.TrimPrefix(updateValidatorPoolID, "0x")
			poolIDBytes, err := hex.DecodeString(poolIDHex)
			if err != nil {
				return fmt.Errorf("invalid pool ID hex: %w", err)
			}
			if len(poolIDBytes) != 32 {
				return fmt.Errorf("pool ID must be 32 bytes, got %d", len(poolIDBytes))
			}
			copy(poolIDBytes32[:], poolIDBytes)
		} else {
			// Compute from domain public key
			domainPubKey, err := readPublicKey(updateDomainPubKeyPath)
			if err != nil {
				return fmt.Errorf("failed to read domain public key: %w", err)
			}
			pubKeyBytes, err := hex.DecodeString(domainPubKey)
			if err != nil {
				return fmt.Errorf("failed to decode public key: %w", err)
			}
			poolID := sha256.Sum256(pubKeyBytes)
			copy(poolIDBytes32[:], poolID[:])
		}
		fmt.Printf("Pool ID: %s\n", hex.EncodeToString(poolIDBytes32[:]))

		// Parse ABI
		parsedABI, err := abi.JSON(strings.NewReader(stakingABI))
		if err != nil {
			return fmt.Errorf("failed to parse ABI: %w", err)
		}

		contractAddr := common.HexToAddress(stakingAddress)

		// Pack transaction data for updateValidator
		data, err := parsedABI.Pack("updateValidator", poolIDBytes32, updateDescription, updateEndpoint)
		if err != nil {
			return fmt.Errorf("failed to pack transaction data: %w", err)
		}

		if updateValidatorUnsigned {
			printUnsignedTx("updateValidator", big.NewInt(0), data)
			return nil
		}

		// Get private key from environment variable
		privateKeyHex := os.Getenv(ValidatorPrivateKeyEnv)
		if privateKeyHex == "" {
			return fmt.Errorf("private key not set. Please set environment variable %s", ValidatorPrivateKeyEnv)
		}
		privateKeyHex = strings.TrimPrefix(privateKeyHex, "0x")

		// Load private key
		privateKey, err := crypto.HexToECDSA(privateKeyHex)
		if err != nil {
			return fmt.Errorf("failed to load private key: %w", err)
		}

		// Get account address
		publicKey := privateKey.Public()
		publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("failed to get public key")
		}
		accountAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
		fmt.Printf("Account address: %s\n", accountAddress.Hex())

		// Connect to Ethereum client
		client, err := ethclient.Dial(updateValidatorRPCEndpoint)
		if err != nil {
			return fmt.Errorf("failed to connect to endpoint: %w", err)
		}
		defer client.Close()

		fmt.Println("Connected to endpoint")

		// Get chain ID
		chainID, err := client.ChainID(cmd.Context())
		if err != nil {
			return fmt.Errorf("failed to get chain ID: %w", err)
		}

		// Create transactor
		auth, err := bind.NewKeyedTransactorWithChainID(privateKey, chainID)
		if err != nil {
			return fmt.Errorf("failed to create transactor: %w", err)
		}

		// Set transaction parameters
		auth.Value = big.NewInt(0)
		auth.GasPrice = big.NewInt(1000000000) // 1 Gwei
		auth.GasLimit = 2000000

		// Get nonce
		nonce, err := client.PendingNonceAt(cmd.Context(), auth.From)
		if err != nil {
			return fmt.Errorf("failed to get nonce: %w", err)
		}
		auth.Nonce = big.NewInt(int64(nonce))

		// Create transaction
		tx := types.NewTransaction(
			auth.Nonce.Uint64(),
			contractAddr,
			auth.Value,
			auth.GasLimit,
			auth.GasPrice,
			data,
		)

		// Sign transaction
		signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
		if err != nil {
			return fmt.Errorf("failed to sign transaction: %w", err)
		}

		// Send transaction
		err = client.SendTransaction(cmd.Context(), signedTx)
		if err != nil {
			return fmt.Errorf("failed to send transaction: %w", err)
		}

		fmt.Printf("Validator update tx: %s\n", signedTx.Hash().Hex())

		// Wait for receipt
		receipt, err := bind.WaitMined(cmd.Context(), client, signedTx)
		if err != nil {
			return fmt.Errorf("failed to wait for transaction: %w", err)
		}

		if receipt.Status == 1 {
			fmt.Println("Validator update success")
		} else {
			fmt.Println("Validator update failed")
		}

		return nil
	},
}

// Helper functions

func readPublicKey(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	// Trim whitespace and newlines
	key := strings.TrimSpace(string(data))

	// Strip prefixes from public key
	// Possible prefixes: "0x1003", "1003", "0x4003", "0x4002", "0x"
	if strings.HasPrefix(key, "0x1003") {
		key = key[6:] // Remove "0x1003"
	} else if strings.HasPrefix(key, "0x4003") {
		key = key[6:] // Remove "0x4003"
	} else if strings.HasPrefix(key, "0x4002") {
		key = key[6:] // Remove "0x4002"
	} else if strings.HasPrefix(key, "1003") {
		key = key[4:] // Remove "1003"
	} else if strings.HasPrefix(key, "0x") {
		key = key[2:] // Remove "0x"
	}

	return key, nil
}

func init() {
	rootCmd.AddCommand(addValidatorCmd)
	rootCmd.AddCommand(exitValidatorCmd)
	rootCmd.AddCommand(updateValidatorCmd)

	// add-validator flags
	addValidatorCmd.Flags().StringVar(&validatorRPCEndpoint, "rpc-endpoint", "http://127.0.0.1:18100", "RPC endpoint URL")
	addValidatorCmd.Flags().StringVar(&validatorStake, "stake", "", "Stake amount in tokens (default: 1000000 tokens)")
	addValidatorCmd.Flags().StringVar(&domainLabel, "domain-label", "", "Domain label/description")
	addValidatorCmd.Flags().StringVar(&domainEndpoint, "domain-endpoint", "", "Domain endpoint URL")
	addValidatorCmd.Flags().StringVar(&domainPubKeyPath, "domain-pubkey", "./keys/domain.pub", "Path to domain public key file")
	addValidatorCmd.Flags().StringVar(&stabilizingPubKeyPath, "stabilizing-pubkey", "./keys/stabilizing.pub", "Path to stabilizing public key file")
	addValidatorCmd.Flags().BoolVar(&addValidatorUnsigned, "unsigned", false, "Print unsigned tx fields (To/Value/Data) for Safe multisig instead of signing and broadcasting")

	addValidatorCmd.MarkFlagRequired("domain-label")
	addValidatorCmd.MarkFlagRequired("domain-endpoint")

	// exit-validator flags
	exitValidatorCmd.Flags().StringVar(&exitValidatorRPCEndpoint, "rpc-endpoint", "http://127.0.0.1:18100", "RPC endpoint URL")
	exitValidatorCmd.Flags().StringVar(&exitDomainPubKeyPath, "domain-pubkey", "./keys/domain.pub", "Path to domain public key file")
	exitValidatorCmd.Flags().BoolVar(&exitValidatorUnsigned, "unsigned", false, "Print unsigned tx fields (To/Value/Data) for Safe multisig instead of signing and broadcasting")

	// update-validator flags
	updateValidatorCmd.Flags().StringVar(&updateValidatorRPCEndpoint, "rpc-endpoint", "http://127.0.0.1:18100", "RPC endpoint URL")
	updateValidatorCmd.Flags().StringVar(&updateValidatorPoolID, "pool-id", "", "Pool ID (hex, 64 characters). If empty, computed from --domain-pubkey")
	updateValidatorCmd.Flags().StringVar(&updateDomainPubKeyPath, "domain-pubkey", "./keys/domain.pub", "Path to domain public key file (used if --pool-id is empty)")
	updateValidatorCmd.Flags().StringVar(&updateDescription, "description", "", "New validator description")
	updateValidatorCmd.Flags().StringVar(&updateEndpoint, "endpoint", "", "New validator endpoint URL")
	updateValidatorCmd.Flags().BoolVar(&updateValidatorUnsigned, "unsigned", false, "Print unsigned tx fields (To/Value/Data) for Safe multisig instead of signing and broadcasting")

	updateValidatorCmd.MarkFlagRequired("description")
	updateValidatorCmd.MarkFlagRequired("endpoint")
}
