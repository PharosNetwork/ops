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
	stakingABI     = `[{"inputs":[],"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"poolId","type":"bytes32"},{"indexed":false,"internalType":"string","name":"description","type":"string"},{"indexed":false,"internalType":"string","name":"publicKey","type":"string"},{"indexed":false,"internalType":"string","name":"blsPublicKey","type":"string"},{"indexed":false,"internalType":"string","name":"endpoint","type":"string"},{"indexed":false,"internalType":"uint64","name":"effectiveBlockNum","type":"uint64"},{"indexed":false,"internalType":"uint8","name":"status","type":"uint8"}],"name":"DomainUpdate","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"uint256","name":"epochNumber","type":"uint256"},{"indexed":true,"internalType":"uint256","name":"blockNumber","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"timestamp","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"totalStake","type":"uint256"},{"indexed":false,"internalType":"bytes32[]","name":"activeValidators","type":"bytes32[]"}],"name":"EpochChange","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"delegator","type":"address"},{"indexed":true,"internalType":"bytes32","name":"poolId","type":"bytes32"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"StakeAdded","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"poolId","type":"bytes32"}],"name":"ValidatorExitRequested","type":"event"},{"inputs":[{"internalType":"bytes32","name":"poolId","type":"bytes32"}],"name":"exitValidator","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"string","name":"description","type":"string"},{"internalType":"string","name":"publicKey","type":"string"},{"internalType":"string","name":"proofOfPossession","type":"string"},{"internalType":"string","name":"blsPublicKey","type":"string"},{"internalType":"string","name":"blsProofOfPossession","type":"string"},{"internalType":"string","name":"endpoint","type":"string"}],"name":"registerValidator","outputs":[],"stateMutability":"payable","type":"function"}]`
)

var (
	validatorEndpoint     string
	validatorKey          string
	domainLabel           string
	domainEndpoint        string
	domainPubKeyPath      string
	stabilizingPubKeyPath string
)

var (
	exitValidatorEndpoint string
	exitValidatorKey      string
	exitDomainPubKeyPath  string
)

var addValidatorCmd = &cobra.Command{
	Use:   "add-validator",
	Short: "Add validator to the network",
	Long:  "Register a validator node to the Pharos network by calling the staking contract",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Adding validator...")

		// Read domain public key
		domainPubKey, err := readPublicKey(domainPubKeyPath)
		if err != nil {
			return fmt.Errorf("failed to read domain public key: %w", err)
		}

		// Read stabilizing public key
		stabilizingPubKey, err := readPublicKey(stabilizingPubKeyPath)
		if err != nil {
			return fmt.Errorf("failed to read stabilizing public key: %w", err)
		}

		// Add 0x prefix if not present
		if len(domainPubKey) > 0 && !strings.HasPrefix(domainPubKey, "0x") {
			domainPubKey = "0x" + domainPubKey
		}

		// Connect to Ethereum client
		client, err := ethclient.Dial(validatorEndpoint)
		if err != nil {
			return fmt.Errorf("failed to connect to endpoint: %w", err)
		}
		defer client.Close()

		fmt.Println("Connected to endpoint")

		// Load private key
		privateKey, err := crypto.HexToECDSA(validatorKey)
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
		auth.Value = new(big.Int).Mul(big.NewInt(1000000), big.NewInt(1e18)) // 1,000,000 tokens
		auth.GasPrice = big.NewInt(1000000000)                               // 1 Gwei

		// Get nonce
		nonce, err := client.PendingNonceAt(cmd.Context(), auth.From)
		if err != nil {
			return fmt.Errorf("failed to get nonce: %w", err)
		}
		auth.Nonce = big.NewInt(int64(nonce))

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
			fmt.Println("Validator register success")
		} else {
			fmt.Println("Validator register failed")
		}

		fmt.Printf("Validator register receipt: %+v\n", receipt)
		return nil
	},
}

var exitValidatorCmd = &cobra.Command{
	Use:   "exit-validator",
	Short: "Exit validator from the network",
	Long:  "Request to exit a validator node from the Pharos network by calling the staking contract",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Exiting validator...")

		// Load private key first to get account address
		privateKey, err := crypto.HexToECDSA(exitValidatorKey)
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

		// Connect to Ethereum client
		client, err := ethclient.Dial(exitValidatorEndpoint)
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

		// Parse ABI
		parsedABI, err := abi.JSON(strings.NewReader(stakingABI))
		if err != nil {
			return fmt.Errorf("failed to parse ABI: %w", err)
		}

		contractAddr := common.HexToAddress(stakingAddress)

		// Prepare parameters for exitValidator
		var poolIDBytes32 [32]byte
		copy(poolIDBytes32[:], poolID[:])

		// Pack transaction data
		data, err := parsedABI.Pack("exitValidator", poolIDBytes32)
		if err != nil {
			return fmt.Errorf("failed to pack transaction data: %w", err)
		}

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

		fmt.Printf("Validator exit receipt: %+v\n", receipt)
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
	return key, nil
}

func init() {
	rootCmd.AddCommand(addValidatorCmd)
	rootCmd.AddCommand(exitValidatorCmd)

	// add-validator flags
	addValidatorCmd.Flags().StringVar(&validatorEndpoint, "endpoint", "http://127.0.0.1:18100", "RPC endpoint URL")
	addValidatorCmd.Flags().StringVar(&validatorKey, "key", "", "Private key for transaction signing (required)")
	addValidatorCmd.Flags().StringVar(&domainLabel, "domain-label", "", "Domain label/description")
	addValidatorCmd.Flags().StringVar(&domainEndpoint, "domain-endpoint", "", "Domain endpoint URL")
	addValidatorCmd.Flags().StringVar(&domainPubKeyPath, "domain-pubkey", "./keys/domain.pub", "Path to domain public key file")
	addValidatorCmd.Flags().StringVar(&stabilizingPubKeyPath, "stabilizing-pubkey", "./keys/stabilizing.pub", "Path to stabilizing public key file")

	addValidatorCmd.MarkFlagRequired("key")
	addValidatorCmd.MarkFlagRequired("domain-label")
	addValidatorCmd.MarkFlagRequired("domain-endpoint")

	// exit-validator flags
	exitValidatorCmd.Flags().StringVar(&exitValidatorEndpoint, "endpoint", "http://127.0.0.1:18100", "RPC endpoint URL")
	exitValidatorCmd.Flags().StringVar(&exitValidatorKey, "key", "", "Private key for transaction signing (required)")
	exitValidatorCmd.Flags().StringVar(&exitDomainPubKeyPath, "domain-pubkey", "./keys/domain.pub", "Path to domain public key file")

	exitValidatorCmd.MarkFlagRequired("key")
}
