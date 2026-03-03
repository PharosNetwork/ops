package cmd

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/spf13/cobra"
)

var (
	poolIDPubKeyPath string
)

var (
	delegationRPCEndpoint string
	delegationPoolID      string
	delegationPubKeyPath  string
	delegationEnabled     bool
)

var (
	commissionRPCEndpoint string
	commissionPoolID      string
	commissionPubKeyPath  string
	commissionRate        uint64
)

var (
	getInfoRPCEndpoint string
	getInfoPoolID      string
	getInfoPubKeyPath  string
)

// computePoolID reads a domain public key file, strips prefix, and returns the 0x-prefixed SHA256 hash
func computePoolID(pubKeyPath string) (string, error) {
	pubKey, err := readPublicKey(pubKeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to read public key: %w", err)
	}
	pubKeyBytes, err := hex.DecodeString(pubKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode public key hex: %w", err)
	}
	hash := sha256.Sum256(pubKeyBytes)
	return "0x" + hex.EncodeToString(hash[:]), nil
}

// resolvePoolID returns a [32]byte pool ID either from the --pool-id flag or computed from the public key file
func resolvePoolID(poolIDFlag string, pubKeyPath string) ([32]byte, error) {
	var poolIDBytes32 [32]byte
	poolIDHex := poolIDFlag

	if poolIDHex == "" {
		computed, err := computePoolID(pubKeyPath)
		if err != nil {
			return poolIDBytes32, err
		}
		poolIDHex = computed
		fmt.Printf("Computed Pool ID: %s\n", poolIDHex)
	}

	poolIDHex = strings.TrimPrefix(poolIDHex, "0x")
	poolIDBytes, err := hex.DecodeString(poolIDHex)
	if err != nil {
		return poolIDBytes32, fmt.Errorf("invalid pool ID hex: %w", err)
	}
	if len(poolIDBytes) != 32 {
		return poolIDBytes32, fmt.Errorf("pool ID must be 32 bytes, got %d", len(poolIDBytes))
	}
	copy(poolIDBytes32[:], poolIDBytes)
	return poolIDBytes32, nil
}

// sendStakingTx builds, signs, sends a tx to the staking contract and waits for receipt
func sendStakingTx(cmd *cobra.Command, rpcEndpoint string, data []byte) error {
	privateKeyHex := os.Getenv(ValidatorPrivateKeyEnv)
	if privateKeyHex == "" {
		return fmt.Errorf("private key not set. Please set environment variable %s", ValidatorPrivateKeyEnv)
	}
	privateKeyHex = strings.TrimPrefix(privateKeyHex, "0x")

	client, err := ethclient.Dial(rpcEndpoint)
	if err != nil {
		return fmt.Errorf("failed to connect to endpoint: %w", err)
	}
	defer client.Close()

	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return fmt.Errorf("failed to load private key: %w", err)
	}

	publicKeyECDSA, ok := privateKey.Public().(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("failed to get public key")
	}
	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	fmt.Printf("Account address: %s\n", fromAddress.Hex())

	chainID, err := client.ChainID(cmd.Context())
	if err != nil {
		return fmt.Errorf("failed to get chain ID: %w", err)
	}

	nonce, err := client.PendingNonceAt(cmd.Context(), fromAddress)
	if err != nil {
		return fmt.Errorf("failed to get nonce: %w", err)
	}

	contractAddr := common.HexToAddress(stakingAddress)
	tx := types.NewTransaction(
		nonce,
		contractAddr,
		big.NewInt(0),          // nonpayable
		2000000,                // gas limit
		big.NewInt(1000000000), // 1 Gwei
		data,
	)

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		return fmt.Errorf("failed to sign transaction: %w", err)
	}

	err = client.SendTransaction(cmd.Context(), signedTx)
	if err != nil {
		return fmt.Errorf("failed to send transaction: %w", err)
	}

	fmt.Printf("Transaction sent: %s\n", signedTx.Hash().Hex())

	receipt, err := bind.WaitMined(cmd.Context(), client, signedTx)
	if err != nil {
		return fmt.Errorf("failed to wait for transaction: %w", err)
	}

	if receipt.Status == 1 {
		fmt.Println("Transaction success")
	} else {
		fmt.Println("Transaction failed")
	}
	return nil
}

// ==================== get-pool-id ====================

var getPoolIDCmd = &cobra.Command{
	Use:   "get-pool-id",
	Short: "Get the staking pool ID from domain public key",
	Long:  "Calculate the staking pool ID (0x-prefixed SHA256 hash of the domain public key)",
	RunE: func(cmd *cobra.Command, args []string) error {
		poolID, err := computePoolID(poolIDPubKeyPath)
		if err != nil {
			return err
		}
		fmt.Printf("Pool ID: %s\n", poolID)
		return nil
	},
}

// ==================== set-delegation ====================

var setDelegationCmd = &cobra.Command{
	Use:   "set-delegation",
	Short: "Enable or disable delegation for your validator",
	Long:  "Call setDelegationEnabled on the staking contract to allow or disallow delegators",
	RunE: func(cmd *cobra.Command, args []string) error {
		poolIDBytes32, err := resolvePoolID(delegationPoolID, delegationPubKeyPath)
		if err != nil {
			return err
		}

		fmt.Printf("Setting delegation enabled=%v for pool %s\n", delegationEnabled, hex.EncodeToString(poolIDBytes32[:]))

		parsedABI, err := abi.JSON(strings.NewReader(stakingABI))
		if err != nil {
			return fmt.Errorf("failed to parse ABI: %w", err)
		}

		data, err := parsedABI.Pack("setDelegationEnabled", poolIDBytes32, delegationEnabled)
		if err != nil {
			return fmt.Errorf("failed to pack transaction data: %w", err)
		}

		return sendStakingTx(cmd, delegationRPCEndpoint, data)
	},
}

// ==================== set-commission-rate ====================

var setCommissionRateCmd = &cobra.Command{
	Use:   "set-commission-rate",
	Short: "Set the commission rate for your validator",
	Long:  "Call setCommissionRate on the staking contract. Rate is in basis points (10000 = 100%)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if commissionRate > 10000 {
			return fmt.Errorf("commission rate must be between 0 and 10000 (basis points), got %d", commissionRate)
		}

		poolIDBytes32, err := resolvePoolID(commissionPoolID, commissionPubKeyPath)
		if err != nil {
			return err
		}

		fmt.Printf("Setting commission rate to %d (%.2f%%) for pool %s\n",
			commissionRate, float64(commissionRate)/100.0, hex.EncodeToString(poolIDBytes32[:]))

		parsedABI, err := abi.JSON(strings.NewReader(stakingABI))
		if err != nil {
			return fmt.Errorf("failed to parse ABI: %w", err)
		}

		rate := new(big.Int).SetUint64(commissionRate)
		data, err := parsedABI.Pack("setCommissionRate", poolIDBytes32, rate)
		if err != nil {
			return fmt.Errorf("failed to pack transaction data: %w", err)
		}

		return sendStakingTx(cmd, commissionRPCEndpoint, data)
	},
}

// ==================== get-validator-info ====================

var getValidatorInfoCmd = &cobra.Command{
	Use:   "get-validator-info",
	Short: "Get validator information from the staking contract",
	Long:  "Query validator details, commission rate, and delegation status",
	RunE: func(cmd *cobra.Command, args []string) error {
		poolIDBytes32, err := resolvePoolID(getInfoPoolID, getInfoPubKeyPath)
		if err != nil {
			return err
		}

		client, err := ethclient.Dial(getInfoRPCEndpoint)
		if err != nil {
			return fmt.Errorf("failed to connect to endpoint: %w", err)
		}
		defer client.Close()

		parsedABI, err := abi.JSON(strings.NewReader(stakingABI))
		if err != nil {
			return fmt.Errorf("failed to parse ABI: %w", err)
		}

		contractAddr := common.HexToAddress(stakingAddress)

		// Call getValidator
		validatorData, err := parsedABI.Pack("getValidator", poolIDBytes32)
		if err != nil {
			return fmt.Errorf("failed to pack getValidator call: %w", err)
		}

		validatorResult, err := client.CallContract(cmd.Context(), ethereum.CallMsg{
			To:   &contractAddr,
			Data: validatorData,
		}, nil)
		if err != nil {
			return fmt.Errorf("failed to call getValidator: %w", err)
		}

		var validator struct {
			Description           string
			PublicKey             string
			PublicKeyPop          string
			BlsPublicKey          string
			BlsPublicKeyPop       string
			Endpoint              string
			Status                uint8
			PoolId                [32]byte
			TotalStake            *big.Int
			Owner                 common.Address
			StakeSnapshot         *big.Int
			PendingWithdrawStake  *big.Int
			PendingWithdrawWindow uint8
			PendingOwner          common.Address
		}

		err = parsedABI.UnpackIntoInterface(&validator, "getValidator", validatorResult)
		if err != nil {
			return fmt.Errorf("failed to unpack getValidator result: %w", err)
		}

		// Call getCommissionRate
		commissionData, err := parsedABI.Pack("getCommissionRate", poolIDBytes32)
		if err != nil {
			return fmt.Errorf("failed to pack getCommissionRate call: %w", err)
		}

		commissionResult, err := client.CallContract(cmd.Context(), ethereum.CallMsg{
			To:   &contractAddr,
			Data: commissionData,
		}, nil)
		if err != nil {
			return fmt.Errorf("failed to call getCommissionRate: %w", err)
		}

		var commissionRateBig *big.Int
		err = parsedABI.UnpackIntoInterface(&commissionRateBig, "getCommissionRate", commissionResult)
		if err != nil {
			return fmt.Errorf("failed to unpack getCommissionRate result: %w", err)
		}

		// Call delegationEnabledMapping
		delegationData, err := parsedABI.Pack("delegationEnabledMapping", poolIDBytes32)
		if err != nil {
			return fmt.Errorf("failed to pack delegationEnabledMapping call: %w", err)
		}

		delegationResult, err := client.CallContract(cmd.Context(), ethereum.CallMsg{
			To:   &contractAddr,
			Data: delegationData,
		}, nil)
		if err != nil {
			return fmt.Errorf("failed to call delegationEnabledMapping: %w", err)
		}

		var delegationEnabled bool
		err = parsedABI.UnpackIntoInterface(&delegationEnabled, "delegationEnabledMapping", delegationResult)
		if err != nil {
			return fmt.Errorf("failed to unpack delegationEnabledMapping result: %w", err)
		}

		// Format and print results
		fmt.Println("=== Validator Information ===")
		fmt.Printf("Pool ID:              %s\n", hex.EncodeToString(validator.PoolId[:]))
		fmt.Printf("Description:          %s\n", validator.Description)
		fmt.Printf("Owner:                %s\n", validator.Owner.Hex())
		fmt.Printf("Endpoint:             %s\n", validator.Endpoint)
		fmt.Printf("Status:               %d\n", validator.Status)
		fmt.Printf("Public Key:           %s\n", validator.PublicKey)
		fmt.Printf("BLS Public Key:       %s\n", validator.BlsPublicKey)
		fmt.Println()
		fmt.Println("=== Staking Information ===")
		fmt.Printf("Total Stake:          %s wei\n", validator.TotalStake.String())
		fmt.Printf("Stake Snapshot:       %s wei\n", validator.StakeSnapshot.String())
		fmt.Printf("Pending Withdraw:     %s wei\n", validator.PendingWithdrawStake.String())
		fmt.Printf("Withdraw Window:      %d epochs\n", validator.PendingWithdrawWindow)
		fmt.Println()
		fmt.Println("=== Commission & Delegation ===")
		commissionRateValue := commissionRateBig.Uint64()
		fmt.Printf("Commission Rate:      %d basis points (%.2f%%)\n", commissionRateValue, float64(commissionRateValue)/100.0)
		fmt.Printf("Delegation Enabled:   %v\n", delegationEnabled)

		return nil
	},
}

func init() {
	rootCmd.AddCommand(getPoolIDCmd)
	rootCmd.AddCommand(setDelegationCmd)
	rootCmd.AddCommand(setCommissionRateCmd)
	rootCmd.AddCommand(getValidatorInfoCmd)

	// get-pool-id flags
	getPoolIDCmd.Flags().StringVar(&poolIDPubKeyPath, "domain-pubkey", "./keys/domain.pub", "Path to domain public key file")

	// set-delegation flags
	setDelegationCmd.Flags().StringVar(&delegationRPCEndpoint, "rpc-endpoint", "http://127.0.0.1:18100", "RPC endpoint URL")
	setDelegationCmd.Flags().StringVar(&delegationPoolID, "pool-id", "", "Pool ID (hex). If empty, computed from domain-pubkey")
	setDelegationCmd.Flags().StringVar(&delegationPubKeyPath, "domain-pubkey", "./keys/domain.pub", "Path to domain public key file (used if --pool-id is empty)")
	setDelegationCmd.Flags().BoolVar(&delegationEnabled, "enabled", true, "Enable (true) or disable (false) delegation")

	// set-commission-rate flags
	setCommissionRateCmd.Flags().StringVar(&commissionRPCEndpoint, "rpc-endpoint", "http://127.0.0.1:18100", "RPC endpoint URL")
	setCommissionRateCmd.Flags().StringVar(&commissionPoolID, "pool-id", "", "Pool ID (hex). If empty, computed from domain-pubkey")
	setCommissionRateCmd.Flags().StringVar(&commissionPubKeyPath, "domain-pubkey", "./keys/domain.pub", "Path to domain public key file (used if --pool-id is empty)")
	setCommissionRateCmd.Flags().Uint64Var(&commissionRate, "rate", 0, "Commission rate in basis points (0-10000, where 10000 = 100%)")
	setCommissionRateCmd.MarkFlagRequired("rate")

	// get-validator-info flags
	getValidatorInfoCmd.Flags().StringVar(&getInfoRPCEndpoint, "rpc-endpoint", "http://127.0.0.1:18100", "RPC endpoint URL")
	getValidatorInfoCmd.Flags().StringVar(&getInfoPoolID, "pool-id", "", "Pool ID (hex). If empty, computed from domain-pubkey")
	getValidatorInfoCmd.Flags().StringVar(&getInfoPubKeyPath, "domain-pubkey", "./keys/domain.pub", "Path to domain public key file (used if --pool-id is empty)")
}
