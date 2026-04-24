package cmd

import (
	"crypto/ecdsa"
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

// ==================== delegate (add more stake) ====================

var (
	delegateRPCEndpoint string
	delegatePoolID      string
	delegatePubKeyPath  string
	delegateAmount      string
	delegateUnsigned    bool
)

var delegateCmd = &cobra.Command{
	Use:   "delegate",
	Short: "Add more stake to your validator pool",
	Long:  "Call delegate on the staking contract to add stake to a pool. As the owner you bypass delegation checks.",
	RunE: func(cmd *cobra.Command, args []string) error {
		poolIDBytes32, err := resolvePoolID(delegatePoolID, delegatePubKeyPath)
		if err != nil {
			return err
		}

		// Parse amount (in tokens, convert to wei)
		stakeTokens, ok := new(big.Int).SetString(delegateAmount, 10)
		if !ok {
			return fmt.Errorf("invalid stake amount: %s", delegateAmount)
		}
		stakeValue := new(big.Int).Mul(stakeTokens, big.NewInt(1e18))

		fmt.Printf("Delegating %s tokens (%s wei) to pool %s\n",
			delegateAmount, stakeValue.String(), hex.EncodeToString(poolIDBytes32[:]))

		parsedABI, err := abi.JSON(strings.NewReader(stakingABI))
		if err != nil {
			return fmt.Errorf("failed to parse ABI: %w", err)
		}

		data, err := parsedABI.Pack("delegate", poolIDBytes32)
		if err != nil {
			return fmt.Errorf("failed to pack transaction data: %w", err)
		}

		if delegateUnsigned {
			printUnsignedTx("delegate", stakeValue, data)
			return nil
		}

		return sendStakingTxWithValue(cmd, delegateRPCEndpoint, data, stakeValue)
	},
}

// ==================== set-delegation-approver ====================

var (
	approverRPCEndpoint string
	approverPoolID      string
	approverPubKeyPath  string
	approverAddress     string
	approverUnsigned    bool
)

var setDelegationApproverCmd = &cobra.Command{
	Use:   "set-delegation-approver",
	Short: "Set delegation approver for KYC/permissioned delegation",
	Long:  "Call setDelegationApprover on the staking contract. Set to 0x0 to disable.",
	RunE: func(cmd *cobra.Command, args []string) error {
		poolIDBytes32, err := resolvePoolID(approverPoolID, approverPubKeyPath)
		if err != nil {
			return err
		}

		approver := common.HexToAddress(approverAddress)
		fmt.Printf("Setting delegation approver to %s for pool %s\n",
			approver.Hex(), hex.EncodeToString(poolIDBytes32[:]))

		parsedABI, err := abi.JSON(strings.NewReader(stakingABI))
		if err != nil {
			return fmt.Errorf("failed to parse ABI: %w", err)
		}

		data, err := parsedABI.Pack("setDelegationApprover", poolIDBytes32, approver)
		if err != nil {
			return fmt.Errorf("failed to pack transaction data: %w", err)
		}

		if approverUnsigned {
			printUnsignedTx("setDelegationApprover", big.NewInt(0), data)
			return nil
		}

		return sendStakingTx(cmd, approverRPCEndpoint, data)
	},
}

// ==================== withdraw-stake (partial withdraw) ====================

var (
	withdrawRPCEndpoint string
	withdrawPoolID      string
	withdrawPubKeyPath  string
	withdrawAmount      string
	withdrawUnsigned    bool
)

var withdrawStakeCmd = &cobra.Command{
	Use:   "withdraw-stake",
	Short: "Partially withdraw stake from your validator pool",
	Long:  "Call withdrawStake on the staking contract. After the unlock window (~14 days), call claim-stake to collect.",
	RunE: func(cmd *cobra.Command, args []string) error {
		poolIDBytes32, err := resolvePoolID(withdrawPoolID, withdrawPubKeyPath)
		if err != nil {
			return err
		}

		// Parse amount (in tokens, convert to wei)
		withdrawTokens, ok := new(big.Int).SetString(withdrawAmount, 10)
		if !ok {
			return fmt.Errorf("invalid withdraw amount: %s", withdrawAmount)
		}
		withdrawValue := new(big.Int).Mul(withdrawTokens, big.NewInt(1e18))

		fmt.Printf("Withdrawing %s tokens (%s wei) from pool %s\n",
			withdrawAmount, withdrawValue.String(), hex.EncodeToString(poolIDBytes32[:]))

		parsedABI, err := abi.JSON(strings.NewReader(stakingABI))
		if err != nil {
			return fmt.Errorf("failed to parse ABI: %w", err)
		}

		data, err := parsedABI.Pack("withdrawStake", poolIDBytes32, withdrawValue)
		if err != nil {
			return fmt.Errorf("failed to pack transaction data: %w", err)
		}

		if withdrawUnsigned {
			printUnsignedTx("withdrawStake", big.NewInt(0), data)
			return nil
		}

		return sendStakingTx(cmd, withdrawRPCEndpoint, data)
	},
}

// ==================== claim-stake ====================

var (
	claimStakeRPCEndpoint string
	claimStakePoolID      string
	claimStakePubKeyPath  string
	claimStakeUnsigned    bool
)

var claimStakeCmd = &cobra.Command{
	Use:   "claim-stake",
	Short: "Claim pending withdrawal after unlock window",
	Long:  "Call claimStake on the staking contract to collect funds after the unlock window has passed.",
	RunE: func(cmd *cobra.Command, args []string) error {
		poolIDBytes32, err := resolvePoolID(claimStakePoolID, claimStakePubKeyPath)
		if err != nil {
			return err
		}

		fmt.Printf("Claiming stake for pool %s\n", hex.EncodeToString(poolIDBytes32[:]))

		parsedABI, err := abi.JSON(strings.NewReader(stakingABI))
		if err != nil {
			return fmt.Errorf("failed to parse ABI: %w", err)
		}

		data, err := parsedABI.Pack("claimStake", poolIDBytes32)
		if err != nil {
			return fmt.Errorf("failed to pack transaction data: %w", err)
		}

		if claimStakeUnsigned {
			printUnsignedTx("claimStake", big.NewInt(0), data)
			return nil
		}

		return sendStakingTx(cmd, claimStakeRPCEndpoint, data)
	},
}

// ==================== claim-reward ====================

var (
	claimRewardRPCEndpoint string
	claimRewardPoolID      string
	claimRewardPubKeyPath  string
	claimRewardUnsigned    bool
)

var claimRewardCmd = &cobra.Command{
	Use:   "claim-reward",
	Short: "Claim accumulated commission rewards",
	Long:  "Call claimReward on the staking contract to withdraw accumulated commission immediately.",
	RunE: func(cmd *cobra.Command, args []string) error {
		poolIDBytes32, err := resolvePoolID(claimRewardPoolID, claimRewardPubKeyPath)
		if err != nil {
			return err
		}

		fmt.Printf("Claiming rewards for pool %s\n", hex.EncodeToString(poolIDBytes32[:]))

		parsedABI, err := abi.JSON(strings.NewReader(stakingABI))
		if err != nil {
			return fmt.Errorf("failed to parse ABI: %w", err)
		}

		data, err := parsedABI.Pack("claimReward", poolIDBytes32)
		if err != nil {
			return fmt.Errorf("failed to pack transaction data: %w", err)
		}

		if claimRewardUnsigned {
			printUnsignedTx("claimReward", big.NewInt(0), data)
			return nil
		}

		return sendStakingTx(cmd, claimRewardRPCEndpoint, data)
	},
}

// ==================== compound-rewards ====================

var (
	compoundRPCEndpoint string
	compoundPoolID      string
	compoundPubKeyPath  string
	compoundUnsigned    bool
)

var compoundRewardsCmd = &cobra.Command{
	Use:   "compound-rewards",
	Short: "Re-stake accumulated commission into the pool",
	Long:  "Call compoundRewards on the staking contract to re-stake commission. Rewards enter pending stake and activate at next epoch.",
	RunE: func(cmd *cobra.Command, args []string) error {
		poolIDBytes32, err := resolvePoolID(compoundPoolID, compoundPubKeyPath)
		if err != nil {
			return err
		}

		fmt.Printf("Compounding rewards for pool %s\n", hex.EncodeToString(poolIDBytes32[:]))

		parsedABI, err := abi.JSON(strings.NewReader(stakingABI))
		if err != nil {
			return fmt.Errorf("failed to parse ABI: %w", err)
		}

		data, err := parsedABI.Pack("compoundRewards", poolIDBytes32)
		if err != nil {
			return fmt.Errorf("failed to pack transaction data: %w", err)
		}

		if compoundUnsigned {
			printUnsignedTx("compoundRewards", big.NewInt(0), data)
			return nil
		}

		return sendStakingTx(cmd, compoundRPCEndpoint, data)
	},
}

// sendStakingTxWithValue is like sendStakingTx but supports payable transactions with msg.value
func sendStakingTxWithValue(cmd *cobra.Command, rpcEndpoint string, data []byte, value *big.Int) error {
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
		value,
		3000000,                // gas limit
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

func init() {
	// delegate
	rootCmd.AddCommand(delegateCmd)
	delegateCmd.Flags().StringVar(&delegateRPCEndpoint, "rpc-endpoint", "http://127.0.0.1:18100", "RPC endpoint URL")
	delegateCmd.Flags().StringVar(&delegatePoolID, "pool-id", "", "Pool ID (hex). If empty, computed from domain-pubkey")
	delegateCmd.Flags().StringVar(&delegatePubKeyPath, "domain-pubkey", "./keys/domain.pub", "Path to domain public key file (used if --pool-id is empty)")
	delegateCmd.Flags().StringVar(&delegateAmount, "amount", "", "Stake amount in tokens (min 1)")
	delegateCmd.Flags().BoolVar(&delegateUnsigned, "unsigned", false, "Print unsigned tx fields for Safe multisig instead of signing and broadcasting")
	delegateCmd.MarkFlagRequired("amount")

	// set-delegation-approver
	rootCmd.AddCommand(setDelegationApproverCmd)
	setDelegationApproverCmd.Flags().StringVar(&approverRPCEndpoint, "rpc-endpoint", "http://127.0.0.1:18100", "RPC endpoint URL")
	setDelegationApproverCmd.Flags().StringVar(&approverPoolID, "pool-id", "", "Pool ID (hex). If empty, computed from domain-pubkey")
	setDelegationApproverCmd.Flags().StringVar(&approverPubKeyPath, "domain-pubkey", "./keys/domain.pub", "Path to domain public key file (used if --pool-id is empty)")
	setDelegationApproverCmd.Flags().StringVar(&approverAddress, "approver", "", "Approver address (set to 0x0000000000000000000000000000000000000000 to disable)")
	setDelegationApproverCmd.Flags().BoolVar(&approverUnsigned, "unsigned", false, "Print unsigned tx fields for Safe multisig instead of signing and broadcasting")
	setDelegationApproverCmd.MarkFlagRequired("approver")

	// withdraw-stake
	rootCmd.AddCommand(withdrawStakeCmd)
	withdrawStakeCmd.Flags().StringVar(&withdrawRPCEndpoint, "rpc-endpoint", "http://127.0.0.1:18100", "RPC endpoint URL")
	withdrawStakeCmd.Flags().StringVar(&withdrawPoolID, "pool-id", "", "Pool ID (hex). If empty, computed from domain-pubkey")
	withdrawStakeCmd.Flags().StringVar(&withdrawPubKeyPath, "domain-pubkey", "./keys/domain.pub", "Path to domain public key file (used if --pool-id is empty)")
	withdrawStakeCmd.Flags().StringVar(&withdrawAmount, "amount", "", "Amount to withdraw in tokens")
	withdrawStakeCmd.Flags().BoolVar(&withdrawUnsigned, "unsigned", false, "Print unsigned tx fields for Safe multisig instead of signing and broadcasting")
	withdrawStakeCmd.MarkFlagRequired("amount")

	// claim-stake
	rootCmd.AddCommand(claimStakeCmd)
	claimStakeCmd.Flags().StringVar(&claimStakeRPCEndpoint, "rpc-endpoint", "http://127.0.0.1:18100", "RPC endpoint URL")
	claimStakeCmd.Flags().StringVar(&claimStakePoolID, "pool-id", "", "Pool ID (hex). If empty, computed from domain-pubkey")
	claimStakeCmd.Flags().StringVar(&claimStakePubKeyPath, "domain-pubkey", "./keys/domain.pub", "Path to domain public key file (used if --pool-id is empty)")
	claimStakeCmd.Flags().BoolVar(&claimStakeUnsigned, "unsigned", false, "Print unsigned tx fields for Safe multisig instead of signing and broadcasting")

	// claim-reward
	rootCmd.AddCommand(claimRewardCmd)
	claimRewardCmd.Flags().StringVar(&claimRewardRPCEndpoint, "rpc-endpoint", "http://127.0.0.1:18100", "RPC endpoint URL")
	claimRewardCmd.Flags().StringVar(&claimRewardPoolID, "pool-id", "", "Pool ID (hex). If empty, computed from domain-pubkey")
	claimRewardCmd.Flags().StringVar(&claimRewardPubKeyPath, "domain-pubkey", "./keys/domain.pub", "Path to domain public key file (used if --pool-id is empty)")
	claimRewardCmd.Flags().BoolVar(&claimRewardUnsigned, "unsigned", false, "Print unsigned tx fields for Safe multisig instead of signing and broadcasting")

	// compound-rewards
	rootCmd.AddCommand(compoundRewardsCmd)
	compoundRewardsCmd.Flags().StringVar(&compoundRPCEndpoint, "rpc-endpoint", "http://127.0.0.1:18100", "RPC endpoint URL")
	compoundRewardsCmd.Flags().StringVar(&compoundPoolID, "pool-id", "", "Pool ID (hex). If empty, computed from domain-pubkey")
	compoundRewardsCmd.Flags().StringVar(&compoundPubKeyPath, "domain-pubkey", "./keys/domain.pub", "Path to domain public key file (used if --pool-id is empty)")
	compoundRewardsCmd.Flags().BoolVar(&compoundUnsigned, "unsigned", false, "Print unsigned tx fields for Safe multisig instead of signing and broadcasting")
}
