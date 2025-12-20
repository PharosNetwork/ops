package composer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"

	"pharos-ops/pkg/utils"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

// Staking contract constants are defined in staking.go

// AddValidator registers a new validator on the blockchain
// This is the Go implementation matching Python version core.py:1752-1802
func (c *ComposerRefactor) AddValidator(endpoint string, privateKey string, noPrefix bool) error {
	// Step 1: Read domain public key
	domainPubkey, err := c.getDomainPubKey(noPrefix)
	if err != nil {
		return fmt.Errorf("failed to get domain public key: %w", err)
	}

	// Add 0x prefix to domain public key
	if !strings.HasPrefix(domainPubkey, "0x") {
		domainPubkey = "0x" + domainPubkey
	}

	// Step 2: Read BLS stabilizing public key
	spk, err := c.getStabilizingPubKey(noPrefix)
	if err != nil {
		return fmt.Errorf("failed to get stabilizing public key: %w", err)
	}

	// Step 3: Build transaction parameters
	// parameters = [self.domain_label, domain_pubkey, "0x00", spk, "0x00", self.domain_endpoint]
	domainEndpoint, err := c.getDomainEndpoint()
	if err != nil {
		return fmt.Errorf("failed to get domain endpoint: %w", err)
	}

	// Step 4: Connect to blockchain
	client, err := ethclient.Dial(endpoint)
	if err != nil {
		return fmt.Errorf("failed to connect to blockchain: %w", err)
	}
	defer client.Close()

	utils.Info("web3 is connected")

	// Verify connection
	ctx := context.Background()
	if _, err := client.ChainID(ctx); err != nil {
		utils.Error("web3 is not connected")
		return fmt.Errorf("web3 connection check failed: %w", err)
	}

	// Step 5: Create account from private key
	privateKeyECDSA, err := crypto.HexToECDSA(privateKey)
	if err != nil {
		return fmt.Errorf("invalid private key: %w", err)
	}

	// Get the address from private key
	fromAddress := crypto.PubkeyToAddress(privateKeyECDSA.PublicKey)

	// Step 6: Build transaction
	// Parse ABI
	parsedABI, err := abi.JSON(strings.NewReader(STAKING_ABI))
	if err != nil {
		return fmt.Errorf("failed to parse ABI: %w", err)
	}

	// Contract address
	contractAddress := common.HexToAddress(STAKING_ADDRESS)

	// Get nonce
	nonce, err := client.PendingNonceAt(ctx, fromAddress)
	if err != nil {
		return fmt.Errorf("failed to get nonce: %w", err)
	}

	// Get suggested gas price (or use fixed gas price)
	gasPrice := big.NewInt(GAS_PRICE)

	// Build transaction data
	data, err := parsedABI.Pack("registerValidator",
		c.domain.DomainLabel,   // description
		domainPubkey,           // publicKey
		PROOF_OF_POSSESSION,    // publicKeyPop
		spk,                    // blsPublicKey
		PROOF_OF_POSSESSION,    // blsPublicKeyPop
		domainEndpoint,         // endpoint
	)
	if err != nil {
		return fmt.Errorf("failed to pack transaction data: %w", err)
	}

	// Create stake amount as big.Int (1,000,000 ETH in wei)
	stakeAmount := new(big.Int)
	stakeAmount.SetString(STAKE_AMOUNT_STR, 10)

	// Estimate gas
	msg := ethereum.CallMsg{
		From:      fromAddress,
		To:        &contractAddress,
		Value:     stakeAmount,
		Data:      data,
	}
	gasLimit, err := client.EstimateGas(ctx, msg)
	if err != nil {
		return fmt.Errorf("failed to estimate gas: %w", err)
	}

	// Get chain ID
	chainID, err := client.ChainID(ctx)
	if err != nil {
		return fmt.Errorf("failed to get chain ID: %w", err)
	}

	// Create transaction using LegacyTx for EIP-2930 compatibility
	tx := types.NewTransaction(nonce, contractAddress, stakeAmount, gasLimit, gasPrice, data)

	// Step 7: Sign transaction
	signer := types.NewEIP155Signer(chainID)
	signedTx, err := types.SignTx(tx, signer, privateKeyECDSA)
	if err != nil {
		return fmt.Errorf("failed to sign transaction: %w", err)
	}

	// Step 8: Send transaction
	err = client.SendTransaction(ctx, signedTx)
	if err != nil {
		return fmt.Errorf("failed to send transaction: %w", err)
	}

	txHash := signedTx.Hash()

	// Step 9: Wait for receipt
	receipt, err := bind.WaitMined(ctx, client, signedTx)
	if err != nil {
		return fmt.Errorf("failed to get transaction receipt: %w", err)
	}

	// Step 10: Check status
	if receipt.Status == types.ReceiptStatusSuccessful {
		utils.Info("validator register success")
	} else {
		utils.Error("validator register failed")
	}

	utils.Info("validator register tx: %s", txHash.Hex())
	receiptJSON, _ := json.MarshalIndent(receipt, "", "  ")
	utils.Info("validator register receipt: %s", string(receiptJSON))

	return nil
}

// getDomainPubKey reads the domain public key from file
// Matches Python version core.py:1754-1762
func (c *ComposerRefactor) getDomainPubKey(noPrefix bool) (string, error) {
	keyPubFile := c.domain.Secret.Domain.Files["key_pub"]
	keyFile := c.domain.Secret.Domain.Files["key"]
	keyType := c.domain.Secret.Domain.KeyType

	// Try to read from key_pub file, fallback to generating from private key
	pubkey, _, err := GetPubkey(keyType, keyPubFile, keyFile, noPrefix)
	if err != nil {
		return "", fmt.Errorf("failed to get domain public key: %w", err)
	}

	return pubkey, nil
}

// getStabilizingPubKey reads the BLS stabilizing public key from file
// Matches Python version core.py:1768-1771
func (c *ComposerRefactor) getStabilizingPubKey(noPrefix bool) (string, error) {
	stabilizingPkFile := c.domain.Secret.Domain.Files["stabilizing_pk"]

	data, err := os.ReadFile(stabilizingPkFile)
	if err != nil {
		return "", fmt.Errorf("failed to read stabilizing_pk file: %w", err)
	}

	spk := strings.TrimSpace(string(data))
	if noPrefix && strings.HasPrefix(spk, "4003") {
		spk = spk[4:]
	}

	return spk, nil
}

// getDomainEndpoint constructs the domain endpoint URL
// Matches Python version core.py:525-526
func (c *ComposerRefactor) getDomainEndpoint() (string, error) {
	// Find portal or light instance to get IP and port
	var domainIP string
	var domainPort string

	for _, instance := range c.domain.Cluster {
		if instance.Service == "portal" || instance.Service == "light" {
			domainIP = instance.IP
			if domainIP == "" {
				domainIP = instance.Host
			}
			if domainIP == "" {
				domainIP = "127.0.0.1"
			}

			// Extract port from DOMAIN_LISTEN_URLS0 environment variable
			if listenURL, ok := instance.Env["DOMAIN_LISTEN_URLS0"]; ok {
				parts := strings.Split(listenURL, "//")
				if len(parts) > 1 {
					portParts := strings.Split(parts[len(parts)-1], ":")
					if len(portParts) > 0 {
						domainPort = portParts[len(portParts)-1]
					}
				}
			}
			break
		}
	}

	if domainIP == "" || domainPort == "" {
		return "", fmt.Errorf("failed to determine domain endpoint: IP=%s, Port=%s", domainIP, domainPort)
	}

	return fmt.Sprintf("tcp://%s:%s", domainIP, domainPort), nil
}

// parseHexString is a helper function to parse hex strings with optional 0x prefix
func parseHexString(s string) ([]byte, error) {
	if strings.HasPrefix(s, "0x") {
		return hexutil.Decode(s)
	}
	return hexutil.Decode("0x" + s)
}

// ExitValidator requests a validator to exit from the blockchain
// This is the Go implementation matching Python version core.py:1805-1856
func (c *ComposerRefactor) ExitValidator(endpoint string, privateKey string, noPrefix bool) error {
	// Step 1: Read domain public key
	_, domainPubkeyBytes, err := c.getDomainPubKeyBytes(noPrefix)
	if err != nil {
		return fmt.Errorf("failed to get domain public key: %w", err)
	}

	// Step 2: Connect to blockchain
	client, err := ethclient.Dial(endpoint)
	if err != nil {
		return fmt.Errorf("failed to connect to blockchain: %w", err)
	}
	defer client.Close()

	// Step 3: Compute pool ID from domain public key
	// poolid = hashlib.sha256(bytes(domain_pubkey_bytes)).digest()
	poolID := sha256.Sum256(domainPubkeyBytes)

	utils.Info("poolid: %s", hex.EncodeToString(poolID[:]))
	utils.Info("domain id: %x", poolID)

	// Step 4: Create account from private key
	privateKeyECDSA, err := crypto.HexToECDSA(privateKey)
	if err != nil {
		return fmt.Errorf("invalid private key: %w", err)
	}

	// Get the address from private key
	fromAddress := crypto.PubkeyToAddress(privateKeyECDSA.PublicKey)

	// Step 5: Verify connection
	ctx := context.Background()
	if _, err := client.ChainID(ctx); err != nil {
		utils.Error("web3 is not connected")
		return fmt.Errorf("web3 connection check failed: %w", err)
	}

	utils.Info("web3 is connected")

	// Step 6: Build transaction
	// Parse ABI
	parsedABI, err := abi.JSON(strings.NewReader(STAKING_ABI))
	if err != nil {
		return fmt.Errorf("failed to parse ABI: %w", err)
	}

	// Contract address
	contractAddress := common.HexToAddress(STAKING_ADDRESS)

	// Get nonce
	nonce, err := client.PendingNonceAt(ctx, fromAddress)
	if err != nil {
		return fmt.Errorf("failed to get nonce: %w", err)
	}

	// Get gas price
	gasPrice := big.NewInt(GAS_PRICE)

	// Build transaction data
	// parameters = [poolid]
	data, err := parsedABI.Pack("exitValidator", poolID)
	if err != nil {
		return fmt.Errorf("failed to pack transaction data: %w", err)
	}

	// Create transaction with value 0 and fixed gas limit
	tx := types.NewTransaction(
		nonce,
		contractAddress,
		big.NewInt(0), // value: 0
		EXIT_GAS_LIMIT, // gas: 2000000 (fixed)
		gasPrice,
		data,
	)

	// Step 7: Sign transaction
	chainID, err := client.ChainID(ctx)
	if err != nil {
		return fmt.Errorf("failed to get chain ID: %w", err)
	}

	signer := types.NewEIP155Signer(chainID)
	signedTx, err := types.SignTx(tx, signer, privateKeyECDSA)
	if err != nil {
		return fmt.Errorf("failed to sign transaction: %w", err)
	}

	// Step 8: Send transaction
	err = client.SendTransaction(ctx, signedTx)
	if err != nil {
		return fmt.Errorf("failed to send transaction: %w", err)
	}

	txHash := signedTx.Hash()

	// Step 9: Wait for receipt
	receipt, err := bind.WaitMined(ctx, client, signedTx)
	if err != nil {
		return fmt.Errorf("failed to get transaction receipt: %w", err)
	}

	// Step 10: Check status
	if receipt.Status == types.ReceiptStatusSuccessful {
		utils.Info("validator exit success")
	} else {
		utils.Error("validator exit failed")
	}

	utils.Info("validator exit tx: %s", txHash.Hex())
	receiptJSON, _ := json.MarshalIndent(receipt, "", "  ")
	utils.Info("validator exit receipt: %s", string(receiptJSON))

	return nil
}

// getDomainPubKeyBytes reads the domain public key from file and returns both string and bytes
// Matches Python version core.py:1807-1816
func (c *ComposerRefactor) getDomainPubKeyBytes(noPrefix bool) (string, []byte, error) {
	keyPubFile := c.domain.Secret.Domain.Files["key_pub"]
	keyFile := c.domain.Secret.Domain.Files["key"]
	keyType := c.domain.Secret.Domain.KeyType

	// Try to read from key_pub file, fallback to generating from private key
	pubkey, pubkeyBytes, err := GetPubkey(keyType, keyPubFile, keyFile, noPrefix)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get domain public key: %w", err)
	}

	return pubkey, pubkeyBytes, nil
}
