package composer

// STAKING_ABI is the ABI for the staking contract (DPoSValidatorManager)
// This matches the Python version in aldaba_ops/toolkit/core.py:1160-1748
const STAKING_ABI = `[
  {
    "inputs": [],
    "stateMutability": "nonpayable",
    "type": "constructor"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "internalType": "bytes32",
        "name": "poolId",
        "type": "bytes32"
      },
      {
        "indexed": false,
        "internalType": "string",
        "name": "description",
        "type": "string"
      },
      {
        "indexed": false,
        "internalType": "string",
        "name": "publicKey",
        "type": "string"
      },
      {
        "indexed": false,
        "internalType": "string",
        "name": "blsPublicKey",
        "type": "string"
      },
      {
        "indexed": false,
        "internalType": "string",
        "name": "endpoint",
        "type": "string"
      },
      {
        "indexed": false,
        "internalType": "uint64",
        "name": "effectiveBlockNum",
        "type": "uint64"
      },
      {
        "indexed": false,
        "internalType": "uint8",
        "name": "status",
        "type": "uint8"
      }
    ],
    "name": "DomainUpdate",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "internalType": "uint256",
        "name": "epochNumber",
        "type": "uint256"
      },
      {
        "indexed": true,
        "internalType": "uint256",
        "name": "blockNumber",
        "type": "uint256"
      },
      {
        "indexed": false,
        "internalType": "uint256",
        "name": "timestamp",
        "type": "uint256"
      },
      {
        "indexed": false,
        "internalType": "uint256",
        "name": "totalStake",
        "type": "uint256"
      },
      {
        "indexed": false,
        "internalType": "bytes32[]",
        "name": "activeValidators",
        "type": "bytes32[]"
      }
    ],
    "name": "EpochChange",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "internalType": "address",
        "name": "delegator",
        "type": "address"
      },
      {
        "indexed": true,
        "internalType": "bytes32",
        "name": "poolId",
        "type": "bytes32"
      },
      {
        "indexed": false,
        "internalType": "uint256",
        "name": "amount",
        "type": "uint256"
      }
    ],
    "name": "StakeAdded",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "internalType": "bytes32",
        "name": "poolId",
        "type": "bytes32"
      }
    ],
    "name": "ValidatorExitRequested",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "internalType": "address",
        "name": "validator",
        "type": "address"
      },
      {
        "indexed": true,
        "internalType": "bytes32",
        "name": "poolId",
        "type": "bytes32"
      }
    ],
    "name": "ValidatorRegistered",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "internalType": "bytes32",
        "name": "poolId",
        "type": "bytes32"
      }
    ],
    "name": "ValidatorUpdated",
    "type": "event"
  },
  {
    "inputs": [],
    "name": "EPOCH_DURATION",
    "outputs": [
      {
        "internalType": "uint256",
        "name": "",
        "type": "uint256"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "MAX_POOL_STAKE",
    "outputs": [
      {
        "internalType": "uint256",
        "name": "",
        "type": "uint256"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "MIN_DELEGATOR_STAKE",
    "outputs": [
      {
        "internalType": "uint256",
        "name": "",
        "type": "uint256"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "MIN_POOL_STAKE",
    "outputs": [
      {
        "internalType": "uint256",
        "name": "",
        "type": "uint256"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "MIN_VALIDATOR_STAKE",
    "outputs": [
      {
        "internalType": "uint256",
        "name": "",
        "type": "uint256"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "uint256",
        "name": "",
        "type": "uint256"
      }
    ],
    "name": "activePoolIds",
    "outputs": [
      {
        "internalType": "bytes32",
        "name": "",
        "type": "bytes32"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "bytes32",
        "name": "_poolId",
        "type": "bytes32"
      }
    ],
    "name": "addStake",
    "outputs": [],
    "stateMutability": "payable",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "advanceEpoch",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "currentEpoch",
    "outputs": [
      {
        "internalType": "uint256",
        "name": "",
        "type": "uint256"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "bytes32",
        "name": "_poolId",
        "type": "bytes32"
      }
    ],
    "name": "exitValidator",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "getActiveValidators",
    "outputs": [
      {
        "internalType": "bytes32[]",
        "name": "",
        "type": "bytes32[]"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "bytes32",
        "name": "_poolId",
        "type": "bytes32"
      }
    ],
    "name": "getValidatorInfo",
    "outputs": [
      {
        "components": [
          {
            "internalType": "string",
            "name": "description",
            "type": "string"
          },
          {
            "internalType": "string",
            "name": "publicKey",
            "type": "string"
          },
          {
            "internalType": "string",
            "name": "publicKeyPop",
            "type": "string"
          },
          {
            "internalType": "string",
            "name": "blsPublicKey",
            "type": "string"
          },
          {
            "internalType": "string",
            "name": "blsPublicKeyPop",
            "type": "string"
          },
          {
            "internalType": "string",
            "name": "endpoint",
            "type": "string"
          },
          {
            "internalType": "uint8",
            "name": "status",
            "type": "uint8"
          },
          {
            "internalType": "bytes32",
            "name": "poolId",
            "type": "bytes32"
          },
          {
            "internalType": "uint256",
            "name": "totalStake",
            "type": "uint256"
          }
        ],
        "internalType": "struct DPoSValidatorManager.Validator",
        "name": "",
        "type": "tuple"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "string",
        "name": "str",
        "type": "string"
      }
    ],
    "name": "hexStringToBytes",
    "outputs": [
      {
        "internalType": "bytes",
        "name": "",
        "type": "bytes"
      }
    ],
    "stateMutability": "pure",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "uint256",
        "name": "",
        "type": "uint256"
      }
    ],
    "name": "pendingAddPoolIds",
    "outputs": [
      {
        "internalType": "bytes32",
        "name": "",
        "type": "bytes32"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "uint256",
        "name": "",
        "type": "uint256"
      }
    ],
    "name": "pendingExitPoolIds",
    "outputs": [
      {
        "internalType": "bytes32",
        "name": "",
        "type": "bytes32"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "string",
        "name": "_description",
        "type": "string"
      },
      {
        "internalType": "string",
        "name": "_publicKey",
        "type": "string"
      },
      {
        "internalType": "string",
        "name": "_publicKeyPop",
        "type": "string"
      },
      {
        "internalType": "string",
        "name": "_blsPublicKey",
        "type": "string"
      },
      {
        "internalType": "string",
        "name": "_blsPublicKeyPop",
        "type": "string"
      },
      {
        "internalType": "string",
        "name": "_endpoint",
        "type": "string"
      }
    ],
    "name": "registerValidator",
    "outputs": [],
    "stateMutability": "payable",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "bytes32",
        "name": "_poolId",
        "type": "bytes32"
      }
    ],
    "name": "slashValidator",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "totalStake",
    "outputs": [
      {
        "internalType": "uint256",
        "name": "",
        "type": "uint256"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "bytes32",
        "name": "_poolId",
        "type": "bytes32"
      },
      {
        "internalType": "string",
        "name": "_description",
        "type": "string"
      },
      {
        "internalType": "string",
        "name": "_endpoint",
        "type": "string"
      }
    ],
    "name": "updateValidator",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "bytes32",
        "name": "",
        "type": "bytes32"
      }
    ],
    "name": "validators",
    "outputs": [
      {
        "internalType": "string",
        "name": "description",
        "type": "string"
      },
      {
        "internalType": "string",
        "name": "publicKey",
        "type": "string"
      },
      {
        "internalType": "string",
        "name": "publicKeyPop",
        "type": "string"
      },
      {
        "internalType": "string",
        "name": "blsPublicKey",
        "type": "string"
      },
      {
        "internalType": "string",
        "name": "blsPublicKeyPop",
        "type": "string"
      },
      {
        "internalType": "string",
        "name": "endpoint",
        "type": "string"
      },
      {
        "internalType": "uint8",
        "name": "status",
        "type": "uint8"
      },
      {
        "internalType": "bytes32",
        "name": "poolId",
        "type": "bytes32"
      },
      {
        "internalType": "uint256",
        "name": "totalStake",
        "type": "uint256"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "bytes32",
        "name": "_poolId",
        "type": "bytes32"
      }
    ],
    "name": "withdrawRewards",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  }
]`

// STAKING_ADDRESS is the staking contract address
const STAKING_ADDRESS = "0x4100000000000000000000000000000000000000"

// STAKE_AMOUNT is the amount of wei required for validator registration (1,000,000 ETH)
const STAKE_AMOUNT_STR = "1000000000000000000000000"

// GAS_PRICE is the gas price in wei (1 Gwei)
const GAS_PRICE = 1000000000

// PROOF_OF_POSSESSION is the placeholder for proof of possession
const PROOF_OF_POSSESSION = "0x00"

// Exit validator constants
const (
	// EXIT_GAS_LIMIT is the fixed gas limit for exit transactions
	EXIT_GAS_LIMIT = 2000000
)
