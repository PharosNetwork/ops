package cmd

// Service constants matching Python const.py
const (
	SERVICE_ETCD       = "etcd"
	SERVICE_STORAGE    = "storage"
	SERVICE_TXPOOL     = "txpool"
	SERVICE_COMPUTE    = "compute"
	SERVICE_CONTROLLER = "controller"
	SERVICE_DOG        = "dog"
	SERVICE_PORTAL     = "portal"
	SERVICE_LIGHT      = "light"

	PARTITION_SIZE = 256
	MSU_SIZE       = 256

	ALDABA_CLI = "aldaba_cli"
	EVMONE_SO  = "libevmone.so"
)

// SERVICES order must match Python version exactly
// Python: SERVICES = ['etcd', 'storage', 'txpool', 'compute', 'controller', 'dog', 'portal']
var SERVICES = []string{
	SERVICE_ETCD,
	SERVICE_STORAGE,
	SERVICE_TXPOOL,
	SERVICE_COMPUTE,
	SERVICE_CONTROLLER,
	SERVICE_DOG,
	SERVICE_PORTAL,
}

// GetServiceIndex returns the index of a service in SERVICES list
// Used for port calculation
func GetServiceIndex(service string) int {
	for i, s := range SERVICES {
		if s == service {
			return i
		}
	}
	return -1
}

// System contract addresses
const (
	SYS_STAKING_ADDR   = "4100000000000000000000000000000000000000"
	SYS_CHAINCFG_ADDR  = "3100000000000000000000000000000000000000"
	SYS_RULEMNG_ADDR   = "2100000000000000000000000000000000000000"
	SYS_TREASURY_ADDR  = "4100000000000000000000000000000000000001"

	// Implementation addresses
	STAKING_IMPL_ADDR   = "4100000000000000000000000000000000000001"
	CHAINCFG_IMPL_ADDR  = "3100000000000000000000000000000000000001"
	RULEMNG_IMPL_ADDR   = "2100000000000000000000000000000000000001"

	// Intrinsic transaction sender
	INTRINSIC_TX_SENDER = "1111111111111111111111111111111111111111"

	// Default admin address (to be replaced)
	DEFAULT_ADMIN_ADDR = "2cc298bdee7cfeac9b49f9659e2f3d637e149696"
)

// OpenZeppelin storage locations
const (
	// keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.AccessControl")) - 1)) & ~bytes32(uint256(0xff))
	ACCESS_CONTROL_STORAGE_LOCATION = "02dd7bc7dec4dceedda775e58dd541e08a116c6c53815c0bd028192f7b626800"

	// keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.Initializable")) - 1)) & ~bytes32(uint256(0xff))
	INITIALIZABLE_STORAGE_LOCATION = "f0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00"
)

// GWEI to WEI conversion
const GWEI_TO_WEI = 1000000000

// Default values
const (
	DEFAULT_KEY_PASSWD      = "123abc"
	DEFAULT_TOTAL_SUPPLY    = 1000000000 // 1000000000 ether in base units
	DEFAULT_INFLATION_RATE  = 9125
	DEFAULT_PROVE_THRESHOLD = 1000
)
