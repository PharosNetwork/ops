package composer

// Configuration templates and constants for deployment

// CLIJSON template for CLI configuration
const CLIJSON = `{
	"chain_id": "",
	"domain_id": "",
	"etcd": {
		"enable": 0,
		"timeout": 5000,
		"retry_sleep_time": 1,
		"endpoints": []
	},
	"data_path": "",
	"mygrid_client_id": "",
	"service_name": "",
	"mygrid_client_deploy_mode": ""
}`

// ServiceBinaryMap maps service types to their binary names
var ServiceBinaryMap = map[string]string{
	"etcd":       "etcd",
	"storage":    "mygrid_service",
	"txpool":     "pharos",
	"controller": "pharos",
	"compute":    "pharos",
	"portal":     "pharos",
	"dog":        "pharos",
	"light":      "aldaba_light",
}

// CommonBinaries are binaries that need to be synced for all deployments
var CommonBinaries = []string{
	"aldaba_cli",
	"libevmone.so",
	"VERSION",
	"etcdctl",
	"meta_tool",
}

// DefaultChainProtocols that need libevmone.so
var DefaultChainProtocols = []string{"evm", "all"}

// Configuration paths
const (
	AldabaConfFilename    = "aldaba.conf"
	GenesisConfFilename   = "genesis.conf"
	MygridConfFilename    = "mygrid.conf.json"
	MygridEnvFilename     = "mygrid.env.json"
	MygridGenesisFilename = "mygrid_genesis.conf"
	MetaServiceFilename   = "meta_service.conf"
	ArtifactsDirName      = "artifacts"
)

// Resource paths
const (
	DomainKeysBlsPath    = "scripts/resources/domain_keys/bls12381"
	DomainKeysPrimePath  = "scripts/resources/domain_keys/prime256v1"
)

// Certificate file suffixes
const (
	PrivateKeySuffix = ".key"
	PublicKeySuffix  = ".pub"
	PopSuffix        = ".pop"
)

// DefaultClientID is the default client ID for light instances
const DefaultClientID = "light"

// GetMygridClientConf returns the default mygrid client configuration
func GetMygridClientConf() map[string]interface{} {
	return map[string]interface{}{
		"mygrid": map[string]interface{}{
			"mygrid_client_id": DefaultClientID,
			"pamir_conf_path":  "../conf/" + AldabaConfFilename,
		},
	}
}

// GetMetaServiceConf returns the default meta service configuration
func GetMetaServiceConf() map[string]interface{} {
	return map[string]interface{}{
		"meta_service": map[string]interface{}{
			"myid": 0,
			"etcd": map[string]interface{}{
				"enable":           0,
				"timeout":          5000,
				"retry_sleep_time": 1,
				"endpoints":        []string{},
			},
			"data_path": "",
		},
	}
}

// GetDomainKeyPath returns the path to domain key files
func GetDomainKeyPath(keyType string) string {
	switch keyType {
	case "prime256v1":
		return DomainKeysPrimePath
	case "bls12381":
		return DomainKeysBlsPath
	default:
		return ""
	}
}