package types

type Domain struct {
	BuildRoot          string              `json:"build_root"`
	ChainID            string              `json:"chain_id"`
	ChainProtocol      string              `json:"chain_protocol"` // default: native
	DomainLabel        string              `json:"domain_label"`
	Version            string              `json:"version"`
	RunUser            string              `json:"run_user"`
	DeployDir          string              `json:"deploy_dir"`
	AdminAddr          string              `json:"admin_addr"`
	GenesisConf        string              `json:"genesis_conf"` // default: ../conf/genesis.conf
	Mygrid             MygridConfig        `json:"mygrid"`
	Secret             Secret              `json:"secret"`
	UseGeneratedKeys   bool                `json:"use_generated_keys"` // default: false
	KeyPasswd          string              `json:"key_passwd"`         // default: 123abc
	PortalSslPass      string              `json:"portal_ssl_pass"`    // default: 123abc
	EnableSetkeyEnv    bool                `json:"enable_setkey_env"`  // default: true
	Docker             Docker              `json:"docker"`
	Common             Common              `json:"common"`
	Cluster            map[string]Instance `json:"cluster"`
	InitialStakeInGwei uint64              `json:"initial_stake_in_gwei"` // default: 1000000000
}

type Deploy struct {
	BuildRoot        string                   `json:"build_root"`         // required
	ChainID          string                   `json:"chain_id"`           // required
	ChainProtocol    string                   `json:"chain_protocol"`     // default: "native"
	Version          string                   `json:"version"`            // required
	RunUser          string                   `json:"run_user"`           // required
	DeployRoot       string                   `json:"deploy_root"`        // optional
	AdminAddr        string                   `json:"admin_addr"`         // optional
	ProxyAdminAddr   string                   `json:"proxy_admin_addr"`   // optional
	GenesisTpl       string                   `json:"genesis_tpl"`        // required
	Mygrid           MygridConfig             `json:"mygrid"`             // required
	DomainKeyType    string                   `json:"domain_key_type"`    // required
	ClientKeyType    string                   `json:"client_key_type"`    // optional
	UseGeneratedKeys bool                     `json:"use_generated_keys"` // optional
	UseLatestVersion bool                     `json:"use_latest_version"` // optional
	Docker           Docker                   `json:"docker"`             // required
	Common           *Common                  `json:"common"`             // optional
	Aldaba           *Extra                   `json:"aldaba"`             // optional
	Storage          *StorageExtra            `json:"storage"`            // optional
	Domains          map[string]DomainSummary `json:"domains"`            // optional
}

type MygridConfig struct {
	Conf MygridCommonConfig `json:"conf"`
	Env  MygridCommonConfig `json:"env"`
}

type MygridCommonConfig struct {
	EnableAdaptive bool   `json:"enable_adaptive"` // default: true
	FilePath       string `json:"filepath"`
}

type SecretFiles struct {
	KeyType string            `json:"key_type"` // default: prime256v1
	Files   map[string]string `json:"files"`
}

type Secret struct {
	Domain SecretFiles `json:"domain"`
	Client SecretFiles `json:"client"`
}

type Docker struct {
	Enable   bool   `json:"enable"` // default: false
	Registry string `json:"registry"`
}

type Common struct {
	Env     map[string]string      `json:"env"`
	Log     map[string]LogConfig   `json:"log"`
	Config  map[string]interface{} `json:"config"`
	Gflags  map[string]string      `json:"gflags"`
	Metrics Metrics                `json:"metrics"`
}

type LogConfig struct {
	Filename    string `json:"filename"`
	MaxFileSize uint64 `json:"max_file_size"`
	MaxFiles    int    `json:"max_files"`
	Level       string `json:"level"`
	Flush       bool   `json:"flush"`
}

type Metrics struct {
	Enable       bool   `json:"enable"`
	PushAddress  string `json:"push_address"`
	JobName      string `json:"job_name"`
	PushInterval string `json:"push_interval"`
	PushPort     string `json:"push_port"`
}

type Instance struct {
	Service string                 `json:"service"`
	Name    string                 `json:"name"`
	IP      string                 `json:"ip"`
	Dir     string                 `json:"dir"`
	Args    []string               `json:"args"`
	Env     map[string]string      `json:"env"`
	Log     map[string]interface{} `json:"log"`
	Config  map[string]interface{} `json:"config"`
	Gflags  map[string]string      `json:"gflags"`
}

type StorageExtra struct {
	Args []string          `json:"args"` // default: empty slice
	Env  map[string]string `json:"env"`  // default: empty map
}

type Extra struct {
	Args   []string               `json:"args"`   // default: empty slice
	Env    map[string]string      `json:"env"`    // default: empty map
	Log    map[string]interface{} `json:"log"`    // default: empty map
	Config map[string]interface{} `json:"config"` // default: empty map
	Gflags map[string]string      `json:"gflags"` // default: empty map
}

type Node struct {
	DeployIP  string `json:"deploy_ip"`  // default: "127.0.0.1"
	Host      string `json:"host"`       // default: "127.0.0.1"
	StartPort int    `json:"start_port"` // default: 20000
	Instances string `json:"instances"`  // default: ""
}

type DomainSummary struct {
	DeployDir          string `json:"deploy_dir"`            // default: ""
	DomainRole         int    `json:"domain_role"`           // default: 0
	KeyPasswd          string `json:"key_passwd"`            // default: ""
	PortalSslPass      string `json:"portal_ssl_pass"`       // default: ""
	DomainPort         int    `json:"domain_port"`           // default: 19000
	ClientTcpPort      int    `json:"client_tcp_port"`       // default: 18000
	ClientWsPort       int    `json:"client_ws_port"`        // default: 0
	ClientWssPort      int    `json:"client_wss_port"`       // default: 0
	ClientHttpPort     int    `json:"client_http_port"`      // default: 0
	Cluster            []Node `json:"cluster"`               // default: empty slice
	InitialStakeInGwei int    `json:"initial_stake_in_gwei"` // default: 1000000000
	EnableSetkeyEnv    bool   `json:"enable_setkey_env"`     // default: true
}

type GenesisDomain struct {
	Pubkey            string `json:"pubkey"`
	StabilizingPubkey string `json:"stabilizing_pubkey"`
	Owner             string `json:"owner"`
	Endpoints         string `json:"endpoints"`
	Staking           string `json:"staking"`
	CommissionRate    string `json:"commission_rate"`
	NodeID            string `json:"node_id"`
}
