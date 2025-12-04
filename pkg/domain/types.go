package domain

type Domain struct {
	BuildRoot          string              `json:"build_root"`
	ChainID            string              `json:"chain_id"`
	ChainProtocol      string              `json:"chain_protocol"`
	DomainLabel        string              `json:"domain_label"`
	Version            string              `json:"version"`
	RunUser            string              `json:"run_user"`
	DeployDir          string              `json:"deploy_dir"`
	GenesisConf        string              `json:"genesis_conf"`
	Mygrid             MygridConfig        `json:"mygrid"`
	Secret             SecretConfig        `json:"secret"`
	UseGeneratedKeys   bool                `json:"use_generated_keys"`
	EnableDora         bool                `json:"enable_dora"`
	KeyPasswd          string              `json:"key_passwd"`
	Docker             DockerConfig        `json:"docker"`
	Common             CommonConfig        `json:"common"`
	Cluster            map[string]Instance `json:"cluster"`
	InitialStakeInGwei uint64              `json:"initial_stake_in_gwei"`
}

type Instance struct {
	Name    string                 `json:"name"`
	IP      string                 `json:"ip"`
	Host    string                 `json:"host"`
	Service string                 `json:"service"`
	Dir     string                 `json:"dir"`
	Env     map[string]string      `json:"env"`
	Log     map[string]interface{} `json:"log"`
	Config  map[string]interface{} `json:"config"`
	GFlags  map[string]string      `json:"gflags"`
	Args    []string               `json:"args"`
}

type CommonConfig struct {
	Env     map[string]string      `json:"env"`
	Log     map[string]interface{} `json:"log"`
	Config  map[string]interface{} `json:"config"`
	GFlags  map[string]string      `json:"gflags"`
	Metrics MetricsConfig          `json:"metrics"`
}

type MetricsConfig struct {
	Enable       bool   `json:"enable"`
	PushAddress  string `json:"push_address"`
	PushPort     string `json:"push_port"`
	JobName      string `json:"job_name"`
	PushInterval string `json:"push_interval"`
}

type SecretConfig struct {
	Domain SecretFiles `json:"domain"`
	Client SecretFiles `json:"client"`
}

type SecretFiles struct {
	KeyType string            `json:"key_type"`
	Files   map[string]string `json:"files"`
}

type DockerConfig struct {
	Enable   bool   `json:"enable"`
	Registry string `json:"registry"`
}

type MygridConfig struct {
	Env MygridEnvConfig `json:"env"`
}

type MygridEnvConfig struct {
	Filepath       string `json:"filepath"`
	EnableAdaptive bool   `json:"enable_adaptive"`
}

const (
	ServiceLight = "light"
)