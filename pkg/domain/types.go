package domain

type Domain struct {
	ChainID           string                 `json:"chain_id"`
	DomainLabel       string                 `json:"domain_label"`
	DeployDir         string                 `json:"deploy_dir"`
	BuildRoot         string                 `json:"build_root"`
	RunUser           string                 `json:"run_user"`
	ChainProtocol     string                 `json:"chain_protocol"`
	Version           string                 `json:"version"`
	Cluster           map[string]*Instance    `json:"cluster"`
	Common            CommonConfig           `json:"common"`
	Secret            SecretConfig           `json:"secret"`
	Docker            DockerConfig           `json:"docker"`
	Mygrid            MygridConfig           `json:"mygrid"`
	GenesisConf       string                 `json:"genesis_conf"`
	UseGeneratedKeys  bool                   `json:"use_generated_keys"`
	KeyPasswd         string                 `json:"key_passwd"`
	PortalSslPass     string                 `json:"portal_ssl_pass"`
	EnableSetkeyEnv   bool                   `json:"enable_setkey_env"`
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
	Env          map[string]string      `json:"env"`
	Log          map[string]interface{} `json:"log"`
	Config       map[string]interface{} `json:"config"`
	GFlags       map[string]string      `json:"gflags"`
	Metrics      MetricsConfig          `json:"metrics"`
	MonitorConfig map[string]interface{} `json:"monitor_config"`
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
	ServiceETCD       = "etcd"
	ServiceStorage    = "storage"
	ServiceTxPool     = "txpool"
	ServiceController = "controller"
	ServiceDog        = "dog"
	ServicePortal     = "portal"
	ServiceCompute    = "compute"
	ServiceLight      = "light"
	ServiceMygrid     = "mygrid_service"
)