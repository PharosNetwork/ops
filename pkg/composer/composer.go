package composer

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"pharos-ops/pkg/domain"
	"pharos-ops/pkg/utils"
)

// Composer 类型别名，保持向后兼容
type Composer = ComposerRefactor

// ComposerRefactor 按照Python版本重新实现的Composer
type ComposerRefactor struct {
	domain           *domain.Domain
	domainPath       string
	runUser          string
	isLight          bool
	enableDocker     bool
	chainProtocol    string
	buildRoot        string
	deployDir        string
	localClientDir   string
	remoteClientDir  string
	domainIndex      string
	extraStorageArgs string

	// 配置模板
	aldabaConf       map[string]interface{}
	cliConf          map[string]interface{}
	mygridClientConf map[string]interface{}
	metaConf         map[string]interface{}

	// 实例分组
	allInstances     map[string][]*domain.Instance // 按主机分组的实例
}

// New 创建新的Composer实例
func New(domainFile string) (*ComposerRefactor, error) {
	absPath, err := filepath.Abs(domainFile)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read domain file: %w", err)
	}

	var d domain.Domain
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("failed to parse domain file: %w", err)
	}

	// 转换build_root为绝对路径
	if d.BuildRoot != "" && !filepath.IsAbs(d.BuildRoot) {
		d.BuildRoot = filepath.Join(filepath.Dir(absPath), d.BuildRoot)
	}

	c := &ComposerRefactor{
		domain:      &d,
		domainPath:  filepath.Dir(absPath),
		buildRoot:   d.BuildRoot,
		runUser:     d.RunUser,
		isLight:     false,
		enableDocker: d.Docker.Enable,
		chainProtocol: d.ChainProtocol,
	}

	// 设置domain_index（从domain_label提取）
	if strings.HasPrefix(d.DomainLabel, "domain") {
		c.domainIndex = d.DomainLabel[6:]
		if c.domainIndex == "" {
			c.domainIndex = "0"
		}
	} else {
		c.domainIndex = "0"
	}

	// 设置deploy_dir
	if d.DeployDir != "" {
		c.deployDir = d.DeployDir
	} else {
		c.deployDir = filepath.Join("/data/pharos-node", d.DomainLabel)
	}

	// 设置本地客户端目录
	c.localClientDir = filepath.Join("/tmp", d.ChainID, d.DomainLabel, "client")
	c.remoteClientDir = filepath.Join(c.deployDir, "client")

	// 检查是否为light模式
	if _, exists := d.Cluster[domain.ServiceLight]; exists {
		c.isLight = true
	}

	// 初始化配置模板
	if err := c.initConfigTemplates(); err != nil {
		return nil, fmt.Errorf("failed to init config templates: %w", err)
	}

	// 首先应用domain.common中的配置（确保gflags被正确设置）
	c.updateAldabaConfByDomain()

	// 然后加载global.conf中的其他配置
	if err := c.loadGlobalConfig(); err != nil {
		return nil, fmt.Errorf("failed to load global config: %w", err)
	}

	// 解析实例并按主机分组
	c.parseInstances()

	return c, nil
}

// Status 获取服务状态
// TODO: 参考Python版本实现
func (c *ComposerRefactor) Status(service string) error {
	utils.Info("Status not yet implemented for domain: %s, service: %s", c.domain.DomainLabel, service)
	return nil
}

// Start 启动服务
// TODO: 参考Python版本实现
func (c *ComposerRefactor) Start(service string, extraArgs string) error {
	utils.Info("Start not yet implemented for domain: %s, service: %s, extraArgs: %s", c.domain.DomainLabel, service, extraArgs)
	return nil
}

// Stop 停止服务
// TODO: 参考Python版本实现
func (c *ComposerRefactor) Stop(service string) error {
	utils.Info("Stop not yet implemented for domain: %s, service: %s", c.domain.DomainLabel, service)
	return nil
}



// 以下是从 deploy_refactor.go 复制过来的辅助方法

// initConfigTemplates 初始化配置模板
func (c *ComposerRefactor) initConfigTemplates() error {
	// 加载aldaba.tpl.conf模板（从running_conf配置）
	aldabaConfPath := filepath.Join(c.domainPath, "../conf/aldaba.tpl.conf")
	if data, err := os.ReadFile(aldabaConfPath); err == nil {
		if err := json.Unmarshal(data, &c.aldabaConf); err != nil {
			return fmt.Errorf("failed to parse aldaba.tpl.conf: %w", err)
		}
	} else {
		// 文件不存在时返回错误，与Python版本保持一致
		return fmt.Errorf("failed to read aldaba.tpl.conf: %w", err)
	}

	// 加载CLI JSON模板
	if err := json.Unmarshal([]byte(CLIJSON), &c.cliConf); err != nil {
		return fmt.Errorf("failed to parse CLI JSON template: %w", err)
	}

	// 创建mygrid客户端配置
	c.mygridClientConf = GetMygridClientConf()

	// 创建meta service配置
	c.metaConf = GetMetaServiceConf()

	return nil
}

// needsEVM 检查是否需要EVM支持
func (c *ComposerRefactor) needsEVM() bool {
	for _, protocol := range DefaultChainProtocols {
		if c.chainProtocol == protocol {
			return true
		}
	}
	return false
}

// parseInstances 解析实例并按主机分组
func (c *ComposerRefactor) parseInstances() {
	c.allInstances = make(map[string][]*domain.Instance)

	for name, inst := range c.domain.Cluster {
		// 设置实例名称（优先使用map中的key）
		if inst.Name == "" {
			inst.Name = name
		}

		// 获取主机地址
		host := inst.Host
		if host == "" {
			host = inst.IP
		}
		if host == "" {
			host = "127.0.0.1"
		}

		// 按主机分组
		c.allInstances[host] = append(c.allInstances[host], inst)
	}
}

// loadGlobalConfig 加载global.conf并应用配置
func (c *ComposerRefactor) loadGlobalConfig() error {
	globalConfPath := filepath.Join(c.buildRoot, "conf", "global.conf")
	data, err := os.ReadFile(globalConfPath)
	if err != nil {
		return fmt.Errorf("failed to read global.conf: %w", err)
	}

	var globalConf map[string]interface{}
	if err := json.Unmarshal(data, &globalConf); err != nil {
		return fmt.Errorf("failed to parse global.conf: %w", err)
	}

	// 加载global.conf中的额外parameters（不覆盖已存在的）
	if aldaba, ok := c.aldabaConf["aldaba"].(map[string]interface{}); ok {
		if startup, ok := aldaba["startup_config"].(map[string]interface{}); ok {
			if params, ok := globalConf["parameters"].(map[string]interface{}); ok {
				if existingParams, ok := startup["parameters"].(map[string]interface{}); ok {
					// 只添加不存在到现有parameters的
					for k, v := range params {
						if _, exists := existingParams[k]; !exists {
							existingParams[k] = v
						}
					}
				}
			}
		}
	}

	// 应用metrics配置
	if config, ok := globalConf["config"].(map[string]interface{}); ok {
		if metrics, ok := config["metrics"].(map[string]interface{}); ok {
			if aldaba, ok := c.aldabaConf["aldaba"].(map[string]interface{}); ok {
				if startup, ok := aldaba["startup_config"].(map[string]interface{}); ok {
					if monitorConfig, ok := startup["monitor_config"].(map[string]interface{}); ok {
						// 应用metrics配置
						for k, v := range metrics {
							// 映射字段名
							switch k {
							case "enable_pamir_cetina":
								monitorConfig["enable_pamir_cetina"] = v
							case "pamir_cetina_push_address":
								monitorConfig["pamir_cetina_push_address"] = v
							case "pamir_cetina_push_port":
								monitorConfig["pamir_cetina_push_port"] = v
							case "pamir_cetina_job_name":
								monitorConfig["pamir_cetina_job_name"] = v
							case "pamir_cetina_push_interval":
								monitorConfig["pamir_cetina_push_interval"] = v
							}
						}
					}
				}
			}
		}
	}

	return nil
}

// updateAldabaConfByDomain 应用domain.common中的配置
func (c *ComposerRefactor) updateAldabaConfByDomain() {
	if aldaba, ok := c.aldabaConf["aldaba"].(map[string]interface{}); ok {
		if startup, ok := aldaba["startup_config"].(map[string]interface{}); ok {
			// 应用env配置
			if parameters, ok := startup["parameters"].(map[string]string); ok {
				for k, v := range c.domain.Common.Env {
					parameters["/SetEnv/"+k] = v
				}
			}

			// 应用log配置（深度合并）
			c.deepMerge(startup["log"], c.domain.Common.Log)

			// 应用config配置（深度合并）
			c.deepMerge(startup["config"], c.domain.Common.Config)

			// 应用gflags
			if parameters, ok := startup["parameters"].(map[string]interface{}); ok {
				for k, v := range c.domain.Common.GFlags {
					parameters["/GlobalFlag/"+k] = v
				}
			}
		}

		// 应用monitor_config
		c.deepMerge(aldaba["monitor_config"], c.domain.Common.MonitorConfig)
	}
}

// deepMerge 深度合并两个map
func (c *ComposerRefactor) deepMerge(base, update interface{}) {
	baseMap, baseOk := base.(map[string]interface{})
	updateMap, updateOk := update.(map[string]interface{})

	if !baseOk || !updateOk {
		return
	}

	for key, value := range updateMap {
		if baseValue, exists := baseMap[key]; exists {
			// 如果都是map，递归合并
			if baseValueMap, ok := baseValue.(map[string]interface{}); ok {
				if valueMap, ok := value.(map[string]interface{}); ok {
					c.deepMerge(baseValueMap, valueMap)
					continue
				}
			}
		}
		// 直接覆盖
		baseMap[key] = value
	}
}

// instances 获取指定服务的实例，按主机分组
func (c *ComposerRefactor) instances(service string) map[string][]*domain.Instance {
	if service == "" {
		return c.allInstances
	}

	result := make(map[string][]*domain.Instance)
	for host, instList := range c.allInstances {
		for _, inst := range instList {
			if inst.Service == service {
				result[host] = append(result[host], inst)
			}
		}
	}
	return result
}

// isLocal 检查主机是否为本地
func (c *ComposerRefactor) isLocal(host string) bool {
	return host == "127.0.0.1" || host == "localhost"
}

// getAllInstances 获取所有实例
func (c *ComposerRefactor) getAllInstances() []*domain.Instance {
	var instances []*domain.Instance
	for _, instList := range c.allInstances {
		instances = append(instances, instList...)
	}
	return instances
}

// getInstances 按服务获取实例，按主机分组
func (c *ComposerRefactor) getInstances(serviceType string) map[string][]*domain.Instance {
	if serviceType == "" {
		return c.allInstances
	}

	result := make(map[string][]*domain.Instance)
	for host, instList := range c.allInstances {
		for _, inst := range instList {
			if inst.Service == serviceType {
				result[host] = append(result[host], inst)
			}
		}
	}
	return result
}

// incrementPort 根据域索引增加端口
func (c *ComposerRefactor) incrementPort(url string, index string) string {
	parts := strings.Split(url, ":")
	if len(parts) < 2 {
		return url
	}

	port := parts[len(parts)-1]
	if portNum, err := strconv.Atoi(port); err == nil {
		indexNum, _ := strconv.Atoi(index)
		newPort := portNum + indexNum
		parts[len(parts)-1] = strconv.Itoa(newPort)
	}

	return strings.Join(parts, ":")
}

// toBase64 将文件转换为base64字符串
func (c *ComposerRefactor) toBase64(filePath string) string {
	if filePath == "" {
		return ""
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		utils.Warn("Failed to read file %s: %v", filePath, err)
		return ""
	}

	return base64.StdEncoding.EncodeToString(data)
}