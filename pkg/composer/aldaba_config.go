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
	"pharos-ops/pkg/ssh"
	"pharos-ops/pkg/utils"
)

// CLI_JSON template for CLI configuration
const CLI_JSON = `{
	"chain_id": "",
	"domain_id": ""
}`

// loadAldabaConfig loads the aldaba configuration from the template file
func (c *Composer) loadAldabaConfig() (map[string]interface{}, error) {
	// The template file path is relative to domain directory
	// For now, we'll create a basic structure since we need to add the fields to Domain struct
	templatePath := filepath.Join("/home/ecs-user/conf", "aldaba.tpl.conf")

	data, err := os.ReadFile(templatePath)
	if err != nil {
		// If file doesn't exist, create a basic structure
		utils.Warn("Aldaba template not found at %s, creating basic structure", templatePath)
		config := map[string]interface{}{
			"aldaba": map[string]interface{}{
				"startup_config": map[string]interface{}{
					"config": map[string]interface{}{
						"block_cache": map[string]interface{}{
							"avg_block_size": 512,
							"cache_depth":   1024,
						},
						"block_persister": map[string]interface{}{
							"retry_wait_ms":       50,
							"worker_thread_num":   8,
						},
						"service": map[string]interface{}{
							"inner_debug_url": "0.0.0.0:10000",
						},
						"cubenet": map[string]interface{}{
							"enabled":     true,
							"port_offset": 0,
						},
					},
					"init_config": map[string]interface{}{},
					"log":         map[string]interface{}{},
					"parameters":  map[string]interface{}{},
				},
				"monitor_config": map[string]interface{}{},
				"secret_config": map[string]interface{}{
					"domain": map[string]interface{}{},
				},
			},
			"cubenet": map[string]interface{}{
				"cubenet": map[string]interface{}{
					"p2p": map[string]interface{}{
						"nid":   "",
						"host": []map[string]interface{}{
							{"port": ""},
						},
					},
				},
			},
			"storage": map[string]interface{}{
				"mygrid_conf": map[string]interface{}{},
				"mygrid_env":  map[string]interface{}{},
			},
		}
		return config, nil
	}

	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse aldaba template: %w", err)
	}

	return config, nil
}

// generateInstanceAldabaConf generates aldaba.conf for a specific instance
func (c *Composer) generateInstanceAldabaConf(inst *domain.Instance) (map[string]interface{}, error) {
	// Load base configuration
	config, err := c.loadAldabaConfig()
	if err != nil {
		return nil, err
	}

	// Skip etcd and storage services for modification
	if inst.Service == "etcd" || inst.Service == "storage" {
		return config, nil
	}

	// Get aldaba config section
	aldabaConfig := config["aldaba"].(map[string]interface{})
	startupConfig := aldabaConfig["startup_config"].(map[string]interface{})
	parameters := startupConfig["parameters"].(map[string]interface{})

	// Load CLI JSON template
	var cliConf map[string]interface{}
	if err := json.Unmarshal([]byte(CLI_JSON), &cliConf); err != nil {
		return nil, fmt.Errorf("failed to parse CLI_JSON template: %w", err)
	}

	// Update CLI configuration
	cliConf["chain_id"] = c.domain.ChainID
	cliConf["domain_id"] = c.domain.DomainLabel

	// Set data_path
	instDir := inst.Dir
	if instDir == "" {
		instDir = filepath.Join(c.domain.DeployDir, inst.Name)
	}
	metasvcPath := filepath.Join(instDir, "data")
	cliConf["data_path"] = metasvcPath

	// Set mygrid paths
	cliConf["mygrid_env_path"] = "../conf/mygrid.env.json"
	cliConf["mygrid_conf_path"] = "../conf/mygrid.conf.json"

	// Set client ID and deploy mode
	if c.isLight {
		cliConf["mygrid_client_id"] = "light"
		cliConf["mygrid_client_deploy_mode"] = "light"
	} else {
		cliConf["mygrid_client_id"] = inst.Name
		cliConf["mygrid_client_deploy_mode"] = "ultra"
	}

	// Configure etcd
	etcdConf := map[string]interface{}{
		"enable":            0,
		"timeout":           5000,
		"retry_sleep_time":  1,
		"endpoints":         []string{},
	}

	if !c.isLight {
		// TODO: Get etcd endpoints properly
		etcdConf["enable"] = 1
	}
	cliConf["etcd"] = etcdConf

	// Set as init_config
	startupConfig["init_config"] = cliConf

	// Add standard environment variables
	parameters["/SetEnv/CHAIN_ID"] = c.domain.ChainID
	parameters["/SetEnv/DOMAIN_LABEL"] = c.domain.DomainLabel
	parameters["/SetEnv/SERVICE"] = inst.Service

	// Add instance environment variables
	if inst.Env != nil {
		for key, value := range inst.Env {
			parameters["/SetEnv/"+key] = value
		}
	}

	// Add common environment variables
	if c.domain.Common.Env != nil {
		for key, value := range c.domain.Common.Env {
			parameters["/SetEnv/"+key] = value
		}
	}

	// Update debug port based on domain index
	domainIndex := 0
	if strings.HasPrefix(c.domain.DomainLabel, "domain") {
		if idx, err := strconv.Atoi(c.domain.DomainLabel[6:]); err == nil {
			domainIndex = idx
		}
	}

	// Increment debug port
	if serviceConfig, ok := startupConfig["config"].(map[string]interface{}); ok {
		if debugService, ok := serviceConfig["service"].(map[string]interface{}); ok {
			if debugURL, ok := debugService["inner_debug_url"].(string); ok {
				parts := strings.Split(debugURL, ":")
				if len(parts) == 2 {
					port, _ := strconv.Atoi(parts[1])
					debugService["inner_debug_url"] = fmt.Sprintf("0.0.0.0:%d", port+domainIndex)
				}
			}
		}
	}

	// Configure cubenet for dog and light services
	if inst.Service == "dog" || inst.Service == "light" {
		if cubenetConfig, ok := config["cubenet"].(map[string]interface{}); ok {
			if cubenetInner, ok := cubenetConfig["cubenet"].(map[string]interface{}); ok {
				if p2pConfig, ok := cubenetInner["p2p"].(map[string]interface{}); ok {
					// Set NID from environment
					if inst.Env != nil {
						if nodeID, exists := inst.Env["NODE_ID"]; exists {
							p2pConfig["nid"] = nodeID
						}
					}

					// Configure port
					if hosts, ok := p2pConfig["host"].([]map[string]interface{}); ok && len(hosts) > 0 {
						if inst.Env != nil {
							if domainListenURL0, exists := inst.Env["DOMAIN_LISTEN_URLS0"]; exists {
								portStr := domainListenURL0
								// Extract port from URL (format: tcp://0.0.0.0:19000)
								for i := len(portStr) - 1; i >= 0; i-- {
									if portStr[i] == ':' {
										portStr = portStr[i+1:]
										break
									}
								}

								// Get port_offset from config
								var portOffset int
								if cubenetServiceConfig, ok := startupConfig["config"].(map[string]interface{}); ok {
									if cubenetMap, ok := cubenetServiceConfig["cubenet"].(map[string]interface{}); ok {
										if offset, exists := cubenetMap["port_offset"]; exists {
											if offsetFloat, ok := offset.(float64); ok {
												portOffset = int(offsetFloat)
											}
										}
									}
								}

								// Parse port and add offset
								var port int
								fmt.Sscanf(portStr, "%d", &port)
								hosts[0]["port"] = fmt.Sprintf("%d", port+portOffset)
							}
						}
					}
				}
			}
		}
	}

	// Add domain keys to secret_config
	if secretConfig, ok := aldabaConfig["secret_config"].(map[string]interface{}); ok {
		if domainSecret, ok := secretConfig["domain"].(map[string]interface{}); ok {
			// Domain key paths - read actual key files and encode them
			keySuffix := "generate"
			keyType := c.domain.Secret.Domain.KeyType
			if keyType == "" {
				keyType = "prime256v1"
			}

			// Read and encode domain keys
			keyFiles := map[string]string{
				"key":             fmt.Sprintf("../scripts/resources/domain_keys/%s/%s/%s.key", keyType, inst.Name, keySuffix),
				"key_pub":         fmt.Sprintf("../scripts/resources/domain_keys/%s/%s/%s.pub", keyType, inst.Name, keySuffix),
				"stabilizing_key": fmt.Sprintf("../scripts/resources/domain_keys/bls12381/%s/%s.key", inst.Name, keySuffix),
				"stabilizing_pk":  fmt.Sprintf("../scripts/resources/domain_keys/bls12381/%s/%s.pub", inst.Name, keySuffix),
			}

			encodedKeys := make(map[string]interface{})
			for keyType, keyPath := range keyFiles {
				if data, err := os.ReadFile(keyPath); err == nil {
					encodedKeys[keyType] = base64.StdEncoding.EncodeToString(data)
				} else {
					utils.Warn("Failed to read key file %s: %v", keyPath, err)
				}
			}

			domainSecret["key_type"] = keyType
			domainSecret["files"] = encodedKeys
		}
	}

	return config, nil
}

// deployAldabaConf generates and deploys aldaba.conf (matching Python's deploy_host_conf)
func (c *Composer) deployAldabaConf(sshClient *ssh.Client, inst *domain.Instance) error {
	// Generate instance-specific aldaba configuration
	instanceConfig, err := c.generateInstanceAldabaConf(inst)
	if err != nil {
		return fmt.Errorf("failed to generate aldaba config: %w", err)
	}

	// Get instance directory
	instDir := inst.Dir
	if instDir == "" {
		instDir = filepath.Join(c.domain.DeployDir, inst.Name)
	}

	// Convert to JSON
	aldabaConfData, err := json.MarshalIndent(instanceConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal aldaba config: %w", err)
	}

	// Write to temporary file
	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("aldaba_conf_%s.json", inst.Name))
	if err := os.WriteFile(tmpFile, aldabaConfData, 0644); err != nil {
		return fmt.Errorf("failed to write temp aldaba.conf: %w", err)
	}
	defer os.Remove(tmpFile)

	// Upload to remote
	remotePath := filepath.Join(instDir, "conf", "aldaba.conf")
	if err := sshClient.UploadFile(tmpFile, remotePath); err != nil {
		return fmt.Errorf("failed to upload aldaba.conf: %w", err)
	}

	return nil
}

// generateClientAldabaConf generates aldaba.conf for client (matching Python's client aldaba.conf)
func (c *Composer) generateClientAldabaConf(confDir string) error {
	// Load base configuration
	config, err := c.loadAldabaConfig()
	if err != nil {
		return fmt.Errorf("failed to load base config: %w", err)
	}

	// Convert to JSON
	aldabaConfData, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal client aldaba config: %w", err)
	}

	// Write file
	aldabaConfPath := filepath.Join(confDir, "aldaba.conf")
	if err := os.WriteFile(aldabaConfPath, aldabaConfData, 0644); err != nil {
		return fmt.Errorf("failed to write client aldaba.conf: %w", err)
	}

	utils.Info("Generated client aldaba.conf: %s", aldabaConfPath)
	return nil
}