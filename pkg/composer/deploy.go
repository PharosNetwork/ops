package composer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"pharos-ops/pkg/domain"
	"pharos-ops/pkg/ssh"
	"pharos-ops/pkg/utils"
)

// Deploy 主部署方法（完全按照Python版本）
func (c *ComposerRefactor) Deploy(service string) error {
	utils.Info("Deploying %s, service: %s", c.domain.DomainLabel, service)

	// 1. 清理旧数据
	if err := c.clean(service, true); err != nil {
		utils.Warn("Failed to clean before deploy: %v", err)
	}

	// 2. 并发部署到多个主机
	var wg sync.WaitGroup
	errors := make(chan error, len(c.allInstances))

	for host := range c.instances(service) {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			if err := c.deployHost(host, service, true, true); err != nil {
				errors <- fmt.Errorf("failed to deploy to host %s: %w", host, err)
			}
		}(host)
	}

	wg.Wait()
	close(errors)

	// 检查是否有错误
	for err := range errors {
		if err != nil {
			return err
		}
	}

	// 3. 确定客户端部署主机
	deployClientHost := c.determineDeployClientHost(service)

	// 4. 部署客户端工具
	if deployClientHost != "" {
		// 部署本地客户端
		if err := c.deployLocalCLI(); err != nil {
			return fmt.Errorf("failed to deploy local CLI: %w", err)
		}

		// 同步到远程主机（如果不是本地或目录不同）
		if !c.isLocal(deployClientHost) || c.localClientDir != c.remoteClientDir {
			if err := c.syncClientToRemote(deployClientHost); err != nil {
				utils.Warn("Failed to sync client to remote: %v", err)
			}
		}
	}

	utils.Info("✓ Deploy completed successfully for domain: %s", c.domain.DomainLabel)
	return nil
}



// determineDeployClientHost 确定客户端部署主机
func (c *ComposerRefactor) determineDeployClientHost(service string) string {
	if c.isLight || service == domain.ServiceLight {
		if lightInst, exists := c.domain.Cluster[domain.ServiceLight]; exists {
			return lightInst.IP
		}
	} else if service == "" {
		// 默认部署client到controller所在远程host
		if controllerInst, exists := c.domain.Cluster[domain.ServiceController]; exists {
			return controllerInst.IP
		}
	}
	return ""
}

// deployHost 部署到单个主机
func (c *ComposerRefactor) deployHost(host string, service string, deployBinary bool, deployConf bool) error {
	instances := c.instances(service)[host]
	if len(instances) == 0 {
		return nil
	}

	utils.Info("Deploying %d instances to host: %s", len(instances), host)

	// 创建SSH连接
	user := c.runUser
	if c.isLocal(host) {
		user = ""
	}

	sshClient, err := ssh.NewClient(host, user)
	if err != nil {
		return fmt.Errorf("failed to create SSH client: %w", err)
	}
	defer sshClient.Close()

	if err := sshClient.Connect(); err != nil {
		return fmt.Errorf("failed to connect to %s: %w", host, err)
	}

	// 1. 创建工作空间
	if err := c.makeWorkspace(sshClient, c.deployDir, "bin", "conf"); err != nil {
		return fmt.Errorf("failed to create workspace: %w", err)
	}

	// 2. 部署二进制文件
	if deployBinary {
		if err := c.deployBinary(sshClient, service); err != nil {
			return fmt.Errorf("failed to deploy binaries: %w", err)
		}
	}

	// 3. 部署配置文件
	if deployConf {
		if err := c.deployHostConf(sshClient, service); err != nil {
			return fmt.Errorf("failed to deploy configs: %w", err)
		}
	}

	// 4. 创建元数据存储目录（非自适应模式）
	if !c.domain.Mygrid.Env.EnableAdaptive {
		if err := c.createMetaStore(sshClient); err != nil {
			utils.Warn("Failed to create meta store: %v", err)
		}
	}

	return nil
}

// makeWorkspace 创建工作空间目录
func (c *ComposerRefactor) makeWorkspace(sshClient *ssh.Client, baseDir string, dirs ...string) error {
	// 创建基础目录
	if err := sshClient.MkdirAll(baseDir, 0755); err != nil {
		return fmt.Errorf("failed to create base directory: %w", err)
	}

	// 创建子目录
	for _, dir := range dirs {
		dirPath := filepath.Join(baseDir, dir)
		if err := sshClient.MkdirAll(dirPath, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return nil
}

// deployBinary 部署二进制文件
func (c *ComposerRefactor) deployBinary(sshClient *ssh.Client, service string) error {
	instances := c.instances(service)[sshClient.GetHost()]
	if len(instances) == 0 {
		return nil
	}

	if c.enableDocker {
		// Docker模式部署（待实现）
		return fmt.Errorf("docker mode not yet implemented")
	}

	// 原生模式部署
	deployBinDir := filepath.Join(c.deployDir, "bin")
	binaries := make(map[string]bool)

	// 收集需要部署的二进制文件
	for _, inst := range instances {
		binName := c.getInstanceBinary(inst)
		binaries[binName] = true
	}

	utils.Info("Deploying binaries %v to %s", binaries, deployBinDir)

	// 部署每个二进制文件
	for binary := range binaries {
		srcPath := filepath.Join(c.buildRoot, "bin", binary)
		dstPath := filepath.Join(deployBinDir, binary)

		// 上传新文件
		if err := sshClient.UploadFile(srcPath, dstPath); err != nil {
			return fmt.Errorf("failed to upload %s: %w", binary, err)
		}

		// 上传VERSION文件
		versionSrc := filepath.Join(c.buildRoot, "bin", "VERSION")
		versionDst := filepath.Join(deployBinDir, "VERSION")
		sshClient.UploadFile(versionSrc, versionDst)

		// EVM协议需要额外的EVMone库
		if c.needsEVM() {
			evmoneSrc := filepath.Join(c.buildRoot, "bin", "libevmone.so")
			evmoneDst := filepath.Join(deployBinDir, "libevmone.so")
			sshClient.UploadFile(evmoneSrc, evmoneDst)
		}
	}

	// 创建二进制文件的软链接
	for _, inst := range instances {
		instBin := c.getInstanceBinary(inst)
		instDir := c.getInstanceDir(inst)
		binDir := filepath.Join(instDir, "bin")

		// 创建实例目录
		if err := c.makeWorkspace(sshClient, instDir, "bin", "conf", "log", "data", "certs"); err != nil {
			return err
		}

		// 创建软链接到共享二进制
		srcLink := filepath.Join(c.deployDir, "bin", instBin)
		if err := sshClient.CreateSymlink(srcLink, filepath.Join(binDir, instBin)); err != nil {
			utils.Warn("Failed to create symlink for %s: %v", instBin, err)
		}

		// 链接VERSION
		versionLink := filepath.Join(c.deployDir, "bin", "VERSION")
		if err := sshClient.CreateSymlink(versionLink, filepath.Join(binDir, "VERSION")); err != nil {
			utils.Warn("Failed to create VERSION symlink: %v", err)
		}

		// 链接EVMONE（如果需要）
		if c.needsEVM() {
			evmoneLink := filepath.Join(c.deployDir, "bin", "libevmone.so")
			if err := sshClient.CreateSymlink(evmoneLink, filepath.Join(binDir, "libevmone.so")); err != nil {
				utils.Warn("Failed to create libevmone.so symlink: %v", err)
			}
		}
	}

	return nil
}

// getInstanceBinary 获取实例对应的二进制文件名
func (c *ComposerRefactor) getInstanceBinary(inst *domain.Instance) string {
	if binary, exists := ServiceBinaryMap[inst.Service]; exists {
		return binary
	}
	return "pharos"
}


// deployHostConf 部署主机配置文件
func (c *ComposerRefactor) deployHostConf(sshClient *ssh.Client, service string) error {
	instances := c.instances(service)[sshClient.GetHost()]
	if len(instances) == 0 {
		return nil
	}

	for _, inst := range instances {
		// 1. 配置客户端信息
		c.cliConf["mygrid_client_id"] = inst.Name
		c.cliConf["service_name"] = inst.Service
		c.cliConf["chain_id"] = c.domain.ChainID
		c.cliConf["domain_id"] = c.domain.DomainLabel
		// 设置data_path（使用metasvc_path，与Python一致）
		// Python: self._cli_conf['data_path'] = f'{metasvc_path}'
		metasvcPath := c.getMetasvcPath()
		if metasvcPath == "" {
			metasvcPath = filepath.Join(c.deployDir, inst.Name, "data")
		}
		c.cliConf["data_path"] = metasvcPath
		if c.isLight {
			c.cliConf["mygrid_client_deploy_mode"] = "light"
		} else {
			c.cliConf["mygrid_client_deploy_mode"] = "ultra"
		}

		// 设置mygrid客户端配置
		if mygrid, ok := c.mygridClientConf["mygrid"].(map[string]interface{}); ok {
			mygrid["mygrid_client_id"] = DefaultClientID
			if c.isLight {
				mygrid["mygrid_client_deploy_mode"] = "light"
			} else {
				mygrid["mygrid_client_deploy_mode"] = "ultra"
			}
		}

		instDir := c.getInstanceDir(inst)
		aldabaConfFile := filepath.Join(instDir, "conf", "aldaba.conf")

		// 2. 生成Aldaba配置文件
		if inst.Service != domain.ServiceETCD && inst.Service != domain.ServiceStorage {
			// 配置启动参数
			if aldaba, ok := c.aldabaConf["aldaba"].(map[string]interface{}); ok {
				if startup, ok := aldaba["startup_config"].(map[string]interface{}); ok {
					startup["init_config"] = c.cliConf

					// 设置环境变量
					if params, ok := startup["parameters"].(map[string]interface{}); ok {
						for k, v := range inst.Env {
							params["/SetEnv/"+k] = v
						}
						params["/SetEnv/CHAIN_ID"] = c.domain.ChainID
						params["/SetEnv/DOMAIN_LABEL"] = c.domain.DomainLabel
						params["/SetEnv/SERVICE"] = inst.Service
					}
				}
			}
		}

		// 3. 配置调试端口
		if aldaba, ok := c.aldabaConf["aldaba"].(map[string]interface{}); ok {
			if startup, ok := aldaba["startup_config"].(map[string]interface{}); ok {
				if config, ok := startup["config"].(map[string]interface{}); ok {
					if service, ok := config["service"].(map[string]interface{}); ok {
						if debugURL, ok := service["inner_debug_url"].(string); ok {
							// 根据域索引增加端口
							port := c.incrementPort(debugURL, c.domainIndex)
							service["inner_debug_url"] = port
						}
					}
				}
			}
		}

		// 4. 配置Cubenet（DOG和LIGHT服务）
		if inst.Service == domain.ServiceDog || inst.Service == domain.ServiceLight {
			if nodeID, exists := inst.Env["NODE_ID"]; exists {
				// 更新顶级secret_config
				if aldaba, ok := c.aldabaConf["aldaba"].(map[string]interface{}); ok {
					if secret, ok := aldaba["secret_config"].(map[string]interface{}); ok {
						secret["domain_key"] = c.toBase64(c.domain.Secret.Domain.Files["key"])
						secret["stabilizing_key"] = c.toBase64(c.domain.Secret.Domain.Files["stabilizing_key"])
					}
				}

				if aldaba, ok := c.aldabaConf["aldaba"].(map[string]interface{}); ok {
					if startup, ok := aldaba["startup_config"].(map[string]interface{}); ok {
						if secret, ok := startup["secret_config"].(map[string]interface{}); ok {
							secret["domain_key"] = c.toBase64(c.domain.Secret.Domain.Files["key"])
							secret["stabilizing_key"] = c.toBase64(c.domain.Secret.Domain.Files["stabilizing_key"])
						}
					}
				}

				if cubenet, ok := c.aldabaConf["cubenet"].(map[string]interface{}); ok {
					if cn, ok := cubenet["cubenet"].(map[string]interface{}); ok {
						if p2p, ok := cn["p2p"].(map[string]interface{}); ok {
							p2p["nid"] = nodeID

							// 设置端口
							if domainListenURL, exists := inst.Env["DOMAIN_LISTEN_URLS0"]; exists {
								parts := strings.Split(domainListenURL, ":")
								if len(parts) >= 3 {
									portStr := parts[2]
									if port, err := strconv.Atoi(portStr); err == nil {
										// 获取port_offset
										var portOffset int
										if aldaba, ok := c.aldabaConf["aldaba"].(map[string]interface{}); ok {
											if startup, ok := aldaba["startup_config"].(map[string]interface{}); ok {
												if config, ok := startup["config"].(map[string]interface{}); ok {
													if cubenet, ok := config["cubenet"].(map[string]interface{}); ok {
														if offset, ok := cubenet["port_offset"].(float64); ok {
															portOffset = int(offset)
														}
													}
												}
											}
										}

										newPort := port + portOffset
										if hosts, ok := p2p["host"].([]interface{}); ok && len(hosts) > 0 {
											if host0, ok := hosts[0].(map[string]interface{}); ok {
												host0["port"] = strconv.Itoa(newPort)
											}
										}
									}
								}
							}

							// 处理dog服务的密钥文件
							// Python: target_key_file = key_file if use_generated_keys else 'generate.key'
							// 目标文件名始终是 generate.key（与Python一致）
							if inst.Service == domain.ServiceDog {
								keyFile := "generate" + PrivateKeySuffix
								if !c.domain.UseGeneratedKeys {
									keyFile = "new" + PrivateKeySuffix
								}
								// 目标文件名始终是 generate.key
								targetKeyFile := "generate" + PrivateKeySuffix

								srcKey := filepath.Join(c.buildRoot, "scripts", "resources", "domain_keys",
									"prime256v1", c.domain.DomainLabel, keyFile)
								dstKey := filepath.Join(instDir, "certs", targetKeyFile)

								if _, err := os.Stat(srcKey); err == nil {
									sshClient.UploadFile(srcKey, dstKey)
								}

								// 设置private_key_file
								p2p["private_key_file"] = dstKey
							}
						}
					}
				}
			}
		}

		// 5. 写入配置文件
		aldabaConfData, err := json.MarshalIndent(c.aldabaConf, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal aldaba conf: %w", err)
		}

		// 上传配置文件
		if err := sshClient.UploadFileContent(aldabaConfFile, string(aldabaConfData)); err != nil {
			return fmt.Errorf("failed to upload aldaba.conf: %w", err)
		}

		// 设置文件权限为600（与Python一致）
		if inst.Service == domain.ServiceLight {
			_, _ = sshClient.RunCommand(fmt.Sprintf("chmod 600 %s", aldabaConfFile))
		}

		// 6. 环境配置文件 - Python版本不生成env.json，跳过

		// 7. 处理SSL证书（LIGHT服务）
		if inst.Service == domain.ServiceLight {
			certsDir := filepath.Join(instDir, "certs")

			// 复制域名密钥文件
			keyFiles := []struct {
				srcPattern string
				dstName    string
			}{
				{fmt.Sprintf("%s/%s/generate%s", DomainKeysPrimePath, c.domain.DomainLabel, PrivateKeySuffix), "generate" + PrivateKeySuffix},
				{fmt.Sprintf("%s/%s/generate%s", DomainKeysPrimePath, c.domain.DomainLabel, PublicKeySuffix), "generate" + PublicKeySuffix},
				{fmt.Sprintf("%s/%s/generate%s", DomainKeysPrimePath, c.domain.DomainLabel, PopSuffix), "generate" + PopSuffix},
				{fmt.Sprintf("%s/%s/generate%s", DomainKeysBlsPath, c.domain.DomainLabel, PrivateKeySuffix), "generate_bls" + PrivateKeySuffix},
				{fmt.Sprintf("%s/%s/generate%s", DomainKeysBlsPath, c.domain.DomainLabel, PublicKeySuffix), "generate_bls" + PublicKeySuffix},
				{fmt.Sprintf("%s/%s/generate%s", DomainKeysBlsPath, c.domain.DomainLabel, PopSuffix), "generate_bls" + PopSuffix},
			}

			// 根据use_generated_keys调整源文件名（目标文件名始终是generate.*，与Python一致）
			// Python: target_key_file = key_file if use_generated_keys else 'generate.key'
			// 这意味着目标文件名始终是 generate.* 形式
			if !c.domain.UseGeneratedKeys {
				prefix := "new"
				keyFiles[0].srcPattern = fmt.Sprintf("%s/%s/%s%s", DomainKeysPrimePath, c.domain.DomainLabel, prefix, PrivateKeySuffix)
				keyFiles[1].srcPattern = fmt.Sprintf("%s/%s/%s%s", DomainKeysPrimePath, c.domain.DomainLabel, prefix, PublicKeySuffix)
				keyFiles[2].srcPattern = fmt.Sprintf("%s/%s/%s%s", DomainKeysPrimePath, c.domain.DomainLabel, prefix, PopSuffix)
				keyFiles[3].srcPattern = fmt.Sprintf("%s/%s/%s%s", DomainKeysBlsPath, c.domain.DomainLabel, prefix, PrivateKeySuffix)
				keyFiles[4].srcPattern = fmt.Sprintf("%s/%s/%s%s", DomainKeysBlsPath, c.domain.DomainLabel, prefix, PublicKeySuffix)
				keyFiles[5].srcPattern = fmt.Sprintf("%s/%s/%s%s", DomainKeysBlsPath, c.domain.DomainLabel, prefix, PopSuffix)
				// 注意：不修改 dstName，目标文件名始终保持 generate.* 形式
			}

			for _, kf := range keyFiles {
				srcPath := filepath.Join(c.buildRoot, kf.srcPattern)
				if _, err := os.Stat(srcPath); err == nil {
					dstPath := filepath.Join(certsDir, kf.dstName)
					if err := sshClient.UploadFile(srcPath, dstPath); err != nil {
						utils.Warn("Failed to upload %s: %v", kf.dstName, err)
					}
				}
			}
		}
	}

	return nil
}



// deployLocalCLI 部署本地CLI工具
func (c *ComposerRefactor) deployLocalCLI() error {
	utils.Info("Deploying pharos CLI at localhost: %s", c.localClientDir)

	// 1. 创建本地客户端工作空间
	if err := c.makeWorkspaceLocal(c.localClientDir, "../../bin"); err != nil {
		return fmt.Errorf("failed to create local workspace: %w", err)
	}

	commonCliBinDir := filepath.Join(c.localClientDir, "../../bin")

	// 2. 同步通用二进制文件
	binariesToSync := CommonBinaries

	for _, binary := range binariesToSync {
		srcPath := filepath.Join(c.buildRoot, "bin", binary)
		dstPath := filepath.Join(commonCliBinDir, binary)

		if _, err := os.Stat(srcPath); err == nil {
			if err := copyFileRefactor(srcPath, dstPath); err != nil {
				utils.Warn("Failed to copy %s: %v", binary, err)
			}
		}
	}

	// 3. 复制客户端二进制文件 (Python版本是复制而不是软链接)
	cliBinDir := filepath.Join(c.localClientDir, "bin")
	if err := os.MkdirAll(cliBinDir, 0755); err != nil {
		return fmt.Errorf("failed to create client bin dir: %w", err)
	}

	// 定义需要复制的客户端二进制文件
	clientBinaries := []string{"aldaba_cli", "libevmone.so", "etcdctl", "meta_tool", "VERSION"}

	for _, binary := range clientBinaries {
		srcPath := filepath.Join(c.buildRoot, "bin", binary)
		dstPath := filepath.Join(cliBinDir, binary)

		// 删除现有文件/链接
		os.Remove(dstPath)

		if _, err := os.Stat(srcPath); err == nil {
			if err := copyFileRefactor(srcPath, dstPath); err != nil {
				utils.Warn("Failed to copy client binary %s: %v", binary, err)
			} else {
				utils.Info("Copied client binary: %s", binary)
			}
		}
	}

	// 4. 创建conf目录
	cliConfDir := filepath.Join(c.localClientDir, "conf")
	if err := os.MkdirAll(cliConfDir, 0755); err != nil {
		return fmt.Errorf("failed to create client conf dir: %w", err)
	}

	// 5. 同步配置文件
	// genesis.conf
	genesisSrc := filepath.Join(c.domainPath, c.domain.GenesisConf)
	if _, err := os.Stat(genesisSrc); err == nil {
		// Copy as genesis.conf
		if err := copyFileRefactor(genesisSrc, filepath.Join(cliConfDir, "genesis.conf")); err != nil {
			utils.Warn("Failed to copy genesis.conf: %v", err)
		}
		// Also copy with original filename (e.g., genesis.aldaba-ng.conf)
		origGenesisName := filepath.Base(genesisSrc)
		if err := copyFileRefactor(genesisSrc, filepath.Join(cliConfDir, origGenesisName)); err != nil {
			utils.Warn("Failed to copy %s: %v", origGenesisName, err)
		}
	}

	// artifacts目录
	artifactsSrc := filepath.Join(c.buildRoot, "conf", ArtifactsDirName)
	if _, err := os.Stat(artifactsSrc); err == nil {
		artifactsDst := filepath.Join(c.localClientDir, ArtifactsDirName)
		if err := copyDirRefactor(artifactsSrc, artifactsDst); err != nil {
			utils.Warn("Failed to copy artifacts: %v", err)
		}
	}

	// 更新配置文件中的动态字段
	lightInstance := "light"
	if !c.isLight {
		// Ultra模式，使用controller实例
		for name, inst := range c.domain.Cluster {
			if inst.Service == domain.ServiceController {
				lightInstance = name
				break
			}
		}
	}

	// 设置data_path（使用metasvc_path，与Python一致）
	// Python: metasvc_path = f"{self._aldaba_conf.storage.mygrid_env['mygrid_env']['meta_store_disk']}/{self._aldaba_conf.storage.mygrid_env['mygrid_env']['project_data_path']}"
	metasvcPath := c.getMetasvcPath()
	if metasvcPath == "" {
		// 如果无法从配置获取，回退到默认路径
		metasvcPath = filepath.Join(c.deployDir, lightInstance, "data")
	}
	if metaService, ok := c.metaConf["meta_service"].(map[string]interface{}); ok {
		metaService["data_path"] = metasvcPath
	}

	// 6. 生成客户端配置文件
	// mygrid_genesis.conf
	mygridGenesisFile := filepath.Join(cliBinDir, MygridGenesisFilename)
	if data, err := json.MarshalIndent(c.mygridClientConf, "", "  "); err == nil {
		os.WriteFile(mygridGenesisFile, data, 0666)
	}

	// meta_service.conf
	metaServiceFile := filepath.Join(cliBinDir, MetaServiceFilename)
	if data, err := json.MarshalIndent(c.metaConf, "", "  "); err == nil {
		os.WriteFile(metaServiceFile, data, 0666)
	}

	// aldaba.conf
	aldabaConfFile := filepath.Join(cliConfDir, "aldaba.conf")

	// Add instance environment variables to aldaba configuration (matching Python behavior)
	if inst, exists := c.domain.Cluster[lightInstance]; exists {
		if aldaba, ok := c.aldabaConf["aldaba"].(map[string]interface{}); ok {
			if startup, ok := aldaba["startup_config"].(map[string]interface{}); ok {
				// Get or create parameters map
				var parameters map[string]interface{}
				if params, ok := startup["parameters"].(map[string]interface{}); ok {
					parameters = params
				} else {
					parameters = make(map[string]interface{})
					startup["parameters"] = parameters
				}

				// Add instance environment variables
				for k, v := range inst.Env {
					parameters["/SetEnv/"+k] = v
				}

				// Add common environment variables
				if c.domain.Common.Env != nil {
					for k, v := range c.domain.Common.Env {
						parameters["/SetEnv/"+k] = v
					}
				}

				// Add standard environment variables
				parameters["/SetEnv/CHAIN_ID"] = c.domain.ChainID
				parameters["/SetEnv/DOMAIN_LABEL"] = c.domain.DomainLabel
				parameters["/SetEnv/SERVICE"] = inst.Service
			}
		}
	}

	if data, err := json.MarshalIndent(c.aldabaConf, "", "  "); err == nil {
		os.WriteFile(aldabaConfFile, data, 0666)
	}

	return nil
}

// makeWorkspaceLocal 创建本地工作空间
func (c *ComposerRefactor) makeWorkspaceLocal(baseDir string, dirs ...string) error {
	// 创建基础目录
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return err
	}

	// 创建子目录
	for _, dir := range dirs {
		dirPath := filepath.Join(baseDir, dir)
		if err := os.MkdirAll(dirPath, 0755); err != nil {
			return err
		}
	}

	return nil
}

// syncClientToRemote 同步客户端到远程主机
func (c *ComposerRefactor) syncClientToRemote(host string) error {
	utils.Info("Syncing client tools to remote host: %s", host)

	// 创建SSH连接
	user := c.runUser
	if c.isLocal(host) {
		user = ""
	}

	sshClient, err := ssh.NewClient(host, user)
	if err != nil {
		return fmt.Errorf("failed to create SSH client: %w", err)
	}
	defer sshClient.Close()

	if err := sshClient.Connect(); err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	// 创建远程目录
	if err := sshClient.MkdirAll(c.deployDir, 0755); err != nil {
		return fmt.Errorf("failed to create deploy directory: %w", err)
	}

	// 同步目录
	if c.isLocal(host) {
		// 本地：使用cp命令
		cmd := fmt.Sprintf("cp -aLv %s %s", c.localClientDir, c.deployDir)
		if _, err := sshClient.RunCommand(cmd); err != nil {
			return fmt.Errorf("failed to copy client directory: %w", err)
		}
	} else {
		// 远程：使用rsync
		if err := sshClient.RsyncDirectory(c.localClientDir+"/", c.deployDir, "-avzL"); err != nil {
			return fmt.Errorf("failed to rsync client directory: %w", err)
		}
	}

	utils.Info("✓ Client directory synced successfully")
	return nil
}

// createMetaStore 创建元数据存储目录（非自适应模式）
func (c *ComposerRefactor) createMetaStore(sshClient *ssh.Client) error {
	// 从配置中获取路径
	var metaStoreDisk, projectDataPath string

	if storage, ok := c.aldabaConf["storage"].(map[string]interface{}); ok {
		if mygridEnv, ok := storage["mygrid_env"].(map[string]interface{}); ok {
			if env, ok := mygridEnv["mygrid_env"].(map[string]interface{}); ok {
				if disk, ok := env["meta_store_disk"].(string); ok {
					metaStoreDisk = disk
				}
				if path, ok := env["project_data_path"].(string); ok {
					projectDataPath = path
				}
			}
		}
	}

	if metaStoreDisk != "" && projectDataPath != "" {
		fullPath := filepath.Join(metaStoreDisk, projectDataPath)
		if err := sshClient.MkdirAll(fullPath, 0755); err != nil {
			return fmt.Errorf("failed to create meta store directory: %w", err)
		}
	}

	return nil
}


// copyFileRefactor 复制文件（重命名避免与bootstrap.go冲突）
func copyFileRefactor(src, dst string) error {
	// 获取源文件信息以保留权限
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	// 读取源文件
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	// 写入目标文件并保留权限
	if err := os.WriteFile(dst, data, srcInfo.Mode()); err != nil {
		return err
	}

	return nil
}

// copyDirRefactor 复制目录（重命名避免与bootstrap.go冲突）
func copyDirRefactor(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		dstPath := filepath.Join(dst, relPath)

		if info.IsDir() {
			return os.MkdirAll(dstPath, info.Mode())
		}

		return copyFileRefactor(path, dstPath)
	})
}
