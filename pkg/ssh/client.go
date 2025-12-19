package ssh

import (
	"crypto/md5"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Client represents an SSH client for remote operations
type Client struct {
	client   *ssh.Client
	config   *ssh.ClientConfig
	host     string
	user     string
	keyPath  string
	password string
}

// NewClient creates a new SSH client
func NewClient(host, user string, options ...Option) (*Client, error) {
	c := &Client{
		host: host,
		user: user,
	}

	// If user is empty, use current user
	if c.user == "" {
		c.user = os.Getenv("USER")
		if c.user == "" {
			c.user = os.Getenv("LOGNAME")
		}
		if c.user == "" {
			c.user = "root" // fallback
		}
	}

	// Apply options
	for _, opt := range options {
		opt(c)
	}

	// Create SSH config
	config := &ssh.ClientConfig{
		User:            c.user,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // In production, use proper host key verification
		Timeout:         30 * time.Second,
	}

	// For localhost, try default key paths if no key specified
	if (host == "127.0.0.1" || host == "localhost") && c.keyPath == "" {
		// Try common SSH key paths
		keyPaths := []string{
			filepath.Join(os.Getenv("HOME"), ".ssh", "id_rsa"),
			filepath.Join(os.Getenv("HOME"), ".ssh", "id_ed25519"),
			filepath.Join(os.Getenv("HOME"), ".ssh", "id_ecdsa"),
			filepath.Join(os.Getenv("HOME"), ".ssh", "id_dsa"),
		}

		for _, keyPath := range keyPaths {
			if key, err := os.ReadFile(keyPath); err == nil {
				if signer, err := ssh.ParsePrivateKey(key); err == nil {
					config.Auth = append(config.Auth, ssh.PublicKeys(signer))
					break
				}
			}
		}
	}

	// Try specified key-based authentication
	if c.keyPath != "" {
		key, err := os.ReadFile(c.keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read private key: %w", err)
		}

		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}

		config.Auth = append(config.Auth, ssh.PublicKeys(signer))
	}

	// Fall back to password authentication
	if c.password != "" {
		config.Auth = append(config.Auth, ssh.Password(c.password))
	}

	// For localhost, if still no auth method, try SSH agent
	if (host == "127.0.0.1" || host == "localhost") && len(config.Auth) == 0 {
		if sshAgent, err := getSSHAgentAuth(); err == nil {
			config.Auth = append(config.Auth, sshAgent)
		}
	}

	if len(config.Auth) == 0 {
		return nil, fmt.Errorf("no authentication method provided")
	}

	c.config = config

	return c, nil
}

// Option represents a configuration option for the SSH client
type Option func(*Client)

// WithKeyPath sets the private key file path for authentication
func WithKeyPath(path string) Option {
	return func(c *Client) {
		c.keyPath = path
	}
}

// WithPassword sets the password for authentication
func WithPassword(password string) Option {
	return func(c *Client) {
		c.password = password
	}
}

// Connect establishes an SSH connection to the remote host
func (c *Client) Connect() error {
	addr := net.JoinHostPort(c.host, "22")
	client, err := ssh.Dial("tcp", addr, c.config)
	if err != nil {
		return fmt.Errorf("failed to dial: %w", err)
	}

	c.client = client
	return nil
}

// Close closes the SSH connection
func (c *Client) Close() error {
	if c.client != nil {
		return c.client.Close()
	}
	return nil
}

// RunCommand executes a command on the remote host
func (c *Client) RunCommand(cmd string) (string, error) {
	if c.client == nil {
		return "", fmt.Errorf("not connected to remote host")
	}

	session, err := c.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput(cmd)
	return string(output), err
}

// UploadFile uploads a local file to the remote host using rsync (like Python version)
func (c *Client) UploadFile(localPath, remotePath string) error {
	if c.client == nil {
		return fmt.Errorf("not connected to remote host")
	}

	// Get file info first
	fileInfo, err := os.Stat(localPath)
	if err != nil {
		return fmt.Errorf("failed to stat local file: %w", err)
	}

	fmt.Printf("=== Rsync Upload Debug ===\n")
	fmt.Printf("Local path: %s\n", localPath)
	fmt.Printf("Remote path: %s\n", remotePath)
	fmt.Printf("File size: %d bytes\n", fileInfo.Size())

	// Use rsync like Python version
	// Make sure remote directory exists
	remoteDir := filepath.Dir(remotePath)
	if _, err := c.RunCommand(fmt.Sprintf("mkdir -p %s", remoteDir)); err != nil {
		return fmt.Errorf("failed to create remote directory: %w", err)
	}

	// Build rsync command (matching Python's rsync options)
	// Python uses: rsync -avzL local_file host:remote_path
	var cmd string
	if c.host == "127.0.0.1" || c.host == "localhost" {
		// For localhost, rsync directly without SSH
		cmd = fmt.Sprintf("rsync -avzL %s %s", localPath, remotePath)
	} else {
		// For remote hosts, use SSH
		if c.user != "" {
			cmd = fmt.Sprintf("rsync -avzL -e 'ssh -o StrictHostKeyChecking=no' %s %s@%s:%s",
				localPath, c.user, c.host, remotePath)
		} else {
			cmd = fmt.Sprintf("rsync -avzL -e 'ssh -o StrictHostKeyChecking=no' %s %s:%s",
				localPath, c.host, remotePath)
		}
	}

	fmt.Printf("Rsync command: %s\n", cmd)

	// Execute rsync command locally
	// Since rsync handles the SSH connection itself, we don't need to use the SSH session
	var output []byte
	if c.host == "127.0.0.1" || c.host == "localhost" {
		// For localhost, use local rsync without SSH
		output, err = exec.Command("rsync", "-avzL", localPath, remotePath).CombinedOutput()
	} else {
		// For remote hosts, use rsync with SSH
		if c.user != "" {
			output, err = exec.Command("rsync", "-avzL", "-e", "ssh -o StrictHostKeyChecking=no",
				localPath, fmt.Sprintf("%s@%s:%s", c.user, c.host, remotePath)).CombinedOutput()
		} else {
			output, err = exec.Command("rsync", "-avzL", "-e", "ssh -o StrictHostKeyChecking=no",
				localPath, fmt.Sprintf("%s:%s", c.host, remotePath)).CombinedOutput()
		}
	}

	if err != nil {
		return fmt.Errorf("rsync failed: %w, output: %s", err, string(output))
	}

	fmt.Printf("Rsync output: %s\n", string(output))

	// Verify file integrity with MD5
	fmt.Printf("Verifying file integrity...\n")
	if err := c.verifyFileMD5(localPath, remotePath); err != nil {
		return fmt.Errorf("file verification failed: %w", err)
	}

	return nil
}

// MkdirAll creates directories recursively on the remote host
func (c *Client) MkdirAll(path string, perm os.FileMode) error {
	if c.client == nil {
		return fmt.Errorf("not connected to remote host")
	}

	// Use mkdir -p to create directories recursively
	cmd := fmt.Sprintf("mkdir -p %s", path)
	_, err := c.RunCommand(cmd)
	return err
}

// RemoveAll removes a file or directory recursively on the remote host
func (c *Client) RemoveAll(path string) error {
	cmd := fmt.Sprintf("rm -rf %s", path)
	_, err := c.RunCommand(cmd)
	return err
}

// Remove removes a file on the remote host
func (c *Client) Remove(path string) error {
	cmd := fmt.Sprintf("rm -f %s", path)
	_, err := c.RunCommand(cmd)
	return err
}

// CreateSymlink creates a symbolic link on the remote host
func (c *Client) CreateSymlink(source, target string) error {
	fmt.Printf("=== Create Symlink Debug ===\n")
	fmt.Printf("Source: %s\n", source)
	fmt.Printf("Target: %s\n", target)

	// First check if source exists
	if exists, err := c.FileExists(source); err != nil {
		fmt.Printf("Failed to check if source exists: %v\n", err)
		return fmt.Errorf("failed to check source file: %w", err)
	} else if !exists {
		fmt.Printf("Source file does not exist: %s\n", source)
		return fmt.Errorf("source file does not exist: %s", source)
	}
	fmt.Printf("Source file exists: %s\n", source)

	// Create target directory if needed
	targetDir := filepath.Dir(target)
	mkdirCmd := fmt.Sprintf("mkdir -p %s", targetDir)
	fmt.Printf("Creating target directory: %s\n", mkdirCmd)
	if output, err := c.RunCommand(mkdirCmd); err != nil {
		fmt.Printf("Failed to create target directory: %v, output: %s\n", err, output)
		return fmt.Errorf("failed to create target directory: %w", err)
	}

	// Create the symlink
	cmd := fmt.Sprintf("ln -sf %s %s", source, target)
	fmt.Printf("Symlink command: %s\n", cmd)

	output, err := c.RunCommand(cmd)
	if err != nil {
		fmt.Printf("Failed to create symlink: %v, output: %s\n", err, output)
		return fmt.Errorf("failed to create symlink: %w, output: %s", err, output)
	}

	// Verify symlink was created
	verifyCmd := fmt.Sprintf("ls -la %s", target)
	fmt.Printf("Verifying symlink with: %s\n", verifyCmd)
	verifyOutput, verifyErr := c.RunCommand(verifyCmd)
	if verifyErr != nil {
		fmt.Printf("Failed to verify symlink: %v\n", verifyErr)
	} else {
		fmt.Printf("Symlink verification output: %s\n", verifyOutput)
	}

	fmt.Printf("✓ Symlink created successfully\n")
	return nil
}

// FileExists checks if a file exists on the remote host
func (c *Client) FileExists(path string) (bool, error) {
	cmd := fmt.Sprintf("test -f %s", path)
	_, err := c.RunCommand(cmd)
	if err != nil {
		if strings.Contains(err.Error(), "exit status 1") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// CopyFile copies a file on the remote host
func (c *Client) CopyFile(source, dest string) error {
	cmd := fmt.Sprintf("cp %s %s", source, dest)
	_, err := c.RunCommand(cmd)
	return err
}

// verifyFileMD5 compares MD5 hash of local and remote files
func (c *Client) verifyFileMD5(localPath, remotePath string) error {
	// Calculate local MD5
	localFile, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("failed to open local file for MD5: %w", err)
	}
	defer localFile.Close()

	localHash := md5.New()
	if _, err := io.Copy(localHash, localFile); err != nil {
		return fmt.Errorf("failed to calculate local MD5: %w", err)
	}
	localMD5 := fmt.Sprintf("%x", localHash.Sum(nil))

	// Calculate remote MD5
	remoteMD5Cmd := fmt.Sprintf("md5sum %s | cut -d' ' -f1", remotePath)
	remoteOutput, err := c.RunCommand(remoteMD5Cmd)
	if err != nil {
		return fmt.Errorf("failed to calculate remote MD5: %w", err)
	}
	remoteMD5 := strings.TrimSpace(remoteOutput)

	fmt.Printf("Local MD5:  %s\n", localMD5)
	fmt.Printf("Remote MD5: %s\n", remoteMD5)

	if localMD5 != remoteMD5 {
		return fmt.Errorf("MD5 mismatch: local=%s, remote=%s", localMD5, remoteMD5)
	}

	fmt.Printf("✓ File integrity verified\n")
	return nil
}

// RsyncDirectory syncs a local directory to remote host using rsync
// Matches Python's conn.sync() method behavior
func (c *Client) RsyncDirectory(localPath, remotePath string, rsyncOpts ...string) error {
	// Default rsync options (matching Python)
	defaultOpts := []string{"-avzL"}
	if len(rsyncOpts) > 0 {
		defaultOpts = rsyncOpts
	}

	fmt.Printf("=== Rsync Directory ===\n")
	fmt.Printf("Local path: %s\n", localPath)
	fmt.Printf("Remote path: %s\n", remotePath)
	fmt.Printf("Rsync options: %v\n", defaultOpts)

	// Build rsync command
	var args []string
	args = append(args, defaultOpts...)

	// Add SSH options for remote hosts
	if c.host != "127.0.0.1" && c.host != "localhost" {
		args = append(args, "-e", "ssh -o StrictHostKeyChecking=no")
	}

	// Add source and destination
	args = append(args, localPath)

	if c.host == "127.0.0.1" || c.host == "localhost" {
		// For localhost, rsync directly
		args = append(args, remotePath)
	} else {
		// For remote hosts, add user@host:
		if c.user != "" {
			args = append(args, fmt.Sprintf("%s@%s:%s", c.user, c.host, remotePath))
		} else {
			args = append(args, fmt.Sprintf("%s:%s", c.host, remotePath))
		}
	}

	fmt.Printf("Rsync command: rsync %v\n", args)

	// Execute rsync
	cmd := exec.Command("rsync", args...)
	output, err := cmd.CombinedOutput()

	if err != nil {
		return fmt.Errorf("rsync failed: %w, output: %s", err, string(output))
	}

	fmt.Printf("Rsync output: %s\n", string(output))
	fmt.Printf("✓ Directory sync completed\n")

	return nil
}

// getSSHAgentAuth tries to get authentication from SSH agent
func getSSHAgentAuth() (ssh.AuthMethod, error) {
	sshAuthSock := os.Getenv("SSH_AUTH_SOCK")
	if sshAuthSock == "" {
		return nil, fmt.Errorf("SSH_AUTH_SOCK not set")
	}

	conn, err := net.Dial("unix", sshAuthSock)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SSH agent: %w", err)
	}

	agentClient := agent.NewClient(conn)
	signers, err := agentClient.Signers()
	if err != nil {
		return nil, fmt.Errorf("failed to get signers from SSH agent: %w", err)
	}

	if len(signers) == 0 {
		return nil, fmt.Errorf("no signers available in SSH agent")
	}

	return ssh.PublicKeysCallback(agentClient.Signers), nil
}

// GetHost returns the host address
func (c *Client) GetHost() string {
	return c.host
}

// UploadFileContent uploads content to a file on remote host
func (c *Client) UploadFileContent(remotePath, content string) error {
	if c.client == nil {
		return fmt.Errorf("not connected to remote host")
	}

	// Use cat with heredoc to write content
	cmd := fmt.Sprintf("cat > %s << 'EOF'\n%s\nEOF", remotePath, content)
	_, err := c.RunCommand(cmd)
	return err
}