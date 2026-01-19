package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

const (
	passwordFile = "./.password"
	passwordEnv  = "CONSENSUS_KEY_PWD"
)

var setPasswordCmd = &cobra.Command{
	Use:   "set-password [password]",
	Short: "Set password for pharos node",
	Long: `Set password for pharos node. 
The password will be saved to ./conf/.password for binary deployment.
For Docker deployment, use CONSENSUS_KEY_PWD environment variable instead.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var password string

		// Get password from argument or environment variable
		if len(args) > 0 {
			password = args[0]
		} else if envPassword := os.Getenv(passwordEnv); envPassword != "" {
			password = envPassword
			fmt.Printf("Using password from environment variable %s\n", passwordEnv)
		} else {
			return fmt.Errorf("password not provided. Use: ./ops set-password <password> or set %s environment variable", passwordEnv)
		}

		// Validate password
		password = strings.TrimSpace(password)
		if password == "" {
			return fmt.Errorf("password cannot be empty")
		}

		// Ensure conf directory exists
		confDir := filepath.Dir(passwordFile)
		if err := os.MkdirAll(confDir, 0755); err != nil {
			return fmt.Errorf("failed to create conf directory: %w", err)
		}

		// Save password to file
		if err := os.WriteFile(passwordFile, []byte(password), 0600); err != nil {
			return fmt.Errorf("failed to save password: %w", err)
		}

		fmt.Println("Password saved successfully")
		return nil
	},
}

var getPasswordCmd = &cobra.Command{
	Use:   "get-password",
	Short: "Get current password",
	Long:  "Display the current password for pharos node",
	RunE: func(cmd *cobra.Command, args []string) error {
		password, err := GetPassword()
		if err != nil {
			return err
		}

		fmt.Printf("Current password: %s\n", password)
		return nil
	},
}

// GetPassword retrieves the password from file or environment variable
// Priority: Environment variable > Password file
func GetPassword() (string, error) {
	// First check environment variable (for Docker deployment)
	if envPassword := os.Getenv(passwordEnv); envPassword != "" {
		return strings.TrimSpace(envPassword), nil
	}

	// Then check password file (for binary deployment)
	if _, err := os.Stat(passwordFile); err == nil {
		data, err := os.ReadFile(passwordFile)
		if err != nil {
			return "", fmt.Errorf("failed to read password file: %w", err)
		}
		password := strings.TrimSpace(string(data))
		if password == "" {
			return "", fmt.Errorf("password file is empty")
		}
		return password, nil
	}

	return "", fmt.Errorf("password not found. Please run: ./ops set-password <password> or set %s environment variable", passwordEnv)
}

func init() {
	rootCmd.AddCommand(setPasswordCmd)
	rootCmd.AddCommand(getPasswordCmd)
}
