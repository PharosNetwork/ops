package cmd

// MainPkg holds variables from main package
type MainPkg struct {
	Version   string
	BuildTime string
	GitCommit string
}

var mainPkg = MainPkg{
	Version:   "dev",     // Will be set from main package
	BuildTime: "unknown", // Will be set from main package
	GitCommit: "unknown", // Will be set from main package
}

// SetVersionInfo sets the version information from main package
func SetVersionInfo(version, buildTime, gitCommit string) {
	mainPkg.Version = version
	mainPkg.BuildTime = buildTime
	mainPkg.GitCommit = gitCommit
}

// GetVersionInfo returns the version information
func GetVersionInfo() MainPkg {
	return mainPkg
}