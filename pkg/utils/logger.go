package utils

import (
	"log"
	"os"
)

var (
	debugMode = false
	logger    = log.New(os.Stdout, "", log.LstdFlags)
)

func SetDebug(debug bool) {
	debugMode = debug
}

func Debug(format string, args ...interface{}) {
	if debugMode {
		logger.Printf("DEBUG: "+format, args...)
	}
}

func Info(format string, args ...interface{}) {
	logger.Printf("INFO: "+format, args...)
}

func Warn(format string, args ...interface{}) {
	logger.Printf("WARN: "+format, args...)
}

func Error(format string, args ...interface{}) {
	logger.Printf("ERROR: "+format, args...)
}

func Fatal(format string, args ...interface{}) {
	logger.Printf("FATAL: "+format, args...)
	os.Exit(1)
}