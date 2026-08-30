//go:build !linux

package config

import "errors"

func openSecurePVEEnvironment(string, int64) (secureEnvironmentFile, error) {
	return secureEnvironmentFile{}, errors.New("secure PVE environment loading is supported only on Linux")
}

func pveEnvironmentRunningAsRoot() bool { return false }
