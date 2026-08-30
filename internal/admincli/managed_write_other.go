//go:build !linux

package admincli

import "github.com/ppflight/ppflight-agent/internal/config"

// ValidateInstalledWriteTarget is a Linux root production guard. Non-Linux
// builds have no supported PVE/systemd production management path.
func ValidateInstalledWriteTarget(string, config.Config) error { return nil }

func (c *cli) requireManagedWriteTarget(filename string, cfg config.Config) error {
	if c.managedWritePolicy != nil {
		return c.managedWritePolicy(filename, cfg)
	}
	return nil
}
