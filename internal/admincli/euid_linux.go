//go:build linux

package admincli

import "os"

func platformEffectiveUID() int { return os.Geteuid() }
