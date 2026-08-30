//go:build !linux

package admincli

func platformEffectiveUID() int { return -1 }
