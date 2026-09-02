//go:build !linux

package admincli

func templateBridgeKernelInterfaceExists(string) (bool, error) { return false, nil }

func templateBridgeKernelMembers(string) ([]string, error) { return nil, nil }
