//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows/registry"
)

func machineGUID() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err == nil {
		defer k.Close()
		if v, _, err := k.GetStringValue("MachineGuid"); err == nil && v != "" {
			return v
		}
	}
	host, _ := os.Hostname()
	return host + "|" + os.Getenv("PROCESSOR_IDENTIFIER")
}
