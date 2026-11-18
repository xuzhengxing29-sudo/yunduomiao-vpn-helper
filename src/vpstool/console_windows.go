//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

var (
	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	user32               = syscall.NewLazyDLL("user32.dll")
	procSetConsoleOutput = kernel32.NewProc("SetConsoleOutputCP")
	procSetConsoleCP     = kernel32.NewProc("SetConsoleCP")
	procSetConsoleTitleW = kernel32.NewProc("SetConsoleTitleW")
	procMessageBoxW      = user32.NewProc("MessageBoxW")
)

func setupConsole() {
	_, _, _ = procSetConsoleOutput.Call(65001)
	_, _, _ = procSetConsoleCP.Call(65001)
	if title, err := syscall.UTF16PtrFromString("VPS 一键部署工具"); err == nil {
		_, _, _ = procSetConsoleTitleW.Call(uintptr(unsafe.Pointer(title)))
	}
}

func fatalBox(title, msg string) {
	t, _ := syscall.UTF16PtrFromString(title)
	m, _ := syscall.UTF16PtrFromString(msg)
	_, _, _ = procMessageBoxW.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), 0x10)
}
