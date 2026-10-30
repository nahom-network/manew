//go:build windows

package main

import (
	"os"
	"syscall"
	"unsafe"
)

const enableVirtualTerminalProcessing = 0x0004

var (
	kernel32DLL        = syscall.NewLazyDLL("kernel32.dll")
	getConsoleModeProc = kernel32DLL.NewProc("GetConsoleMode")
	setConsoleModeProc = kernel32DLL.NewProc("SetConsoleMode")
)

// enableANSI turns on VT escape handling for classic Windows consoles.
// Windows Terminal already handles ANSI, so this is only needed for conhost.
func enableANSI() {
	h := syscall.Handle(os.Stdout.Fd())
	var mode uint32
	if r, _, _ := getConsoleModeProc.Call(uintptr(h), uintptr(unsafe.Pointer(&mode))); r == 0 {
		return
	}
	if mode&enableVirtualTerminalProcessing != 0 {
		return
	}
	_, _, _ = setConsoleModeProc.Call(uintptr(h), uintptr(mode|enableVirtualTerminalProcessing))
}
