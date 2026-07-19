//go:build windows

package feed

import (
	"os/exec"
	"syscall"
)

const (
	createNoWindow  = 0x08000000 // CREATE_NO_WINDOW
	detachedProcess = 0x00000008 // DETACHED_PROCESS
)

func hideScriptWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true,
		// DETACHED_PROCESS prevents console programs launched from a GUI app
		// (and their child processes, such as curl.exe) from attaching to or
		// allocating a visible console. CREATE_NO_WINDOW is retained for the
		// immediate process on Windows versions that honour it separately.
		CreationFlags: detachedProcess | createNoWindow,
	}
}
