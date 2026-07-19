//go:build !windows

package feed

import "os/exec"

func hideScriptWindow(cmd *exec.Cmd) {}