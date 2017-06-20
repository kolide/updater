// +build !windows

package updater

import (
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/pkg/errors"
)

func restart(cmd exec.Cmd) error {
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Start()
	if err != nil {
		return errors.Wrap(err, "restaring process")
	}
	parent := syscall.Getppid()
	syscall.Kill(parent, syscall.SIGTERM)
	return nil
}

func copyRecursive(srcDir, targetDir string) error {
	if !strings.HasSuffix(srcDir, "/") {
		srcDir += "/"
	}
	cmd := exec.Command("cp", "-R", "-f", srcDir, targetDir)
	return cmd.Run()
}
