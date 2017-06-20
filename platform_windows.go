package updater

import (
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/pkg/errors"
)

// TODO: check if this actually works on winders
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
	if !strings.HasSuffix(srcDir, `\`) {
		srcDir += `\`
	}
	cmd := exec.Command("xcopy", "/E", "/Y", srcDir, targetDir)
	err := cmd.Run()
	if err != nil {
		return errors.Wrap(err, "copy recursive")
	}
	return nil
}
