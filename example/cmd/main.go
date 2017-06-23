package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kolide/updater"
)

func main() {
	var (
		baseDir = flag.String("base-directory", "./", "the directory where all the things are")
	)
	flag.Parse()

	settings := updater.Settings{
		LocalRepoPath:      filepath.Join(*baseDir, "repo"),
		NotaryURL:          "https://notary-server:4443",
		StagingPath:        filepath.Join(*baseDir, "staging"),
		GUN:                "kolide/greeter/darwin",
		TargetName:         "latest/target",
		InsecureSkipVerify: true,
		MirrorURL:          "https://storage.googleapis.com/kolide_test_mirror",
	}
	// Callback function that will be invoked when an update is triggered.  The
	// stagingDir argument will be the location of the file downloaded from a mirror.
	// It is up to the application to perform whatever subsequent actions need to take
	// place. For example the application might install and restart itself.
	updateHandler := func(stagingDir string, err error) {
		if err != nil {
			fmt.Printf("error: %q\n", err)
			return
		}
		// Do app specific stuff here.
		fmt.Printf("success: %q\n", stagingDir)
	}
	update, err := updater.Start(settings, updateHandler, updater.WithFrequency(1*time.Minute))
	if err != nil {
		fmt.Printf("could not create updater: %q", err)
		os.Exit(1)
	}

	defer update.Stop()

	fmt.Print("Hit enter to stop me: ")
	fmt.Scanln()

	fmt.Println("done...")
}
