package main

import (
	"flag"
	"fmt"
	"os"
	"path"
	"time"

	"github.com/kolide/updater"
)

func main() {
	var (
		baseDir string
		help    bool
	)
	workingDir, err := os.Getwd()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	flag.StringVar(&baseDir, "base-directory", workingDir, "the directory where all the things are")
	flag.BoolVar(&help, "help", false, "show this message")
	flag.Parse()
	if help {
		flag.PrintDefaults()
		os.Exit(0)
	}
	settings := updater.Settings{
		LocalRepoPath:      path.Join(baseDir, "repo"),
		RemoteRepoBaseURL:  "https://notary-server:4443",
		StagingPath:        path.Join(baseDir, "staging"),
		GUN:                "kolide/greeter/darwin",
		TargetName:         "latest/target",
		InsecureSkipVerify: true,
		MirrorURL:          "https://storage.googleapis.com/kolide_test_mirror",
	}
	update, err := updater.New(settings, func(stagingDir string, err error) {
		if err != nil {
			fmt.Printf("error: %q\n", err)
			return
		}
		fmt.Printf("success: %q\n", stagingDir)
	}, updater.WithFrequency(1*time.Minute))
	if err != nil {
		fmt.Printf("could not create updater: %q", err)
		os.Exit(1)
	}
	update.Start()

	defer update.Stop()
	fmt.Print("Hit enter to stop me: ")
	fmt.Scanln()

	fmt.Println("done...")
}
