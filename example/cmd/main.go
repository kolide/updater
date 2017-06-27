package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/kolide/updater"
)

func main() {
	var (
		baseDir       = flag.String("base-directory", "./", "the directory where all the things are")
		flRepo        = flag.String("filerepo", "filerepo", "path to file repo which will serve static assets")
		flServerCerts = flag.String("server-certificates", "../../test/server", "path to folder with server certs. must be named cert.pem and key.pem respectively")
		flGUN         = flag.String("gun", "kolide/greeter/darwin", "the globally unique identifier")
		flBootstrap   = flag.Bool("bootstrap", false, "set up local repository for the GUN from the local notary-server")
		flDownoad     = flag.String("download", "", "download a specific target")
	)
	flag.Parse()

	settings := updater.Settings{
		LocalRepoPath:      filepath.Join(*baseDir, "repo"),
		NotaryURL:          "https://notary-server:4443",
		StagingPath:        filepath.Join(*baseDir, "staging"),
		GUN:                *flGUN,
		TargetName:         "latest/target",
		InsecureSkipVerify: true,
		MirrorURL:          "https://localhost:8888/repo",
	}

	if *flBootstrap {
		// download all the necessary JSON files from the notary server into the "repo" directory.
		roles := []string{"root.json", "snapshot.json", "timestamp.json", "targets.json"}
		repoPath := filepath.Join(*baseDir, "repo")
		os.MkdirAll(repoPath, 0755)
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
		for _, role := range roles {
			urlstring := settings.NotaryURL + path.Join("/v2/", settings.GUN, "_trust/tuf", role)
			resp, err := client.Get(urlstring)
			if err != nil {
				log.Fatalf("could not download %s: %s\n", urlstring, err)
			}
			defer resp.Body.Close()
			data, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				log.Fatal(err)
			}
			roleFile := filepath.Join(repoPath, role)
			if err := ioutil.WriteFile(roleFile, data, 0644); err != nil {
				log.Fatalf("could not save %s to %s: %s\n", urlstring, repoPath, err)
			}
			fmt.Printf("saved %s to %s\n", urlstring, roleFile)
		}
		os.Exit(0)
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

	// serve the static files from a local mirror
	go func() {
		http.Handle("/", staticStaticRepo("/repo/", *flRepo))
		cert, _ := filepath.Abs(filepath.Join(*flServerCerts, "cert.pem"))
		key, _ := filepath.Abs(filepath.Join(*flServerCerts, "key.pem"))
		log.Fatal(http.ListenAndServeTLS(":8888", cert, key, nil))
	}()

	if *flDownoad != "" {
		f, err := ioutil.TempFile(os.TempDir(), "osqueryd")
		defer f.Close()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("downloading %s to %s\n", settings.TargetName, f.Name())
		if err := update.Download("latest/target", f); err != nil {
			log.Fatal(err)
		}
	}

	fmt.Print("Hit enter to stop me: ")
	fmt.Scanln()

	fmt.Println("done...")
}

func staticStaticRepo(path, dir string) http.Handler {
	return http.StripPrefix(path, http.FileServer(http.Dir(dir)))
}
