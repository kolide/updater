package tuf

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/WatchBeam/clock"
	"github.com/pkg/errors"
)

// Client is a TUF client.
type Client struct {
	// values to autoupdate
	checkFrequency      time.Duration
	backupFileAge       time.Duration
	watchedTarget       string
	stagingPath         string
	notificationHandler NotificationHandler
	quit                chan struct{}
	clock               clock.Clock
	client              *http.Client
	maxResponseSize     int64
	jobs                chan func(*repoMan)
	wait                sync.WaitGroup
	// Default true, if true, and autoupdate is enabled check for updates on startup
	// instead of waiting until check interval has elapsed.
	loadOnStart     bool
	forceAutoUpdate chan struct{}
}

const (
	defaultCheckFrequency  = 1 * time.Hour
	defaultBackupAge       = 24 * time.Hour
	defaultMaxResponseSize = int64(5 * 1024 * 1024) // 5 Megabytes
)

// Option allows customization of the Client.
type Option func(*Client)

// WithFrequency allows changing the frequency of autoupdate checks.
func WithFrequency(duration time.Duration) Option {
	return func(c *Client) {
		c.checkFrequency = duration
	}
}

// WithBackupAge changes the amount of time that repository backup files
// are kept before being removed. Current default is one day.
func WithBackupAge(age time.Duration) Option {
	return func(c *Client) {
		c.backupFileAge = age
	}
}

// NotificationHandler gets called when the hosting application has a new version
// of a target that it needs to deal with.  The hosting application will need to
// check the err object, if err is nil the stagingPath will point to a validated
// target which is the hosting application's responsibility to deal with.
type NotificationHandler func(stagingPath string, err error)

// WithAutoUpdate specifies a target which will be auto-downloaded into a staging path by the client.
// WithAutoUpdate requires a NotificationHandler which will be called whenever there is a new upate.
// Use WithFrequency to configure how often the autoupdate goroutine runs.
// There can only be one NotificationHandler per Client.
func WithAutoUpdate(targetName, stagingPath string, onUpdate NotificationHandler) Option {
	return func(c *Client) {
		c.stagingPath = stagingPath
		c.watchedTarget = targetName
		c.notificationHandler = onUpdate
	}
}

// WithHTTPClient configures a custom HTTP Client to be used by the Client.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *Client) {
		c.client = httpClient
	}
}

// NewClient creates a TUF Client which can securely download packages from a remote mirror.
// The Client downloads payloads(also called targets) from a remote mirror, validating
// each payload according to the TUF spec. The Client uses a Docker Notary service to
// fetch TUF metadata files stored in the local repository.
//
// You can use one of the provided Options to customize the client configuration.
func NewClient(settings *Settings, opts ...Option) (*Client, error) {
	if err := settings.verify(); err != nil {
		return nil, err
	}

	client := Client{
		maxResponseSize: defaultMaxResponseSize,
		client:          defaultHttpClient(),
		checkFrequency:  defaultCheckFrequency,
		backupFileAge:   defaultBackupAge,
		quit:            make(chan struct{}),
		clock:           &clock.DefaultClock{},
		jobs:            make(chan func(*repoMan)),
		loadOnStart:     true,
		forceAutoUpdate: make(chan struct{}),
	}
	for _, opt := range opts {
		opt(&client)
	}
	notary, err := newNotaryRepo(settings, client.maxResponseSize, client.client)
	if err != nil {
		return nil, errors.Wrap(err, "creating notary client")
	}
	err = notary.ping()
	if err != nil {
		return nil, errors.Wrap(err, "pinging notary server failed")
	}
	localRepo, err := newLocalRepo(settings.LocalRepoPath)
	if err != nil {
		return nil, errors.New("creating local tuf role repo")
	}
	rm := newRepoMan(localRepo, notary, settings, notary.client, client.backupFileAge, client.clock)
	var autoupdate *autoupdater
	if client.watchedTarget != "" {
		if client.notificationHandler == nil {
			return nil, errors.New("notification handler required for autoupdate")
		}
		autoupdate = newAutoupdater(&client)
	}
	ticker := client.clock.NewTicker(client.checkFrequency).Chan()
	client.wait.Add(1)
	go workerLoop(
		ticker,
		client.quit,
		client.jobs,
		&client.wait,
		rm,
		client.forceAutoUpdate,
		autoupdate,
	)
	// This will force autoupdate to run as soon as we start instead of waiting
	// until checkFrequency has elapsed.
	if client.loadOnStart {
		client.forceAutoUpdate <- struct{}{}
	}

	return &client, nil
}

// Update updates the local TUF metadata from a remote repository. If the update is successful,
// a list of files that have changed will be returned.
//
// Update gets the current metadata from the notary repository and performs
// requisite checks and validations as specified in the TUF spec section 5.1 'The Client Application'.
// Note that we expect that we do not use consistent snapshots and delegations are
// not supported because for our purposes, both are unnecessary.
// See https://github.com/theupdateframework/tuf/blob/904fa9b8df8ab8c632a210a2b05fd741e366788a/docs/tuf-spec.txt
func (c *Client) Update() (files FimMap, latest bool, err error) {
	type resultUpdate struct {
		files  FimMap
		latest bool
		err    error
	}
	resultC := make(chan resultUpdate)
	c.jobs <- func(rm *repoMan) {

		latest, err := rm.refresh()
		if err != nil {
			resultC <- resultUpdate{nil, false, err}
			return
		}
		if rm.targets == nil {
			resultC <- resultUpdate{nil, false, errors.New("root target not present")}
			return
		}
		resultC <- resultUpdate{rm.targets.paths.clone(), latest, nil}

	}
	result := <-resultC
	return result.files, result.latest, result.err
}

// Download downloads a local resource from a remote URL.
// Download will use local TUF metadata, so it's important to call Update before dowloading a new file.
func (c *Client) Download(targetName string, destination io.Writer) error {
	resultC := make(chan error)
	c.jobs <- func(rm *repoMan) {

		resultC <- rm.downloadTarget(targetName, destination)

	}
	return <-resultC
}

type autoupdater struct {
	watchedTarget string
	stagingPath   string
	notifier      NotificationHandler
	currentFim    FileIntegrityMeta
}

func newAutoupdater(client *Client) *autoupdater {
	return &autoupdater{
		watchedTarget: client.watchedTarget,
		stagingPath:   client.stagingPath,
		notifier:      client.notificationHandler,
		currentFim: FileIntegrityMeta{
			Hashes: make(map[hashingMethod]string),
		},
	}
}

func (au *autoupdater) update(rm *repoMan) {
	_, err := rm.refresh()
	if err != nil {
		au.notifier("", errors.Wrap(err, "calling update"))
		return
	}
	if rm.targets == nil {
		au.notifier("", errors.New("expected root target missing in update"))
		return
	}
	if newFim, ok := rm.targets.paths[au.watchedTarget]; ok {
		if !newFim.Equal(au.currentFim) {
			if err := downloadAndNotify(rm, au.watchedTarget, au.stagingPath, au.notifier); err != nil {
				return
			}
			au.currentFim = newFim
		}
	}
}

// workerLoop is the only method that has a reference to the tuf repository manager. It will
// run as a seperate goroutine. Operations that interact with the tuf repository
// will be executed in the sequence that jobs are recieved.
func workerLoop(
	ticker <-chan time.Time,
	quit <-chan struct{},
	jobs <-chan func(*repoMan),
	wait *sync.WaitGroup,
	rm *repoMan,
	forceAutoUpdate <-chan struct{},
	autoupdate *autoupdater,
) {
	defer wait.Done()
	for {
		select {
		case job := <-jobs:
			job(rm)
		case <-ticker:
			if autoupdate != nil {
				autoupdate.update(rm)
			}
		case <-forceAutoUpdate:
			if autoupdate != nil {
				autoupdate.update(rm)
			}
		case <-quit:
			return
		}
	}
}

func downloadAndNotify(rm *repoMan, watchedTarget, stagingPath string, cb NotificationHandler) error {
	dpath := filepath.Join(stagingPath, watchedTarget)
	if err := os.MkdirAll(filepath.Dir(dpath), 0755); err != nil {
		cb("", err)
		return err
	}
	destination, err := os.Create(dpath)
	if err != nil {
		cb("", err)
		return err
	}
	if err := rm.downloadTarget(watchedTarget, destination); err != nil {
		destination.Close()
		os.Remove(dpath)
		cb("", err)
		return err
	}
	// the file descriptor must be closed in order to allow the
	// notificationHandler to work with the file in the staging path.
	destination.Close()
	cb(dpath, nil)
	return nil
}

// Stop must be called when done with the updater.
func (c *Client) Stop() {
	// cause all goroutines that have the quit channel to exit
	close(c.quit)
	// wait until they are all done
	c.wait.Wait()
}

func defaultHttpClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSHandshakeTimeout: 5 * time.Second,
		},
		Timeout: 5 * time.Second,
	}
}
