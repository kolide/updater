package tuf

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/WatchBeam/clock"
	"github.com/pkg/errors"
)

// Client is a TUF client.
type Client struct {
	// Client wraps the private repoMan type which contains the actual
	// methods for working with TUF repositories. In the future it might
	// be worthwile to export the repoMan type as Client instead, but
	// wrapping it reduces the amount of present refactoring work.
	manager *repoMan
	// values to autoupdate
	checkFrequency      time.Duration
	backupFileAge       time.Duration
	watchedTarget       string
	stagingPath         string
	notificationHandler NotificationHandler
	quit                chan chan struct{}
	clock               clock.Clock
	client              *http.Client
	maxResponseSize     int64
}

const (
	defaultCheckFrequency  = 1 * time.Hour
	defaultBackupAge       = 24 * time.Hour
	defaultMaxResponseSize = 5 * 1024 * 1024 // 5 Megabytes
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
		quit:            make(chan chan struct{}),
		clock:           &clock.DefaultClock{},
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
	client.manager = newRepoMan(localRepo, notary, settings, notary.client, client.backupFileAge, client.clock)
	if client.watchedTarget != "" {
		go client.monitorTarget()
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
	latest, err = c.manager.refresh()
	if err != nil {
		return nil, false, errors.Wrap(err, "refreshing state")
	}
	files = c.manager.getLocalTargets()
	return files, latest, nil
}

// Download downloads a local resource from a remote URL.
// Download will use local TUF metadata, so it's important to call Update before dowloading a new file.
func (c *Client) Download(targetName string, destination io.Writer) error {
	if err := c.manager.downloadTarget(targetName, destination); err != nil {
		return errors.Wrap(err, "downloading target")
	}
	return nil
}

// Note that the returned fim is always non-null.  In case of error an 'empty'
// fim will be returned that will never be equal to a fim that refers to a real file.
func (c *Client) getCurrentFileInfo(watched string) (*FileIntegrityMeta, error) {
	emptyFim := newFileItegrityMeta()
	// get current file state from local repository
	var local localRepo
	currentTargets, err := local.targets(&localTargetFetcher{c.manager.settings.LocalRepoPath})
	if err != nil {
		return emptyFim, errors.Wrap(err, "getting local targets")
	}
	fim, ok := currentTargets.paths[watched]
	if !ok {
		return emptyFim, errors.Errorf("no such target %q", watched)
	}
	return &fim, nil
}

func (c *Client) monitorTarget() {
	var err error
	old := newFileItegrityMeta()
	ticker := c.clock.NewTicker(c.checkFrequency).Chan()
	for {
		// Get the state of our current files from the local repo
		if old.Length == 0 {
			old, err = c.getCurrentFileInfo(c.watchedTarget)
			if err != nil {
				c.notificationHandler("", err)
			}
		}
		files, _, err := c.Update()
		if err != nil {
			c.notificationHandler("", err)
		}
		current, ok := files[c.watchedTarget]
		if ok {
			c.downloadIfNew(old, &current)
			old = &current
		} else {
			c.notificationHandler("", errors.Errorf("no such target %q", c.watchedTarget))
		}
		select {
		case <-ticker:
		case quit := <-c.quit:
			close(quit)
			return
		}
	}
}

func (c *Client) downloadIfNew(old, current *FileIntegrityMeta) {
	if old.Equal(*current) {
		return
	}
	dpath := filepath.Join(c.stagingPath, c.watchedTarget)
	if err := os.MkdirAll(filepath.Dir(dpath), 0755); err != nil {
		c.notificationHandler("", err)
		return
	}
	destination, err := os.Create(dpath)
	if err != nil {
		c.notificationHandler("", err)
		return
	}
	if err := c.Download(c.watchedTarget, destination); err != nil {
		destination.Close()
		os.Remove(dpath)
		c.notificationHandler("", err)
	} else {
		// the file descriptor must be closed in order to allow the
		// notificationHandler to work with the file in the staging path.
		destination.Close()
		c.notificationHandler(dpath, nil)
	}
}

func (c *Client) Stop() {
	// stop autoupdate loop
	if c.watchedTarget != "" {
		quit := make(chan struct{})
		c.quit <- quit
		<-quit
	}
	c.manager.Stop()
}

func defaultHttpClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSHandshakeTimeout: 5 * time.Second,
		},
		Timeout: 5 * time.Second,
	}
}
