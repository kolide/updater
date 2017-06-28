package tuf

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

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
	watchedTarget       string
	stagingPath         string
	notificationHandler NotificationHandler
	quit                chan chan struct{}

	client          *http.Client
	maxResponseSize int64
}

const (
	defaultCheckFrequency  = 1 * time.Hour
	defaultMaxResponseSize = 5 * 1024 * 1024 // 5 Megabytes
)

type Option func(*Client)

// WithFrequency allows changing the frequency of update checks.
func WithFrequency(duration time.Duration) Option {
	return func(c *Client) {
		c.checkFrequency = duration
	}
}

func WithAutoUpdate(targetName, stagingPath string, onUpdate NotificationHandler) Option {
	return func(c *Client) {
		c.stagingPath = stagingPath
		c.watchedTarget = targetName
		c.notificationHandler = onUpdate
		c.notificationHandler = onUpdate
	}
}

func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *Client) {
		c.client = httpClient
	}
}

func NewClient(settings *Settings, opts ...Option) (*Client, error) {
	if err := settings.verify(); err != nil {
		return nil, err
	}

	client := Client{
		maxResponseSize: defaultMaxResponseSize,
		client:          defaultHttpClient(),
		checkFrequency:  defaultCheckFrequency,
		quit:            make(chan chan struct{}),
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
	client.manager = newRepoMan(localRepo, notary, settings, notary.client)
	if client.watchedTarget != "" {
		go client.monitorTarget()
	}
	return &client, nil
}

func (c *Client) Update() (files map[string]FileIntegrityMeta, latest bool, err error) {
	latest, err = c.manager.refresh()
	if err != nil {
		return nil, latest, errors.Wrap(err, "refreshing state")
	}

	if err := c.manager.save(getTag()); err != nil {
		return nil, latest, errors.Wrap(err, "unable to save tuf repo state")
	}

	files = c.manager.getLocalTargets()
	return files, latest, nil
}

func (c *Client) Download(targetName string, destination io.Writer) error {
	files := c.manager.getLocalTargets()
	fim, ok := files[targetName]
	if !ok {
		return errNoSuchTarget
	}
	if err := c.manager.downloadTarget(targetName, &fim, destination); err != nil {
		return errors.Wrap(err, "downloading target")
	}
	return nil
}

func (c *Client) monitorTarget() {
	var hash string
	ticker := time.NewTicker(c.checkFrequency).C
	for {
		files, _, err := c.Update()
		if err != nil {
			c.notificationHandler("", err)
		}
		target, ok := files[c.watchedTarget]
		if !ok {
			c.notificationHandler("", errors.New("no such target"))
		}
		metaHash := func() string {
			if h, ok := target.Hashes["sha256"]; ok {
				return h
			} else if h, ok := target.Hashes["sha512"]; ok {
				return h
			} else {
				return ""
			}
		}
		h := metaHash()
		c.downloadIfNew(hash, h)
		hash = h

		select {
		case <-ticker:
		case quit := <-c.quit:
			close(quit)
			return
		}
	}
}

func (c *Client) downloadIfNew(old, new string) {
	if old == "" || old == new {
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
	defer destination.Close()
	if err := c.Download(c.watchedTarget, destination); err != nil {
		destination.Close()
		os.Remove(dpath)
		return
	} else {
		c.notificationHandler(dpath, nil)
		return
	}
}

// NotificationHandler gets called when the hosting application has a new version
// of a target that it needs to deal with.  The hosting application will need to
// check the err object, if err is nil the stagingPath will point to a validated
// target which is the hosting application's responsibility to deal with.
type NotificationHandler func(stagingPath string, err error)

func (c *Client) Stop() {
	c.manager.Stop()

	// stop autoupdate loop
	if c.watchedTarget != "" {
		quit := make(chan struct{})
		c.quit <- quit
		<-quit
	}
}

func defaultHttpClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSHandshakeTimeout: 5 * time.Second,
		},
		Timeout: 5 * time.Second,
	}
}
