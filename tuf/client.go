package tuf

import (
	"io"

	"github.com/pkg/errors"
)

// Client is a TUF client.
type Client struct {
	// Client wraps the private repoMan type which contains the actual
	// methods for working with TUF repositories. In the future it might
	// be worthwile to export the repoMan type as Client instead, but
	// wrapping it reduces the amount of present refactoring work.
	manager *repoMan
}

func NewClient(settings *Settings) (*Client, error) {
	if settings.MaxResponseSize == 0 {
		settings.MaxResponseSize = defaultMaxResponseSize
	}
	// check to see if Notary server is available
	notary, err := newNotaryRepo(settings)
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
	// store intermediate state until all validation succeeds, then write
	// changed roles to non-volitile storage
	manager := newRepoMan(localRepo, notary, settings, notary.client)
	return &Client{manager: manager}, nil
}

func (c *Client) Update() (files map[targetNameType]FileIntegrityMeta, latest bool, err error) {
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
	target := targetNameType(targetName)
	fim, ok := files[target]
	if !ok {
		return errNoSuchTarget
	}
	if err := c.manager.downloadTarget(target, &fim, destination); err != nil {
		return errors.Wrap(err, "downloading target")
	}
	return nil
}

func (c *Client) Stop() {
	c.manager.Stop()
}
