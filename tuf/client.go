package tuf

import (
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"

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
	latest, err = c.manager.refresSafe()
	if err != nil {
		return nil, latest, errors.Wrap(err, "refreshing state")
	}

	if err := c.manager.save(getTag()); err != nil {
		return nil, latest, errors.Wrap(err, "unable to save tuf repo state")
	}

	ff := make(chan map[targetNameType]FileIntegrityMeta)
	c.manager.actionc <- func() {
		ff <- c.manager.targets.Signed.Targets
	}

	return <-ff, latest, nil
}

func (c *Client) Download(targetName string, destination io.Writer) error {
	files, _, err := c.Update()
	if err != nil {
		return errors.Wrap(err, "refreshing repo state")
	}
	currentMeta, ok := files[targetNameType(targetName)]
	if !ok {
		return errors.Errorf("targetName %s not found", targetName)
	}
	mirrorURL, err := url.Parse(c.manager.settings.MirrorURL)
	if err != nil {
		return errors.Wrap(err, "parse mirror url for download")
	}

	mirrorURL.Path = path.Join(mirrorURL.Path, c.manager.settings.GUN, targetName)
	request, err := http.NewRequest(http.MethodGet, mirrorURL.String(), nil)
	if err != nil {
		return errors.Wrapf(err, "creating request to %s", mirrorURL.String())
	}
	request.Header.Add(cacheControl, cachePolicyNoStore)

	resp, err := c.manager.client.Do(request)
	if err != nil {
		return errors.Wrap(err, "fetching target from mirror")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("get target returned %q", resp.Status)
	}

	size, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 0)
	if err != nil {
		return errors.Wrap(err, "getting file size from Content-Length header")
	}

	stream := io.LimitReader(resp.Body, size)
	if err := currentMeta.verifyIO(stream, size); err != nil {
		return err
	}

	return nil
}

func (c *Client) Stop() {
	c.manager.Stop()
}
