package updater

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"os"
	"path"
	"strings"

	"github.com/pkg/errors"
)

// Updater exposes methods for this package
type Updater struct {
	statusFile *os.File
	settings   *UpdateSettings
}

type certReader interface {
	readPem() ([]byte, error)
}

type tlsConfigurer interface {
	tlsConfig(certPool *x509.CertPool) *tls.Config
}

type readerConfigurer interface {
	certReader
	tlsConfigurer
}

// UpdateSettings settings that define remote repository
type UpdateSettings struct {
	// BaseURL is the url of the notary server
	BaseURL string `json:"base_url"`
	// RepositoryID is the Globally Unique Name (GUN) for this repo. The GUN
	// should be of the form <root>/<project>/<platform>
	RepositoryID string `json:"repository_id"`
	// BaseDir is the location for the local cached repository.  The process must
	// have read and write permissions to this location.
	BaseDir string `json:"base_dir"`
	// PackageURL is the base url where distribution package is stored
	PackageURL string `json:"package_url"`
	// RootCAFile path to certificate to verify the TLS cert of the server relative
	// to BaseDir
	RootCAFile string `json:"root_ca_path"`
	// InsecureSkipVerify if true, TLS accepts any certificate
	// presented by the server and any host name in that certificate
	InsecureSkipVerify bool `json:"insecure_skip_verify"`
}

func (u *UpdateSettings) readPem() ([]byte, error) {
	certPath := path.Join(u.BaseDir, u.RootCAFile)
	return ioutil.ReadFile(certPath)
}

func (u *UpdateSettings) tlsConfig(certPool *x509.CertPool) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: u.InsecureSkipVerify,
		RootCAs:            certPool,
	}
}

// NewUpdater creates an Updater with UpdateSettings
func NewUpdater(settings *UpdateSettings) (*Updater, error) {
	updater := Updater{
		settings: settings,
	}
	repoPath := path.Join(settings.BaseDir, osPath(settings.RepositoryID))
	err := updater.maybeCreateDir(repoPath)
	if err != nil {
		return nil, errors.Wrap(err, "creating new updater")
	}
	return &updater, nil
}

// Close frees up Updater resources
func (u *Updater) Close() error {
	if u.statusFile != nil {
		return u.statusFile.Close()
	}
	return nil
}

// Update will check to see if updates are available then install them
func (u *Updater) Update() error {
	transport, err := getTransport(u.settings)
	if err != nil {
		return errors.Wrap(err, "getting transport in update")
	}
	err = pingNotary(transport, u.settings.BaseURL)
	if err != nil {
		return errors.Wrap(err, "unable to ping notary server")
	}
	return nil
}

func (u *Updater) maybeCreateDir(dir string) error {
	status, err := os.Stat(dir)
	if os.IsNotExist(err) {
		// Create directory, the base directory is for the local notary repo,
		// the full directory is for project specific files.
		err = os.MkdirAll(dir, 0755)
		if err != nil {
			return errors.Wrap(err, "creating repository directory")
		}
	}
	if status != nil && !status.IsDir() {
		return errors.Errorf("%s is not a directory", dir)
	}
	// Create status file to keep track of updates
	statusFile := path.Join(dir, "status")
	u.statusFile, err = os.OpenFile(statusFile, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return errors.Wrap(err, "creating status file")
	}
	return nil
}

func osPath(dir string) string {
	parts := strings.Split(dir, "/")
	return path.Join(parts...)
}

// func getTransport(repoID string) (http.RoundTripper, error) {
//
// }
