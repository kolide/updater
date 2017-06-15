package tuf

// Settings various parameters needed to find updates
type Settings struct {
	// LocalRepoPath is the directory where we will cache TUF roles. This
	// directory should be seeded with TUF role files with 0600 permissions.
	LocalRepoPath string
	// RemoteRepoBaseURL is the base URL of the notary server where we get new
	// keys and update information.  i.e. https://notary.kolide.co. Must use
	// https scheme.
	RemoteRepoBaseURL string
	// MirrorURL is the base URL where distribution packages are found and
	// downloaded. Must use https scheme.
	MirrorURL string
	// StagingPath is where new distribution packages are stored after they
	// have been validated.
	StagingPath string
	// InsecureSkipVerify if true, the client accepts unsigned certificates.  This
	// option should only be used for testing.
	InsecureSkipVerify bool
	// GUN Globally Unique Identifier, an ID used by Notary to identify
	// a repository. Typically in the form organization/reponame/platform
	GUN string
}

// GetStagedPaths returns a list of paths to any validated update packages
// which are stored in staging.  If the returned array is empty the application
// is up to date.
func GetStagedPaths(settings *Settings) ([]string, error) {
	return nil, nil
}
