package tuf

// Settings various parameters needed to find updates
type Settings struct {
	// LocalRepoPath is the directory where we will cache TUF roles. This
	// directory should be seeded with TUF role files with 0600 permissions.
	LocalRepoPath string
	// RemoteRepoBaseURL is the base URL of the notary server where we get new
	// keys and update information.  i.e. https://notary.kolide.co
	RemoteRepoBaseURL string
	// MirrorURL is the base URL where distribution packages are found and
	// downloaded.
	MirrorURL string
	// StagingPath is where new distribution packages are stored after they
	// have been validated.
	StagingPath string
}

// GetStagedPaths returns a list of paths to any validated update packages
// which are stored in staging.  If the returned array is empty the application
// is up to data.
func GetStagedPaths(settings *Settings) ([]string, error) {
	return nil, nil
}
