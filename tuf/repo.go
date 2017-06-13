package tuf

type repo interface {
	root(opts ...func() interface{}) (*Root, error)
	snapshot() (*Snapshot, error)
	targets() (*Targets, error)
	timestamp() (*Timestamp, error)
}

type persistantRepo interface {
	repo
	save() error
}

type localRepo struct {
}

type remoteRepo struct {
}

func newLocalRepo(repoPath string) *localRepo {
	return nil
}

func newRemoteRepo(baseURL string) *remoteRepo {
	return nil
}
