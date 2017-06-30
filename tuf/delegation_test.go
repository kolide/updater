package tuf

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"

	"github.com/kolide/updater/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockLocalRepoReader struct {
	rootDir string
}

func (lr *mockLocalRepoReader) fetch(role string) (*Targets, error) {
	buff, err := test.Asset(lr.rootDir + role + ".json")
	if err != nil {
		return nil, err
	}
	var targ Targets
	err = json.NewDecoder(bytes.NewBuffer(buff)).Decode(&targ)
	if err != nil {
		return nil, err
	}
	return &targ, err
}

func TestMockReader(t *testing.T) {
	rdr := mockLocalRepoReader{"test/delegation/0/"}
	targ, err := rdr.fetch("targets")
	require.Nil(t, err)
	require.NotNil(t, targ)
	targ, err = rdr.fetch("targets/bar")
	require.Nil(t, err)
	require.NotNil(t, targ)
	targ, err = rdr.fetch("targets/role/foo")
	require.Nil(t, err)
	require.NotNil(t, targ)

}

func TestPopulateLocalTargetsWithChildren(t *testing.T) {
	rdr := mockLocalRepoReader{"test/delegation/0/"}
	root, err := getTargetTree(&rdr)
	require.Nil(t, err)
	require.NotNil(t, root)
	assert.Len(t, root.targetPrecedence, 4)
	tt := []struct {
		role               string
		expectedPrecedence int
	}{
		{"targets", 0},
		{"targets/role", 1},
		{"targets/role/foo", 2},
		{"targets/bar", 3},
	}
	for _, tc := range tt {
		targ, ok := root.targetLookup[tc.role]
		require.True(t, ok)
		assert.Equal(t, targ, root.targetPrecedence[tc.expectedPrecedence])
	}
}

func setupValidationTest(testRoot string) (*Root, *Snapshot, *RootTarget, error) {
	rdr := mockLocalRepoReader{testRoot + "/"}
	rootTarget, err := getTargetTree(&rdr)
	if err != nil {
		return nil, nil, nil, err
	}
	var ss Snapshot
	buff, err := test.Asset(path.Join(testRoot, string(roleSnapshot)+".json"))
	if err != nil {
		return nil, nil, nil, err
	}
	err = json.NewDecoder(bytes.NewBuffer(buff)).Decode(&ss)
	if err != nil {
		return nil, nil, nil, err
	}
	var root Root
	buff, err = test.Asset(path.Join(testRoot, string(roleRoot)+".json"))
	if err != nil {
		return nil, nil, nil, err
	}
	err = json.NewDecoder(bytes.NewBuffer(buff)).Decode(&root)
	if err != nil {
		return nil, nil, nil, err
	}
	return &root, &ss, rootTarget, nil
}

func TestTargetReadWithValidations(t *testing.T) {
	testRootPath := "test/delegation/0"
	svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testDataPath := strings.Replace(strings.Replace(r.RequestURI, "/v2/", "", 1), "/_trust/tuf", "", 1)
		buff, err := test.Asset(testDataPath)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Write(buff)
	}))
	defer svr.Close()
	rootRole, snapshotRole, rootTarget, err := setupValidationTest(testRootPath)
	require.Nil(t, err)
	require.NotNil(t, rootTarget)
	require.NotNil(t, snapshotRole)
	require.NotNil(t, rootRole)

	rrs := notaryTargetFetcherSettings{
		gun: testRootPath,
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
		url:             svr.URL,
		maxResponseSize: defaultMaxResponseSize,
		rootRole:        rootRole,
		snapshotRole:    snapshotRole,
		localRootTarget: rootTarget,
	}
	rtr, err := newNotaryTargetFetcher(&rrs)
	require.Nil(t, err)
	require.NotNil(t, rtr)
	var notary notaryRepo
	remoteRootTarget, err := notary.targets(rtr)
	require.Nil(t, err)
	require.NotNil(t, remoteRootTarget)
}
