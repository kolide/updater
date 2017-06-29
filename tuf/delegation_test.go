package tuf

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/kolide/updater/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockLocalRepoReader struct {
	rootDir string
}

func (lr *mockLocalRepoReader) read(role string) (*Targets, error) {
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
	targ, err := rdr.read("targets")
	require.Nil(t, err)
	require.NotNil(t, targ)
	targ, err = rdr.read("targets/bar")
	require.Nil(t, err)
	require.NotNil(t, targ)
	targ, err = rdr.read("targets/role/foo")
	require.Nil(t, err)
	require.NotNil(t, targ)

}

func TestPopulateLocalTargetsWithChildren(t *testing.T) {
	rdr := mockLocalRepoReader{"test/delegation/0/"}
	root, err := getTargetRole(&rdr)
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
