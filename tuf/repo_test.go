package tuf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsRoleCorrect(t *testing.T) {
	tt := []struct {
		match bool
		r     role
		cls   interface{}
		msg   string
	}{
		{true, roleRoot, Root{}, "matching root"},
		{true, roleRoot, &Root{}, "matching root pointer"},
		{true, roleSnapshot, Snapshot{}, "matching snapshot"},
		{true, roleSnapshot, &Snapshot{}, "matching snapshot pointer"},
		{true, roleTimestamp, Timestamp{}, "matching timestamp"},
		{true, roleTimestamp, &Timestamp{}, "matching timestamp pointer"},
		{true, roleTargets, Targets{}, "matching targets"},
		{true, roleTargets, &Targets{}, "matching targets pointer"},
		{false, roleRoot, Targets{}, "root role and target class"},
		{false, roleTargets, Root{}, "targets role and root class"},
		{false, roleTargets, &Snapshot{}, "targets role and snapshot pointer"},
		{false, role("garbage"), Root{}, "non exiting role and root class"},
		{false, roleRoot, "a string", "root role and non role class"},
	}

	for _, testCase := range tt {
		if testCase.match {
			assert.NotPanics(t, func() { isRoleCorrect(testCase.r, testCase.cls) }, testCase.msg)
		} else {
			assert.Panics(t, func() { isRoleCorrect(testCase.r, testCase.cls) }, testCase.msg)
		}
	}
}
