package tuf

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"testing"
	"time"

	"github.com/kolide/updater/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildRoleURL(t *testing.T) {
	baseURL, _ := url.Parse("https://notary.kolide.com")
	r := notaryRepo{
		gun: "kolide/agent/darwin",
		url: baseURL,
	}

	tt := []struct {
		valid    bool
		expected string
		testRole role
		errText  string
	}{
		{true, "https://notary.kolide.com/v2/kolide/agent/darwin/_trust/tuf/1.root.json", "1.root", ""},
		{true, "https://notary.kolide.com/v2/kolide/agent/darwin/_trust/tuf/root.json", "root", ""},
		{true, "https://notary.kolide.com/v2/kolide/agent/darwin/_trust/tuf/targets.json", "targets", ""},
		{true, "https://notary.kolide.com/v2/kolide/agent/darwin/_trust/tuf/snapshot.json", "snapshot", ""},
		{true, "https://notary.kolide.com/v2/kolide/agent/darwin/_trust/tuf/timestamp.json", "timestamp", ""},
		{false, "", "notarole", `"notarole" is not a valid role`},
		{false, "", "roots", `"roots" is not a valid role`},
		{false, "", "xtargets", `"xtargets" is not a valid role`},
		{false, "", "2.targets", `"2.targets" is not a valid role`},
	}

	for _, v := range tt {
		actual, err := r.buildRoleURL(v.testRole)
		if v.valid {
			assert.Nil(t, err)
			assert.Equal(t, v.expected, actual)
		} else {
			assert.NotNil(t, err)
			assert.EqualError(t, err, v.errText)
		}
	}
}

func TestGetRemoteRole(t *testing.T) {
	roles := []role{
		roleRoot,
		roleSnapshot,
		roleTargets,
		roleTimestamp,
		"none",
	}
	for _, roleVal := range roles {
		svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if roleVal == "none" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			buff, err := test.Asset(fmt.Sprintf("test/data/%s.json", roleVal))
			require.Nil(t, err)
			w.Write(buff)
		}))
		defer svr.Close()

		baseURL, _ := url.Parse(svr.URL)
		r := notaryRepo{
			gun:             "kolide/agent/darwin",
			url:             baseURL,
			maxResponseSize: defaultMaxResponseSize,
			client: &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
				},
			},
		}

		var intf interface{}
		switch roleVal {
		case roleRoot:
			intf = &Root{}
		case roleSnapshot:
			intf = &Snapshot{}
		case roleTargets:
			intf = &Targets{}
		case roleTimestamp:
			intf = &Timestamp{}
		case "none":
			intf = &Root{}
			err := r.getRole("root", intf)
			assert.Equal(t, errNotFound, err)
			return
		}
		err := r.getRole(roleVal, intf)
		assert.Nil(t, err)
	}
}

func TestTheReadSizeLimitsAreEnforced(t *testing.T) {
	svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buff, err := test.Asset("test/data/snapshot.json")
		require.Nil(t, err)
		w.Write(buff)
	}))
	defer svr.Close()

	baseURL, _ := url.Parse(svr.URL)
	r := notaryRepo{
		gun:             "kolide/agent/darwin",
		url:             baseURL,
		maxResponseSize: defaultMaxResponseSize,
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
	}
	// it should fail if the expected size is smaller than the remote response
	_, err := r.snapshot(withRoleExpectedLength(901))
	require.NotNil(t, err)
	assert.EqualError(t, err, "parsing json returned from server: unexpected EOF")
	// it should succeed if the expected size is the same as the actual size of
	// the remote response
	_, err = r.snapshot(withRoleExpectedLength(903))
	require.Nil(t, err)

}

func TestGetVersionRoot(t *testing.T) {
	svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Regexp(t, regexp.MustCompile(`1.root.json$`), r.RequestURI)
		buff, err := test.Asset("test/data/root.json")
		require.Nil(t, err)
		w.Write(buff)
	}))
	defer svr.Close()

	baseURL, _ := url.Parse(svr.URL)
	r := notaryRepo{
		gun:             "kolide/agent/darwin",
		url:             baseURL,
		maxResponseSize: defaultMaxResponseSize,
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
	}

	root, err := r.root(withRootVersion(1))
	require.Nil(t, err)
	require.NotNil(t, root)

	assert.Equal(t, "2027-06-10T13:25:45.170347322-05:00", root.Signed.Expires.Format(time.RFC3339Nano))
}

func TestGetRoot(t *testing.T) {
	svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		buff, err := test.Asset("test/data/root.json")
		require.Nil(t, err)
		w.Write(buff)
	}))
	defer svr.Close()

	baseURL, _ := url.Parse(svr.URL)
	r := notaryRepo{
		gun:             "kolide/agent/darwin",
		url:             baseURL,
		maxResponseSize: defaultMaxResponseSize,
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
	}

	root, err := r.root()
	require.Nil(t, err)
	require.NotNil(t, root)

	assert.Equal(t, "2027-06-10T13:25:45.170347322-05:00", root.Signed.Expires.Format(time.RFC3339Nano))
}

func TestGetTimestamp(t *testing.T) {
	svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buff, err := test.Asset("test/data/timestamp.json")
		require.Nil(t, err)
		w.Write(buff)
	}))
	defer svr.Close()

	baseURL, _ := url.Parse(svr.URL)
	r := notaryRepo{
		gun:             "kolide/agent/darwin",
		url:             baseURL,
		maxResponseSize: defaultMaxResponseSize,
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
	}

	timestamp, err := r.timestamp()
	require.Nil(t, err)
	require.NotNil(t, timestamp)

	assert.Equal(t, "2017-06-26T19:32:36.967988706Z", timestamp.Signed.Expires.Format(time.RFC3339Nano))
}

func TestGetSnapshot(t *testing.T) {
	svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buff, err := test.Asset("test/data/snapshot.json")
		require.Nil(t, err)
		w.Write(buff)
	}))
	defer svr.Close()

	baseURL, _ := url.Parse(svr.URL)
	r := notaryRepo{
		gun:             "kolide/agent/darwin",
		url:             baseURL,
		maxResponseSize: defaultMaxResponseSize,
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
	}

	snapshot, err := r.snapshot()
	require.Nil(t, err)
	require.NotNil(t, snapshot)

	assert.Equal(t, "2020-06-11T14:32:32.161365749-05:00", snapshot.Signed.Expires.Format(time.RFC3339Nano))
}

func Test404ErrorPassesThrough(t *testing.T) {
	svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer svr.Close()

	baseURL, _ := url.Parse(svr.URL)
	r := notaryRepo{
		gun:             "kolide/agent/darwin",
		url:             baseURL,
		maxResponseSize: defaultMaxResponseSize,
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
	}

	_, err := r.snapshot()
	require.NotNil(t, err)
	require.Equal(t, errNotFound, err)
}

func TestPingSuccess(t *testing.T) {
	svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Regexp(t, regexp.MustCompile(`/_notary_server/health$`), r.RequestURI)
	}))
	defer svr.Close()

	baseURL, _ := url.Parse(svr.URL)
	r := notaryRepo{
		gun:             "kolide/agent/darwin",
		url:             baseURL,
		maxResponseSize: defaultMaxResponseSize,
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
	}

	err := r.ping()
	assert.Nil(t, err)
}

func TestPingFail(t *testing.T) {
	svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer svr.Close()

	baseURL, _ := url.Parse(svr.URL)
	r := notaryRepo{
		gun:             "kolide/agent/darwin",
		url:             baseURL,
		maxResponseSize: defaultMaxResponseSize,
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
	}

	err := r.ping()
	assert.NotNil(t, err)
}
