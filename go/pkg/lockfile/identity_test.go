package lockfile

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeHostname(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{name: "dotcom", in: "github.com", want: "github.com", ok: true},
		{name: "ghe tenant", in: "octocorp.ghe.com", want: "octocorp.ghe.com", ok: true},
		{name: "uppercase dotcom folds", in: "GITHUB.COM", want: "github.com", ok: true},
		{name: "mixed case folds", in: "GitHub.COM", want: "github.com", ok: true},
		{name: "uppercase tenant folds", in: "OctoCorp.GHE.COM", want: "octocorp.ghe.com", ok: true},
		{name: "trailing root dot stripped", in: "github.com.", want: "github.com", ok: true},
		{name: "case and trailing dot together", in: "GitHub.com.", want: "github.com", ok: true},
		{name: "tenant trailing root dot", in: "octocorp.ghe.com.", want: "octocorp.ghe.com", ok: true},
		{name: "surrounding whitespace trimmed", in: "  github.com  ", want: "github.com", ok: true},
		{name: "empty fails closed", in: "", ok: false},
		{name: "whitespace only fails closed", in: "   ", ok: false},
		{name: "unknown host fails closed", in: "example.com", ok: false},
		{name: "scheme rejected", in: "https://github.com", ok: false},
		{name: "port rejected", in: "github.com:443", ok: false},
		{name: "path rejected", in: "github.com/path", ok: false},
		{name: "query rejected", in: "github.com?tenant=x", ok: false},
		{name: "fragment rejected", in: "github.com#frag", ok: false},
		{name: "nested ghe label rejected", in: "api.octocorp.ghe.com", ok: false},
		{name: "illegal leading hyphen rejected", in: "-octo.ghe.com", ok: false},
		{name: "illegal trailing hyphen rejected", in: "octo-.ghe.com", ok: false},
		{name: "double trailing dot fails", in: "github.com..", ok: false},
		{name: "internal dot label rejected", in: "github..com", ok: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := NormalizeHostname(tc.in)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.ok, IsKnownHostname(tc.in))
			if tc.ok {
				assert.Equal(t, tc.want, CanonicalHostname(tc.in))
			} else {
				assert.Empty(t, CanonicalHostname(tc.in))
			}
		})
	}
}

func TestParseActionIdentity_UnifiedKey(t *testing.T) {
	// The same logical action reached via host casing, a trailing DNS dot,
	// and owner/repo casing must yield one identical identity key.
	variants := []string{
		"actions/cache/save@v4",
		"Actions/Cache/save@v4",
	}
	hosts := []string{"github.com", "GITHUB.COM", "github.com."}

	wantKey := "github.com/actions/cache/save@v4"
	for _, uses := range variants {
		for _, host := range hosts {
			id, ok := ParseActionIdentity(host, uses)
			require.True(t, ok, "host=%q uses=%q", host, uses)
			assert.Equal(t, "github.com", id.Host)
			assert.Equal(t, "actions", id.Owner)
			assert.Equal(t, "cache", id.Repo)
			assert.Equal(t, "save", id.Path, "sub-action path casing is preserved verbatim")
			assert.Equal(t, "v4", id.Ref)
			assert.Equal(t, wantKey, id.Key())
			assert.Equal(t, "actions/cache@v4", id.PinKey())
			assert.Equal(t, "actions/cache", id.NWO())
		}
	}

	// A differently-cased sub-action path is a distinct in-repo path string:
	// the path keeps its source casing while everything else canonicalizes.
	upper, ok := ParseActionIdentity("github.com", "actions/cache/Save@v4")
	require.True(t, ok)
	assert.Equal(t, "Save", upper.Path)
	assert.NotEqual(t, wantKey, upper.Key())
	assert.Equal(t, "github.com/actions/cache/Save@v4", upper.Key())
}

func TestParseActionIdentity_RootActionHasNoPathSegment(t *testing.T) {
	id, ok := ParseActionIdentity("GitHub.COM.", "actions/checkout@v4")
	require.True(t, ok)
	assert.Equal(t, "github.com/actions/checkout@v4", id.Key())
	assert.Empty(t, id.Path)
}

func TestParseActionIdentity_UnknownHostFailsClosed(t *testing.T) {
	for _, host := range []string{"", "example.com", "https://github.com", "github.com:443"} {
		_, ok := ParseActionIdentity(host, "actions/checkout@v4")
		assert.False(t, ok, "host=%q", host)
	}
}

func TestParseActionIdentity_AmbiguousPathFailsClosed(t *testing.T) {
	uses := []string{
		"actions/checkout.@v4",
		"actions./checkout@v4",
		"actions/repo./sub@v4",
		"actions/repo/sub.@v4",
		"actions/repo/sub./deep@v4",
	}
	for _, u := range uses {
		_, ok := ParseActionIdentity("github.com", u)
		assert.False(t, ok, "uses=%q", u)
	}
}

func TestActionRefIdentity(t *testing.T) {
	ref := ParseActionRef("actions/cache/save@v4")
	require.NotNil(t, ref)

	id, ok := ref.Identity("OctoCorp.GHE.COM.")
	require.True(t, ok)
	assert.Equal(t, "octocorp.ghe.com", id.Host)
	assert.Equal(t, "octocorp.ghe.com/actions/cache/save@v4", id.Key())

	_, ok = ref.Identity("evil.example.com")
	assert.False(t, ok)

	_, ok = ActionRef{}.Identity("github.com")
	assert.False(t, ok)
}

func TestParseWorkflowIdentity_UnifiedKey(t *testing.T) {
	id, ok := ParseWorkflowIdentity("GITHUB.COM.", "Octo/Repo/.github/workflows/CI.yml@release@2024")
	require.True(t, ok)
	assert.Equal(t, "github.com", id.Host)
	assert.Equal(t, "octo", id.Owner)
	assert.Equal(t, "repo", id.Repo)
	assert.Equal(t, ".github/workflows/CI.yml", id.Path)
	assert.Equal(t, "release@2024", id.Ref)
	assert.Equal(t, "github.com/octo/repo/.github/workflows/CI.yml@release@2024", id.Key())

	// A non-workflow uses: string cannot become a workflow identity.
	_, ok = ParseWorkflowIdentity("github.com", "actions/checkout@v4")
	assert.False(t, ok)
	// Unknown host fails closed.
	_, ok = ParseWorkflowIdentity("example.com", "octo/repo/.github/workflows/ci.yml@v1")
	assert.False(t, ok)
}

func TestReusableWorkflowRefIdentity(t *testing.T) {
	ref := ParseReusableWorkflowRef("octo/repo/.github/workflows/ci.yml@v1")
	require.NotNil(t, ref)
	id, ok := ref.Identity("github.com")
	require.True(t, ok)
	assert.Equal(t, "github.com/octo/repo/.github/workflows/ci.yml@v1", id.Key())

	_, ok = ReusableWorkflowRef{}.Identity("github.com")
	assert.False(t, ok)
}

func TestPinIdentity(t *testing.T) {
	pin, ok := ParsePin("Actions/Checkout@v4")
	require.True(t, ok)

	id, ok := pin.Identity("GitHub.COM.")
	require.True(t, ok)
	assert.Equal(t, "github.com", id.Host)
	assert.Equal(t, "actions/checkout@v4", id.PinKey())
	assert.Equal(t, "github.com/actions/checkout@v4", id.Key())

	_, ok = pin.Identity("evil.example.com")
	assert.False(t, ok)

	_, ok = Pin{}.Identity("github.com")
	assert.False(t, ok)
}

func TestIdentityKeys_DistinctOriginsAndPathsNeverCollide(t *testing.T) {
	dotcom, ok := ParseActionIdentity("github.com", "actions/cache/save@v4")
	require.True(t, ok)
	tenant, ok := ParseActionIdentity("octocorp.ghe.com", "actions/cache/save@v4")
	require.True(t, ok)
	root, ok := ParseActionIdentity("github.com", "actions/cache@v4")
	require.True(t, ok)

	// Repo-granularity pin keys can coincide across hosts; the full identity
	// keys cannot, so audit comparisons never merge distinct origins.
	assert.Equal(t, dotcom.PinKey(), tenant.PinKey())
	assert.NotEqual(t, dotcom.Key(), tenant.Key())
	assert.NotEqual(t, dotcom.Key(), root.Key())
	assert.Equal(t, dotcom.PinKey(), root.PinKey())
}

func TestZeroIdentity(t *testing.T) {
	assert.Empty(t, Identity{}.NWO())
	assert.Equal(t, "@", Identity{}.PinKey())
	assert.Equal(t, "//@", Identity{}.Key())
}

func TestParsePin_TrailingDotRejected(t *testing.T) {
	for _, entry := range []string{
		"actions/checkout.@v4",
		"actions./checkout@v4",
		"Actions./Checkout.@v4",
	} {
		_, ok := ParsePin(entry)
		assert.False(t, ok, "pin=%q", entry)
	}
}

func TestParseActionRef_TrailingDotRejected(t *testing.T) {
	for _, uses := range []string{
		"actions/checkout.@v4",
		"actions./checkout@v4",
		"owner/repo/dir.@v1",
		"owner/repo/dir./x@v1",
	} {
		assert.Nil(t, ParseActionRef(uses), "uses=%q", uses)
		assert.Nil(t, ParseReusableWorkflowRef(uses), "uses=%q", uses)
	}
}

func TestFilePinIdentity_V003ExplicitHostname(t *testing.T) {
	input := []byte(`version: v0.0.3
dependencies:
  Actions/Checkout@v4:
    hostname: octocorp.ghe.com
    ref: v4
    commit: sha1-34e114876b0b11c390a56381ad16ebd13914f8d5
    owner_id: 1
    repo_id: 2
`)
	f, err := Parse(input)
	require.NoError(t, err)

	// Lookups work through either casing; the identity folds host and NWO
	// casing into a single key.
	for _, key := range []string{"Actions/Checkout@v4", "actions/checkout@v4"} {
		id, ok := f.PinIdentity(key, "github.com")
		require.True(t, ok, "key=%q", key)
		assert.Equal(t, "octocorp.ghe.com", id.Host)
		assert.Equal(t, "octocorp.ghe.com/actions/checkout@v4", id.Key())
		assert.Equal(t, "actions/checkout@v4", id.PinKey())
	}
}

func TestFilePinIdentity_OmittedHostnameUsesHomeHost(t *testing.T) {
	input := []byte(`version: v0.0.3
dependencies:
  actions/checkout@v4:
    ref: v4
    commit: sha1-34e114876b0b11c390a56381ad16ebd13914f8d5
    owner_id: 1
    repo_id: 2
`)
	f, err := Parse(input)
	require.NoError(t, err)

	id, ok := f.PinIdentity("actions/checkout@v4", "octocorp.ghe.com")
	require.True(t, ok)
	assert.Equal(t, "octocorp.ghe.com", id.Host)

	// No home host supplied: fail closed instead of inventing an origin.
	_, ok = f.PinIdentity("actions/checkout@v4", "")
	assert.False(t, ok)

	// An unknown home host fails closed too.
	_, ok = f.PinIdentity("actions/checkout@v4", "evil.example.com")
	assert.False(t, ok)

	// Missing dependency and unparseable pin both fail.
	_, ok = f.PinIdentity("actions/missing@v4", "github.com")
	assert.False(t, ok)
	_, ok = f.PinIdentity("not-a-pin", "github.com")
	assert.False(t, ok)
}

func TestFilePinIdentity_LegacyDotcomMigration(t *testing.T) {
	// v0.0.1 and v0.0.2 files had no hostname field; every pin is a
	// github.com pin and must resolve to a github.com identity after
	// migration, including when the caller has no home host of its own.
	v002 := []byte(`version: v0.0.2
dependencies:
  actions/checkout@v4:
    ref: v4
    commit: sha1-34e114876b0b11c390a56381ad16ebd13914f8d5
    owner_id: 1
    repo_id: 2
`)
	f, err := Parse(v002)
	require.NoError(t, err)
	id, ok := f.PinIdentity("actions/checkout@v4", "")
	require.True(t, ok)
	assert.Equal(t, "github.com", id.Host)
	assert.Equal(t, "github.com/actions/checkout@v4", id.Key())

	v001 := []byte(`version: v0.0.1
dependencies:
  actions/checkout@v4:sha1-34e114876b0b11c390a56381ad16ebd13914f8d5:
    tag: v4
    commit: sha1-34e114876b0b11c390a56381ad16ebd13914f8d5
    owner_id: 1
    repo_id: 2
`)
	f1, err := Parse(v001)
	require.NoError(t, err)
	id1, ok := f1.PinIdentity("actions/checkout@v4", "")
	require.True(t, ok)
	assert.Equal(t, "github.com", id1.Host)
}

func TestFilePinIdentity_TwoHostsStayDistinct(t *testing.T) {
	// Two lockfile entries that share a repo-granularity pin key spelling but
	// carry different hostnames must not be merged by an audit comparison:
	// the identity keys differ.
	dotcom, err := Parse([]byte(`version: v0.0.3
dependencies:
  actions/checkout@v4:
    hostname: github.com
    ref: v4
    commit: sha1-34e114876b0b11c390a56381ad16ebd13914f8d5
    owner_id: 1
    repo_id: 2
`))
	require.NoError(t, err)
	tenant, err := Parse([]byte(`version: v0.0.3
dependencies:
  actions/checkout@v4:
    hostname: octocorp.ghe.com
    ref: v4
    commit: sha1-34e114876b0b11c390a56381ad16ebd13914f8d5
    owner_id: 1
    repo_id: 2
`))
	require.NoError(t, err)

	a, ok := dotcom.PinIdentity("actions/checkout@v4", "")
	require.True(t, ok)
	b, ok := tenant.PinIdentity("actions/checkout@v4", "")
	require.True(t, ok)
	assert.Equal(t, a.PinKey(), b.PinKey())
	assert.NotEqual(t, a.Key(), b.Key())
}

func TestParse_LockfileTrailingDotPinRejected(t *testing.T) {
	for _, version := range []string{"v0.0.2", "v0.0.3"} {
		input := []byte(`version: ` + version + `
dependencies:
  actions/checkout.@v4:
    ref: v4
    commit: sha1-34e114876b0b11c390a56381ad16ebd13914f8d5
    owner_id: 1
    repo_id: 2
`)
		_, err := Parse(input)
		require.Error(t, err, version)
	}
}
