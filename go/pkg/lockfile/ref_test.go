package lockfile

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSplitRef(t *testing.T) {
	cases := []struct {
		ref    string
		tag    string
		branch string
	}{
		{"", "", ""},
		{"v4.3.1", "v4.3.1", ""},
		{"v1.0.0", "v1.0.0", ""},
		{"1.2.3", "1.2.3", ""},
		{"v4", "v4", ""},                       // major-only is still stable semver
		{"v4.2", "v4.2", ""},                   // major.minor is still stable semver
		{"v1.0.0-beta.1", "", "v1.0.0-beta.1"}, // pre-release → branch
		{"main", "", "main"},
		{"trunk", "", "trunk"},
		{"release/v4", "", "release/v4"},
		{"my-feature", "", "my-feature"},
	}
	for _, tc := range cases {
		t.Run(tc.ref, func(t *testing.T) {
			tag, branch := SplitRef(tc.ref)
			assert.Equal(t, tc.tag, tag, "tag")
			assert.Equal(t, tc.branch, branch, "branch")
		})
	}
}

func TestBestRef(t *testing.T) {
	cases := []struct {
		tag    string
		branch string
		want   string
	}{
		{"v4.3.1", "main", "v4.3.1"},
		{"v4", "main", "v4"},
		{"", "main", "main"},
		{"", "", ""},
		{"v1.0.0", "", "v1.0.0"},
	}
	for _, tc := range cases {
		t.Run(tc.tag+"/"+tc.branch, func(t *testing.T) {
			assert.Equal(t, tc.want, BestRef(tc.tag, tc.branch))
		})
	}
}

func TestRefKind_String(t *testing.T) {
	assert.Equal(t, "invalid", RefKindInvalid.String())
	assert.Equal(t, "commit", RefKindCommit.String())
	assert.Equal(t, "tag", RefKindTag.String())
	assert.Equal(t, "branch", RefKindBranch.String())
}

func TestNormalizeRef(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
		ok   bool
	}{
		{"tag unchanged", "v4.3.1", "v4.3.1", true},
		{"branch unchanged", "main", "main", true},
		{"slash branch unchanged", "release/v4", "release/v4", true},
		{"tag case preserved", "V4.3.1", "V4.3.1", true},
		{"percent-decoded slash", "release%2Fv4", "release/v4", true},
		{"percent-decoded at", "feature%40x", "feature@x", true},
		{"uppercase sha1 lowercased", "11BD71901BBE5B1630CEEA73D27597364C9AF683", "11bd71901bbe5b1630ceea73d27597364c9af683", true},
		{"mixed-case sha256 lowercased", "A1B2C3D4A1B2C3D4A1B2C3D4A1B2C3D4A1B2C3D4A1B2C3D4A1B2C3D4A1B2C3D4", "a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4", true},
		{"empty rejected", "", "", false},
		{"colon rejected", "v4:foo", "", false},
		{"bare percent rejected", "100%", "", false},
		{"truncated escape rejected", "v4%2", "", false},
		{"invalid escape rejected", "v4%zz", "", false},
		{"encoded colon rejected", "v4%3Afoo", "", false},
		{"encoded NUL rejected", "v4%00", "", false},
		{"control char rejected", "v4\t", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := NormalizeRef(tc.raw)
			assert.Equal(t, tc.ok, ok, "ok")
			assert.Equal(t, tc.want, got, "ref")
		})
	}
}

func TestParseRefIdentity(t *testing.T) {
	const sha1Lower = "11bd71901bbe5b1630ceea73d27597364c9af683"
	cases := []struct {
		name       string
		raw        string
		wantRef    string
		wantKind   RefKind
		wantCommit string
	}{
		{"commit sha1", sha1Lower, sha1Lower, RefKindCommit, sha1Lower},
		{"commit sha1 uppercase", "11BD71901BBE5B1630CEEA73D27597364C9AF683", sha1Lower, RefKindCommit, sha1Lower},
		{"release tag", "v4.3.1", "v4.3.1", RefKindTag, ""},
		{"bare release tag", "1.2.3", "1.2.3", RefKindTag, ""},
		{"partial major tag", "v4", "v4", RefKindTag, ""},
		{"partial minor tag", "v4.2", "v4.2", RefKindTag, ""},
		{"pre-release is branch", "v1.0.0-beta.1", "v1.0.0-beta.1", RefKindBranch, ""},
		{"branch", "main", "main", RefKindBranch, ""},
		{"encoded branch", "release%2Fv4", "release/v4", RefKindBranch, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, ok := ParseRefIdentity(tc.raw)
			assert.True(t, ok)
			assert.Equal(t, tc.raw, id.Raw, "Raw preserves the original string")
			assert.Equal(t, tc.wantRef, id.Ref, "Ref")
			assert.Equal(t, tc.wantKind, id.Kind, "Kind")
			assert.Equal(t, tc.wantCommit, id.Commit, "Commit")
			assert.Equal(t, tc.wantKind == RefKindCommit, id.IsImmutable(), "IsImmutable fails closed for mutable refs")
		})
	}
}

func TestParseRefIdentity_Invalid(t *testing.T) {
	for _, raw := range []string{"", "v4:foo", "%zz", "v4%00"} {
		t.Run(raw, func(t *testing.T) {
			id, ok := ParseRefIdentity(raw)
			assert.False(t, ok)
			assert.Equal(t, RefIdentity{}, id)
		})
	}
}

func TestRefIdentity_IsReleaseTag(t *testing.T) {
	cases := []struct {
		raw  string
		want bool
	}{
		{"v4.3.1", true},
		{"1.2.3", true},
		{"v4", false},   // partial major tag is a rolling ref
		{"v4.2", false}, // partial minor tag is a rolling ref
		{"v1.0.0-beta.1", false},
		{"main", false},
		{"11bd71901bbe5b1630ceea73d27597364c9af683", false},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			id, ok := ParseRefIdentity(tc.raw)
			assert.True(t, ok)
			assert.Equal(t, tc.want, id.IsReleaseTag())
		})
	}
}
