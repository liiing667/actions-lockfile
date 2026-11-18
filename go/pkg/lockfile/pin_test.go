package lockfile

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePin(t *testing.T) {
	tests := []struct {
		name  string
		entry string
		want  Pin
	}{
		{
			name:  "owner repo",
			entry: "actions/checkout@v4",
			want: Pin{
				NWO:   "actions/checkout",
				Owner: "actions",
				Repo:  "checkout",
				Ref:   "v4",
			},
		},
		{
			name:  "full SHA ref",
			entry: "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
			want: Pin{
				NWO:   "actions/checkout",
				Owner: "actions",
				Repo:  "checkout",
				Ref:   "11bd71901bbe5b1630ceea73d27597364c9af683",
			},
		},
		{
			// Monorepo sub-action tags can embed an '@' in the ref, producing
			// a double-'@' key. The first '@' bounds the NWO; the rest is the ref.
			name:  "ref containing at (monorepo sub-action tag)",
			entry: "actions/attest-build-provenance@predicate@1.1.4",
			want: Pin{
				NWO:   "actions/attest-build-provenance",
				Owner: "actions",
				Repo:  "attest-build-provenance",
				Ref:   "predicate@1.1.4",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ParsePin(tt.entry)
			require.True(t, ok)
			assert.Equal(t, tt.want, got)
			// Round-trip: serializing the parsed pin reproduces the entry.
			assert.Equal(t, tt.entry, got.String())
		})
	}
}

func TestParsePin_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		entry string
	}{
		{"empty", ""},
		{"missing at", "actions/checkout"},
		{"empty owner", "/@v4"},
		{"empty repo", "actions/@v4"},
		{"sub-action path rejected", "actions/cache/save@v4"},
		{"deep sub-action path rejected", "owner/repo/a/b@v1"},
		{"colon in ref rejected", "actions/checkout@v4:foo"},
		{"colon only ref rejected", "actions/checkout@:"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ParsePin(tt.entry)
			assert.False(t, ok)
			assert.Equal(t, Pin{}, got)
		})
	}
}

func TestIndexKey(t *testing.T) {
	assert.Equal(t, "actions/checkout@v4", IndexKey("actions", "checkout", "v4"))
}

func TestPin_IndexKey(t *testing.T) {
	tests := []struct {
		name string
		pin  Pin
		want string
	}{
		{
			name: "owner repo",
			pin:  Pin{Owner: "actions", Repo: "checkout", Ref: "v4"},
			want: "actions/checkout@v4",
		},
		{
			name: "mixed case is lowercased",
			pin:  Pin{Owner: "Actions", Repo: "Checkout", Ref: "v4"},
			want: "actions/checkout@v4",
		},
		{
			name: "empty ref",
			pin:  Pin{Owner: "actions", Repo: "checkout"},
			want: "actions/checkout@",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.pin.IndexKey())
		})
	}
}

func TestParsePin_NormalizesRef(t *testing.T) {
	tests := []struct {
		name  string
		entry string
		want  string // canonical Pin.String()
	}{
		{
			name:  "uppercase SHA ref lowercased",
			entry: "actions/checkout@11BD71901BBE5B1630CEEA73D27597364C9AF683",
			want:  "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
		},
		{
			name:  "percent-encoded slash decoded",
			entry: "actions/checkout@release%2Fv4",
			want:  "actions/checkout@release/v4",
		},
		{
			name:  "tag case preserved",
			entry: "Actions/Checkout@V4",
			want:  "actions/checkout@V4",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pin, ok := ParsePin(tt.entry)
			require.True(t, ok)
			assert.Equal(t, tt.want, pin.String())
		})
	}
}

func TestParsePin_MalformedRefEncoding(t *testing.T) {
	tests := []struct {
		name  string
		entry string
	}{
		{"bare percent", "actions/checkout@100%"},
		{"invalid escape", "actions/checkout@v4%zz"},
		{"encoded colon", "actions/checkout@v4%3Afoo"},
		{"encoded NUL", "actions/checkout@v4%00"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ParsePin(tt.entry)
			assert.False(t, ok)
			assert.Equal(t, Pin{}, got)
		})
	}
}

func TestPin_RefIdentity(t *testing.T) {
	t.Run("commit pin is immutable", func(t *testing.T) {
		pin, ok := ParsePin("actions/checkout@11BD71901BBE5B1630CEEA73D27597364C9AF683")
		require.True(t, ok)
		id, ok := pin.RefIdentity()
		require.True(t, ok)
		assert.Equal(t, RefKindCommit, id.Kind)
		assert.Equal(t, "11bd71901bbe5b1630ceea73d27597364c9af683", id.Commit)
		assert.True(t, id.IsImmutable())
	})

	t.Run("tag pin fails closed", func(t *testing.T) {
		pin, ok := ParsePin("actions/checkout@v4.3.1")
		require.True(t, ok)
		id, ok := pin.RefIdentity()
		require.True(t, ok)
		assert.Equal(t, RefKindTag, id.Kind)
		assert.Empty(t, id.Commit, "a tag is not an immutable identity")
		assert.False(t, id.IsImmutable())
		assert.True(t, id.IsReleaseTag())
	})

	t.Run("branch pin fails closed", func(t *testing.T) {
		pin, ok := ParsePin("actions/checkout@main")
		require.True(t, ok)
		id, ok := pin.RefIdentity()
		require.True(t, ok)
		assert.Equal(t, RefKindBranch, id.Kind)
		assert.Empty(t, id.Commit)
		assert.False(t, id.IsImmutable())
	})
}
