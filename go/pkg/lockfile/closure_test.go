package lockfile

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClassifyUses(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantKind UsesKind
		wantNWO  string
		wantPath string
	}{
		{name: "remote action", input: "actions/checkout@v4", wantKind: UsesRemote, wantNWO: "actions/checkout"},
		{name: "remote sub-action path", input: "actions/cache/save@v4", wantKind: UsesRemote, wantNWO: "actions/cache"},
		{name: "local sub-action", input: "./tools/my-action", wantKind: UsesLocal, wantPath: "tools/my-action"},
		{name: "local reusable workflow", input: "./.github/workflows/ci.yml", wantKind: UsesReusableWorkflow},
		{name: "dynamic expression", input: "${{ matrix.action }}", wantKind: UsesDynamic},
		{name: "dynamic local path", input: "./${{ matrix.path }}", wantKind: UsesDynamic},
		{name: "docker image", input: "docker://alpine:3.18", wantKind: UsesDocker},
		{name: "remote reusable workflow", input: "octo/repo/.github/workflows/release.yml@v1", wantKind: UsesReusableWorkflow},
		{name: "empty", input: "", wantKind: UsesInvalid},
		{name: "whitespace only", input: "   ", wantKind: UsesInvalid},
		{name: "missing ref", input: "actions/checkout", wantKind: UsesInvalid},
		{name: "control characters", input: "actions/check\tout@v4", wantKind: UsesInvalid},
		{name: "local traversal", input: "../escape", wantKind: UsesInvalid},
		{name: "local path with traversal", input: "./tools/../../escape", wantKind: UsesInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyUses(tt.input)
			assert.Equal(t, tt.wantKind, got.Kind)
			if tt.wantNWO != "" {
				require.NotNil(t, got.Ref)
				assert.Equal(t, tt.wantNWO, got.Ref.NWO())
			}
			if tt.wantPath != "" {
				assert.Equal(t, tt.wantPath, got.Path)
			}
		})
	}
}

// closureFixture is a two-workflow lockfile exercising entry, nested, and
// diamond-shaped uses graphs.
const closureFixture = `version: v0.0.3
workflows:
  .github/workflows/deploy.yml:
    - octo/composite@v1
    - actions/checkout@v6
  .github/workflows/flat.yml:
    - actions/checkout@v6
dependencies:
  actions/checkout@v6:
    ref: v6
    commit: sha1-34e114876b0b11c390a56381ad16ebd13914f8d5
    owner_id: 44036562
    repo_id: 197814629
  octo/composite@v1:
    ref: v1
    commit: sha1-1111111111111111111111111111111111111111
    owner_id: 1
    repo_id: 2
    uses:
      - octo/inner@v2
      - actions/checkout@v6
  octo/inner@v2:
    ref: v2
    commit: sha1-2222222222222222222222222222222222222222
    owner_id: 3
    repo_id: 4
    uses:
      - octo/leaf@v3
  octo/leaf@v3:
    ref: v3
    commit: sha1-3333333333333333333333333333333333333333
    owner_id: 5
    repo_id: 6
`

func TestResolveClosure_RecursivePreservesSourcePathPin(t *testing.T) {
	f, err := Parse([]byte(closureFixture))
	require.NoError(t, err)

	c, err := f.ResolveClosure(".github/workflows/deploy.yml")
	require.NoError(t, err)

	assert.Equal(t, []string{
		"octo/composite@v1",
		"actions/checkout@v6",
		"octo/inner@v2",
		"octo/leaf@v3",
	}, c.Pins())

	// Entry node: sourced by the workflow, depth 0, immutable pin recorded.
	entry, ok := c.Lookup("octo/composite@v1")
	require.True(t, ok)
	assert.Equal(t, []string{".github/workflows/deploy.yml"}, entry.Sources)
	assert.Equal(t, []string{"octo/composite@v1"}, entry.Path)
	assert.Equal(t, 0, entry.Depth)
	assert.Equal(t, "v1", entry.Ref)
	assert.Equal(t, "sha1-1111111111111111111111111111111111111111", entry.Commit)

	// Transitively nested node: source is the parent pin, path is the full
	// reference chain, pin stays immutable.
	leaf, ok := c.Lookup("octo/leaf@v3")
	require.True(t, ok)
	assert.Equal(t, []string{"octo/inner@v2"}, leaf.Sources)
	assert.Equal(t, []string{"octo/composite@v1", "octo/inner@v2", "octo/leaf@v3"}, leaf.Path)
	assert.Equal(t, 2, leaf.Depth)
	assert.Equal(t, "sha1-3333333333333333333333333333333333333333", leaf.Commit)

	// Diamond: actions/checkout is both an entry and a nested use; both
	// sources are preserved on the single deduplicated node.
	checkout, ok := c.Lookup("actions/checkout@v6")
	require.True(t, ok)
	assert.Equal(t, []string{".github/workflows/deploy.yml", "octo/composite@v1"}, checkout.Sources)
}

func TestResolveClosure_SingleLayerRemainsReadable(t *testing.T) {
	f, err := Parse([]byte(closureFixture))
	require.NoError(t, err)

	c, err := f.ResolveClosure(".github/workflows/flat.yml")
	require.NoError(t, err)
	require.Len(t, c.Nodes, 1)
	assert.Equal(t, "actions/checkout@v6", c.Nodes[0].Pin)
	assert.Equal(t, 0, c.Nodes[0].Depth)
	assert.Equal(t, "sha1-34e114876b0b11c390a56381ad16ebd13914f8d5", c.Nodes[0].Commit)
}

func TestResolveClosure_MissingNestedNodeFailsClosed(t *testing.T) {
	yaml := `version: v0.0.3
workflows:
  .github/workflows/ci.yml:
    - octo/composite@v1
dependencies:
  octo/composite@v1:
    ref: v1
    commit: sha1-1111111111111111111111111111111111111111
    owner_id: 1
    repo_id: 2
    uses:
      - octo/absent@v9
`
	f, err := Parse([]byte(yaml))
	require.NoError(t, err)

	_, err = f.ResolveClosure(".github/workflows/ci.yml")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMissingDependency))
	assert.Contains(t, err.Error(), "octo/absent@v9")
}

func TestResolveClosure_MissingEntryFailsClosed(t *testing.T) {
	yaml := `version: v0.0.3
workflows:
  .github/workflows/ci.yml:
    - octo/ghost@v1
dependencies: {}
`
	f, err := Parse([]byte(yaml))
	require.NoError(t, err)

	_, err = f.ResolveClosure(".github/workflows/ci.yml")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMissingDependency))
}

func TestResolveClosure_UnknownWorkflow(t *testing.T) {
	f, err := Parse([]byte(closureFixture))
	require.NoError(t, err)

	_, err = f.ResolveClosure(".github/workflows/nope.yml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not onboarded")
}

func TestResolveNestedUses(t *testing.T) {
	f, err := Parse([]byte(closureFixture))
	require.NoError(t, err)

	pins, locals, err := f.ResolveNestedUses("octo/composite@v1", []string{
		"Actions/Checkout@v6", // casing canonicalized
		"./tools/helper",
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"actions/checkout@v6"}, pins)
	assert.Equal(t, []LocalRef{{Source: "octo/composite@v1", Path: "tools/helper"}}, locals)
}

func TestResolveNestedUses_DynamicFailsClosed(t *testing.T) {
	f, err := Parse([]byte(closureFixture))
	require.NoError(t, err)

	_, _, err = f.ResolveNestedUses("octo/composite@v1", []string{"${{ matrix.action }}"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDynamicUses))
}

func TestResolveNestedUses_MissingFailsClosed(t *testing.T) {
	f, err := Parse([]byte(closureFixture))
	require.NoError(t, err)

	_, _, err = f.ResolveNestedUses("octo/composite@v1", []string{"octo/absent@v9"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMissingDependency))
}

func TestResolveNestedUses_RejectsUnpinnableKinds(t *testing.T) {
	f, err := Parse([]byte(closureFixture))
	require.NoError(t, err)

	for _, raw := range []string{
		"docker://alpine:3.18",
		"./.github/workflows/ci.yml",
		"octo/repo/.github/workflows/release.yml@v1",
		"not-a-valid-uses",
	} {
		_, _, err = f.ResolveNestedUses("octo/composite@v1", []string{raw})
		assert.Error(t, err, "uses %q must fail closed", raw)
	}
}
