package lockfile

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testGoodDigest = "sha1-34e114876b0b11c390a56381ad16ebd13914f8d5"
	testEvilDigest = "sha1-deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
)

func assertParseError(t *testing.T, err error, msgFragment string) {
	t.Helper()
	require.Error(t, err)
	var pe *ParseError
	require.True(t, errors.As(err, &pe), "expected a *ParseError, got %T", err)
	assert.Contains(t, pe.Msg, msgFragment)
	assert.Greater(t, pe.Line, 0, "error must carry a line position")
	assert.Greater(t, pe.Column, 0, "error must carry a column position")
}

func TestParse_WorkflowDanglingReferenceRejected(t *testing.T) {
	input := `version: v0.0.3
workflows:
  .github/workflows/w.yml:
    - actions/checkout@v4.3.1
    - actions/evil@v1
dependencies:
  actions/checkout@v4.3.1:
    ref: v4.3.1
    commit: ` + testGoodDigest + `
    owner_id: 1
    repo_id: 2
`
	_, err := Parse([]byte(input))
	assertParseError(t, err, `has no matching dependencies entry`)
	assert.Contains(t, err.Error(), "actions/evil@v1")
}

func TestParse_WorkflowDuplicateCanonicalPinRejected(t *testing.T) {
	input := `version: v0.0.3
workflows:
  .github/workflows/w.yml:
    - actions/checkout@v4.3.1
    - Actions/Checkout@v4.3.1
dependencies:
  actions/checkout@v4.3.1:
    ref: v4.3.1
    commit: ` + testGoodDigest + `
    owner_id: 1
    repo_id: 2
`
	_, err := Parse([]byte(input))
	assertParseError(t, err, "more than once")
}

func TestParse_WorkflowUpgradeDowngradeRefsRejected(t *testing.T) {
	// Two distinct refs of the same owner/repo inside one workflow closure
	// leave the runner free to pick either version — an upgrade/downgrade
	// conflict that must fail rather than hide behind the first record.
	input := `version: v0.0.3
workflows:
  .github/workflows/w.yml:
    - actions/checkout@v4.3.1
    - actions/checkout@v4.3.2
dependencies:
  actions/checkout@v4.3.1:
    ref: v4.3.1
    commit: ` + testGoodDigest + `
    owner_id: 1
    repo_id: 2
  actions/checkout@v4.3.2:
    ref: v4.3.2
    commit: ` + testEvilDigest + `
    owner_id: 1
    repo_id: 2
`
	_, err := Parse([]byte(input))
	assertParseError(t, err, "conflicting refs")
	assert.Contains(t, err.Error(), "actions/checkout")
}

func TestParse_SameNWOTwoVersionsAcrossWorkflowsAccepted(t *testing.T) {
	// Different workflows may legitimately pin different refs of the same
	// action; the single-ref rule is scoped to one workflow's closure.
	input := `version: v0.0.3
workflows:
  .github/workflows/a.yml:
    - actions/checkout@v4.3.1
  .github/workflows/b.yml:
    - actions/checkout@v4.3.2
dependencies:
  actions/checkout@v4.3.1:
    ref: v4.3.1
    commit: ` + testGoodDigest + `
    owner_id: 1
    repo_id: 2
  actions/checkout@v4.3.2:
    ref: v4.3.2
    commit: ` + testEvilDigest + `
    owner_id: 1
    repo_id: 2
`
	f, err := Parse([]byte(input))
	require.NoError(t, err)
	assert.Len(t, f.Dependencies, 2)
}

func TestParse_UsesDanglingReferenceRejected(t *testing.T) {
	input := `version: v0.0.3
workflows:
  .github/workflows/w.yml:
    - actions/cache@v4.0.0
dependencies:
  actions/cache@v4.0.0:
    ref: v4.0.0
    commit: ` + testGoodDigest + `
    owner_id: 1
    repo_id: 2
    uses:
      - actions/missing@v1
`
	_, err := Parse([]byte(input))
	assertParseError(t, err, `uses "actions/missing@v1"`)
}

func TestParse_ClosedGraphAccepted(t *testing.T) {
	input := `version: v0.0.2
workflows:
  .github/workflows/w.yml:
    - actions/cache@v4
dependencies:
  actions/cache@v4:
    ref: v4
    commit: sha1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    owner_id: 1
    repo_id: 2
    uses:
      - actions/checkout@v4
  actions/checkout@v4:
    ref: v4
    commit: ` + testGoodDigest + `
    owner_id: 1
    repo_id: 3
`
	f, err := Parse([]byte(input))
	require.NoError(t, err)
	assert.Len(t, f.Dependencies, 2)
}

func TestParse_V001WorkflowDigestMismatchRejected(t *testing.T) {
	input := `version: v0.0.1
workflows:
  .github/workflows/w.yml:
    - actions/checkout@v4.3.1:sha1-deadbeefdeadbeefdeadbeefdeadbeefdeadbeef
dependencies:
  actions/checkout@v4.3.1:sha1-34e114876b0b11c390a56381ad16ebd13914f8d5:
    tag: v4.3.1
    commit: ` + testGoodDigest + `
    owner_id: 1
    repo_id: 2
`
	_, err := Parse([]byte(input))
	assertParseError(t, err, "requests legacy digest")
}

func TestParse_V001DependencyKeyDigestMismatchRejected(t *testing.T) {
	input := `version: v0.0.1
workflows: {}
dependencies:
  actions/checkout@v4.3.1:sha1-deadbeefdeadbeefdeadbeefdeadbeefdeadbeef:
    tag: v4.3.1
    commit: ` + testGoodDigest + `
    owner_id: 1
    repo_id: 2
`
	_, err := Parse([]byte(input))
	assertParseError(t, err, "legacy pin key digest")
}

func TestParse_V001UsesDigestMismatchRejected(t *testing.T) {
	input := `version: v0.0.1
workflows:
  .github/workflows/w.yml:
    - actions/cache@v4:sha1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
dependencies:
  actions/cache@v4:sha1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:
    tag: v4
    commit: sha1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    owner_id: 1
    repo_id: 2
    uses:
      - actions/checkout@v4.3.1:sha1-deadbeefdeadbeefdeadbeefdeadbeefdeadbeef
  actions/checkout@v4.3.1:sha1-34e114876b0b11c390a56381ad16ebd13914f8d5:
    tag: v4.3.1
    commit: ` + testGoodDigest + `
    owner_id: 1
    repo_id: 3
`
	_, err := Parse([]byte(input))
	assertParseError(t, err, "legacy uses digest")
}

func TestParse_V001MatchingLegacyDigestAccepted(t *testing.T) {
	// A legacy request digest that agrees with the locked commit migrates
	// cleanly and keeps the existing v0.0.1 compatibility behavior.
	input := `version: v0.0.1
workflows:
  .github/workflows/w.yml:
    - actions/checkout@v4:sha1-34e114876b0b11c390a56381ad16ebd13914f8d5
dependencies:
  actions/checkout@v4:sha1-34e114876b0b11c390a56381ad16ebd13914f8d5:
    tag: v4
    commit: ` + testGoodDigest + `
    owner_id: 1
    repo_id: 2
`
	f, err := Parse([]byte(input))
	require.NoError(t, err)
	wf, ok := f.LookupWorkflow(".github/workflows/w.yml")
	require.True(t, ok)
	assert.Equal(t, []string{"actions/checkout@v4"}, wf)
}

func TestParse_V001DanglingWorkflowReferenceRejected(t *testing.T) {
	input := `version: v0.0.1
workflows:
  .github/workflows/w.yml:
    - actions/checkout@v4.3.1:sha1-34e114876b0b11c390a56381ad16ebd13914f8d5
dependencies:
  actions/other@v1:
    tag: v1
    commit: ` + testGoodDigest + `
    owner_id: 1
    repo_id: 2
`
	_, err := Parse([]byte(input))
	assertParseError(t, err, `has no matching dependencies entry`)
}
