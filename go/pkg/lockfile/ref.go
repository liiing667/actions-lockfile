package lockfile

import (
	"net/url"
	"strings"
)

// RefKind classifies what a git ref string names. Tags, branches, annotated
// tags, and commits all arrive as the same bare string in a `uses:` line or
// pin key; the kind keeps the parsed classification separate from that string
// so a moved ref can never masquerade as an immutable identity.
type RefKind int

const (
	// RefKindInvalid is the zero value: the ref failed validation.
	RefKindInvalid RefKind = iota
	// RefKindCommit is a full commit SHA — the only immutable ref identity.
	RefKindCommit
	// RefKindTag is a stable semver tag (e.g. "v4.3.1", "v4"). Release tags
	// are conventionally immutable but can be deleted and recreated, so they
	// are not an identity on their own.
	RefKindTag
	// RefKindBranch is any other symbolic ref. Branches move freely.
	RefKindBranch
)

// String returns a human-readable name for the kind: "invalid", "commit",
// "tag", or "branch".
func (k RefKind) String() string {
	switch k {
	case RefKindCommit:
		return "commit"
	case RefKindTag:
		return "tag"
	case RefKindBranch:
		return "branch"
	default:
		return "invalid"
	}
}

// RefIdentity keeps the three facets of a dependency ref separate:
//
//   - Raw: the ref exactly as written in the workflow or lockfile.
//   - Ref: the normalized ref (percent-decoded; full SHAs lowercased).
//   - Kind: the parsed classification of Ref.
//   - Commit: the immutable commit identity, set only when the ref itself is
//     a full commit SHA. Tags and branches can be moved after a lock is
//     written, so they never populate Commit — for those, the immutable
//     identity lives in the lockfile's separate commit field.
//
// Whether a tag is annotated or lightweight cannot be told from the string
// alone, which is exactly why the commit identity is recorded separately
// rather than inferred from the ref.
type RefIdentity struct {
	Raw    string
	Ref    string
	Kind   RefKind
	Commit string
}

// IsImmutable reports whether the ref is an immutable identity on its own —
// true only for full commit SHAs. It fails closed: tags (including release
// tags) and branches are mutable and always report false.
func (r RefIdentity) IsImmutable() bool {
	return r.Kind == RefKindCommit
}

// IsReleaseTag reports whether the ref is a full, stable release tag
// (major.minor.patch with no pre-release suffix, e.g. "v4.3.1"). Partial
// tags like "v4" or "v4.2" classify as [RefKindTag] but are mutable
// rolling tags, so they report false.
func (r RefIdentity) IsReleaseTag() bool {
	if r.Kind != RefKindTag {
		return false
	}
	sv, ok := ParseSemVer(r.Ref)
	return ok && sv.IsFull()
}

// ParseRefIdentity parses a raw ref string into its safe identity form. It
// returns ok=false for anything that fails [NormalizeRef] — empty refs,
// control characters, colons, or malformed percent-encoding — so callers
// fail closed on ambiguous input.
func ParseRefIdentity(raw string) (RefIdentity, bool) {
	ref, ok := NormalizeRef(raw)
	if !ok {
		return RefIdentity{}, false
	}
	id := RefIdentity{Raw: raw, Ref: ref}
	switch {
	case IsFullSha(ref):
		id.Kind = RefKindCommit
		id.Commit = ref // already lowercased by NormalizeRef
	default:
		if sv, ok := ParseSemVer(ref); ok && sv.IsStable() {
			id.Kind = RefKindTag
		} else {
			id.Kind = RefKindBranch
		}
	}
	return id, true
}

// NormalizeRef returns the canonical form of a git ref, unifying the two
// representations that otherwise let one ref masquerade as several:
//
//   - Percent-encoding is decoded ("release%2Fv4" → "release/v4"), matching
//     how GitHub's API decodes ref path segments. Malformed escapes ("%",
//     "%zz") are rejected — a ref that cannot be decoded unambiguously fails
//     closed rather than passing through as a distinct literal.
//   - Full commit SHAs are lowercased ("11BD..." → "11bd..."), since hex
//     digests are case-insensitive.
//
// Tag and branch casing is preserved: git refs are case-sensitive, so
// folding "V4" to "v4" would merge two distinct refs. The result is
// validated like any ref (non-empty, no colons, no control characters);
// ok=false means the input is not a usable ref.
func NormalizeRef(raw string) (string, bool) {
	if raw == "" || containsControlChars(raw) {
		return "", false
	}
	ref := raw
	if strings.Contains(raw, "%") {
		decoded, err := url.PathUnescape(raw)
		if err != nil {
			return "", false
		}
		ref = decoded
	}
	if !isValidRef(ref) || containsControlChars(ref) {
		return "", false
	}
	if IsFullSha(ref) {
		ref = strings.ToLower(ref)
	}
	return ref, true
}

// SplitRef classifies a lockfile ref value back into its tag/branch
// constituents. If ref parses as a stable semver (via ParseSemVer +
// IsStable), it's returned as tag; otherwise it's returned as branch.
// An empty ref yields both empty.
func SplitRef(ref string) (tag, branch string) {
	if ref == "" {
		return "", ""
	}
	if sv, ok := ParseSemVer(ref); ok && sv.IsStable() {
		return ref, ""
	}
	return "", ref
}

// BestRef picks the single ref value for lockfile serialization.
// Tag wins if non-empty, else branch. Both empty yields empty.
func BestRef(tag, branch string) string {
	if tag != "" {
		return tag
	}
	return branch
}
