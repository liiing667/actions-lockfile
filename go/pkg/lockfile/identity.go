package lockfile

import "strings"

// This file is the single place that turns a parsed network origin (host) and
// action location (owner/repo[/subpath] plus ref) into canonical identity
// keys. Every parser — repository actions, reusable workflows, and lockfile
// pin keys — funnels through it so the same logical identity can never
// produce two different keys (and two keys can never denote one identity),
// regardless of URL casing or trailing-dot spellings.

// Network origin normalization.
//
// DNS hostnames are case-insensitive, and a single trailing dot is the DNS
// root label: "GITHUB.COM", "github.com", and "github.com." all name the same
// host. Normalize those spellings into the one canonical form used inside
// identity keys. Anything that does not resolve to a GitHub host the
// lockfile format knows about fails closed rather than being silently
// accepted as a new origin.

// NormalizeHostname canonicalizes a network-origin hostname for use in an
// identity key. It lower-cases the value and strips a single trailing DNS
// root dot, then verifies the result is a host the lockfile format trusts:
// github.com or a single-tenant label under ghe.com.
//
// ok=false is the fail-closed result for an unknown or malformed host —
// schemes, ports, paths, query strings, fragments, surrounding whitespace,
// empty labels, and non-GitHub domains. Callers must reject the input rather
// than fall back to a default host, since falling back would attribute an
// untrusted origin's action to a trusted one.
func NormalizeHostname(host string) (canonical string, ok bool) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", false
	}
	// A trailing dot is the absolute (root) form of an otherwise identical
	// DNS name. Only strip a single trailing dot; repeated dots leave an
	// empty label and must fail validation below.
	host = strings.TrimSuffix(host, ".")
	host = strings.ToLower(host)
	if !canonicalHostnameRE.MatchString(host) {
		return "", false
	}
	return host, true
}

// IsKnownHostname reports whether host normalizes to a trusted GitHub
// network origin. It is the boolean form of NormalizeHostname.
func IsKnownHostname(host string) bool {
	_, ok := NormalizeHostname(host)
	return ok
}

// CanonicalHostname returns the normalized network-origin key for host. It
// returns the empty string for an unknown host; prefer NormalizeHostname in
// parse paths so the failure is explicit.
func CanonicalHostname(host string) string {
	canonical, ok := NormalizeHostname(host)
	if !ok {
		return ""
	}
	return canonical
}

// Ambiguous action path handling.
//
// GitHub owner/repo names are matched case-insensitively, while git refs and
// in-repo subpaths keep their source casing. A segment ending in a dot is
// never a valid GitHub owner/repo/path name (the web UI strips trailing dots
// on some platforms, so two spellings could resolve to one object); rather
// than guess which object was meant, reject it.

// canonicalSegment lower-cases an owner or repo segment. isValidSegment has
// already enforced the GitHub character set and rejected "." / ".."; this
// additionally fails closed on trailing-dot names, which cannot name a real
// GitHub object and would otherwise be ambiguous.
func canonicalSegment(segment string) (string, bool) {
	if strings.HasSuffix(segment, ".") {
		return "", false
	}
	return strings.ToLower(segment), true
}

// canonicalActionPath normalizes the sub-action portion of a uses: reference
// (everything after owner/repo). Each segment must be a valid, non-ambiguous
// GitHub path segment; the path's own casing is preserved. The empty path is
// valid and means the repository root action.
func canonicalActionPath(path string) (string, bool) {
	if path == "" {
		return "", true
	}
	for _, seg := range strings.Split(path, "/") {
		if !isValidSegment(seg) || strings.HasSuffix(seg, ".") {
			return "", false
		}
	}
	return path, true
}

// Identity is the canonical, host-qualified identity of an action or
// reusable workflow reference. It is the shared representation behind both
// the repo-granularity pin keys serialized in lockfiles and the
// path-granularity keys auditors use to compare `uses:` references.
//
// ParseActionIdentity and ParseWorkflowIdentity are the only constructors;
// treat the zero value as invalid.
type Identity struct {
	// Host is the canonical network origin (e.g. "github.com",
	// "octocorp.ghe.com"). Always populated: callers that do not carry an
	// explicit host pass their home host explicitly.
	Host string
	// Owner and Repo are the lower-cased Name-With-Owner components.
	Owner string
	Repo  string
	// Path is the in-repo sub-action or workflow file path with source
	// casing preserved. Empty for a repository root action.
	Path string
	// Ref preserves source casing — git refs are case-sensitive.
	Ref string
}

// NWO returns the canonical owner/repo (Name With Owner), or the empty string
// for a zero-value Identity.
func (i Identity) NWO() string {
	if i.Owner == "" && i.Repo == "" {
		return ""
	}
	return i.Owner + "/" + i.Repo
}

// PinKey returns the repo-granularity canonical lockfile key:
// "OWNER/REPO@REF". It deliberately omits Host and Path: within one lockfile
// the pin namespace is host-qualified via the Action.Hostname field, and the
// runner downloads owner/repo@ref once for every sub-action path.
func (i Identity) PinKey() string {
	return i.NWO() + "@" + i.Ref
}

// Key returns the fully-qualified canonical identity key, unique across
// network origins, repositories, sub-action paths, and refs:
//
//	host/OWNER/REPO[/path]@REF
//
// Two references that resolve to the same action produce the same Key even
// when their raw spellings differ in host casing, a trailing DNS dot, or
// owner/repo casing. Use Key for audit comparisons; use PinKey when emitting
// the lockfile's repo-granularity pin strings.
func (i Identity) Key() string {
	if i.Path != "" {
		return i.Host + "/" + i.Owner + "/" + i.Repo + "/" + i.Path + "@" + i.Ref
	}
	return i.Host + "/" + i.Owner + "/" + i.Repo + "@" + i.Ref
}

// ParseActionIdentity builds the canonical Identity for a repository action
// `uses:` string (see ParseActionRef) on the given network origin. host is
// normalized through NormalizeHostname and the path through
// canonicalActionPath; an unknown host or ambiguous path yields ok=false so
// callers fail closed.
func ParseActionIdentity(host, uses string) (Identity, bool) {
	ref := ParseActionRef(uses)
	if ref == nil {
		return Identity{}, false
	}
	return identityFromParts(host, ref.Owner, ref.Repo, ref.Path, ref.Ref)
}

// ParseWorkflowIdentity builds the canonical Identity for a remote reusable
// workflow `uses:` string (see ParseReusableWorkflowRef) on the given network
// origin. The same fail-closed rules as ParseActionIdentity apply.
func ParseWorkflowIdentity(host, uses string) (Identity, bool) {
	ref := ParseReusableWorkflowRef(uses)
	if ref == nil {
		return Identity{}, false
	}
	return identityFromParts(host, ref.Owner, ref.Repo, ref.Path, ref.Ref)
}

// identityFromParts is the shared normalizer every constructor funnels
// through: one host rule, one owner/repo rule, one path rule.
func identityFromParts(host, owner, repo, path, ref string) (Identity, bool) {
	canonicalHost, ok := NormalizeHostname(host)
	if !ok {
		return Identity{}, false
	}
	canonicalOwner, ok := canonicalSegment(owner)
	if !ok {
		return Identity{}, false
	}
	canonicalRepo, ok := canonicalSegment(repo)
	if !ok {
		return Identity{}, false
	}
	canonicalPath, ok := canonicalActionPath(path)
	if !ok {
		return Identity{}, false
	}
	if !isValidRef(ref) {
		return Identity{}, false
	}
	return Identity{
		Host:  canonicalHost,
		Owner: canonicalOwner,
		Repo:  canonicalRepo,
		Path:  canonicalPath,
		Ref:   ref,
	}, true
}
