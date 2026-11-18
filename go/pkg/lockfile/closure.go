package lockfile

import (
	"errors"
	"fmt"
	"strings"
)

// ErrDynamicUses is returned (via errors.Is) when closure resolution meets a
// `uses:` value containing a ${{ }} expression. Dynamic references cannot be
// pinned, so resolution fails closed instead of silently skipping them.
var ErrDynamicUses = errors.New("dynamic uses expression cannot be pinned")

// ErrMissingDependency is returned (via errors.Is) when a reference in the
// closure graph names a pin that is absent from the lockfile's dependencies.
// A missing node means the transitive reference is not proven pinned, so
// resolution fails closed.
var ErrMissingDependency = errors.New("dependency missing from lockfile")

// UsesKind classifies a raw `uses:` value. ParseActionRef deliberately
// collapses everything that is not a repository action into nil; UsesKind
// keeps the distinction that closure resolution needs — in particular
// between a dynamic expression (unpinnable, fail closed) and a local
// sub-action (pinned implicitly by the parent checkout).
type UsesKind int

const (
	// UsesInvalid is an empty, unparseable, or unsafe `uses:` value.
	UsesInvalid UsesKind = iota
	// UsesRemote is a pinnable repository action: owner/repo[/path]@ref.
	UsesRemote
	// UsesLocal is a local sub-action path ("./...") inside the same repo
	// checkout. It needs no lockfile entry of its own.
	UsesLocal
	// UsesDynamic is a `uses:` value containing a ${{ }} expression. It
	// cannot be resolved statically and must fail closed.
	UsesDynamic
	// UsesDocker is a docker:// image reference, not a repository action.
	UsesDocker
	// UsesReusableWorkflow is a local or remote reusable workflow file.
	UsesReusableWorkflow
)

// ClassifiedUses is the result of classifying one raw `uses:` value.
type ClassifiedUses struct {
	Kind UsesKind
	// Ref is the parsed action reference. Non-nil only when Kind is
	// UsesRemote.
	Ref *ActionRef
	// Path is the repo-relative local sub-action path (leading "./"
	// stripped). Set only when Kind is UsesLocal.
	Path string
	// Raw is the original `uses:` string, trimmed.
	Raw string
}

// ClassifyUses classifies a raw `uses:` value, distinguishing the shapes
// that ParseActionRef collapses to nil. It performs no locking decisions —
// callers decide which kinds are acceptable in their context.
func ClassifyUses(uses string) ClassifiedUses {
	trimmed := strings.TrimSpace(uses)
	c := ClassifiedUses{Raw: trimmed}
	switch {
	case trimmed == "" || containsControlChars(trimmed):
		c.Kind = UsesInvalid
	case strings.Contains(trimmed, "${"):
		c.Kind = UsesDynamic
	case strings.HasPrefix(trimmed, "docker://"):
		c.Kind = UsesDocker
	case strings.HasPrefix(trimmed, "./"):
		if IsLocalReusableWorkflow(trimmed) {
			c.Kind = UsesReusableWorkflow
			return c
		}
		path := strings.TrimPrefix(trimmed, "./")
		if !isValidPath(path) {
			c.Kind = UsesInvalid
			return c
		}
		c.Kind = UsesLocal
		c.Path = path
	default:
		if ref := ParseActionRef(trimmed); ref != nil {
			c.Kind = UsesRemote
			c.Ref = ref
			return c
		}
		if rw := ParseReusableWorkflowRef(trimmed); rw != nil {
			c.Kind = UsesReusableWorkflow
			return c
		}
		c.Kind = UsesInvalid
	}
	return c
}

// ClosureNode is one resolved action in a workflow's reference closure.
type ClosureNode struct {
	// Pin is the canonical pin key (OWNER/REPO@REF) indexing Dependencies.
	Pin string
	// Ref is the git ref the pin was resolved from.
	Ref string
	// Commit is the immutable algo-hex digest the ref resolves to — the
	// value that proves this node of the closure is pinned.
	Commit string
	// Hostname is the GitHub instance owning the dependency ("" = home host).
	Hostname string
	// Sources lists every referrer that pulled this node into the closure:
	// the workflow path for entry dependencies and/or the pin keys of
	// composite actions whose uses: edge names this node.
	Sources []string
	// Path is the reference chain of pin keys from the entry dependency
	// down to this node (Path[0] is the entry, Path[len-1] == Pin).
	Path []string
	// Depth is the nesting depth: 0 for the workflow's direct dependencies,
	// 1 for their nested uses, and so on.
	Depth int
}

// LocalRef records a local sub-action reference ("./...") encountered while
// resolving a composite action's nested uses. It carries no pin of its own:
// it is pinned implicitly by the referencing repo's checkout.
type LocalRef struct {
	// Source is the pin key of the composite action that referenced it.
	Source string
	// Path is the repo-relative path of the local sub-action.
	Path string
}

// Closure is the resolved transitive reference graph for one workflow.
type Closure struct {
	// Workflow is the repo-relative workflow path the closure was
	// resolved from.
	Workflow string
	// Nodes holds every reachable dependency in breadth-first order from
	// the workflow's entry pins. Each node's Commit is the immutable pin.
	Nodes []ClosureNode
	// Locals records local sub-action references discovered via
	// ResolveNestedUses during resolution. ResolveClosure (which walks the
	// lockfile's canonical pin graph only) always leaves this empty.
	Locals []LocalRef

	index map[string]int // pin -> Nodes index
}

// Pins returns the canonical pin keys of every node in closure order.
func (c *Closure) Pins() []string {
	pins := make([]string, len(c.Nodes))
	for i, n := range c.Nodes {
		pins[i] = n.Pin
	}
	return pins
}

// Lookup returns the closure node for a canonical pin key, or ok=false when
// the pin is not part of this closure.
func (c *Closure) Lookup(pin string) (ClosureNode, bool) {
	i, ok := c.index[pin]
	if !ok {
		return ClosureNode{}, false
	}
	return c.Nodes[i], true
}

// ResolveClosure computes the recursive reference closure for a workflow
// already onboarded in the lockfile: it starts from the workflow's entry
// pins and walks every dependency's uses: edges transitively, recording for
// each node its source referrers, its reference path, and its immutable pin
// (canonical pin key plus commit digest).
//
// Resolution fails closed: any uses: edge — or workflow entry — naming a pin
// absent from Dependencies is an error matching ErrMissingDependency, since
// a missing node means a transitive reference is not proven pinned. A
// single-layer lockfile (no uses: edges) resolves to exactly its entry
// dependencies. The uses graph is a DAG (Parse rejects cycles); hand-built
// Files with cycles terminate because each pin is expanded at most once.
func (f File) ResolveClosure(workflowPath string) (*Closure, error) {
	entries, ok := f.Workflows[workflowPath]
	if !ok {
		return nil, fmt.Errorf("workflow %q is not onboarded in the lockfile", workflowPath)
	}
	c := &Closure{Workflow: workflowPath, index: make(map[string]int)}
	var queue []string

	enqueue := func(pin, source string, path []string) error {
		action, ok := f.Dependencies[pin]
		if !ok {
			return fmt.Errorf("%w: %q referenced by %s", ErrMissingDependency, pin, source)
		}
		if i, seen := c.index[pin]; seen {
			node := &c.Nodes[i]
			if !containsString(node.Sources, source) {
				node.Sources = append(node.Sources, source)
			}
			return nil
		}
		c.index[pin] = len(c.Nodes)
		c.Nodes = append(c.Nodes, ClosureNode{
			Pin:      pin,
			Ref:      action.Ref,
			Commit:   action.Commit,
			Hostname: action.Hostname,
			Sources:  []string{source},
			Path:     path,
			Depth:    len(path) - 1,
		})
		queue = append(queue, pin)
		return nil
	}

	for _, entry := range entries {
		if err := enqueue(entry, workflowPath, []string{entry}); err != nil {
			return nil, err
		}
	}
	for len(queue) > 0 {
		pin := queue[0]
		queue = queue[1:]
		node := c.Nodes[c.index[pin]]
		for _, used := range f.Dependencies[pin].Uses {
			childPath := make([]string, len(node.Path)+1)
			copy(childPath, node.Path)
			childPath[len(node.Path)] = used
			if err := enqueue(used, pin, childPath); err != nil {
				return nil, err
			}
		}
	}
	return c, nil
}

// ResolveNestedUses resolves the raw nested `uses:` strings of a composite
// action (see ActionMeta.NestedUses) against the lockfile, returning the
// canonical pin keys of the remote actions it references and the local
// sub-actions it uses. source identifies the referrer (typically the
// composite action's pin key) for diagnostics and LocalRef records.
//
// Resolution fails closed: a dynamic ${{ }} expression yields an error
// matching ErrDynamicUses, and a remote action whose pin is absent from
// Dependencies yields an error matching ErrMissingDependency. Docker images,
// reusable workflows, and unparseable values are likewise rejected — the
// lockfile cannot prove them pinned.
func (f File) ResolveNestedUses(source string, nested []string) (pins []string, locals []LocalRef, err error) {
	for _, raw := range nested {
		c := ClassifyUses(raw)
		switch c.Kind {
		case UsesDynamic:
			return nil, nil, fmt.Errorf("%w: %q referenced by %s", ErrDynamicUses, c.Raw, source)
		case UsesLocal:
			locals = append(locals, LocalRef{Source: source, Path: c.Path})
		case UsesRemote:
			pin := Pin{Owner: c.Ref.Owner, Repo: c.Ref.Repo, Ref: c.Ref.Ref}.String()
			if _, ok := f.Dependencies[pin]; !ok {
				return nil, nil, fmt.Errorf("%w: %q (pin %s) referenced by %s", ErrMissingDependency, c.Raw, pin, source)
			}
			pins = append(pins, pin)
		default:
			return nil, nil, fmt.Errorf("unsupported uses value %q referenced by %s: not a pinnable repository action", c.Raw, source)
		}
	}
	return pins, locals, nil
}

func containsString(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}
