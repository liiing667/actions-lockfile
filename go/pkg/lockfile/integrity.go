package lockfile

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// validateGraphIntegrity enforces the cross-reference invariants that turn the
// lockfile into a closed, self-describing dependency graph:
//
//   - every pin listed in a workflow's closure resolves to an entry in
//     Dependencies (no dangling workflow reference);
//   - every pin in an action's uses list resolves to an entry in
//     Dependencies (no dangling nested-dependency reference);
//   - each canonical pin appears at most once in any single workflow's
//     closure (no duplicate/upgrade-downgrade ambiguity).
//
// It runs after canonicalization, so f.Workflows and every Action.Uses entry
// already hold canonical pin strings. The retained YAML node supplies
// positions for the source (pre-canonicalization) entries.
func validateGraphIntegrity(f *File) *ParseError {
	if pe := validateWorkflowClosures(f); pe != nil {
		return pe
	}
	return validateUsesReferences(f)
}

// validateWorkflowClosures checks each workflow's flat transitive pin list:
// every entry must exist in Dependencies, no canonical pin may repeat, and no
// action (owner/repo) may be pinned to two different refs. The last rule
// closes the upgrade/downgrade ambiguity where two versions of the same
// action coexist in one workflow's closure.
func validateWorkflowClosures(f *File) *ParseError {
	_, workflowsNode := mappingEntry(docMapping(f.node), "workflows")

	// Stable workflow order keeps diagnostics deterministic across map
	// iteration.
	workflowPaths := make([]string, 0, len(f.Workflows))
	for path := range f.Workflows {
		workflowPaths = append(workflowPaths, path)
	}
	sortStrings(workflowPaths)

	for _, path := range workflowPaths {
		canonicalPins := f.Workflows[path]
		seen := make(map[string]struct{}, len(canonicalPins))
		refByNWO := make(map[string]string, len(canonicalPins))
		for idx, canonicalPin := range canonicalPins {
			if _, exists := f.Dependencies[canonicalPin]; !exists {
				pe := &ParseError{
					Msg: fmt.Sprintf(
						"workflow %q references dependency %q that has no matching dependencies entry",
						path, canonicalPin,
					),
				}
				if l, c, ok := workflowEntryPosition(workflowsNode, path, idx); ok {
					pe.Line, pe.Column = l, c
				}
				return pe
			}
			if _, dup := seen[canonicalPin]; dup {
				pe := &ParseError{
					Msg: fmt.Sprintf(
						"workflow %q lists dependency %q more than once; a workflow must pin each action to a single ref",
						path, canonicalPin,
					),
				}
				if l, c, ok := workflowEntryPosition(workflowsNode, path, idx); ok {
					pe.Line, pe.Column = l, c
				}
				return pe
			}
			seen[canonicalPin] = struct{}{}

			pin, pinOK := ParsePin(canonicalPin)
			if !pinOK {
				continue // malformed pin is rejected during canonicalization
			}
			if priorRef, conflict := refByNWO[pin.NWO]; conflict && priorRef != pin.Ref {
				pe := &ParseError{
					Msg: fmt.Sprintf(
						"workflow %q pins %s to conflicting refs %q and %q; each action must resolve to a single ref",
						path, pin.NWO, priorRef, pin.Ref,
					),
				}
				if l, c, ok := workflowEntryPosition(workflowsNode, path, idx); ok {
					pe.Line, pe.Column = l, c
				}
				return pe
			}
			refByNWO[pin.NWO] = pin.Ref
		}
	}
	return nil
}

// validateUsesReferences checks every action's uses list resolves to an entry
// in Dependencies. The uses graph is already known to be a DAG at this point.
func validateUsesReferences(f *File) *ParseError {
	for key, action := range f.Dependencies {
		for _, used := range action.Uses {
			if _, exists := f.Dependencies[used]; !exists {
				pe := &ParseError{
					Msg: fmt.Sprintf(
						"dependency %q uses %q, which has no matching dependencies entry",
						key, used,
					),
				}
				if l, c, ok := usesEntryPosition(f.node, key, used); ok {
					pe.Line, pe.Column = l, c
				}
				return pe
			}
		}
	}
	return nil
}

// workflowEntryPosition resolves the YAML position of the index-th raw entry
// of the sequence stored under workflows[path].
func workflowEntryPosition(workflowsNode *yaml.Node, path string, index int) (line, col int, ok bool) {
	if workflowsNode == nil || workflowsNode.Kind != yaml.MappingNode {
		return 0, 0, false
	}
	_, seq := mappingEntry(workflowsNode, path)
	if seq == nil || seq.Kind != yaml.SequenceNode || index >= len(seq.Content) {
		return 0, 0, false
	}
	node := seq.Content[index]
	return node.Line, node.Column, true
}

// usesEntryPosition resolves the YAML position of the uses entry in
// dependencies[ownerKey] whose canonical form equals canonicalUsed. The raw
// entry may be casing- or (for v0.0.1) suffix-variant, so it is matched by
// canonicalization rather than string equality.
func usesEntryPosition(node *yaml.Node, ownerKey, canonicalUsed string) (line, col int, ok bool) {
	_, deps := mappingEntry(docMapping(node), "dependencies")
	if deps == nil || deps.Kind != yaml.MappingNode {
		return 0, 0, false
	}
	_, actionNode := mappingEntry(deps, ownerKey)
	if actionNode == nil || actionNode.Kind != yaml.MappingNode {
		return 0, 0, false
	}
	_, usesNode := mappingEntry(actionNode, "uses")
	if usesNode == nil || usesNode.Kind != yaml.SequenceNode {
		return 0, 0, false
	}
	for _, entry := range usesNode.Content {
		if canonicalPinForVersion(entry.Value, lockfileVersion(node)) == canonicalUsed {
			return entry.Line, entry.Column, true
		}
	}
	// Fall back to the uses key position when no individual entry matches.
	return usesNode.Line, usesNode.Column, true
}

// validateLegacyDigestSuffixes enforces, for v0.0.1 lockfiles, that the
// algo-hex digest carried by a legacy pin key
// (OWNER/REPO@REF:ALGO-HEX) agrees with the digest recorded in the matching
// dependency body. Migration strips the suffix and keeps the body, so a
// disagreement would otherwise silently discard the requested pin and let the
// action resolve to an unverified, possibly attacker-chosen commit.
//
// It inspects every place a legacy pin appears: dependency keys, action uses
// entries, and workflow closure entries.
func validateLegacyDigestSuffixes(f *File) *ParseError {
	if f.Version != "v0.0.1" {
		return nil
	}
	root := docMapping(f.node)
	_, depsNode := mappingEntry(root, "dependencies")
	_, workflowsNode := mappingEntry(root, "workflows")

	if pe := checkLegacyDepKeyDigests(depsNode); pe != nil {
		return pe
	}
	if pe := checkLegacyUsesDigests(f, depsNode); pe != nil {
		return pe
	}
	return checkLegacyWorkflowDigests(f, workflowsNode)
}

// checkLegacyDepKeyDigests compares each dependency key's legacy digest suffix
// against the body's commit digest.
func checkLegacyDepKeyDigests(depsNode *yaml.Node) *ParseError {
	if depsNode == nil || depsNode.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(depsNode.Content); i += 2 {
		keyNode := depsNode.Content[i]
		actionNode := depsNode.Content[i+1]

		suffix, hasSuffix := legacyDigestSuffix(keyNode.Value)
		if !hasSuffix {
			continue
		}
		bodyDigest := bodyCommitDigest(actionNode)
		if bodyDigest != "" && !strings.EqualFold(suffix, bodyDigest) {
			return &ParseError{
				Line:   keyNode.Line,
				Column: keyNode.Column,
				Msg: fmt.Sprintf(
					"legacy pin key digest %q does not match the dependency commit digest %q for %q",
					suffix, bodyDigest, keyNode.Value,
				),
			}
		}
	}
	return nil
}

// checkLegacyUsesDigests compares the legacy digest suffix of each uses entry
// against the commit digest of the dependency it resolves to.
func checkLegacyUsesDigests(f *File, depsNode *yaml.Node) *ParseError {
	if depsNode == nil || depsNode.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(depsNode.Content); i += 2 {
		ownerKeyNode := depsNode.Content[i]
		actionNode := depsNode.Content[i+1]
		if actionNode.Kind != yaml.MappingNode {
			continue
		}
		_, usesNode := mappingEntry(actionNode, "uses")
		if usesNode == nil || usesNode.Kind != yaml.SequenceNode {
			continue
		}
		for _, entry := range usesNode.Content {
			suffix, hasSuffix := legacyDigestSuffix(entry.Value)
			if !hasSuffix {
				continue
			}
			pin, ok := parsePinV001(entry.Value)
			if !ok {
				continue // malformed entry is rejected during canonicalization
			}
			target, exists := f.Dependencies[pin.String()]
			if !exists {
				continue // dangling reference is rejected by graph integrity
			}
			bodyDigest := digestFromAlgoHex(target.Commit)
			if bodyDigest != "" && !strings.EqualFold(suffix, bodyDigest) {
				return &ParseError{
					Line:   entry.Line,
					Column: entry.Column,
					Msg: fmt.Sprintf(
						"legacy uses digest %q in dependency %q does not match the resolved commit digest %q for %q",
						suffix, ownerKeyNode.Value, bodyDigest, pin.String(),
					),
				}
			}
		}
	}
	return nil
}

// checkLegacyWorkflowDigests compares the legacy digest suffix of each
// workflow closure entry against the resolved dependency's commit digest.
func checkLegacyWorkflowDigests(f *File, workflowsNode *yaml.Node) *ParseError {
	if workflowsNode == nil || workflowsNode.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(workflowsNode.Content); i += 2 {
		pathNode := workflowsNode.Content[i]
		seq := workflowsNode.Content[i+1]
		if seq.Kind != yaml.SequenceNode {
			continue
		}
		for _, entry := range seq.Content {
			suffix, hasSuffix := legacyDigestSuffix(entry.Value)
			if !hasSuffix {
				continue
			}
			pin, ok := parsePinV001(entry.Value)
			if !ok {
				continue
			}
			target, exists := f.Dependencies[pin.String()]
			if !exists {
				continue
			}
			bodyDigest := digestFromAlgoHex(target.Commit)
			if bodyDigest != "" && !strings.EqualFold(suffix, bodyDigest) {
				return &ParseError{
					Line:   entry.Line,
					Column: entry.Column,
					Msg: fmt.Sprintf(
						"workflow %q requests legacy digest %q for %q but the locked commit digest is %q",
						pathNode.Value, suffix, pin.String(), bodyDigest,
					),
				}
			}
		}
	}
	return nil
}

// legacyDigestSuffix splits a v0.0.1 pin key into the algo-hex suffix after
// the final colon. Returns ("", false) when no algo-hex suffix is present.
func legacyDigestSuffix(rawPin string) (digest string, ok bool) {
	colonIdx := strings.LastIndexByte(rawPin, ':')
	if colonIdx <= 0 || colonIdx == len(rawPin)-1 {
		return "", false
	}
	suffix := rawPin[colonIdx+1:]
	if !looksLikeAlgoHex(suffix) {
		return "", false
	}
	return digestFromAlgoHex(suffix), true
}

// digestFromAlgoHex returns the lowercase hex portion of an "algo-hex"
// string, or "" when the shape is wrong.
func digestFromAlgoHex(algoHex string) string {
	dashIdx := strings.IndexByte(algoHex, '-')
	if dashIdx <= 0 || dashIdx == len(algoHex)-1 {
		return ""
	}
	return strings.ToLower(algoHex[dashIdx+1:])
}

// bodyCommitDigest reads the lowercase hex digest from an action mapping's
// commit field, or "" when absent or malformed.
func bodyCommitDigest(actionNode *yaml.Node) string {
	_, commitNode := mappingEntry(actionNode, "commit")
	if commitNode == nil {
		return ""
	}
	return digestFromAlgoHex(commitNode.Value)
}

// lockfileVersion reads the declared schema version from the retained YAML
// node. Returns "" when the version field is absent.
func lockfileVersion(node *yaml.Node) string {
	_, versionNode := mappingEntry(docMapping(node), "version")
	if versionNode == nil {
		return ""
	}
	return versionNode.Value
}

// sortStrings is a tiny insertion sort to avoid pulling in the sort package
// for the small, nearly-ordered workflow key sets seen in lockfiles.
func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j-1] > values[j]; j-- {
			values[j-1], values[j] = values[j], values[j-1]
		}
	}
}
