package main

import (
	"sort"
	"strings"
)

type ScopeWithActions struct {
	Path    string
	Actions []string
}

/*
algorithm outline:
 1. get g related to the subject
 2. need further filtering based on domain matching function, here need to be concern about two things:
    consider domain org/1/project/p9
    - then all the policies with domain org/1/project/p9/* should be considered  (child level scopes)
    - also policies with domain , org/1/* (parent level wildcard) should also be considered
 3. for each matching role, get its permissions
 4. sort the scopes based on depth, wildcards(easier for tree building)
 5. build tree while skipping scopes covered by ancestor wildcards
*/
func sortScopes(scopes []ScopeWithActions) {
	sort.Slice(scopes, func(i, j int) bool {
		pathI := scopes[i].Path
		pathJ := scopes[j].Path

		// Primary: sort by depth (number of segments)
		depthI := strings.Count(pathI, "/") + 1
		depthJ := strings.Count(pathJ, "/") + 1

		if depthI != depthJ {
			return depthI < depthJ
		}

		// Secondary: wildcards before specific IDs at same depth
		wildcardI := strings.HasSuffix(pathI, "/*")
		wildcardJ := strings.HasSuffix(pathJ, "/*")

		if wildcardI != wildcardJ {
			return wildcardI // true (wildcard) comes before false (specific)
		}

		// Tertiary: lexicographic for deterministic ordering
		return pathI < pathJ
	})
}

type HierarchyNodeV2 struct {
	Type     string            `json:"type"`
	ID       string            `json:"id"`
	Actions  []string          `json:"actions,omitempty"`
	Scope    string            `json:"scope,omitempty"`
	Children []HierarchyNodeV2 `json:"children,omitempty"`
}

func buildTree(scopes []ScopeWithActions) *HierarchyNodeV2 {
	// Sort first
	sortScopes(scopes)

	root := &HierarchyNodeV2{}

	for _, scope := range scopes {
		// Check if covered by ancestor wildcard
		if isCoveredByAncestor(scope, root) {
			continue
		}

		addToTree(root, scope)
	}

	return root
}

func isCoveredByAncestor(scope ScopeWithActions, root *HierarchyNodeV2) bool {
	segments := strings.Split(strings.TrimSuffix(scope.Path, "/*"), "/")

	current := root
	wildcardActions := []string{}

	// Walk down the tree collecting wildcard permissions
	for i := 0; i < len(segments); i += 2 {
		if i+1 >= len(segments) {
			break
		}

		resourceType := segments[i]
		resourceID := segments[i+1]

		// Find matching child
		found := false
		for _, child := range current.Children {
			if child.Type == resourceType && (child.ID == resourceID || child.ID == "*") {
				if child.ID == "*" {
					// Wildcard node - collect actions
					wildcardActions = append(wildcardActions, child.Actions...)
				}
				current = &child
				found = true
				break
			}
		}

		if !found {
			return false // No ancestor wildcard covers this
		}
	}

	// Check if scope's actions are subset of wildcard actions
	return isSubset(scope.Actions, wildcardActions)
}

func isSubset(subset, superset []string) bool {
	if len(subset) == 0 {
		return false
	}

	superMap := make(map[string]bool)
	for _, action := range superset {
		superMap[action] = true
	}

	for _, action := range subset {
		if !superMap[action] {
			return false
		}
	}

	return true
}

func addToTree(root *HierarchyNodeV2, scope ScopeWithActions) {
	path := strings.TrimSuffix(scope.Path, "/*")
	segments := strings.Split(path, "/")
	isWildcard := strings.HasSuffix(scope.Path, "/*")

	current := root

	for i := 0; i < len(segments); i += 2 {
		if i+1 >= len(segments) {
			break
		}

		resourceType := segments[i]
		resourceID := segments[i+1]

		// Check if child already exists
		var childNode *HierarchyNodeV2
		for j := range current.Children {
			if current.Children[j].Type == resourceType && current.Children[j].ID == resourceID {
				childNode = &current.Children[j]
				break
			}
		}

		// Create new child if doesn't exist
		if childNode == nil {
			newNode := HierarchyNodeV2{
				Type: resourceType,
				ID:   resourceID,
			}
			current.Children = append(current.Children, newNode)
			childNode = &current.Children[len(current.Children)-1]
		}

		// If this is the final segment and it's a wildcard or leaf node
		if i+2 >= len(segments) {
			if isWildcard {
				childNode.ID = "*"
			}
			childNode.Actions = scope.Actions
			childNode.Scope = scope.Path
		}

		current = childNode
	}
}
