package main

import (
	"encoding/csv"
	"fmt"
	"math/rand"
	"os"
)

// PolicyEntry represents a policy rule in the Casbin model
type PolicyEntry struct {
	Grp  string // e.g., "group:team-100"
	Dom  string // e.g., "//openchoreo.orgs/org001"
	Role string // e.g., "roles/developer.450"
	Eft  string // "allow" or "deny"
	Cond string // JSON: "{}" or "{\"allowedEnvironments\":[\"development\"]}"
}

// RoleDefEntry represents a role-to-action mapping (g rule in Casbin)
type RoleDefEntry struct {
	Action string // e.g., "component.create"
	Role   string // e.g., "roles/developer.450"
}

// EnforceScenario represents a test scenario for authorization checks
type EnforceScenario struct {
	Groups  []string // Multiple groups for realistic testing (min 3)
	Domain  string
	Action  string
	Context string // JSON string
}

// generateRoles creates a specified number of roles with realistic permission distributions
func generateRoles(count int) map[string][]string {
	roles := make(map[string][]string)

	actionTypes := []string{"component", "deployment", "project", "ou", "org"}
	verbs := []string{"create", "read", "update", "delete", "deploy", "view"}

	for i := 0; i < count; i++ {
		var roleType string
		var permCount int

		// Distribute roles by type and permission count
		// 40% viewer/reader roles (3-5 permissions)
		// 40% developer/editor roles (6-10 permissions)
		// 15% admin roles (11-20 permissions)
		// 5% super admin roles (20+ permissions)
		switch {
		case i < count*40/100:
			roleType = "viewer"
			permCount = 3 + rand.Intn(3)
		case i < count*80/100:
			roleType = "developer"
			permCount = 6 + rand.Intn(5)
		case i < count*95/100:
			roleType = "admin"
			permCount = 11 + rand.Intn(10)
		default:
			roleType = "superadmin"
			permCount = 20 + rand.Intn(10)
		}

		roleName := fmt.Sprintf("roles/%s.%d", roleType, i)
		permissions := make([]string, 0, permCount)

		// Generate unique permissions
		permSet := make(map[string]bool)
		for len(permSet) < permCount {
			action := actionTypes[rand.Intn(len(actionTypes))]
			verb := verbs[rand.Intn(len(verbs))]
			perm := fmt.Sprintf("%s.%s", action, verb)
			permSet[perm] = true
		}

		for perm := range permSet {
			permissions = append(permissions, perm)
		}

		roles[roleName] = permissions
	}

	return roles
}

// generateRoleDefinitions creates action-to-role mappings (g rules)
func generateRoleDefinitions(roles map[string][]string) []RoleDefEntry {
	var roleDefs []RoleDefEntry

	for roleName, permissions := range roles {
		for _, perm := range permissions {
			roleDefs = append(roleDefs, RoleDefEntry{
				Action: perm,
				Role:   roleName,
			})
		}
	}

	return roleDefs
}

// generatePolicies creates a specified number of role bindings across a realistic resource hierarchy
func generatePolicies(count int, roles map[string][]string) []PolicyEntry {
	policies := make([]PolicyEntry, 0, count)

	// Extract role names
	roleNames := make([]string, 0, len(roles))
	for roleName := range roles {
		roleNames = append(roleNames, roleName)
	}

	// Resource hierarchy configuration
	numOrgs := 100
	numOUsPerOrg := 50
	numProjectsPerOU := 100
	numComponentsPerProject := 50

	// Group pools - using larger numbers for 100K policies
	numGroups := 10000

	environments := []string{"development", "staging", "production"}

	bindingCount := 0

	// Helper to create a policy
	createPolicy := func(resource, role, effect string, hasCondition bool) {
		if bindingCount >= count {
			return
		}

		group := fmt.Sprintf("group:team-%d", rand.Intn(numGroups))

		var cond string
		if !hasCondition {
			cond = "{}"
		} else {
			if rand.Float64() < 0.8 {
				// Single environment condition
				env := environments[rand.Intn(len(environments))]
				cond = fmt.Sprintf("{\"allowedEnvironments\":[\"%s\"]}", env)
			} else {
				// Multiple environments
				cond = "{\"allowedEnvironments\":[\"development\",\"staging\"]}"
			}
		}

		policies = append(policies, PolicyEntry{
			Grp:  group,
			Dom:  resource,
			Role: roleNames[rand.Intn(len(roleNames))],
			Eft:  effect,
			Cond: cond,
		})
		bindingCount++
	}

	// 1% at org level
	orgBindings := count * 1 / 100
	for i := 0; i < orgBindings && bindingCount < count; i++ {
		orgID := rand.Intn(numOrgs)
		resource := fmt.Sprintf("//openchoreo.orgs/org%03d", orgID)
		effect := "allow"
		if rand.Float64() < 0.05 {
			effect = "deny"
		}
		hasCondition := rand.Float64() < 0.30
		createPolicy(resource, "", effect, hasCondition)
	}

	// 10% at OU level
	ouBindings := count * 10 / 100
	for i := 0; i < ouBindings && bindingCount < count; i++ {
		orgID := rand.Intn(numOrgs)
		ouID := rand.Intn(numOUsPerOrg)
		resource := fmt.Sprintf("//openchoreo.orgs/org%03d/ous/ou%03d", orgID, ouID)
		effect := "allow"
		if rand.Float64() < 0.05 {
			effect = "deny"
		}
		hasCondition := rand.Float64() < 0.30
		createPolicy(resource, "", effect, hasCondition)
	}

	// 30% at project level
	projectBindings := count * 30 / 100
	for i := 0; i < projectBindings && bindingCount < count; i++ {
		orgID := rand.Intn(numOrgs)
		ouID := rand.Intn(numOUsPerOrg)
		projectID := rand.Intn(numProjectsPerOU)
		resource := fmt.Sprintf("//openchoreo.orgs/org%03d/ous/ou%03d/projects/proj%04d", orgID, ouID, projectID)
		effect := "allow"
		if rand.Float64() < 0.05 {
			effect = "deny"
		}
		hasCondition := rand.Float64() < 0.25
		createPolicy(resource, "", effect, hasCondition)
	}

	// 59% at component level (remaining bindings)
	for bindingCount < count {
		orgID := rand.Intn(numOrgs)
		ouID := rand.Intn(numOUsPerOrg)
		projectID := rand.Intn(numProjectsPerOU)
		componentID := rand.Intn(numComponentsPerProject)
		resource := fmt.Sprintf("//openchoreo.orgs/org%03d/ous/ou%03d/projects/proj%04d/components/comp%04d",
			orgID, ouID, projectID, componentID)
		effect := "allow"
		if rand.Float64() < 0.05 {
			effect = "deny"
		}
		hasCondition := rand.Float64() < 0.25
		createPolicy(resource, "", effect, hasCondition)
	}

	return policies
}

// writePolicyCSV writes policies and role definitions to a CSV file
func writePolicyCSV(filename string, policies []PolicyEntry, roleDefs []RoleDefEntry) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write policy entries (p rules)
	for _, policy := range policies {
		record := []string{"p", policy.Grp, policy.Dom, policy.Role, policy.Eft, policy.Cond}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("failed to write policy: %w", err)
		}
	}

	// Write role definitions (g rules)
	for _, roleDef := range roleDefs {
		record := []string{"g", roleDef.Action, roleDef.Role}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("failed to write role definition: %w", err)
		}
	}

	return nil
}

// generateTypicalScenario creates a typical authorization check scenario
func generateTypicalScenario() EnforceScenario {
	// Generate subject with at least 3 groups
	groupID := rand.Intn(10000)
	return EnforceScenario{
		Groups:  []string{fmt.Sprintf("group:team-%d", groupID), fmt.Sprintf("group:team-%d", groupID+1), fmt.Sprintf("group:team-%d", groupID+2)},
		Domain:  "//openchoreo.orgs/org001/ous/ou005/projects/proj0100/components/comp0050",
		Action:  "component.read",
		Context: "{}",
	}
}

// generateScenarioForResource creates an authorization check for a specific resource path
func generateScenarioForResource(resourcePath string) EnforceScenario {
	groupID := rand.Intn(10000)
	return EnforceScenario{
		Groups:  []string{fmt.Sprintf("group:team-%d", groupID), fmt.Sprintf("group:team-%d", groupID+1), fmt.Sprintf("group:team-%d", groupID+2)},
		Domain:  resourcePath,
		Action:  "component.read",
		Context: "{}",
	}
}

// generateScenarioWithGroupCount creates a scenario with specific number of groups
func generateScenarioWithGroupCount(groupCount int) EnforceScenario {
	// Ensure minimum 3 groups
	if groupCount < 3 {
		groupCount = 3
	}

	groupID := rand.Intn(10000)
	groups := make([]string, groupCount)
	for i := 0; i < groupCount; i++ {
		groups[i] = fmt.Sprintf("group:team-%d", groupID+i)
	}

	return EnforceScenario{
		Groups:  groups,
		Domain:  "//openchoreo.orgs/org001/ous/ou005/projects/proj0100/components/comp0050",
		Action:  "component.read",
		Context: "{}",
	}
}

// generateVariedScenarios creates multiple varied authorization check scenarios
func generateVariedScenarios(count int) []EnforceScenario {
	scenarios := make([]EnforceScenario, count)

	actions := []string{"component.create", "component.read", "component.update", "component.delete",
		"deployment.create", "deployment.read", "project.read"}
	envs := []string{"development", "staging", "production"}

	for i := 0; i < count; i++ {
		groupID := rand.Intn(10000)

		// Generate 3-5 groups per subject
		numGroups := 3 + rand.Intn(3)
		groups := make([]string, numGroups)
		for j := 0; j < numGroups; j++ {
			groups[j] = fmt.Sprintf("group:team-%d", groupID+j)
		}

		// Vary resource depth
		var resourcePath string
		depth := rand.Intn(4)
		orgID := rand.Intn(100)
		switch depth {
		case 0: // Org level
			resourcePath = fmt.Sprintf("//openchoreo.orgs/org%03d", orgID)
		case 1: // OU level
			ouID := rand.Intn(50)
			resourcePath = fmt.Sprintf("//openchoreo.orgs/org%03d/ous/ou%03d", orgID, ouID)
		case 2: // Project level
			ouID := rand.Intn(50)
			projectID := rand.Intn(100)
			resourcePath = fmt.Sprintf("//openchoreo.orgs/org%03d/ous/ou%03d/projects/proj%04d", orgID, ouID, projectID)
		case 3: // Component level
			ouID := rand.Intn(50)
			projectID := rand.Intn(100)
			componentID := rand.Intn(50)
			resourcePath = fmt.Sprintf("//openchoreo.orgs/org%03d/ous/ou%03d/projects/proj%04d/components/comp%04d",
				orgID, ouID, projectID, componentID)
		}

		// Vary context (70% empty, 30% with environment)
		var context string
		if rand.Float64() < 0.70 {
			context = "{}"
		} else {
			env := envs[rand.Intn(len(envs))]
			context = fmt.Sprintf("{\"environment\":\"%s\"}", env)
		}

		scenarios[i] = EnforceScenario{
			Groups:  groups,
			Domain:  resourcePath,
			Action:  actions[rand.Intn(len(actions))],
			Context: context,
		}
	}

	return scenarios
}

// generateScenarioForPattern creates specific scenarios for testing different authorization patterns
func generateScenarioForPattern(pattern string) EnforceScenario {
	baseGroups := []string{"group:team-100", "group:team-101", "group:team-102"}
	noPermGroups := []string{"group:team-9997", "group:team-9998", "group:team-9999"}

	switch pattern {
	case "allow-direct-group":
		// Group directly has policy binding
		return EnforceScenario{
			Groups:  baseGroups,
			Domain:  "//openchoreo.orgs/org001/ous/ou001/projects/proj0001",
			Action:  "component.read",
			Context: "{}",
		}

	case "allow-inherited":
		// Permission inherited from parent resource (tests prefixMatch)
		return EnforceScenario{
			Groups:  baseGroups,
			Domain:  "//openchoreo.orgs/org001/ous/ou001/projects/proj0001/components/comp0001",
			Action:  "component.read",
			Context: "{}",
		}

	case "allow-with-condition":
		// Authorization with environment condition check (tests ctxAllowed)
		return EnforceScenario{
			Groups:  baseGroups,
			Domain:  "//openchoreo.orgs/org001/ous/ou001/projects/proj0001",
			Action:  "deployment.create",
			Context: "{\"environment\":\"development\"}",
		}

	case "deny-no-permission":
		// No permission exists (fast-fail path)
		return EnforceScenario{
			Groups:  noPermGroups,
			Domain:  "//openchoreo.orgs/org999/ous/ou999/projects/proj9999",
			Action:  "component.delete",
			Context: "{}",
		}

	case "deny-explicit":
		// Explicit deny effect
		return EnforceScenario{
			Groups:  baseGroups,
			Domain:  "//openchoreo.orgs/org001/ous/ou001/projects/proj0001",
			Action:  "component.delete",
			Context: "{\"environment\":\"production\"}",
		}

	default:
		return generateTypicalScenario()
	}
}
