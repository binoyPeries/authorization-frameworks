package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/casbin/casbin/v2"
)

type AccessScenario struct {
	description  string
	subjects     []string // Array of group ids (e.g., ["group:devs", "group:admins"])
	action       string   // Action string (e.g., "component.create", "deployment.read")
	resourcePath string   // Hierarchical resource path (e.g., "//openchoreo.orgs/acme/project/p1")
	ctx          string   // Context JSON (e.g., {"environment":"production"})
}

// prefixMatch checks if the request resourcePath starts with the policy resourcePath prefix
func prefixMatch(reqResourcePath, polResourcePath string) bool {
	return reqResourcePath == polResourcePath || strings.HasPrefix(reqResourcePath, polResourcePath+"/")
}

// ctxAllowed checks if the request context satisfies the policy conditions
func ctxAllowed(reqCtx, polCond string) bool {
	// If policy has no conditions, allow
	if polCond == "{}" || polCond == "" {
		return true
	}

	// Parse the policy conditions
	var conditions map[string]interface{}
	if err := json.Unmarshal([]byte(polCond), &conditions); err != nil {
		return false
	}

	// Parse the request context
	var context map[string]interface{}
	if err := json.Unmarshal([]byte(reqCtx), &context); err != nil {
		return false
	}

	// Check allowedEnvironments condition
	if allowedEnvs, ok := conditions["allowedEnvironments"].([]interface{}); ok {
		if env, ok := context["environment"].(string); ok {
			for _, allowedEnv := range allowedEnvs {
				if allowedEnvStr, ok := allowedEnv.(string); ok && allowedEnvStr == env {
					return true
				}
			}
			return false
		}
		// If environment is required but not provided in context, deny
		return false
	}

	// No specific conditions to check, allow
	return true
}

func main() {
	enforcer3, err := casbin.NewEnforcer("model.conf", "policy.csv")
	if err != nil {
		log.Fatalf("Error creating enforcer: %v", err)
	}

	// Register custom functions for the matcher
	enforcer3.AddFunction("prefixMatch", func(args ...interface{}) (interface{}, error) {
		reqResourcePath := args[0].(string)
		polResourcePath := args[1].(string)
		return prefixMatch(reqResourcePath, polResourcePath), nil
	})
	enforcer3.AddFunction("ctxAllowed", func(args ...interface{}) (interface{}, error) {
		reqCtx := args[0].(string)
		polCond := args[1].(string)
		return ctxAllowed(reqCtx, polCond), nil
	})
	scenariosSet3 := []AccessScenario{
		{
			description:  "group:devs can create components under //openchoreo.orgs/acme",
			subjects:     []string{"group:devs"},
			action:       "component.create",
			resourcePath: "//openchoreo.orgs/acme/project/p1/component/c1",
			ctx:          "{\"environment\":\"development\"}",
		},
		{
			description:  "group:devs can read components under //openchoreo.orgs/acme",
			subjects:     []string{"group:devs"},
			action:       "component.read",
			resourcePath: "//openchoreo.orgs/acme/project/p2/component/c1",
			ctx:          "{\"environment\":\"development\"}",
		},
		{
			description:  "group:devs can update components under //openchoreo.orgs/acme",
			subjects:     []string{"group:devs"},
			action:       "component.update",
			resourcePath: "//openchoreo.orgs/acme",
			ctx:          "{\"environment\":\"development\"}",
		},
		{
			description:  "group:devs can deploy in dev environment (context condition)",
			subjects:     []string{"group:devs"},
			action:       "deployment.create",
			resourcePath: "//openchoreo.orgs/acme/ous/dev/env/development",
			ctx:          "{\"environment\":\"development\"}",
		},
		{
			description:  "group:devs CANNOT deploy in prod environment (fails context condition)",
			subjects:     []string{"group:devs"},
			action:       "deployment.create",
			resourcePath: "//openchoreo.orgs/acme/ous/dev/env/production",
			ctx:          "{\"environment\":\"production\"}",
		},
		{
			description:  "group:prod-ops can deploy in production (context condition)",
			subjects:     []string{"group:prod-ops"},
			action:       "deployment.create",
			resourcePath: "//openchoreo.orgs/acme/env/production",
			ctx:          "{\"environment\":\"production\"}",
		},
		{
			description:  "group:prod-ops can read deployments in production",
			subjects:     []string{"group:prod-ops"},
			action:       "deployment.read",
			resourcePath: "//openchoreo.orgs/acme",
			ctx:          "{\"environment\":\"production\"}",
		},
		{
			description:  "unknown group cannot access anything",
			subjects:     []string{"group:unknown"},
			action:       "component.read",
			resourcePath: "//openchoreo.orgs/acme",
			ctx:          "{}",
		},
		{
			description:  "group:devs cannot access different org",
			subjects:     []string{"group:devs"},
			action:       "component.read",
			resourcePath: "//openchoreo.orgs/different-org",
			ctx:          "{}",
		},
		{
			description:  "user with multiple groups - at least one has permission",
			subjects:     []string{"group:unknown", "group:devs", "group:guests"},
			action:       "component.read",
			resourcePath: "//openchoreo.orgs/acme",
			ctx:          "{\"environment\":\"development\"}",
		},
		{
			description:  "user with multiple groups - none have permission",
			subjects:     []string{"group:unknown", "group:guests"},
			action:       "component.read",
			resourcePath: "//openchoreo.orgs/acme",
			ctx:          "{\"environment\":\"development\"}",
		},
	}

	// Test Profile Service
	fmt.Println("\n=== Testing Profile Service ===")
	listAllRoles(enforcer3)

	// Requirement 1: Check whether a user U can perform action X on resource Y
	fmt.Println("\n=== Testing Access Checks ===")
	testAccessChecks(enforcer3, scenariosSet3)

}

// Get all roles in the system
func listAllRoles(enforcer *casbin.Enforcer) {
	// Get all unique roles from the grouping policy (g)
	roles, err := enforcer.GetAllRoles()
	if err != nil {
		log.Printf("Error getting roles: %v", err)
		return
	}
	fmt.Println("All roles in system:", roles)
}

// Requirement: Check whether user can perform action X on resource Y
func testAccessChecks(enforcer *casbin.Enforcer, scenarios []AccessScenario) {
	for _, scenario := range scenarios {
		// Check if at least one group in the subjects array has permission
		hasPermission := false
		for _, subject := range scenario.subjects {
			// The request order is: grp, resourcePath, act, ctx (as defined in model.conf)
			result, _ := enforcer.Enforce(
				subject,               // grp
				scenario.resourcePath, // resourcePath
				scenario.action,       // act
				scenario.ctx,          // ctx
			)
			if result {
				hasPermission = true
				break
			}
		}

		fmt.Printf("Scenario: %s\n", scenario.description)
		fmt.Printf("Subjects: %v, Action: %s, ResourcePath: %s\n", scenario.subjects, scenario.action, scenario.resourcePath)
		fmt.Printf("Result: %v\n\n", hasPermission)
	}
}
