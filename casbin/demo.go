package main

import (
	"fmt"
	"log"

	"github.com/casbin/casbin/v2"
)

func main() {
	// Create enforcer with Option 2 model and policies
	enforcer, err := casbin.NewEnforcer("option2/model.conf", "option2/policy.csv")
	if err != nil {
		log.Fatalf("Error creating enforcer: %v", err)
	}
	// Requirement 1: Check whether a user can perform action X on resource Y
	testAccessChecks(enforcer)

}

// Requirement: Check whether user can perform action X on resource Y
func testAccessChecks(enforcer *casbin.Enforcer) {

	scenarios := []struct {
		description string
		subject     string
		resource    string
		action      string
	}{
		{ // derived from org level role
			"Alice can deploy payment components as admin",
			"alice", "component:billing", "view",
		},
		{ // derived from project level role
			"full read access to dev-team on all components in projectA",
			"teamA", "component:acme/payments/billing", "view",
		},
		// promotion check, need two checks
		{

			"team DevOps can promote billing component",
			"teamDevOps", "component:billing", "promote",
		},
		{
			"team DevOps can deploy to staging environment",
			"teamDevOps", "env:acme/staging", "deploy_to",
		},
	}

	for _, scenario := range scenarios {
		result, _ := enforcer.Enforce(
			scenario.subject,
			scenario.resource,
			scenario.action,
		)
		fmt.Printf("Scenario: %s || result=%v\n", scenario.description, result)
		testGetUserPermissions(enforcer, scenario.subject)
		fmt.Println("--------------------------------------------------")

	}
}

// Requirement: UI needs to get permissions for a given user
func testGetUserPermissions(enforcer *casbin.Enforcer, user string) {
	// Get all permissions for user
	permissions, _ := enforcer.GetPermissionsForUser(user)
	implicitPermissions, _ := enforcer.GetImplicitPermissionsForUser(user)
	roles, _ := enforcer.GetRolesForUser(user)
	implicitRoles, _ := enforcer.GetImplicitRolesForUser(user)
	fmt.Printf("user: %s\n", user)
	fmt.Printf("Direct Permissions: %v\n", permissions)
	fmt.Printf("Inherited Permissions: %v\n", implicitPermissions)
	fmt.Printf("Roles: %v\n", roles)
	fmt.Printf("Inherited Roles: %v\n", implicitRoles)

}
