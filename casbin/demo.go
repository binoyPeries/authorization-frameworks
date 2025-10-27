package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/rbac"
)

type AccessScenario struct {
	description string
	subject     string
	domain      string
	resource    string
	action      string
}

func main() {
	// Create enforcer with Option 1 model and policies
	// enforcer1, err := casbin.NewEnforcer("option1/model.conf", "option1/policy.csv")
	// if err != nil {
	// 	log.Fatalf("Error creating enforcer: %v", err)
	// }
	// scenariosSet1 := []AccessScenario{
	// 	{ // derived from org level role
	// 		"Alice can deploy payment components as admin",
	// 		"alice", "component:billing", "view",
	// 	},
	// 	{ // derived from project level role
	// 		"full read access to dev-team on all components in projectA",
	// 		"teamA", "component:acme/payments/billing", "view",
	// 	},
	// 	// promotion check, need two checks
	// 	{

	// 		"team DevOps can promote billing component",
	// 		"teamDevOps", "component:billing", "promote",
	// 	},
	// 	{
	// 		"team DevOps can deploy to staging environment",
	// 		"teamDevOps", "env:acme/staging", "deploy_to",
	// 	},
	// }
	// // Requirement 1: Check whether a user U can perform action X on resource Y
	// testAccessChecks(enforcer1, scenariosSet1)

	// Create enforcer with Option 3 model and policies
	enforcer3, err := casbin.NewEnforcer("option4/model.conf", "option4/policy.csv")
	var DomainPrefix rbac.MatchingFunc = func(reqDom, polDom string) bool {
		return reqDom == polDom || strings.HasPrefix(reqDom, polDom+"/")
	}

	// Register it for the "g" role system (name it anything you like).
	enforcer3.AddNamedDomainMatchingFunc("g", "DomainPrefix", DomainPrefix)

	if err != nil {
		log.Fatalf("Error creating enforcer: %v", err)
	}
	scenariosSet3 := []AccessScenario{
		{ // derived from org level role
			"TeamA can deploy billing components as proj-deployer",
			"group:teamA", // r.sub
			"org:acme/project:payments/component:billing", // r.dom
			"component", // r.obj
			"deploy",
		},
		{ // derived from org level role
			"TeamB can deploy billing components as proj-deployer",
			"group:teamB", // r.sub
			"org:acme/project:hello/component:billing", // r.dom
			"component", // r.obj
			"deploy",
		},
		{ // derived from org level role
			"TeamB can deploy billing components as proj-deployer",
			"group:teamC", // r.sub
			"org:acme/project:payments/component:hello", // r.dom
			"component", // r.obj
			"deploy",
		},

	}

	// Requirement 1: Check whether a user U can perform action X on resource Y
	testAccessChecks(enforcer3, scenariosSet3)

}

// Requirement: Check whether user can perform action X on resource Y
func testAccessChecks(enforcer *casbin.Enforcer, scenarios []AccessScenario) {
	for _, scenario := range scenarios {
		result, _ := enforcer.Enforce(
			scenario.subject,
			scenario.domain,
			scenario.resource,
			scenario.action,
		)
		fmt.Printf("Scenario: %s\n", scenario.description)
		fmt.Printf("  Result: %v\n\n", result)
		getUserActions(enforcer, scenario.subject, scenario.domain)

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

func getUserActions(enforcer *casbin.Enforcer, user string, domain string) {
	roles := enforcer.GetRolesForUserInDomain(user, domain)
	fmt.Printf("User: %s, Domain: %s, Roles: %v\n", user, domain, roles)
	for _, role := range roles {
		permissions, _ := enforcer.GetFilteredPolicy(0, role)
		fmt.Printf("  Role: %s, Permissions: %v\n", role, permissions)
	}
}
