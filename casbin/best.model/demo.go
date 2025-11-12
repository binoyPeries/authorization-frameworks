package main

import (
	"fmt"
	"log"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/util"
)

type AccessScenario struct {
	description string
	subject     string
	action      string // Now in "resource:verb" format (e.g., "component:view")
	domain      string
	ctx         string
}

func main() {
	enforcer3, err := casbin.NewEnforcer("model.conf", "policy.csv")
	if err != nil {
		log.Fatalf("Error creating enforcer: %v", err)
	}

	enforcer3.AddNamedDomainMatchingFunc("g", "DomainPrefix", util.KeyMatch2)

	// var DomainPrefix rbac.MatchingFunc = func(reqDom, polDom string) bool {
	// 	return reqDom == polDom || strings.HasPrefix(reqDom, polDom+"/")
	// }

	// // Register it for the "g" role system
	// enforcer3.AddNamedDomainMatchingFunc("g", "DomainPrefix", DomainPrefix)

	// enforcer3.BuildRoleLinks()
	scenariosSet3 := []AccessScenario{
		{
			description: "Bob (Reader role) can read components",
			subject:     "bob",
			action:      "component:read",
			domain:      "/org/1/project/p9/component/c3",
			ctx:         "{}",
		},
		{
			description: "Bob (Reader role) cannot deploy components",
			subject:     "bob",
			action:      "component:deploy",
			domain:      "/org/1/project/p9/component/c3",
			ctx:         "{}",
		},
		{
			description: "TeamA (dev role) can create components",
			subject:     "team:teamA",
			action:      "component:create",
			domain:      "/org/1/project/p1/component/c1",
			ctx:         "{}",
		},
		{
			description: "TeamB (dev role) can create components",
			subject:     "team:teamB",
			action:      "component:update",
			domain:      "/org/1/project/p9/component/c1",
			ctx:         "{}",
		},
		{
			description: "TeamA (devops role) can deploy components in project p9",
			subject:     "team:teamA",
			action:      "component:deploy",
			domain:      "/org/2/project/p9/component/c3",
			ctx:         "{}",
		},
		{
			description: "Developer can view components",
			subject:     "group:developer_proj_a",
			action:      "component:view",
			domain:      "/org/1/project/a/component/c1",
			ctx:         "{}",
		},
		{
			description: "Alice (OrgAdmin) can do anything - delete component",
			subject:     "alice",
			action:      "component:delete",
			domain:      "/org/1/project/p9/component/c3",
			ctx:         "{}",
		},
		{
			description: "Team payments (ProjectAdmin) can deploy components in their project",
			subject:     "team:payments",
			action:      "component:deploy",
			domain:      "/org/1/project/p9/component/billing",
			ctx:         "{}",
		},
	}

	// Test Profile Service
	fmt.Println("\n=== Testing Profile Service ===")
	// TBA

	// Requirement 1: Check whether a user U can perform action X on resource Y
	fmt.Println("\n=== Testing Access Checks ===")
	testAccessChecks(enforcer3, scenariosSet3)

}

// Requirement: Check whether user can perform action X on resource Y
func testAccessChecks(enforcer *casbin.Enforcer, scenarios []AccessScenario) {
	for _, scenario := range scenarios {
		result, _ := enforcer.Enforce(
			scenario.subject,
			scenario.action,
			scenario.domain,
			scenario.ctx,
		)
		fmt.Printf("Scenario: %s\n", scenario.description)
		fmt.Printf("Subject: %s, Action: %s, Domain: %s\n", scenario.subject, scenario.action, scenario.domain)
		fmt.Printf("Result: %v\n\n", result)

	}
}
