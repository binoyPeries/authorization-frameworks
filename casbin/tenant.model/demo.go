package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/casbin/casbin/v2"
)

const pathSeparator = "/"

type AccessScenario struct {
	description string
	subject     string
	action      string // In "resource:verb" format (e.g., "component:view")
	domain      string // Relative path within the organization
	tenant      string // Organization identifier (e.g., "org/acme", "org/techcorp")
	ctx         string
}

func main() {
	enforcer, err := casbin.NewEnforcer("model.conf", "policy.csv")
	if err != nil {
		log.Fatalf("Error creating enforcer: %v", err)
	}

	// Custom domain matching with wildcard support
	// Rules:
	// 1. If policy domain ends with '*':
	//    a. If slash count is even (after trim): match descendants (prefix match) ex: "/project/p1/*" matches "/project/p1/component/c1" ,"/project/p1/api/v1/hello/v2"
	//    b. If slash count is odd (after trim): star is for resource ID (exact level match) ex: "project/p1/component/*" matches "/project/p1/component/c1" but NOT "/project/p1/component/c1/logs/v2"
	// 2. Otherwise: exact match only
	domainPrefixMatch := func(requestDomain string, policyDomain string) bool {
		// Trim both domains once at the start
		reqDomain := strings.Trim(requestDomain, pathSeparator)
		polDomain := strings.Trim(policyDomain, pathSeparator)

		// Rule 2: Exact match only no wildcards
		if !strings.HasSuffix(polDomain, "*") {
			return reqDomain == polDomain
		}

		// Rule 1: Policy domain ends with '*'
		// Get prefix without the trailing '*'
		prefix := polDomain[:len(polDomain)-1]

		// if request is shorter than prefix, it can't match
		if len(reqDomain) < len(prefix) {
			return false
		}

		// Check prefix match and count slashes simultaneously
		slashCount := 0
		for i := 0; i < len(prefix); i++ {
			if reqDomain[i] != prefix[i] {
				return false
			}
			if prefix[i] == '/' {
				slashCount++
			}
		}

		// Rule 1a: Even slash count - match descendants (prefix match)
		// Example: "/project/p1/*" (2 slashes after trim) matches "/project/p1/component/c1" and "/project/p1/api/v1/hello/v2"
		if slashCount%2 == 0 {
			return true
		}

		// Rule 1b: Odd slash count - exact level match
		// Example: "/project/p1/component/*" (3 slashes after trim) matches "/project/p1/component/c1" but NOT "/project/p1/component/c1/logs/v2"
		// Get the remaining part after the prefix (use slice to avoid allocation)
		remaining := reqDomain[len(prefix):]
		remaining = strings.Trim(remaining, pathSeparator)

		// Should have exactly one more segment (no nested paths)n
		if remaining == "" || strings.Contains(remaining, pathSeparator) {
			return false
		}

		return true
	}

	enforcer.AddNamedDomainMatchingFunc("g", "DomainPrefix", domainPrefixMatch)

	scenarios := []AccessScenario{
		// ===== ALICE (OrgAdmin in org/acme, developer in org/techcorp) =====
		{
			description: "[SHOULD PASS] alice (OrgAdmin) can delete components in org/acme",
			subject:     "alice",
			action:      "component:delete",
			domain:      "/project/p9/component/c1",
			tenant:      "org/acme",
			ctx:         "{}",
		},
		{
			description: "[SHOULD PASS] team:teamB (ProjectAdmin) can deploy components in org/acme",
			subject:     "team:teamB",
			action:      "component:view",
			domain:      "/project/p9/component/c3",
			tenant:      "org/acme",
			ctx:         "{}",
		},
		{
			description: "[SHOULD PASS] team:teamA (developer) can view components in org/acme",
			subject:     "team:teamA",
			action:      "component:view",
			domain:      "/project/p8/",
			tenant:      "org/acme",
			ctx:         "{}",
		},
		{
			description: "[SHOULD PASS] team:idk (idk) can create components in org/hello",
			subject:     "team:idk",
			action:      "component:create",
			domain:      "/project/p10/component/c1",
			tenant:      "org/hello",
			ctx:         "{}",
		},
		// {
		// 	description: "[SHOULD PASS] alice (OrgAdmin) can do anything (*) in org/acme",
		// 	subject:     "alice",
		// 	action:      "project:delete",
		// 	domain:      "/*",
		// 	tenant:      "org/acme",
		// 	ctx:         "{}",
		// },
		// {
		// 	description: "[SHOULD PASS] alice (developer) can view components in org/techcorp",
		// 	subject:     "alice",
		// 	action:      "component:view",
		// 	domain:      "/project/p5/component/c1",
		// 	tenant:      "org/techcorp",
		// 	ctx:         "{}",
		// },
		// {
		// 	description: "[SHOULD FAIL] alice (developer) CANNOT delete in org/techcorp (lacks permission)",
		// 	subject:     "alice",
		// 	action:      "component:delete",
		// 	domain:      "/project/p5/component/c1",
		// 	tenant:      "org/techcorp",
		// 	ctx:         "{}",
		// },

		// // ===== BOB (Reader in org/acme only) =====
		// {
		// 	description: "[SHOULD PASS] bob (Reader) can read components in org/acme",
		// 	subject:     "bob",
		// 	action:      "component:read",
		// 	domain:      "/project/p8/component/c1",
		// 	tenant:      "org/acme",
		// 	ctx:         "{}",
		// },
		// {
		// 	description: "[SHOULD PASS] bob (Reader with /* domain) can read in any project in org/acme",
		// 	subject:     "bob",
		// 	action:      "component:read",
		// 	domain:      "/project/p9/component/c1",
		// 	tenant:      "org/acme",
		// 	ctx:         "{}",
		// },
		// {
		// 	description: "[SHOULD FAIL] bob (Reader) CANNOT update components (lacks permission)",
		// 	subject:     "bob",
		// 	action:      "component:update",
		// 	domain:      "/project/p8/component/c1",
		// 	tenant:      "org/acme",
		// 	ctx:         "{}",
		// },
		// {
		// 	description: "[SHOULD FAIL] bob (Reader) CANNOT deploy components (lacks permission)",
		// 	subject:     "bob",
		// 	action:      "component:deploy",
		// 	domain:      "/project/p8/component/c1",
		// 	tenant:      "org/acme",
		// 	ctx:         "{}",
		// },
		// {
		// 	description: "[SHOULD FAIL] bob CANNOT access org/techcorp (no role assigned)",
		// 	subject:     "bob",
		// 	action:      "component:read",
		// 	domain:      "/project/p1/component/c1",
		// 	tenant:      "org/techcorp",
		// 	ctx:         "{}",
		// },

		// // ===== TEAM:PAYMENTS (ProjectAdmin in specific projects) =====
		// {
		// 	description: "[SHOULD PASS] team:payments (ProjectAdmin) can deploy in org/acme/p9",
		// 	subject:     "team:payments",
		// 	action:      "component:deploy",
		// 	domain:      "/project/p9/component/billing",
		// 	tenant:      "org/acme",
		// 	ctx:         "{}",
		// },
		// {
		// 	description: "[SHOULD PASS] team:payments (ProjectAdmin) can delete projects in org/acme/p9",
		// 	subject:     "team:payments",
		// 	action:      "project:delete",
		// 	domain:      "/project/p9/api",
		// 	tenant:      "org/acme",
		// 	ctx:         "{}",
		// },
		// {
		// 	description: "[SHOULD PASS] team:payments (ProjectAdmin) can read components in org/techcorp/p5",
		// 	subject:     "team:payments",
		// 	action:      "component:read",
		// 	domain:      "/project/p5/component/api",
		// 	tenant:      "org/techcorp",
		// 	ctx:         "{}",
		// },
		// {
		// 	description: "[SHOULD FAIL] team:payments CANNOT access org/acme/p8 (domain mismatch)",
		// 	subject:     "team:payments",
		// 	action:      "component:deploy",
		// 	domain:      "/project/p8/component/c1",
		// 	tenant:      "org/acme",
		// 	ctx:         "{}",
		// },
		// {
		// 	description: "[SHOULD FAIL] team:payments CANNOT access org/techcorp/p9 (domain mismatch)",
		// 	subject:     "team:payments",
		// 	action:      "component:deploy",
		// 	domain:      "/project/p9/component/c1",
		// 	tenant:      "org/techcorp",
		// 	ctx:         "{}",
		// },

		// // ===== TEAM:TEAMA (dev in org/acme/p8, devops in org/techcorp/p9) =====
		// {
		// 	description: "[SHOULD PASS] team:teamA (dev role) can do component:* in org/acme/p8",
		// 	subject:     "team:teamA",
		// 	action:      "component:create",
		// 	domain:      "/project/p8/component/c1",
		// 	tenant:      "org/acme",
		// 	ctx:         "{}",
		// },
		// {
		// 	description: "[SHOULD PASS] team:teamA (dev role) can deploy in org/acme/p8",
		// 	subject:     "team:teamA",
		// 	action:      "component:deploy",
		// 	domain:      "/project/p8/component/c1",
		// 	tenant:      "org/acme",
		// 	ctx:         "{}",
		// },
		// {
		// 	description: "[SHOULD FAIL] team:teamA CANNOT access org/acme/p9 (domain mismatch)",
		// 	subject:     "team:teamA",
		// 	action:      "component:create",
		// 	domain:      "/project/p9/component/c1",
		// 	tenant:      "org/acme",
		// 	ctx:         "{}",
		// },
		// {
		// 	description: "[SHOULD PASS] team:teamA (devops role) can deploy in org/techcorp/p9",
		// 	subject:     "team:teamA",
		// 	action:      "component:deploy",
		// 	domain:      "/project/p9/component/c1",
		// 	tenant:      "org/techcorp",
		// 	ctx:         "{}",
		// },
		// {
		// 	description: "[SHOULD FAIL] team:teamA (devops role) CANNOT view in org/techcorp/p9 (lacks permission)",
		// 	subject:     "team:teamA",
		// 	action:      "component:view",
		// 	domain:      "/project/p9/component/c1",
		// 	tenant:      "org/techcorp",
		// 	ctx:         "{}",
		// },

		// // ===== TEAM:TEAMB (developer in org/acme/p9/component/c3) =====
		// {
		// 	description: "[SHOULD PASS] team:teamB (developer) can view org/acme/p9/component/c3",
		// 	subject:     "team:teamB",
		// 	action:      "component:view",
		// 	domain:      "/project/p9/component/c3",
		// 	tenant:      "org/acme",
		// 	ctx:         "{}",
		// },
		// {
		// 	description: "[SHOULD FAIL] team:teamB CANNOT access org/acme/p9/component/c1 (domain mismatch)",
		// 	subject:     "team:teamB",
		// 	action:      "component:view",
		// 	domain:      "/project/p9/component/c1",
		// 	tenant:      "org/acme",
		// 	ctx:         "{}",
		// },
		// {
		// 	description: "[SHOULD FAIL] team:teamB (developer) CANNOT deploy (lacks permission)",
		// 	subject:     "team:teamB",
		// 	action:      "component:deploy",
		// 	domain:      "/project/p9/component/c3",
		// 	tenant:      "org/acme",
		// 	ctx:         "{}",
		// },

		// // ===== CHARLIE (OrgAdmin in org/techcorp only) =====
		// {
		// 	description: "[SHOULD PASS] charlie (OrgAdmin) can do anything in org/techcorp",
		// 	subject:     "charlie",
		// 	action:      "project:delete",
		// 	domain:      "/project/p5/api",
		// 	tenant:      "org/techcorp",
		// 	ctx:         "{}",
		// },
		// {
		// 	description: "[SHOULD PASS] charlie (OrgAdmin) can delete components in org/techcorp",
		// 	subject:     "charlie",
		// 	action:      "component:delete",
		// 	domain:      "/project/p9/component/c1",
		// 	tenant:      "org/techcorp",
		// 	ctx:         "{}",
		// },
		// {
		// 	description: "[SHOULD FAIL] charlie CANNOT access org/acme (no role assigned)",
		// 	subject:     "charlie",
		// 	action:      "component:view",
		// 	domain:      "/*",
		// 	tenant:      "org/acme",
		// 	ctx:         "{}",
		// },

		// // ===== SVC:CI-RUNNER (ProjectAdmin in org/acme/p9) =====
		// {
		// 	description: "[SHOULD PASS] svc:ci-runner (ProjectAdmin) can deploy in org/acme/p9",
		// 	subject:     "svc:ci-runner",
		// 	action:      "component:deploy",
		// 	domain:      "/project/p9/component/api",
		// 	tenant:      "org/acme",
		// 	ctx:         "{}",
		// },
		// {
		// 	description: "[SHOULD PASS] svc:ci-runner (ProjectAdmin) can read components in org/acme/p9",
		// 	subject:     "svc:ci-runner",
		// 	action:      "component:read",
		// 	domain:      "/project/p9/component/api",
		// 	tenant:      "org/acme",
		// 	ctx:         "{}",
		// },
		// {
		// 	description: "[SHOULD FAIL] svc:ci-runner CANNOT access org/acme/p8 (domain mismatch)",
		// 	subject:     "svc:ci-runner",
		// 	action:      "component:deploy",
		// 	domain:      "/project/p8/component/c1",
		// 	tenant:      "org/acme",
		// 	ctx:         "{}",
		// },

		// // ===== CROSS-ORG ISOLATION TESTS =====
		// {
		// 	description: "[SHOULD FAIL] alice CANNOT use org/acme permissions in org/techcorp",
		// 	subject:     "alice",
		// 	action:      "project:delete",
		// 	domain:      "/*",
		// 	tenant:      "org/techcorp",
		// 	ctx:         "{}",
		// },
		// {
		// 	description: "[SHOULD FAIL] Non-existent user CANNOT access anything",
		// 	subject:     "unknown-user",
		// 	action:      "component:read",
		// 	domain:      "/*",
		// 	tenant:      "org/acme",
		// 	ctx:         "{}",
		// },
		// {
		// 	description: "[SHOULD FAIL] alice CANNOT access non-existent org",
		// 	subject:     "alice",
		// 	action:      "component:view",
		// 	domain:      "/*",
		// 	tenant:      "org/nonexistent",
		// 	ctx:         "{}",
		// },
	}

	// Test all scenarios
	fmt.Println("\n=== Testing Tenant-Based Authorization with org/* Wildcard Support ===")
	testAccessChecks(enforcer, scenarios)

	// Print summary
	fmt.Println("\n=== Summary ===")
	fmt.Println("Key Features Demonstrated:")
	fmt.Println("1. Global roles (org/*) work across ALL organizations")
	fmt.Println("2. Organization-specific roles are isolated per organization")
	fmt.Println("3. Domain-based hierarchical access control within organizations")
	fmt.Println("4. Users can have different roles in different organizations")
}

// Requirement: Check whether user can perform action X on resource Y in tenant Z
func testAccessChecks(enforcer *casbin.Enforcer, scenarios []AccessScenario) {
	passCount := 0
	failCount := 0

	for i, scenario := range scenarios {
		result, _ := enforcer.Enforce(
			scenario.subject,
			scenario.action,
			scenario.domain,
			scenario.tenant,
			scenario.ctx,
		)

		fmt.Printf("\n[%d] %s\n", i+1, scenario.description)
		fmt.Printf("    Subject: %s\n", scenario.subject)
		fmt.Printf("    Action:  %s\n", scenario.action)
		fmt.Printf("    Domain:  %s\n", scenario.domain)
		fmt.Printf("    Tenant:  %s\n", scenario.tenant)
		fmt.Printf("    Result:  %v", result)

		if result {
			fmt.Printf(" ✅\n")
			passCount++
		} else {
			fmt.Printf(" ❌\n")
			failCount++
		}
	}

	fmt.Printf("\n\nTotal Scenarios: %d | Passed: %d | Failed: %d\n", len(scenarios), passCount, failCount)
}
