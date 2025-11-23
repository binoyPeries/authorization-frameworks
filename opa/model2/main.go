package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
)

// AuthzInput represents the authorization request input
type AuthzInput struct {
	Principal Principal `json:"principal"`
	Action    string    `json:"action"`
	Resource  Resource  `json:"resource"`
	Context   Context   `json:"context"`
}

type Principal struct {
	ID     string   `json:"id"`
	Groups []string `json:"groups"`
}

type Resource struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type Context struct {
	Time string `json:"time"`
}

// AuthzResult represents the authorization decision
type AuthzResult struct {
	Allow bool `json:"allow"`
	Deny  bool `json:"deny"`
}

func main() {
	fmt.Println("========================================")
	fmt.Println("OPA Authorization Model Test Suite")
	fmt.Println("========================================")
	fmt.Println()

	// Load policy
	policyContent, err := os.ReadFile("policy.rego")
	if err != nil {
		log.Fatalf("Failed to read policy file: %v", err)
	}

	// Embedded roles data
	rolesData := map[string]interface{}{
		"roles/component.developer": []string{
			"component.create",
			"component.read",
			"component.update",
			"component.delete",
		},
		"roles/component.viewer": []string{
			"component.read",
		},
		"roles/env.deployer": []string{
			"deployment.create",
			"deployment.read",
			"deployment.update",
		},
		"roles/env.viewer": []string{
			"deployment.read",
		},
		"roles/project.admin": []string{
			"project.create",
			"project.read",
			"project.update",
			"project.delete",
			"component.create",
			"component.read",
			"component.update",
			"component.delete",
			"deployment.create",
			"deployment.read",
			"deployment.update",
			"deployment.delete",
		},
		"roles/org.admin": []string{
			"org.read",
			"org.update",
			"ou.create",
			"ou.read",
			"ou.update",
			"ou.delete",
			"project.create",
			"project.read",
			"project.update",
			"project.delete",
			"component.create",
			"component.read",
			"component.update",
			"component.delete",
			"deployment.create",
			"deployment.read",
			"deployment.update",
			"deployment.delete",
		},
	}

	// Embedded bindings data
	bindingsData := map[string]interface{}{
		"bindings": []interface{}{
			map[string]interface{}{
				"resource": "//openchoreo.orgs/acme",
				"role":     "roles/org.admin",
				"members": []string{
					"user:admin@acme.com",
					"group:org-admins",
				},
				"effect":    "allow",
				"condition": nil,
			},
			map[string]interface{}{
				"resource": "//openchoreo.orgs/acme/ous/devs/hello",
				"role":     "roles/component.developer",
				"members": []string{
					"group:devs",
					"user:alice",
				},
				"effect":    "allow",
				"condition": nil,
			},
			map[string]interface{}{
				"resource": "//openchoreo.orgs/acme/ous/prod",
				"role":     "roles/component.viewer",
				"members": []string{
					"group:devs",
				},
				"effect":    "allow",
				"condition": nil,
			},
			map[string]interface{}{
				"resource": "//openchoreo.orgs/acme/ous/prod",
				"role":     "roles/env.deployer",
				"members": []string{
					"group:prod-deployers",
					"user:bob",
				},
				"effect":    "allow",
				"condition": nil,
			},
			map[string]interface{}{
				"resource": "//openchoreo.orgs/acme/ous/dev/projects/payments",
				"role":     "roles/project.admin",
				"members": []string{
					"user:charlie",
					"group:payments-team",
				},
				"effect":    "allow",
				"condition": nil,
			},
			map[string]interface{}{
				"resource": "//openchoreo.orgs/acme/ous/dev/projects/payments",
				"role":     "roles/component.developer",
				"members": []string{
					"user:eve",
				},
				"effect":    "allow",
				"condition": nil,
			},
		},
	}

	// Combine data into the structure expected by the policy
	data := map[string]interface{}{
		"roles": rolesData,
		"iam":   bindingsData,
	}

	// Create OPA query evaluator
	ctx := context.Background()

	// Create a store with the data
	store := inmem.NewFromObject(data)

	query, err := rego.New(
		rego.Query("data.openchoreo.authz"),
		rego.Module("policy.rego", string(policyContent)),
		rego.Store(store),
	).PrepareForEval(ctx)

	if err != nil {
		log.Fatalf("Failed to prepare OPA query: %v", err)
	}

	fmt.Println("✓ OPA policy loaded successfully")
	fmt.Printf("  Loaded %d roles\n", len(rolesData))
	fmt.Printf("  Loaded %d bindings\n", len(bindingsData["bindings"].([]interface{})))
	fmt.Println()

	// Test scenarios with embedded test data
	testScenarios := []struct {
		name        string
		input       AuthzInput
		expectAllow bool
		expectDeny  bool
	}{
		{
			name: "User alice creating component (should ALLOW)",
			input: AuthzInput{
				Principal: Principal{
					ID:     "group:devs",
					Groups: []string{"group:devs", "group:ou-dev"},
				},
				Action: "component.create",
				Resource: Resource{
					Name: "//openchoreo.orgs/",
					Type: "project",
				},
				Context: Context{
					Time: "2025-11-21T09:00:00Z",
				},
			},
			expectAllow: true,
			expectDeny:  false,
		},
		// {
		// 	name: "User eve with explicit deny (should DENY)",
		// 	input: AuthzInput{
		// 		Principal: Principal{
		// 			ID:     "user:eve",
		// 			Groups: []string{"group:devs"},
		// 		},
		// 		Action: "component.create",
		// 		Resource: Resource{
		// 			Name: "//openchoreo.orgs/acme/ous/dev/projects/payments/components/api",
		// 			Type: "component",
		// 		},
		// 		Context: Context{
		// 			Time: "2025-11-21T09:00:00Z",
		// 		},
		// 	},
		// 	expectAllow: false,
		// 	expectDeny:  true,
		// },
		// {
		// 	name: "Unknown user (should be UNAUTHORIZED)",
		// 	input: AuthzInput{
		// 		Principal: Principal{
		// 			ID:     "user:unknown",
		// 			Groups: []string{},
		// 		},
		// 		Action: "component.delete",
		// 		Resource: Resource{
		// 			Name: "//openchoreo.orgs/acme/ous/prod/projects/billing",
		// 			Type: "project",
		// 		},
		// 		Context: Context{
		// 			Time: "2025-11-21T09:00:00Z",
		// 		},
		// 	},
		// 	expectAllow: false,
		// 	expectDeny:  false,
		// },
		// {
		// 	name: "Org admin with inherited permissions (should ALLOW)",
		// 	input: AuthzInput{
		// 		Principal: Principal{
		// 			ID:     "user:admin@acme.com",
		// 			Groups: []string{"group:org-admins"},
		// 		},
		// 		Action: "component.delete",
		// 		Resource: Resource{
		// 			Name: "//openchoreo.orgs/acme/ous/dev/projects/payments/components/api",
		// 			Type: "component",
		// 		},
		// 		Context: Context{
		// 			Time: "2025-11-21T09:00:00Z",
		// 		},
		// 	},
		// 	expectAllow: true,
		// 	expectDeny:  false,
		// },
	}

	fmt.Println("========================================")
	fmt.Println("Running test scenarios...")
	fmt.Println("========================================")
	fmt.Println()

	passedTests := 0
	failedTests := 0

	for i, scenario := range testScenarios {
		fmt.Printf("Test %d: %s\n", i+1, scenario.name)
		fmt.Println("----------------------------------------")

		// Display input
		fmt.Printf("  Principal: %s\n", scenario.input.Principal.ID)
		if len(scenario.input.Principal.Groups) > 0 {
			fmt.Printf("  Groups: %v\n", scenario.input.Principal.Groups)
		}
		fmt.Printf("  Action: %s\n", scenario.input.Action)
		fmt.Printf("  Resource: %s\n", scenario.input.Resource.Name)
		fmt.Println()

		// Evaluate policy
		results, err := query.Eval(ctx, rego.EvalInput(scenario.input))
		if err != nil {
			log.Printf("Failed to evaluate policy: %v", err)
			failedTests++
			continue
		}

		if len(results) == 0 {
			log.Printf("No results returned from policy evaluation")
			failedTests++
			continue
		}

		// Extract allow and deny decisions
		authz, ok := results[0].Expressions[0].Value.(map[string]interface{})
		if !ok {
			log.Printf("Unexpected result format: %+v", results[0])
			failedTests++
			continue
		}

		allow, okAllow := authz["allow"].(bool)
		if !okAllow {
			log.Printf("allow field not found or not boolean: %+v", authz)
			failedTests++
			continue
		}

		deny, okDeny := authz["deny"].(bool)
		if !okDeny {
			log.Printf("deny field not found or not boolean: %+v", authz)
			failedTests++
			continue
		}

		// Display result
		fmt.Printf("  Result:\n")
		fmt.Printf("    Allow: %v\n", allow)
		fmt.Printf("    Deny: %v\n", deny)
		fmt.Println()

		// Check expectations
		passed := true
		if allow != scenario.expectAllow {
			fmt.Printf("  ❌ FAILED: Expected allow=%v, got allow=%v\n", scenario.expectAllow, allow)
			passed = false
		}
		if deny != scenario.expectDeny {
			fmt.Printf("  ❌ FAILED: Expected deny=%v, got deny=%v\n", scenario.expectDeny, deny)
			passed = false
		}

		if passed {
			fmt.Printf("  ✓ PASSED\n")
			passedTests++
		} else {
			failedTests++
		}

		fmt.Println()
	}

	// Summary
	fmt.Println("========================================")
	fmt.Println("Test Summary")
	fmt.Println("========================================")
	fmt.Printf("Total: %d\n", len(testScenarios))
	fmt.Printf("Passed: %d\n", passedTests)
	fmt.Printf("Failed: %d\n", failedTests)
	fmt.Println()

	if failedTests == 0 {
		fmt.Println("✓ All tests passed!")
	} else {
		fmt.Printf("❌ %d test(s) failed\n", failedTests)
		os.Exit(1)
	}
}
