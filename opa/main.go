package main

import (
	"context"
	"fmt"
	"log"

	authz "opa/authz"
)

func main() {
	ctx := context.Background()

	client, err := authz.NewClient(ctx)
	if err != nil {
		log.Fatal(err)
	}

	// Step 1: Define Roles - each role is a set of permissions
	// Roles are scope-agnostic and can be assigned at any level of the hierarchy
	roles := []authz.Role{
		{
			Name: "ComponentCreator",
			Permissions: []string{
				"component:create",
				"component:read",
			},
		},
		{
			Name: "ComponentManager",
			Permissions: []string{
				"component:create",
				"component:read",
				"component:update",
				"component:delete",
			},
		},
		{
			Name: "Deployer",
			Permissions: []string{
				"component:deploy",
				"component:read",
			},
		},
		{
			Name: "ProjectAdmin",
			Permissions: []string{
				"project:create",
				"project:read",
				"project:update",
				"project:delete",
				"component:create",
				"component:read",
				"component:update",
				"component:delete",
			},
		},
		{
			Name: "OrgAdmin",
			Permissions: []string{
				"org:create",
				"org:read",
				"org:update",
				"org:delete",
				"orgUnit:create",
				"orgUnit:read",
				"orgUnit:update",
				"orgUnit:delete",
				"project:create",
				"project:read",
				"project:update",
				"project:delete",
				"component:create",
				"component:read",
				"component:update",
				"component:delete",
				"component:deploy",
			},
		},
		{
			Name: "Viewer",
			Permissions: []string{
				"org:read",
				"orgUnit:read",
				"project:read",
				"component:read",
			},
		},
	}

	// Step 2: Create Role Bindings - Map IDPGroup → Role → Resource Hierarchy Level
	// This defines: "IDP Group X gets Role Y at resource scope Z"
	// The Ancestors field disambiguates resources (e.g., project-a in orgUnit-1 vs orgUnit-2)
	bindings := []authz.RoleBinding{
		// Org-level admins: full access to everything under acme-corp
		{
			Role:            "OrgAdmin",
			IDPGroup:        "asgardeo:acme-org-admins",
			ResourceType:    "org",
			ResourceID:      "acme-corp",
			Ancestors:       []authz.Ancestor{}, // Top-level resource, no ancestors
			ResourcePattern: "wildcard",          // Grants to all descenants
		},
		// Platform team: can create components anywhere in the org
		{
			Role:            "ComponentCreator",
			IDPGroup:        "asgardeo:platform-team",
			ResourceType:    "org",
			ResourceID:      "acme-corp",
			Ancestors:       []authz.Ancestor{},
			ResourcePattern: "wildcard",
		},
		// DevOps team: can deploy components anywhere in the org
		{
			Role:            "Deployer",
			IDPGroup:        "asgardeo:devops-team",
			ResourceType:    "org",
			ResourceID:      "acme-corp",
			Ancestors:       []authz.Ancestor{},
			ResourcePattern: "wildcard",
		},
		// Frontend project leads: admin access to their specific project
		// Assumes frontend-app exists directly under org (no orgUnit)
		{
			Role:         "ProjectAdmin",
			IDPGroup:     "asgardeo:frontend-project-leads",
			ResourceType: "project",
			ResourceID:   "frontend-app",
			Ancestors: []authz.Ancestor{
				{Type: "org", ID: "acme-corp"},
			},
			ResourcePattern: "wildcard",
		},
		// Backend project leads: admin access to backend-services project
		// With full hierarchical context
		{
			Role:         "ProjectAdmin",
			IDPGroup:     "asgardeo:backend-project-leads",
			ResourceType: "project",
			ResourceID:   "backend-services",
			Ancestors: []authz.Ancestor{
				{Type: "org", ID: "acme-corp"},
			},
			ResourcePattern: "wildcard",
		},
		// Security auditors: read-only access to everything
		{
			Role:            "Viewer",
			IDPGroup:        "asgardeo:security-auditors",
			ResourceType:    "org",
			ResourceID:      "acme-corp",
			Ancestors:       []authz.Ancestor{},
			ResourcePattern: "wildcard",
		},
	}

	if err := client.LoadData(ctx, roles, bindings); err != nil {
		log.Fatal(err)
	}

	fmt.Println("=== Authorization Tests ===")
	fmt.Println("Testing simplified IDP Group-based authorization model")
	fmt.Println("(Groups are provided directly in each request, no user-to-group mapping needed)")
	fmt.Println()

	// Test 1: Org admin can do everything
	fmt.Println("Test 1: User with [asgardeo:acme-org-admins] can delete components")
	testAuthz(ctx, client, authz.AuthzRequest{
		Groups: []string{"asgardeo:acme-org-admins"},
		Action: "delete",
		Resource: authz.Resource{
			Type: "component",
			ID:   "api-gateway",
			Ancestors: []authz.Ancestor{
				{Type: "org", ID: "acme-corp"},
				{Type: "project", ID: "backend-services"},
			},
		},
	})

	// Test 2: Platform team can create components
	fmt.Println("\nTest 2: User with [asgardeo:platform-team] can create components")
	testAuthz(ctx, client, authz.AuthzRequest{
		Groups: []string{"asgardeo:platform-team"},
		Action: "create",
		Resource: authz.Resource{
			Type: "component",
			ID:   "new-component",
			Ancestors: []authz.Ancestor{
				{Type: "org", ID: "acme-corp"},
				{Type: "project", ID: "frontend-app"},
			},
		},
	})

	// Test 3: Platform team CANNOT deploy (no deploy permission in ComponentCreator role)
	fmt.Println("\nTest 3: User with [asgardeo:platform-team] CANNOT deploy (missing permission)")
	testAuthz(ctx, client, authz.AuthzRequest{
		Groups: []string{"asgardeo:platform-team"},
		Action: "deploy",
		Resource: authz.Resource{
			Type: "component",
			ID:   "api-gateway",
			Ancestors: []authz.Ancestor{
				{Type: "org", ID: "acme-corp"},
				{Type: "project", ID: "backend-services"},
			},
		},
	})

	// Test 4: DevOps team CAN deploy
	fmt.Println("\nTest 4: User with [asgardeo:devops-team] can deploy components")
	testAuthz(ctx, client, authz.AuthzRequest{
		Groups: []string{"asgardeo:devops-team"},
		Action: "deploy",
		Resource: authz.Resource{
			Type: "component",
			ID:   "api-gateway",
			Ancestors: []authz.Ancestor{
				{Type: "org", ID: "acme-corp"},
				{Type: "project", ID: "backend-services"},
			},
		},
	})

	// Test 5: Frontend project lead can delete in their project
	fmt.Println("\nTest 5: User with [asgardeo:frontend-project-leads] can delete in their project")
	testAuthz(ctx, client, authz.AuthzRequest{
		Groups: []string{"asgardeo:frontend-project-leads"},
		Action: "delete",
		Resource: authz.Resource{
			Type: "component",
			ID:   "react-ui",
			Ancestors: []authz.Ancestor{
				{Type: "org", ID: "acme-corp"},
				{Type: "project", ID: "frontend-app"},
			},
		},
	})

	// Test 6: Frontend project lead CANNOT delete in backend project
	fmt.Println("\nTest 6: User with [asgardeo:frontend-project-leads] CANNOT delete in backend project")
	testAuthz(ctx, client, authz.AuthzRequest{
		Groups: []string{"asgardeo:frontend-project-leads"},
		Action: "delete",
		Resource: authz.Resource{
			Type: "component",
			ID:   "api-gateway",
			Ancestors: []authz.Ancestor{
				{Type: "org", ID: "acme-corp"},
				{Type: "project", ID: "backend-services"},
			},
		},
	})

	// Test 7: Backend project lead can update
	fmt.Println("\nTest 7: User with [asgardeo:backend-project-leads] can update")
	testAuthz(ctx, client, authz.AuthzRequest{
		Groups: []string{"asgardeo:backend-project-leads"},
		Action: "update",
		Resource: authz.Resource{
			Type: "component",
			ID:   "api-gateway",
			Ancestors: []authz.Ancestor{
				{Type: "org", ID: "acme-corp"},
				{Type: "project", ID: "backend-services"},
			},
		},
	})

	// Test 8: Security auditors can read everything
	fmt.Println("\nTest 8: User with [asgardeo:security-auditors] can read everything")
	testAuthz(ctx, client, authz.AuthzRequest{
		Groups: []string{"asgardeo:security-auditors"},
		Action: "read",
		Resource: authz.Resource{
			Type: "component",
			ID:   "api-gateway",
			Ancestors: []authz.Ancestor{
				{Type: "org", ID: "acme-corp"},
				{Type: "project", ID: "backend-services"},
			},
		},
	})

	// Test 9: Security auditors CANNOT delete (only have read permissions)
	fmt.Println("\nTest 9: User with [asgardeo:security-auditors] CANNOT delete (read-only)")
	testAuthz(ctx, client, authz.AuthzRequest{
		Groups: []string{"asgardeo:security-auditors"},
		Action: "delete",
		Resource: authz.Resource{
			Type: "component",
			ID:   "api-gateway",
			Ancestors: []authz.Ancestor{
				{Type: "org", ID: "acme-corp"},
				{Type: "project", ID: "backend-services"},
			},
		},
	})

	// Test 10: User with multiple groups gets union of permissions
	fmt.Println("\nTest 10: User with [asgardeo:platform-team, asgardeo:devops-team] can deploy")
	testAuthz(ctx, client, authz.AuthzRequest{
		Groups: []string{"asgardeo:platform-team", "asgardeo:devops-team"},
		Action: "deploy",
		Resource: authz.Resource{
			Type: "component",
			ID:   "api-gateway",
			Ancestors: []authz.Ancestor{
				{Type: "org", ID: "acme-corp"},
				{Type: "project", ID: "backend-services"},
			},
		},
	})
}

func testAuthz(ctx context.Context, client *authz.Client, req authz.AuthzRequest) {
	allowed, err := client.IsAllowed(ctx, req)
	if err != nil {
		log.Printf("Error: %v", err)
		return
	}

	status := "✗"
	if allowed {
		status = "✓"
	}

	fmt.Printf("%s Groups %v → %s %s/%s\n",
		status, req.Groups, req.Action, req.Resource.Type, req.Resource.ID)
}
