package opa

// Role defines a set of permissions.
type Role struct {
    Name        string   `json:"name"`        // e.g., "ComponentCreator", "ProjectAdmin"
    Permissions []string `json:"permissions"` // e.g., ["component:create", "component:read"]
}

// RoleBinding assigns a Role to an IDPGroup at a specific level of the resource hierarchy.

// IMPORTANT: Ancestors are ordered PARENT → CHILD (root to leaf), which builds paths like:
// "org/acme-corp/orgUnit/sales/project/project-a"
//
// Examples:
//   - Grant "ProjectAdmin" to "team-a" for "project-a" in "orgUnit/sales/org/acme-corp":
//     {Role: "ProjectAdmin", IDPGroup: "team-a", ResourceType: "project",
//      ResourceID: "project-a", Ancestors: [{Type: "org", ID: "acme-corp"}, {Type: "orgUnit", ID: "sales"}],
//      ResourcePattern: "wildcard"}
//     Path: "org/acme-corp/orgUnit/sales/project/project-a/*"
type RoleBinding struct {
    Role         string     `json:"role"`          // Role name to assign
    IDPGroup     string     `json:"idp_group"`     // IDP group identifier
    ResourceType string     `json:"resource_type"` // Resource type: org, orgUnit, project, component
    ResourceID   string     `json:"resource_id"`   // Specific resource ID
    Ancestors    []Ancestor `json:"ancestors"`     // Hierarchical context, ordered PARENT → CHILD
    // ResourcePattern determines permission inheritance:
    //   "exact"    - only applies to this specific resource (no descendants)
    //   "wildcard" - applies to this resource and all descendants
    ResourcePattern string `json:"resource_pattern"`
}

// AuthzRequest for authorization check.
// Groups should be provided by the authentication layer (e.g., from IDP token claims).
// No user information is needed - only the groups the user belongs to.
type AuthzRequest struct {
    Groups   []string `json:"groups"`   // IDP groups the user belongs to (e.g., ["asgardeo:org-admins", "asgardeo:platform-team"])
    Action   string   `json:"action"`   // Action to perform (e.g., "create", "read", "update", "delete")
    Resource Resource `json:"resource"` // Resource being accessed
}

type Resource struct {
    Type      string     `json:"type"`
    ID        string     `json:"id"`
    Ancestors []Ancestor `json:"ancestors"` // Ordered PARENT → CHILD (same as RoleBinding)
}

type Ancestor struct {
    Type string `json:"type"`
    ID   string `json:"id"`
}