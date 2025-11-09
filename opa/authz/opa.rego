package choreo.authz

import future.keywords.contains
import future.keywords.if
import future.keywords.in

default allow = false

# Main authorization decision
# Allow if ANY of the user's groups have a role binding that grants the permission
allow if {
    some binding in effective_bindings
    has_permission(binding.role, input.action, input.resource.type)
    binding_covers_resource(binding)
}

# Get all effective role bindings for the groups provided in the request
# Simply match the input groups against role bindings
effective_bindings contains binding if {
    some group_name in input.groups
    some binding in data.role_bindings
    binding.idp_group == group_name
}

# Check if a role has the required permission for the action on resource type
# Permissions are stored as "resourcetype:action" strings (e.g., "component:create")
has_permission(role_name, action, resource_type) if {
    some role in data.roles
    role.name == role_name
    required_permission := sprintf("%s:%s", [resource_type, action])
    required_permission in role.permissions
}

# Exact resource match: binding applies ONLY to this specific resource (no descendants)
binding_covers_resource(binding) if {
    binding.resource_pattern == "exact"
    binding_path := build_path(binding.ancestors, binding.resource_type, binding.resource_id)
    resource_path := build_path(input.resource.ancestors, input.resource.type, input.resource.id)
    binding_path == resource_path
}

# Wildcard match: binding path is a prefix of resource path
# Examples:
#   - Binding: "org/acme-corp" matches "org/acme-corp/project/backend-services"
#   - Binding: "org/acme-corp/project/backend-services" matches itself and all components under it
binding_covers_resource(binding) if {
    binding.resource_pattern == "wildcard"
    binding_path := build_path(binding.ancestors, binding.resource_type, binding.resource_id)
    resource_path := build_path(input.resource.ancestors, input.resource.type, input.resource.id)
    # Match if paths are equal OR resource_path starts with binding_path/
    path_matches_wildcard(binding_path, resource_path)
}

# Check if resource_path matches binding_path with wildcard semantics
path_matches_wildcard(binding_path, resource_path) if {
    binding_path == resource_path  # Exact match
}

path_matches_wildcard(binding_path, resource_path) if {
    startswith(resource_path, concat("", [binding_path, "/"]))  # Descendant match
}

# Build hierarchical path from ancestors (parent → child) + current resource
# Examples:
#   - ancestors: [{org, acme-corp}], type: project, id: backend-services
#     → "org/acme-corp/project/backend-services"
#   - ancestors: [], type: org, id: acme-corp
#     → "org/acme-corp"
build_path(ancestors, resource_type, resource_id) := path if {
    count(ancestors) > 0
    ancestor_parts := [sprintf("%s/%s", [a.type, a.id]) | a := ancestors[_]]
    current_part := sprintf("%s/%s", [resource_type, resource_id])
    all_parts := array.concat(ancestor_parts, [current_part])
    path := concat("/", all_parts)
}

# Handle case with no ancestors (top-level resource)
build_path(ancestors, resource_type, resource_id) := path if {
    count(ancestors) == 0
    path := sprintf("%s/%s", [resource_type, resource_id])
}