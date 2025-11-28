package openchoreo.authz

import future.keywords.every

#
# ===========
# INPUT SHAPE
# ===========
#
# Expected input:
#
# {
#   "groups": ["group:devs", "group:ou-dev"],
#   "action": "deployment.create",
#   "resource": {
#     "name": "org/acme/ou/dev/project/payments/component/api",
#     "type": "component",
#     "context": {
#       "toEnv": "development"
#     }
#   },
#   "context": {
#     "time": "2025-11-21T09:00:00Z"
#   }
# }
#
# Expected data (separate JSON/YAML, not in this module):
#
# data.roles = {
#   "roles/component.developer": [
#     "component.create",
#     "component.read",
#     "component.update"
#   ],
#   "roles/env.deployer": [
#     "deployment.create",
#     "deployment.read"
#   ]
# }
#
# data.iam.bindings = [
#   {
#     "resource": "org/acme",
#     "role": "roles/component.developer",
#     "group": "group:devs",
#     "effect": "allow",
#     "condition": null
#   },
#   {
#     "resource": "org/acme/ou/dev",
#     "role": "roles/env.deployer",
#     "group": "group:devs",
#     "effect": "allow",
#     "condition": {
#       "allowedEnvironments": ["development", "staging"]
#     }
#   },
#   {
#     "resource": "org/acme",
#     "role": "roles/env.deployer",
#     "group": "group:prod-ops",
#     "effect": "allow",
#     "condition": {
#       "allowedEnvironments": ["production"]
#     }
#   }
# ]
#

#
# ===================
# TOP-LEVEL DECISION
# ===================
#

default allow := false
default deny  := false

# Simple API: `allow` and `deny` booleans.
# Your service usually checks `allow` (and you can use `deny` for debugging / explicit-deny semantics if you like).
allow {
    not deny   # no matching explicit deny
    binding_allows
}

deny {
    binding_denies
}

#
# ==================
# BINDING EVALUATION (Single Pass)
# ==================
#
# Collect all matching bindings in a single iteration
# then check their effects
#

# Get all bindings that match the current request
matching_bindings[b] {
    b := data.iam.bindings[_]
    binding_matches(b)
}

# Check if any matching binding has allow effect
binding_allows {
    b := matching_bindings[_]
    b.effect == "allow"
}

# Check if any matching binding has deny effect
binding_denies {
    b := matching_bindings[_]
    b.effect == "deny"
}

# Core predicate: does this binding apply to the current input?
# Ordered from cheapest to most expensive checks for early exit optimization
binding_matches(b) {
    # 1) Group match (CHEAPEST: simple array membership check)
    #    Filters out most bindings immediately
    group_matches(b.group, input.groups)

    # 2) Role grants the requested action (MEDIUM: hash lookup + array scan)
    #    Cheaper than path parsing
    role_has_permission(b.role, input.action)

    # 3) Conditions evaluation (MEDIUM: varies by condition complexity)
    #    Usually just null check or simple comparisons
    conditions_ok(b.condition)

    # 4) Scope / hierarchy (MOST EXPENSIVE: path splitting + segment comparison)
    #    Do this last to minimize expensive path operations
    resource_applies(b.resource, input.resource.name)
}

#
# =========================
# HIERARCHY / SCOPE LOGIC
# =========================
#

# resource_applies(binding_resource, requested_resource)
#
# Example:
#  binding_resource   = "org/acme/ou/dev"
#  requested_resource = "org/acme/ou/dev/project/p1/component/c1"
#
#  => true (requested is inside binding scope)
#
resource_applies(binding_res, req_res) {
    path_prefix(binding_res, req_res)
}

# path_prefix("a/b", "a/b/c/d") == true
# Uses startswith() for optimal performance.
# Handles exact match and ensures segment boundary to avoid
# mismatches like "foo/bar" vs "foo/barista".
path_prefix(binding_res, req_res) {
    # Exact match
    binding_res == req_res
}

path_prefix(binding_res, req_res) {
    startswith(req_res, concat("", [binding_res, "/"]))
}

#
# =======================
# GROUP MATCHING
# =======================
#

# group_matches(binding_group, input_groups)
#
# Check if the binding's group is in the input's groups array
#
group_matches(binding_group, input_groups) {
    # At least one input group matches the binding group
    binding_group == input_groups[_]
}

#
# ==================
# ROLES / PERMISSIONS
# ==================
#

# role_has_permission("roles/component.developer", "component.create")
role_has_permission(role, action) {
    perms := data.roles[role]
    perms[_] == action
}

#
# ===================
# CONDITION EVALUATION
# ===================
#
# Validates binding conditions, including environment restrictions
#

# No condition specified - always passes
conditions_ok(cond) {
    cond == null
}

# Condition has allowedEnvironments - validate target environment
conditions_ok(cond) {
    cond != null
    cond.allowedEnvironments

    # Get target environment from context or resource
    target_env := get_target_environment

    # Check if target environment is in the allowed list
    target_env == cond.allowedEnvironments[_]
}

# Condition exists but no allowedEnvironments specified - passes
conditions_ok(cond) {
    cond != null
    not cond.allowedEnvironments
}

# Helper to get the target environment from input
get_target_environment = env {
    # Get from resource.context.toEnv
    env := input.resource.context.toEnv
}


#
# ================
# PROFILE GENERATION
# ================
#
# Goal:
#   For a given principal (and optional context like env),
#   return a flat list of scopes with actions.
#
# Input shape for profile queries:
#
# {
#   "groups": ["group:devs", "group:ou-dev"],
#   "resource": {
#     "context": {
#       "toEnv": "development"
#     }
#   }
# }
#
# Note: Profile queries don't require resource.name since we're listing
#       all scopes the user has access to.
#
# Note:
#   - We reuse conditions_ok(cond) from the main policy.
#   - For env based conditions, set input.resource.context.toEnv in the profile query.
#

#
# Each binding expanded to (scope, action) if it applies to the principal
#
profile_flat_bindings[entry] {
    b := data.iam.bindings[_]
    b.effect == "allow"

    # At least one input group matches the binding group
    group_matches(b.group, input.groups)

    # Conditions are satisfied under the profile input context
    conditions_ok(b.condition)

    # For each permission granted by the role, treat it as an action
    action := data.roles[b.role][_]

    entry := {
        "scope":  b.resource,  # resource path, eg org/acme/ou/dev
        "action": action,
    }
}

#
# Set of all scopes where this principal has at least one allowed action
#
profile_scopes[scope] {
    e := profile_flat_bindings[_]
    scope := e.scope
}

#
# Aggregated view per scope:
#   - scope: resource path
#   - actions: set of allowed actions at that scope
#
# Query:
#   data.openchoreo.authz.profile_flat_agg
#
# Example result:
# [
#   {"scope": "org/acme", "actions": {"component.create", "component.read"}},
#   {"scope": "org/acme/ou/dev", "actions": {"deployment.create"}}
# ]
#
profile_flat_agg[entry] {
    scope := profile_scopes[_]

    actions := { action |
        e := profile_flat_bindings[_]
        e.scope == scope
        action := e.action
    }

    entry := {
        "scope":   scope,
        "actions": actions,
    }
}
