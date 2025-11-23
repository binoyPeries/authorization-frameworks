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
#   "principal": {
#     "id": "user:alice",
#     "groups": ["group:devs", "group:ou-dev"]
#   },
#   "action": "component.create",
#   "resource": {
#     "name": "//openchoreo.orgs/acme/ous/dev/projects/payments",
#     "type": "project"
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
#     "resource": "//openchoreo.orgs/acme",
#     "role": "roles/component.developer",
#     "members": ["group:devs"],
#     "effect": "allow",         # "allow" | "deny"
#     "condition": null          # kept in model, ignored by policy for now
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
# BINDING EVALUATION
# ==================
#

binding_allows {
    b := data.iam.bindings[_]
    b.effect == "allow"
    binding_matches(b)
}

binding_denies {
    b := data.iam.bindings[_]
    b.effect == "deny"
    binding_matches(b)
}

# Core predicate: does this binding apply to the current input?
binding_matches(b) {
    # 1) Scope / hierarchy
    resource_applies(b.resource, input.resource.name)

    # 2) Principal membership (user or any of their groups)
    member_matches(b.members, input.principal)

    # 3) Role grants the requested action
    role_has_permission(b.role, input.action)

    # 4) Conditions exist in the model but are ignored for now
    conditions_ok(b.condition)
}

#
# =========================
# HIERARCHY / SCOPE LOGIC
# =========================
#

# resource_applies(binding_resource, requested_resource)
#
# Example:
#  binding_resource   = "//openchoreo.orgs/acme/ous/dev"
#  requested_resource = "//openchoreo.orgs/acme/ous/dev/projects/p1/components/c1"
#
#  => true (requested is inside binding scope)
#
resource_applies(binding_res, req_res) {
    path_prefix(binding_res, req_res)
}

# path_prefix("a/b", "a/b/c/d") == true
# Prefix test done on path segments, not raw string, to avoid
# mismatches like "foo/bar" vs "foo/barista".
path_prefix(binding_res, req_res) {
    bs := split_path(binding_res)
    rs := split_path(req_res)

    count(bs) <= count(rs)

    # Check all segments match by ensuring no mismatches exist
    not has_segment_mismatch(bs, rs)
}

# Helper to check if there's any segment mismatch
has_segment_mismatch(bs, rs) {
    bs[i] != rs[i]
}

# Split canonical resource name into segments, ignoring leading "//"
# e.g. "//openchoreo.orgs/acme/ous/dev" -> ["openchoreo.orgs", "acme", "ous", "dev"]
split_path(p) = segs {
    no_scheme := trim_prefix(p, "//")
    segs := split(no_scheme, "/")
}

#
# =======================
# PRINCIPAL / MEMBERSHIP
# =======================
#

# member_matches(binding_members, principal)
#
# A binding can list user IDs or groups:
#   "members": ["user:alice", "group:devs"]
#
member_matches(members, principal) {
    # Direct user match
    principal.id == members[_]
} else {
    # Group membership match
    g := principal.groups[_]
    g == members[_]
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
# =================
# CONDITIONS (STUB)
# =================
#
# Condition is kept in the model (for future use),
# but currently DOES NOT influence allow/deny.
#

conditions_ok(_cond) {
    # Always true for now; hook real logic here later.
    true
}

#
# =======================
# OPTIONAL: ENV COUPLING
# =======================
#
# Example helper if later you want env-specific checks.
# Not wired into allow/deny by default.
#

# has_permission_on_resource(principal, action, resource_name)
has_permission_on_resource(principal, action, resource_name) {
    b := data.iam.bindings[_]

    resource_applies(b.resource, resource_name)
    member_matches(b.members, principal)
    role_has_permission(b.role, action)
    conditions_ok(b.condition)
}
