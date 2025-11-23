package openchoreo.authz

# Test data
test_roles := {
    "roles/component.developer": [
        "component.create",
        "component.read",
        "component.update"
    ],
    "roles/org.admin": [
        "org.read",
        "component.delete"
    ]
}

test_bindings := [
    {
        "resource": "//openchoreo.orgs/acme/ous/dev",
        "role": "roles/component.developer",
        "members": ["group:devs", "user:alice"],
        "effect": "allow",
        "condition": null
    },
    {
        "resource": "//openchoreo.orgs/acme",
        "role": "roles/org.admin",
        "members": ["group:org-admins"],
        "effect": "allow",
        "condition": null
    },
    {
        "resource": "//openchoreo.orgs/acme/ous/dev/projects/payments/components/api",
        "role": "roles/component.developer",
        "members": ["user:eve"],
        "effect": "deny",
        "condition": null
    }
]

# Test: Allow - User alice can create component in dev OU
test_allow_user_in_dev_ou {
    allow with input as {
        "principal": {
            "id": "user:alice",
            "groups": []
        },
        "action": "component.create",
        "resource": {
            "name": "//openchoreo.orgs/acme/ous/dev/projects/payments",
            "type": "project"
        }
    }
    with data.roles as test_roles
    with data.iam.bindings as test_bindings
}

# Test: Allow - Group member can create component
test_allow_group_member {
    allow with input as {
        "principal": {
            "id": "user:bob",
            "groups": ["group:devs"]
        },
        "action": "component.create",
        "resource": {
            "name": "//openchoreo.orgs/acme/ous/dev/projects/payments",
            "type": "project"
        }
    }
    with data.roles as test_roles
    with data.iam.bindings as test_bindings
}

# Test: Allow - Hierarchical permission inheritance (org admin)
test_allow_inherited_from_org {
    allow with input as {
        "principal": {
            "id": "user:admin",
            "groups": ["group:org-admins"]
        },
        "action": "component.delete",
        "resource": {
            "name": "//openchoreo.orgs/acme/ous/dev/projects/payments/components/api",
            "type": "component"
        }
    }
    with data.roles as test_roles
    with data.iam.bindings as test_bindings
}

# Test: Deny - User without permission
test_deny_unauthorized_user {
    not allow with input as {
        "principal": {
            "id": "user:unknown",
            "groups": []
        },
        "action": "component.create",
        "resource": {
            "name": "//openchoreo.orgs/acme/ous/prod/projects/billing",
            "type": "project"
        }
    }
    with data.roles as test_roles
    with data.iam.bindings as test_bindings
}

# Test: Deny - Explicit deny takes precedence
test_deny_explicit_deny {
    deny with input as {
        "principal": {
            "id": "user:eve",
            "groups": ["group:devs"]
        },
        "action": "component.create",
        "resource": {
            "name": "//openchoreo.orgs/acme/ous/dev/projects/payments/components/api",
            "type": "component"
        }
    }
    with data.roles as test_roles
    with data.iam.bindings as test_bindings
}

# Test: Deny - Action not in role
test_deny_action_not_in_role {
    not allow with input as {
        "principal": {
            "id": "user:alice",
            "groups": []
        },
        "action": "component.delete",
        "resource": {
            "name": "//openchoreo.orgs/acme/ous/dev/projects/payments",
            "type": "project"
        }
    }
    with data.roles as test_roles
    with data.iam.bindings as test_bindings
}

# Test: Deny - Resource outside scope
test_deny_outside_scope {
    not allow with input as {
        "principal": {
            "id": "user:alice",
            "groups": []
        },
        "action": "component.create",
        "resource": {
            "name": "//openchoreo.orgs/acme/ous/prod/projects/billing",
            "type": "project"
        }
    }
    with data.roles as test_roles
    with data.iam.bindings as test_bindings
}

# Test: Path prefix matching
test_path_prefix_exact_match {
    path_prefix("//openchoreo.orgs/acme", "//openchoreo.orgs/acme")
}

test_path_prefix_child_match {
    path_prefix("//openchoreo.orgs/acme", "//openchoreo.orgs/acme/ous/dev")
}

test_path_prefix_deep_child_match {
    path_prefix(
        "//openchoreo.orgs/acme/ous/dev",
        "//openchoreo.orgs/acme/ous/dev/projects/p1/components/c1"
    )
}

test_path_prefix_no_match {
    not path_prefix("//openchoreo.orgs/acme/ous/prod", "//openchoreo.orgs/acme/ous/dev")
}

test_path_prefix_no_partial_match {
    not path_prefix("//openchoreo.orgs/acme/ous/dev", "//openchoreo.orgs/acme/ous/development")
}
