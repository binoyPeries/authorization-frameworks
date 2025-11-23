# OpenChoreo Authorization Model

A hierarchical, IAM-style authorization model for OpenChoreo using Open Policy Agent (OPA).

## Overview

This authorization model implements:

- **Hierarchical resource scoping**: Permissions granted at a parent level (e.g., org) automatically apply to all children (e.g., OUs, projects, components)
- **Role-based access control (RBAC)**: Roles define sets of permissions
- **IAM bindings**: Map roles to principals (users/groups) on specific resources
- **Explicit allow/deny**: Support for both allow and deny effects with deny taking precedence
- **Group membership**: Users can be granted permissions directly or through group membership

## Resource Hierarchy

Resources follow a hierarchical naming convention:

```
//openchoreo.orgs/{org}/ous/{ou}/projects/{project}/components/{component}
```

Example:
```
//openchoreo.orgs/acme/ous/dev/projects/payments/components/api
```

## Model Components

### 1. Roles (roles.json)

Defines roles and their associated permissions:

```json
{
  "roles": {
    "roles/component.developer": [
      "component.create",
      "component.read",
      "component.update",
      "component.delete"
    ],
    "roles/org.admin": [
      "org.read",
      "org.update",
      ...
    ]
  }
}
```

### 2. IAM Bindings (bindings.json)

Maps roles to principals on specific resources:

```json
{
  "iam": {
    "bindings": [
      {
        "resource": "//openchoreo.orgs/acme/ous/dev",
        "role": "roles/component.developer",
        "members": ["group:devs", "user:alice"],
        "effect": "allow",
        "condition": null
      }
    ]
  }
}
```

### 3. Policy (policy.rego)

The OPA policy that evaluates authorization requests.

## Input Format

Authorization requests use the following input format:

```json
{
  "principal": {
    "id": "user:alice",
    "groups": ["group:devs", "group:ou-dev"]
  },
  "action": "component.create",
  "resource": {
    "name": "//openchoreo.orgs/acme/ous/dev/projects/payments",
    "type": "project"
  },
  "context": {
    "time": "2025-11-21T09:00:00Z"
  }
}
```

## Key Features

### Hierarchical Permission Inheritance

Permissions granted at a higher level automatically apply to all nested resources:

- A binding at `//openchoreo.orgs/acme` applies to all OUs, projects, and components within that org
- A binding at `//openchoreo.orgs/acme/ous/dev` applies to all projects and components in the `dev` OU

### Allow/Deny Precedence

- **Deny takes precedence**: If any binding explicitly denies access, the request is denied
- **Allow requires explicit binding**: Access is granted only if there's a matching allow binding and no deny binding

### Group Membership

Users inherit permissions from all groups they belong to. A user gains access if either:
- They are directly listed in a binding's members
- Any of their groups is listed in a binding's members

## Testing

### Using Go Test Program (Recommended)

A Go program is provided to test the OPA policy with all example scenarios:

1. **Navigate to the model directory**:
   ```bash
   cd opa/model2
   ```

2. **Download dependencies**:
   ```bash
   go mod download
   ```

3. **Run the test program**:
   ```bash
   go run main.go
   ```

The program will:
- Load the OPA policy and data files
- Run all test scenarios (allow, deny, unauthorized, inherited)
- Display detailed results for each test
- Show a summary of passed/failed tests

**Example output**:
```
========================================
OPA Authorization Model Test Suite
========================================

✓ OPA policy loaded successfully

========================================
Running test scenarios...
========================================

Test 1: User alice creating component (should ALLOW)
----------------------------------------
  Principal: user:alice
  Groups: [group:devs group:ou-dev]
  Action: component.create
  Resource: //openchoreo.orgs/acme/ous/dev/projects/payments

  Result:
    Allow: true
    Deny: false

  ✓ PASSED
...
```

### Using OPA CLI

1. **Install OPA**:
   ```bash
   brew install opa  # macOS
   # or download from https://www.openpolicyagent.org/docs/latest/#running-opa
   ```

2. **Run evaluation**:
   ```bash
   cd opa/model2

   # Test allow scenario
   opa eval -d policy.rego -d roles.json -d bindings.json -i input-allow.json "data.openchoreo.authz.allow"

   # Test deny scenario
   opa eval -d policy.rego -d roles.json -d bindings.json -i input-deny.json "data.openchoreo.authz.deny"

   # Test unauthorized scenario
   opa eval -d policy.rego -d roles.json -d bindings.json -i input-unauthorized.json "data.openchoreo.authz.allow"

   # Test inherited permissions
   opa eval -d policy.rego -d roles.json -d bindings.json -i input-inherited.json "data.openchoreo.authz.allow"
   ```

3. **Run unit tests**:
   ```bash
   opa test . -v
   ```

4. **Interactive testing**:
   ```bash
   opa run policy.rego roles.json bindings.json
   ```

   Then in the REPL:
   ```
   > data.openchoreo.authz.allow
   > data.openchoreo.authz.deny
   ```

### Using OPA Server

1. **Start OPA server**:
   ```bash
   opa run --server --bundle policy.rego roles.json bindings.json
   ```

2. **Query via HTTP**:
   ```bash
   curl -X POST http://localhost:8181/v1/data/openchoreo/authz/allow \
     -H "Content-Type: application/json" \
     -d @input-allow.json
   ```

## Example Scenarios

### Scenario 1: Developer Creating Component (ALLOWED)

**Input**: [input-allow.json](input-allow.json)
- User: `alice` (member of `group:devs`)
- Action: `component.create`
- Resource: `//openchoreo.orgs/acme/ous/dev/projects/payments`

**Result**: ✅ ALLOWED
- The binding at `//openchoreo.orgs/acme/ous/dev` grants `roles/component.developer` to `group:devs`
- This role includes `component.create` permission
- The permission applies to all resources under `dev` OU, including the `payments` project

### Scenario 2: Explicit Deny (DENIED)

**Input**: [input-deny.json](input-deny.json)
- User: `eve` (member of `group:devs`)
- Action: `component.create`
- Resource: `//openchoreo.orgs/acme/ous/dev/projects/payments/components/api`

**Result**: ❌ DENIED
- Although `eve` is in `group:devs` with inherited permissions
- There's an explicit deny binding for `user:eve` on this specific component
- Deny takes precedence over allow

### Scenario 3: Unauthorized User (DENIED)

**Input**: [input-unauthorized.json](input-unauthorized.json)
- User: `unknown` (no groups)
- Action: `component.delete`
- Resource: `//openchoreo.orgs/acme/ous/prod/projects/billing`

**Result**: ❌ DENIED (default)
- No matching bindings for this user
- Default behavior is to deny access

### Scenario 4: Inherited Org Admin (ALLOWED)

**Input**: [input-inherited.json](input-inherited.json)
- User: `admin@acme.com` (member of `group:org-admins`)
- Action: `component.delete`
- Resource: `//openchoreo.orgs/acme/ous/dev/projects/payments/components/api`

**Result**: ✅ ALLOWED
- The binding at org level `//openchoreo.orgs/acme` grants `roles/org.admin` to `group:org-admins`
- This role includes all permissions including `component.delete`
- Org-level permissions cascade to all nested resources

## Future Enhancements

### Conditions (Planned)

The model includes a `condition` field in bindings for future use:

```json
{
  "resource": "...",
  "role": "...",
  "members": ["..."],
  "effect": "allow",
  "condition": {
    "expression": "context.time > '09:00' && context.time < '17:00'"
  }
}
```

Currently, conditions are modeled but not evaluated (always return true). Future implementations can add:
- Time-based access controls
- IP-based restrictions
- Resource attribute checks
- Custom business logic

## Integration

To integrate this model into your service:

1. **Bundle the policy**: Package `policy.rego`, `roles.json`, and `bindings.json` into an OPA bundle
2. **Deploy OPA**: Run OPA as a sidecar or separate service
3. **Query for decisions**: Send authorization requests to OPA and check the `allow` field
4. **Manage data**: Store roles and bindings in your database and sync to OPA regularly

## API Response

The policy provides two primary decision points:

- `data.openchoreo.authz.allow` - Returns `true` if access should be granted
- `data.openchoreo.authz.deny` - Returns `true` if access is explicitly denied

Typical integration logic:
```
if (data.openchoreo.authz.allow == true) {
  // Grant access
} else {
  // Deny access
}
```
