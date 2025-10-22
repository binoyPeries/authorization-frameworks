## OpenFGA

### Note:

In OpenFGA, tuples follow the pattern:

```
{user} has {relation} on {object}
```

For your selected tuple:

```json
{
  "user": "group:devops#member",
  "relation": "deployer",
  "object": "env:stage"
}
```

This reads as: **"group:devops#member has deployer on env:stage"**

## How to Decide "Who's Who"

The key is to think about **direction of permission flow**:

### 1. **Object** = The thing being acted upon or providing the capability

- This is what **grants** or **receives** the permission
- In your case: `"object": "env:stage"`
- The stage environment is the target that **receives** the deployment action

### 2. **User** = The entity that receives or holds the relationship

- This is who/what **has** the permission or relationship
- In your case: `"user": "group:devops#member"`
- The stage environment **has the ability to accept promotions from** devops group

### 3. **Relation** = The type of connection

- `"can_accept_promotion"` describes what the stage environment can do with respect to the devops group

## The Logic Flow

This tuple is saying:

- **Stage environment** can accept promotions **from the devops group**
- Members of the devops group can promote things to the stage environment

## Rule of Thumb

Ask yourself: **"Who/what is performing the action?"**

- The **user** field contains the subject (actor or entity with the capability)
- The **object** field contains the target (what the relation applies to)

