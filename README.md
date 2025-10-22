## OpenChoreo's Architecture

High level Hierarchy mapping for authorization in OpenChoreo is structured as follows:

```
Organization (acme)
├── Environment (dev, staging, prod)
├── DeploymentPipeline (promotion workflow)
└── Project (bounded context - payments, ecommerce, analytics)
    └── Component (deployable unit - billing, user-service, catalog)
        ├── Build (build artifacts)
        ├── Deployment (runtime instances)
        └── ....
```

## Authorization Model
OpenChoreo should implement a hierarchical authorization model where permissions can be inherited from parent entities. Each entity in the hierarchy can define its own roles and permissions, which can also include permissions inherited from its parent entity.

## Frameworks explored
1. OpenFGA
2. Casbin