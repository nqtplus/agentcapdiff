# Architecture

AgentCapDiff uses a deliberately small pipeline:

```text
JSON/YAML tool definitions
        |
        v
    Discovery
        |
        v
Normalized ToolRecord
        |
        v
Capability inference
        |
        +------> Inventory / snapshot
        |
        v
Policy evaluation
        |
        +------> Text / JSON / SARIF
```

The normalization boundary is the key extension point. Framework-specific adapters should emit `ToolRecord` objects; policy and diff logic should remain framework-neutral.
