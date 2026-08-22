# Sanitized MCP fixture corpus

These fixtures are intentionally tiny rewrites of public MCP tool-schema patterns. They contain no credentials, tokens, personal data, or proprietary payloads.

Public pattern references:
- MCP tools specification: https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/server/tools.mdx
- Reference filesystem server: https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem
- Reference fetch server: https://github.com/modelcontextprotocol/servers/tree/main/src/fetch

Expected classifications:
- `filesystem_restricted.json` → `filesystem.read`, restricted to `./reports/**`.
- `filesystem_ambiguous.yaml` → `filesystem.write`, scope unknown because a free-form path is not a static restriction.
- `network_exact.json` → `network.external`, restricted to `https://api.example.com/v1`.
- `network_wildcard.yaml` → `network.external`, restricted to `*.example.com` (wildcard is preserved, never widened silently).
- `network_broad.json` → `network.external`, broad because the description explicitly permits arbitrary URLs.
- `negative_catalog_search.json` → no high-risk capability.

The fixtures model schema shapes, not runtime enforcement. A statically restricted scope does not prove that the underlying implementation enforces the same restriction.
