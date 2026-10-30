# Security policy

## Reporting a vulnerability

Please report security problems privately, not in a public issue.

Use GitHub's private reporting: open this repository's **Security** tab and choose
**Report a vulnerability**. Include what you found, how to reproduce it, and the
commit you tested.

This is a young project with one maintainer: reports are read, but there is no
guaranteed response time. Please do not publish details until a fix
is available or we have agreed a date.

## What is in scope

- The gateway (`gateway/`), the MCP proxy (`mcp_proxy/`), the feedback loop (`loop/`)
  and the verification gate (`tests/gate/`): authentication and authorization bypasses,
  ways to get a call allowed that policy should refuse, approval bypasses, key leakage.
- A request that makes the proxy or gateway fail open instead of refusing.

## What is not a vulnerability

`redteam/target_agent` is **intentionally vulnerable** (plaintext secrets in its prompt,
weak tool sandboxing, unauthenticated MCP-style tools) and its `/admin/*` routes are for
the red-team judge. Findings against it are the point of the project. Never deploy it.

## Supported versions

Only the latest commit on `main`. There are no maintained release branches yet.
