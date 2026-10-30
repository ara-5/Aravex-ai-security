# Roadmap

Ordered by what most changes whether this is useful to someone else. This is a plan, not
a promise, and it assumes demand for agent and MCP security keeps growing; nothing here
has been validated with customers yet.

## The pitch to build toward

**CI for agent security: find the hole, fix it, prove it stays fixed.**

## Next

1. **Evidence on real models.** Run the loop on several models, more than once, with
   mutated attacks, and report the spread. The first real-model run showed nothing for the
   gateway to block ([EVIDENCE.md](EVIDENCE.md)); a model that takes harmful tool actions
   is needed. Publish failures too.
2. **One command from scan to gate.** `aravex scan <agent or MCP server>` → findings →
   proposed policy → CI gate, doing something useful in ten minutes for a stranger.
3. **Test the proxy on real MCP servers** (it has only met stand-ins), then add the
   HTTP/SSE transport.
4. **Cover where MCP attacks actually land:** tool descriptions that change after approval,
   injected instructions in tool *results*, resources and prompts.
5. **Monitor-only mode** that logs what would have been blocked, so a team can trust a
   policy before enforcing it, and benign-action sets learned from real traffic.

## Then

- Enterprise basics: sign-on for approvers, key rotation, persistent storage, audit export,
  container and deployment packaging.
- Map findings to OWASP's LLM/agentic lists and MITRE ATLAS for compliance-style reports.
- One dashboard instead of two.

## Decisions only the owner can make

- Stay fully proprietary, or open-source the scanner and sell the enforcement and CI layer?
  (The repo is public today.)
- Trademark and domain check for "Aravex"; lawyer review of the license.
- Which two or three teams running agents with real tool access will try it first.
