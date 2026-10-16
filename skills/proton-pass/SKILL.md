---
name: proton-pass
description: Use when a task needs a password, API key, token or other credential stored in Proton Pass, or needs to run a command that requires such a secret.
---

# Proton Pass (agent token, audited)

The `proton-pass` MCP server acts as a Proton Pass **agent**, not as Andrew: it uses a scoped agent token in its own isolated session, and every access is written to an audit log.

**Every tool requires `reason`.** Describe the concrete task, e.g. `"Run DB migration 0042 on staging: needs Prod DB password"`, not `"need secret"`. Max 300 chars, one line. Andrew reviews these with `pass-cli agent monitor <agent-name>`.

Workflow:
1. `search_items {reason, vault?, query?, limit?}`: find the item by title or type. Returns `{total, items:[{vault, title, type, uri, id_uri, modify_time}]}`. Pass `vault` when you know it, because scanning every vault is slow.
2. `describe_item {reason, id_uri}` (or `{reason, vault, item}`): returns field **names** only, plus `field_uris` (`pass://.../field`).
3. `run_with_secrets {reason, command:[argv], env:{NAME:"pass://..."}}`: **preferred**. The secret is resolved inside the child and masked in output.
4. `get_secret {reason, uri}`: last resort. The value enters the transcript. Use it only when Andrew explicitly needs the value itself.

Rules:
- Never paste, echo, log, or write secret values into files, messages, commits, or command arguments. Pass them only through `env` refs.
- Never invent vaults, items, fields, or values. If something isn't in tool output, say so.
- If a tool reports setup or login problems, relay the instructions to Andrew. Never ask for his Proton password and never try to log in as him. An item the agent can't see may need `pass-cli agent access grant`.
