# proton-pass: Proton Pass for AI agents (Agent Plugin)

Gives an AI agent audited, least-privilege access to [Proton Pass](https://proton.me/pass) secrets through the official [`pass-cli`](https://protonpass.github.io/pass-cli/).
The plugin authenticates as a Proton Pass **agent** (a scoped, expiring token with audit logging), never as you.
Secrets are used through `pass://` references that are resolved inside the command being run, so they never need to enter the chat.

- Zero-dependency Node.js (>= 18) stdio MCP server. Every CLI call uses `execFile` with an argv array (no shell).
- Bundles an MCP server (`mcp.json`) and a skill (`skills/proton-pass/SKILL.md`).

## Tools
Every tool requires `reason`: the concrete task the access is for (1–300 chars, single line). It is recorded in the agent audit log.

| Tool | What it does | pass-cli command(s) |
|---|---|---|
| `list_vaults` | Vault names and share IDs | `pass-cli vault list --output json` |
| `search_items {vault?, query?, limit?=50}` | Find items by title or type. Returns `{total, items:[{vault, title, type, uri, id_uri, modify_time}]}` with no values | `vault list`, then `pass-cli item list --share-id <id> --output json` |
| `describe_item {id_uri}` or `{vault, item}` | Field **names** only, plus `field_uris` (e.g. `pass://Dev/Bifrost Virtual Key/Secret`) | `pass-cli item view --share-id <sid> --item-id <iid> --output json` (or `--vault-name/--item-title`) |
| `run_with_secrets {command[], env{NAME: pass://…}}` | Runs a command with the secrets injected into its env. Output is masked by pass-cli and truncated to 16 KB per stream | `pass-cli run -- <command…>` |
| `get_secret {uri}` | Returns one raw value. **The value enters the transcript.** Prefer `run_with_secrets` | `pass-cli item view "pass://vault/item/field"` |

## Setup
1. Install `pass-cli` ([instructions](https://protonpass.github.io/pass-cli/get-started/installation/)).
2. Create an agent as yourself, in your own terminal:
   ```sh
   pass-cli login
   pass-cli agent create cursor-agent --expiration 1m --vault "Dev"
   # -> {"token": "PROTON_PASS_PERSONAL_ACCESS_TOKEN=pst_…::…", "instruction": "…"}
   # optional: grant more access (whole vault or one item)
   pass-cli agent access grant cursor-agent --vault-name "Staging" --role viewer
   pass-cli agent access grant cursor-agent --vault-name "Prod" --item-title "Deploy key"
   ```
3. Give the token to the plugin. Use **one** of these:
   - **Token file (recommended):**
     ```sh
     mkdir -p ~/.config/proton-pass-agent && chmod 700 ~/.config/proton-pass-agent
     umask 077 && pbpaste > ~/.config/proton-pass-agent/token   # or paste with an editor
     ```
     Either the bare `pst_…::…` token or the whole `PROTON_PASS_PERSONAL_ACCESS_TOKEN=…` line works. Use `PROTON_PASS_AGENT_TOKEN_FILE` for a different path.
   - **Variable:** set `PROTON_PASS_AGENT_TOKEN`, the secret plugin variable that `mcp.json` references as `${PROTON_PASS_AGENT_TOKEN}`, or set it in the environment the client launches the server with.
4. Install the plugin:
   ```sh
   mkdir -p ~/.cursor/plugins/local
   tar xzf proton-pass-plugin.tgz -C /tmp && cp -R /tmp/proton-pass-plugin ~/.cursor/plugins/local/proton-pass
   ```
   Then reload your agent client.
5. Review what the agent did: `pass-cli agent monitor cursor-agent`. Rotate the token with `pass-cli agent renew cursor-agent --expiration 1m`. Revoke it with `pass-cli agent delete cursor-agent`.

Never put the token in `mcp.json`, a repository, or a chat.

## Security model
- **Agent token only:** the server runs `PROTON_PASS_PERSONAL_ACCESS_TOKEN=<token> pass-cli login` itself:
  - on the first call,
  - whenever `pass-cli info` fails (checked at most every 5 minutes; agent sessions last 2 h),
  - and once more if a command reports "not logged in".

  The token appears only in the env of that `login` call and is redacted from errors.
- **Agent sessions only:** after login, `pass-cli info --output json` must report an `[Agent] <name>` token. Plain PATs and user sessions are refused.
- **Isolated session:** `PROTON_PASS_SESSION_DIR` is set to `${PLUGIN_DATA}/pass-agent-session` (fallback `~/.local/state/proton-pass-agent-plugin/session`, mode 0700).
  - pass-cli keys its keyring entry to the session directory, so your personal `pass-cli` session is never read, reused or overwritten.
  - The default personal session directories are refused.
- **Mandatory reason:** `PROTON_PASS_AGENT_REASON=<reason>` is set on **every** pass-cli invocation, including list commands. Calls with a missing, empty, oversized or multi-line reason are rejected before anything runs.
- **Least exposure:**
  - Search and describe return metadata and field names only. All values are stripped.
  - `run_with_secrets` resolves references inside the child, keeps pass-cli's output masking on, and removes the token and other credential variables from the child's env.
  - `get_secret` validates `pass://vault/item/field[?totp=code|uri]` strictly.
- **No token, no access:** without a token, every tool refuses and returns setup instructions.

Limitations:
- Masking covers only stdout and stderr; a command can still write a secret elsewhere.
- The child of `run_with_secrets` inherits `PROTON_PASS_SESSION_DIR`, so it could call `pass-cli` as the agent. Such calls are still audited and limited to what you granted.
- Searching every vault is slow on large accounts (about 20 s for ~1,600 items). Pass `vault` to narrow it.

## Development
```sh
node test/e2e.js    # stdio JSON-RPC end-to-end test against the stub test/bin/pass-cli (no Proton account needed)
(cd /tmp && npm i --no-save ajv@8) && NODE_PATH=/tmp/node_modules node test/validate-schemas.js
```
The stub's `item list` output matches pass-cli 2.4.2. Its `item view --output json` shape is approximate.

## License
MIT
