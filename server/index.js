#!/usr/bin/env node
// Zero-dependency stdio MCP server wrapping Proton Pass CLI (pass-cli).
// All CLI calls use execFile with an args array: no shell, no string interpolation.
'use strict';
const { execFile } = require('node:child_process');
const readline = require('node:readline');

const { AsyncLocalStorage } = require('node:async_hooks');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const PASS_CLI = process.env.PASS_CLI_BIN || 'pass-cli';
const MAX_OUT = 16 * 1024;           // per stream returned to the agent
const CLI_TIMEOUT_MS = 60_000;
const RUN_TIMEOUT_MS = 10 * 60_000;
const SESSION_RECHECK_MS = 5 * 60_000; // agent sessions last 2h; re-verify with `pass-cli info` at most every 5 min
const PROTOCOL = '2025-06-18';

class ToolError extends Error {}
const callCtx = new AsyncLocalStorage(); // holds { reason } for the current tool call

// ---------- agent token + isolated session ----------
const PAT_VAR = 'PROTON_PASS_PERSONAL_ACCESS_TOKEN';
const TOKEN_VAR = 'PROTON_PASS_AGENT_TOKEN';         // plugin variable (set by the user/client), never inherited by children
const SECRET_ENV = [PAT_VAR, TOKEN_VAR, 'PROTON_PASS_PASSWORD', 'PROTON_PASS_PASSWORD_FILE', 'PROTON_PASS_TOTP', 'PROTON_PASS_TOTP_FILE',
  'PROTON_PASS_SECOND_PASSWORD', 'PROTON_PASS_SECOND_PASSWORD_FILE', 'PROTON_PASS_EXTRA_PASSWORD', 'PROTON_PASS_EXTRA_PASSWORD_FILE',
  'PROTON_PASS_ENCRYPTION_KEY'];
const isPlaceholder = (v) => typeof v === 'string' && /^\$\{[^}]*\}$/.test(v.trim()); // unexpanded ${VAR}

function readToken() {
  let t = process.env[TOKEN_VAR];
  if (!t || isPlaceholder(t)) {
    let f = process.env[TOKEN_VAR + '_FILE'];
    if (!f || isPlaceholder(f)) f = path.join(os.homedir(), '.config/proton-pass-agent/token');
    if (f) { try { t = fs.readFileSync(f, 'utf8'); } catch { t = ''; } }
  }
  if (!t || isPlaceholder(t)) return null;
  t = t.trim().replace(new RegExp('^' + PAT_VAR + '='), ''); // accept the raw `agent create` "token" string too
  return t || null;
}
const TOKEN = readToken();

function defaultUserSessionDirs() {
  const h = os.homedir();
  return [path.join(h, 'Library/Application Support/proton-pass-cli'), path.join(h, '.local/share/proton-pass-cli')];
}
function resolveSessionDir() {
  let d = process.env.PROTON_PASS_PLUGIN_SESSION_DIR;
  if (!d || isPlaceholder(d)) {
    const data = process.env.PLUGIN_DATA;
    d = data && !isPlaceholder(data) ? path.join(data, 'pass-agent-session')
      : path.join(os.homedir(), '.local/state/proton-pass-agent-plugin/session');
  }
  d = path.resolve(d);
  for (const u of defaultUserSessionDirs()) if (d === u || d.startsWith(u + path.sep))
    throw new Error(`Refusing to use the personal pass-cli session dir ${d}`);
  fs.mkdirSync(d, { recursive: true, mode: 0o700 });
  try { fs.chmodSync(d, 0o700); } catch {}
  return d;
}
let SESSION_DIR = null, SESSION_DIR_ERR = null;
try { SESSION_DIR = resolveSessionDir(); } catch (e) { SESSION_DIR_ERR = e.message; }

const SETUP_HELP = `Proton Pass plugin is not configured. Andrew must set it up (do NOT ask for his Proton password):
  1. pass-cli login                                   # as himself, in his own terminal
  2. pass-cli agent create cursor-agent --expiration 1m --vault "<Vault>"
  3. Save the printed token (pst_...::...) to ~/.config/proton-pass-agent/token (chmod 600), or set ${TOKEN_VAR}; then reload the plugin.
See the plugin README.`;

// Base env for every pass-cli call: no credentials, isolated session dir, mandatory audit reason.
function baseEnv(extra = {}) {
  const env = { ...process.env };
  for (const k of SECRET_ENV) delete env[k];
  for (const k of Object.keys(env)) if (k.startsWith(TOKEN_VAR)) delete env[k];
  env.PROTON_PASS_SESSION_DIR = SESSION_DIR;
  const ctx = callCtx.getStore();
  if (!ctx || !ctx.reason) throw new Error('internal: pass-cli invoked without a reason');
  env.PROTON_PASS_AGENT_REASON = ctx.reason;
  return Object.assign(env, extra);
}

function validateReason(reason) {
  if (typeof reason !== 'string' || !reason.trim())
    throw new ToolError('`reason` is required: a short description of the concrete task this access is for (it is written to the Proton Pass agent audit log).');
  if (reason.length > 300) throw new ToolError(`\`reason\` must be at most 300 characters (got ${reason.length}).`);
  if (/[\x00-\x1f\x7f]/.test(reason)) throw new ToolError('`reason` must not contain control characters or newlines.');
  return reason.trim();
}

// ---------- pass-cli helpers ----------
const NOT_LOGGED_IN = /not logged in|no (active )?session|session (has )?expired|login required|please (log ?in|run .?pass-cli login)|unauthenticated|unauthori[sz]ed|\b401\b/i;
const redact = (s) => (TOKEN ? String(s).split(TOKEN).join('[token redacted]') : String(s));

function rawCli(args, env, timeout = CLI_TIMEOUT_MS) {
  return new Promise((resolve) => {
    execFile(PASS_CLI, args, { env, timeout, maxBuffer: 32 * 1024 * 1024, windowsHide: true, shell: false }, (err, stdout, stderr) => {
      let code = 0;
      if (err) {
        if (err.code === 'ENOENT') return resolve({ missing: true, code: 127, stdout: '', stderr: '' });
        code = typeof err.code === 'number' ? err.code : (err.killed ? 124 : 1);
      }
      resolve({ code, stdout: String(stdout), stderr: redact(stderr), timedOut: !!(err && err.killed) });
    });
  });
}
const missingCli = () => new ToolError('pass-cli was not found on PATH. Install it (https://protonpass.github.io/pass-cli/get-started/installation/) or set PASS_CLI_BIN.');

let verifiedAt = 0, agentName = null, loginInFlight = null;
async function agentInfo() {
  const r = await rawCli(['info', '--output', 'json'], baseEnv());
  if (r.missing) throw missingCli();
  if (r.code !== 0) return null;
  try { return JSON.parse(r.stdout); } catch { return null; }
}
async function login() {
  const r = await rawCli(['login'], baseEnv({ [PAT_VAR]: TOKEN })); // token only ever reaches this one invocation
  if (r.missing) throw missingCli();
  if (r.code !== 0) throw new ToolError(`Agent login with ${TOKEN_VAR} failed (token invalid, expired or revoked?). Ask Andrew to run \`pass-cli agent renew <name> --expiration 1m\` and update the plugin variable. CLI said: ${truncate(r.stderr.trim(), 500)}`);
}
// Ensure an isolated, verified AGENT session. force=true after an auth failure.
async function ensureSession(force = false) {
  if (SESSION_DIR_ERR) throw new ToolError(SESSION_DIR_ERR);
  if (!TOKEN) throw new ToolError(SETUP_HELP);
  if (!force && Date.now() - verifiedAt < SESSION_RECHECK_MS) return;
  if (loginInFlight) return loginInFlight;
  loginInFlight = (async () => {
    let info = force ? null : await agentInfo();
    if (!info) { await login(); info = await agentInfo(); }
    if (!info) throw new ToolError('Logged in with the agent token but `pass-cli info` still fails; refusing to continue.');
    const pat = info.personal_access_token_name;
    if (typeof pat !== 'string' || !pat.startsWith('[Agent] ')) {
      verifiedAt = 0;
      throw new ToolError('Refusing: the isolated pass-cli session is not an agent session (`pass-cli info` shows no "[Agent]" token). The token must come from `pass-cli agent create`, not a plain PAT or a user login.');
    }
    agentName = pat.slice(8); verifiedAt = Date.now(); vaultCache = null;
  })().finally(() => { loginInFlight = null; });
  return loginInFlight;
}

// Run pass-cli for a tool: session ensured, reason set, one transparent re-login on auth failure.
async function cli(args, { extraEnv = {}, timeout } = {}) {
  await ensureSession();
  let r = await rawCli(args, baseEnv(extraEnv), timeout);
  if (r.missing) throw missingCli();
  if (r.code !== 0 && NOT_LOGGED_IN.test(r.stderr) && !r.stdout) {
    await ensureSession(true);
    r = await rawCli(args, baseEnv(extraEnv), timeout);
  }
  return r;
}

function authOrFail(r, what) {
  if (r.missing) throw missingCli();
  if (r.code !== 0 && NOT_LOGGED_IN.test(r.stderr + '\n' + r.stdout))
    throw new ToolError('Proton Pass agent session is not logged in even after automatic re-login. Ask Andrew to check the agent token (`pass-cli agent list`, `pass-cli agent renew`).');
  if (r.code !== 0) throw new ToolError(`${what} failed (exit ${r.code}): ${truncate(r.stderr.trim() || redact(r.stdout).trim(), 2000)}`);
}

async function cliJson(args, what) {
  const r = await cli([...args, '--output', 'json']);
  authOrFail(r, what);
  try { return JSON.parse(r.stdout); }
  catch { throw new ToolError(`${what}: could not parse pass-cli JSON output.`); }
}

function truncate(s, n = MAX_OUT) {
  if (s.length <= n) return s;
  return s.slice(0, n) + `\n…[truncated ${s.length - n} chars]`;
}

// ---------- defensive JSON shape handling (JSON schema is not documented) ----------
function asArray(j, keys) {
  if (Array.isArray(j)) return j;
  if (j && typeof j === 'object') for (const k of keys) if (Array.isArray(j[k])) return j[k];
  return [];
}
const pick = (o, ...ks) => { for (const k of ks) if (o && o[k] != null && o[k] !== '') return o[k]; };

function normVault(v) {
  return { name: pick(v, 'name', 'vault_name', 'title') ?? pick(v.content, 'name') ?? null,
           share_id: pick(v, 'share_id', 'shareId', 'id') ?? null };
}

const META_KEYS = new Set(['id', 'item_id', 'itemId', 'share_id', 'shareId', 'vault_id', 'title', 'name', 'type', 'item_type',
  'state', 'flags', 'pinned', 'create_time', 'modify_time', 'createTime', 'modifyTime', 'last_use_time', 'revision',
  'content_format_version', 'vault', 'vault_name', 'attachments', 'extra_fields', 'extraFields', 'sections', 'fields',
  'content', 'item_uuid', 'state', 'share']);

// Collect field NAMES only; values are never copied.
function fieldNames(item) {
  const names = new Set();
  const visitFields = (arr, prefix) => {
    for (const f of asArray(arr, [])) {
      const n = pick(f, 'name', 'field_name', 'label');
      if (typeof n === 'string') names.add(prefix ? `${prefix}.${n}` : n);
    }
  };
  const walk = (o, depth) => {
    if (!o || typeof o !== 'object' || depth > 4) return;
    for (const [k, v] of Object.entries(o)) {
      if (k === 'extra_fields' || k === 'extraFields' || k === 'fields') { visitFields(v, ''); continue; }
      if (k === 'sections' && Array.isArray(v)) {
        for (const s of v) visitFields(s.fields || s.section_fields, pick(s, 'name', 'section_name'));
        continue;
      }
      if (META_KEYS.has(k) && k !== 'content') continue;
      if (v !== null && typeof v === 'object' && !Array.isArray(v)) walk(v, depth + 1);
      else if (v !== null && v !== '' && !(Array.isArray(v) && v.length === 0)) names.add(k === 'urls' ? 'url' : k === 'totp_uri' ? 'totp' : k);
    }
  };
  walk(item.content ?? item, 0);
  if (item.note || (item.content && item.content.note)) names.add('note');
  return [...names];
}

function itemType(item) {
  let t = pick(item, 'type', 'item_type') ?? pick(item.content || {}, 'type');
  if (!t && item.content && item.content.content && typeof item.content.content === 'object') t = Object.keys(item.content.content)[0];
  return t ? String(t).toLowerCase() : 'unknown';
}

const seg = (s) => String(s); // CLI accepts spaces; '/' in names cannot be expressed, so prefer ids.
function toRef(item, vault) {
  const title = pick(item, 'title', 'name') ?? pick(item.content || {}, 'title', 'name') ?? '(untitled)';
  const itemId = pick(item, 'id', 'item_id', 'itemId');
  const shareId = pick(item, 'share_id', 'shareId') ?? vault.share_id;
  const vaultName = vault.name ?? pick(item, 'vault_name') ?? shareId;
  const vSeg = /[/?#]/.test(vaultName || '') || !vaultName ? shareId : vaultName;
  const iSeg = /[/?#]/.test(title) ? itemId : title;
  return { vault: vaultName, title, type: itemType(item), fields: fieldNames(item),
           uri: `pass://${seg(vSeg)}/${seg(iSeg)}`,
           ...(shareId && itemId ? { id_uri: `pass://${shareId}/${itemId}` } : {}) };
}

// ---------- URI validation ----------
// pass://<vault>/<item>/<field>[?totp=code|uri]; segments: no '/', '?', '#', control chars; not blank.
const URI_RE = /^pass:\/\/([^/?#\x00-\x1f\x7f]+)\/([^/?#\x00-\x1f\x7f]+)\/([^/?#\x00-\x1f\x7f]+)(\?totp=(?:code|uri))?$/;
function validateUri(uri) {
  if (typeof uri !== 'string' || uri.length > 1024) throw new ToolError('uri must be a string of at most 1024 chars.');
  const m = URI_RE.exec(uri);
  if (!m || [m[1], m[2], m[3]].some((s) => !s.trim() || s !== s.trim()))
    throw new ToolError(`Invalid secret reference. Expected exactly pass://<vault>/<item>/<field> (optional ?totp=code|uri), no empty segments, no trailing slash. Got: ${JSON.stringify(uri.slice(0, 200))}`);
  return uri;
}
const REF_IN_VALUE = /pass:\/\/[^\s/?#]+\/[^/?#]+\/[^\s/?#@]+/;

// ---------- tools ----------
let vaultCache = null; // [{name, share_id}], cleared whenever the session is (re)established
async function listVaults() {
  const j = await cliJson(['vault', 'list'], 'vault list');
  vaultCache = asArray(j, ['vaults', 'shares', 'items', 'data']).map(normVault);
  return vaultCache;
}
async function vaultNameFor(shareId) {
  const find = () => vaultCache && vaultCache.find((v) => v.share_id === shareId);
  if (!find()) await listVaults();
  const v = find(); return v && v.name ? v.name : null;
}
const SAFE_SEG = (x) => typeof x === 'string' && x.trim() !== '' && x === x.trim() && !/[/?#\x00-\x1f\x7f]/.test(x);

async function searchItems({ vault, query, limit } = {}) {
  if (vault != null && (typeof vault !== 'string' || !vault.trim())) throw new ToolError('vault must be a non-empty string.');
  if (query != null && typeof query !== 'string') throw new ToolError('query must be a string.');
  const lim = limit == null ? 50 : Math.floor(Number(limit));
  if (!(lim >= 1 && lim <= 500)) throw new ToolError('limit must be 1..500.');
  let vaults = await listVaults();
  if (vault) {
    vaults = vaults.filter((v) => v.name === vault || v.share_id === vault);
    if (!vaults.length) throw new ToolError(`No vault named or with share id ${JSON.stringify(vault)}. Use list_vaults.`);
  }
  const q = (query || '').toLowerCase().trim();
  const all = [];
  for (const v of vaults) {
    const args = v.share_id ? ['item', 'list', '--share-id', v.share_id] : ['item', 'list', '--vault-name', v.name];
    const j = await cliJson(args, `item list (${v.name})`);
    for (const it of asArray(j, ['items', 'data'])) {
      const { fields, ...ref } = toRef(it, v); // item list has metadata only; never return a fields key here
      ref.modify_time = pick(it, 'modify_time', 'modifyTime') ?? null;
      if (!q || ref.title.toLowerCase().includes(q) || ref.type.includes(q)) all.push(ref);
    }
  }
  return { total: all.length, items: all.slice(0, lim) };
}

// describe_item: whole-item view, return field NAMES only.
const KNOWN_FIELDS = ['username', 'email', 'password', 'urls', 'url', 'totp', 'totp_uri', 'note', 'notes'];
const LIST_KEYS = ['extra_fields', 'extraFields', 'custom_fields', 'customFields', 'fields'];
const SECTION_KEYS = ['sections', 'extra_sections', 'extraSections'];
const SKIP = new Set([...META_KEYS].filter((k) => k !== 'content'));
function describeFields(root) {
  const names = new Set();
  const label = (f) => { const n = pick(f, 'name', 'field_name', 'label', 'title'); return typeof n === 'string' && n.trim() ? n : null; };
  const add = (n) => names.add(n === 'urls' ? 'url' : n === 'totp_uri' ? 'totp' : n === 'notes' ? 'note' : n);
  const walk = (o, depth, prefix) => {
    if (!o || typeof o !== 'object' || depth > 6) return;
    if (Array.isArray(o)) { for (const x of o) walk(x, depth + 1, prefix); return; }
    for (const [k, v] of Object.entries(o)) {
      if (LIST_KEYS.includes(k) && Array.isArray(v)) { for (const f of v) { const n = label(f); if (n) add(prefix ? `${prefix}.${n}` : n); } continue; }
      if (SECTION_KEYS.includes(k) && Array.isArray(v)) {
        for (const sec of v) { const sn = label(sec) || pick(sec, 'section_name');
          const fs = pick(sec, 'fields', 'section_fields', 'extra_fields') || [];
          for (const f of asArray(fs, [])) { const n = label(f); if (n) add(sn ? `${sn}.${n}` : n); } }
        continue;
      }
      if (KNOWN_FIELDS.includes(k)) { if (v != null && v !== '' && !(Array.isArray(v) && !v.length)) add(prefix ? `${prefix}.${k}` : k); continue; }
      if (SKIP.has(k)) continue;
      if (v && typeof v === 'object') walk(v, depth + 1, prefix);
      else if (depth >= 1 && v != null && v !== '' && typeof v !== 'boolean') add(k); // type-specific keys (e.g. card number, ssid)
    }
  };
  walk(root, 0, '');
  return [...names];
}

async function describeItem({ vault, item, id_uri } = {}) {
  let args, vSeg, iSeg;
  if (id_uri != null) {
    if (vault != null || item != null) throw new ToolError('Give either id_uri or vault+item, not both.');
    const m = typeof id_uri === 'string' && /^pass:\/\/([^/?#\s\x00-\x1f]+)\/([^/?#\s\x00-\x1f]+)$/.exec(id_uri);
    if (!m) throw new ToolError('id_uri must be pass://<share_id>/<item_id> (from search_items).');
    args = ['item', 'view', '--share-id', m[1], '--item-id', m[2]]; vSeg = m[1]; iSeg = m[2];
  } else {
    for (const [n, x] of [['vault', vault], ['item', item]])
      if (typeof x !== 'string' || !x.trim() || x !== x.trim() || /[/?#\x00-\x1f\x7f]/.test(x) || x.startsWith('-'))
        throw new ToolError(`${n} must be a non-empty name/id without '/', '?', '#', control chars or leading '-'. For such names use id_uri.`);
    args = ['item', 'view', '--vault-name', vault, '--item-title', item]; vSeg = vault; iSeg = item;
  }
  const j = await cliJson(args, 'item view');
  const it = (j && typeof j === 'object' && !Array.isArray(j) && j.item && typeof j.item === 'object') ? j.item : j;
  const title = pick(it, 'title', 'name') ?? pick(it.content || {}, 'title', 'name') ?? (id_uri ? null : item);
  const shareId = pick(it, 'share_id', 'shareId') ?? (id_uri ? vSeg : null);
  const itemId = pick(it, 'id', 'item_id', 'itemId') ?? (id_uri ? iSeg : null);
  let vaultName = id_uri ? (pick(it, 'vault_name') ?? (shareId ? await vaultNameFor(shareId) : null)) : vault;
  const fields = describeFields(it);
  // Prefer readable names in URIs; fall back to IDs per segment when a name is missing or unsafe.
  const vPart = SAFE_SEG(vaultName) ? vaultName : (shareId ?? vSeg);
  const iPart = SAFE_SEG(title) ? title : (itemId ?? iSeg);
  const base = `pass://${vPart}/${iPart}`;
  const idUri = shareId && itemId ? `pass://${shareId}/${itemId}` : undefined;
  return { vault: vaultName ?? shareId ?? vSeg, title: title ?? iSeg, type: itemType(it), fields, uri: base,
           ...(idUri ? { id_uri: idUri } : {}),
           field_uris: Object.fromEntries(fields.map((f) => [f, `${base}/${f}`])) };
}

async function runWithSecrets({ command, env, timeout_ms } = {}) {
  if (!Array.isArray(command) || !command.length || command.some((c) => typeof c !== 'string' || c.includes('\0')))
    throw new ToolError('command must be a non-empty array of strings (argv; no shell is used).');
  if (env == null) env = {};
  if (typeof env !== 'object' || Array.isArray(env)) throw new ToolError('env must be an object of NAME -> value.');
  const childEnv = {};
  for (const [k, v] of Object.entries(env)) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(k)) throw new ToolError(`Invalid env var name ${JSON.stringify(k)}.`);
    if (typeof v !== 'string' || v.includes('\0')) throw new ToolError(`env.${k} must be a string.`);
    if (v.startsWith('pass://')) validateUri(v);
    else if (!REF_IN_VALUE.test(v)) throw new ToolError(`env.${k} must be a pass://vault/item/field reference (or text embedding one). Do not pass literal secrets.`);
    if (k.startsWith('PROTON_PASS_') || k === 'PLUGIN_ROOT' || k === 'PLUGIN_DATA') throw new ToolError(`env.${k}: reserved name.`);
    childEnv[k] = v;
  }
  const t = Math.min(Math.max(Number(timeout_ms) || 120_000, 1000), RUN_TIMEOUT_MS);
  // Masking is ON by default in `pass-cli run`; we never pass --no-masking.
  // baseEnv() strips the token/credential vars, so the child never inherits them.
  const r = await cli(['run', '--', ...command], { extraEnv: childEnv, timeout: t });
  return { exit_code: r.code, timed_out: r.timedOut || false, stdout: truncate(r.stdout), stderr: truncate(r.stderr),
           note: 'Secrets were resolved by pass-cli inside the child process; pass-cli masks resolved values in stdout/stderr.' };
}

async function getSecret({ uri } = {}) {
  validateUri(uri);
  const r = await cli(['item', 'view', uri]);
  authOrFail(r, 'item view');
  return { uri, value: r.stdout.replace(/\r?\n$/, '') };
}

const REASON_PROP = { type: 'string', minLength: 1, maxLength: 300,
  description: 'REQUIRED. The concrete task this access is for (e.g. "Deploy api-server to staging: needs DB password"). Logged to the Proton Pass agent audit log. Max 300 chars, single line.' };
const TOOLS = [
  { name: 'list_vaults', description: 'List Proton Pass vaults (name and share_id). Returns no secrets.',
    inputSchema: { type: 'object', required: ['reason'], properties: { reason: REASON_PROP,}, additionalProperties: false }, handler: () => listVaults() },
  { name: 'search_items',
    description: 'Search Proton Pass items by title/type (metadata only, no values, no field names). Returns {total, items: [{vault, title, type, uri, id_uri, modify_time}]}. Scanning all vaults can be slow (~20s for large accounts); pass vault when you can. Then call describe_item for field names.',
    inputSchema: { type: 'object', required: ['reason'], properties: { reason: REASON_PROP,
      vault: { type: 'string', description: 'Vault name or share id (optional; default all vaults).' },
      query: { type: 'string', description: 'Case-insensitive substring of title or type (optional).' },
      limit: { type: 'number', description: 'Max items returned (default 50, max 500). total is always the full match count.' } }, additionalProperties: false },
    handler: searchItems },
  { name: 'describe_item',
    description: 'List the field NAMES of one item (all values stripped), with a pass://vault/item/field uri per field for run_with_secrets/get_secret. Identify the item by id_uri (preferred, from search_items) or vault+item names.',
    inputSchema: { type: 'object', required: ['reason'], properties: { reason: REASON_PROP,
      id_uri: { type: 'string', description: 'pass://<share_id>/<item_id> from search_items.' },
      vault: { type: 'string', description: 'Vault name (with item).' },
      item: { type: 'string', description: 'Item title (with vault).' } }, additionalProperties: false },
    handler: describeItem },
  { name: 'run_with_secrets',
    description: 'PREFERRED way to use secrets. Runs `pass-cli run -- <command...>` with env vars set to pass://vault/item/field references; pass-cli resolves them only inside the child process and masks them in output. Returns exit_code, stdout, stderr (truncated at 16KB each). No shell is used: give argv, e.g. ["sh","-c","curl -H \\"Authorization: Bearer $TOKEN\\" ..."] if you need expansion.',
    inputSchema: { type: 'object', required: ['reason', 'command'], properties: { reason: REASON_PROP,
      command: { type: 'array', items: { type: 'string' }, minItems: 1, description: 'argv of the command to run.' },
      env: { type: 'object', additionalProperties: { type: 'string' }, description: 'NAME -> "pass://vault/item/field" (may be embedded in text).' },
      timeout_ms: { type: 'number', description: 'Default 120000, max 600000.' } }, additionalProperties: false },
    handler: runWithSecrets },
  { name: 'get_secret',
    description: 'WARNING: returns the raw secret value, which then enters the conversation transcript and model context. Prefer run_with_secrets whenever the secret is only needed by a command. Use only when the user explicitly needs the value. uri must be exactly pass://<vault>/<item>/<field> (optional ?totp=code|uri).',
    inputSchema: { type: 'object', required: ['reason', 'uri'], properties: { reason: REASON_PROP, uri: { type: 'string' } }, additionalProperties: false },
    handler: getSecret },
];

// ---------- JSON-RPC over stdio (newline-delimited) ----------
const send = (msg) => process.stdout.write(JSON.stringify({ jsonrpc: '2.0', ...msg }) + '\n');

async function handle(req) {
  const { id, method, params } = req;
  const isNotification = id === undefined || id === null;
  try {
    let result;
    switch (method) {
      case 'initialize':
        result = { protocolVersion: (params && params.protocolVersion) || PROTOCOL, capabilities: { tools: { listChanged: false } },
                   serverInfo: { name: 'proton-pass', version: '0.1.0' } };
        break;
      case 'notifications/initialized': case 'notifications/cancelled': return;
      case 'ping': result = {}; break;
      case 'tools/list':
        result = { tools: TOOLS.map(({ handler, ...t }) => t) }; break;
      case 'tools/call': {
        const tool = TOOLS.find((t) => t.name === (params && params.name));
        if (!tool) { if (!isNotification) send({ id, error: { code: -32602, message: `Unknown tool: ${params && params.name}` } }); return; }
        try {
          const args = { ...((params && params.arguments) || {}) };
          const reason = validateReason(args.reason); // rejected before any pass-cli invocation
          delete args.reason;
          const data = await callCtx.run({ reason }, () => tool.handler(args));
          result = { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }], structuredContent: Array.isArray(data) ? { items: data } : data, isError: false };
        } catch (e) {
          if (!(e instanceof ToolError)) process.stderr.write(`[proton-pass] ${e && e.stack}\n`);
          result = { content: [{ type: 'text', text: e instanceof ToolError ? e.message : 'Internal error.' }], isError: true };
        }
        break;
      }
      default:
        if (!isNotification) send({ id, error: { code: -32601, message: `Method not found: ${method}` } });
        return;
    }
    if (!isNotification) send({ id, result });
  } catch (e) {
    if (!isNotification) send({ id, error: { code: -32603, message: 'Internal error' } });
  }
}

const rl = readline.createInterface({ input: process.stdin });
rl.on('line', (line) => {
  if (!line.trim()) return;
  let req;
  try { req = JSON.parse(line); } catch { return send({ id: null, error: { code: -32700, message: 'Parse error' } }); }
  handle(req);
});
rl.on('close', () => process.exit(0));
