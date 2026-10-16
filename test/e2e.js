// End-to-end JSON-RPC over stdio against the stub pass-cli in test/bin.
'use strict';
const { spawn } = require('node:child_process');
const path = require('node:path');
const assert = require('node:assert');
const ROOT = path.join(__dirname, '..');
const BIN = path.join(__dirname, 'bin');
const fs = require('node:fs'); const os = require('node:os');
const TOKEN = 'pst_testtoken::TOKENKEY';
const REASON = 'e2e: verify proton-pass plugin tools against stub';
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-e2e-'));
const readLog = (f) => fs.existsSync(f) ? fs.readFileSync(f, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse) : [];

let nServers = 0;
function startServer(extraEnv = {}) {
  const id = ++nServers; const sessionDir = path.join(TMP, `session${id}`); const log = path.join(TMP, `log${id}.jsonl`);
  const env = { ...process.env, PATH: `${BIN}:${process.env.PATH}`, PROTON_PASS_AGENT_TOKEN: TOKEN,
                PROTON_PASS_PLUGIN_SESSION_DIR: sessionDir, STUB_LOG: log, ...extraEnv };
  for (const k of Object.keys(env)) if (env[k] === undefined) delete env[k];
  const p = spawn('node', ['server/index.js'], { cwd: ROOT, env });
  let buf = ''; const waiters = new Map(); let next = 1;
  p.stdout.on('data', (d) => { buf += d; let i; while ((i = buf.indexOf('\n')) >= 0) {
    const m = JSON.parse(buf.slice(0, i)); buf = buf.slice(i + 1); const w = waiters.get(m.id); if (w) { waiters.delete(m.id); w(m); } } });
  p.stderr.on('data', (d) => process.stderr.write('[server] ' + d));
  const rpc = (method, params) => new Promise((res) => { const id = next++; waiters.set(id, res);
    p.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n'); });
  const call = async (name, args, ...rest) => { const reason = rest.length ? rest[0] : REASON; const m = await rpc('tools/call', { name, arguments: reason === undefined ? args : { reason, ...args } });
    return { isError: m.result.isError, text: m.result.content[0].text, data: m.result.structuredContent }; };
  return { p, rpc, call, sessionDir, log, notify: (method) => p.stdin.write(JSON.stringify({ jsonrpc: '2.0', method }) + '\n') };
}

let pass = 0, failN = 0;
async function t(name, fn) { try { await fn(); console.log('PASS', name); pass++; } catch (e) { console.log('FAIL', name, '-', e.message); failN++; } }

(async () => {
  const s = startServer();
  await t('initialize', async () => { const m = await s.rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'e2e', version: '0' } });
    assert.equal(m.result.serverInfo.name, 'proton-pass'); assert.ok(m.result.capabilities.tools); s.notify('notifications/initialized'); });
  await t('tools/list has 5 tools', async () => { const m = await s.rpc('tools/list', {});
    assert.deepEqual(m.result.tools.map((x) => x.name).sort(), ['describe_item', 'get_secret', 'list_vaults', 'run_with_secrets', 'search_items']);
    assert.match(m.result.tools.find((x) => x.name === 'get_secret').description, /transcript/); });
  await t('list_vaults', async () => { const r = await s.call('list_vaults', {}); assert.ok(!r.isError, r.text);
    assert.deepEqual(r.data.items, [{ name: 'Work', share_id: 'shWORK1' }, { name: 'Personal', share_id: 'shPERS2' }, { name: 'Dev', share_id: 'shMUSE3' }]); });
  await t('search_items: metadata only, {total, items}, no fields key', async () => {
    const r = await s.call('search_items', { vault: 'Work', query: 'git' }); assert.ok(!r.isError, r.text);
    assert.equal(r.data.total, 1); const it = r.data.items[0];
    assert.deepEqual(it, { vault: 'Work', title: 'GitHub', type: 'login', uri: 'pass://Work/GitHub', id_uri: 'pass://shWORK1/itGH', modify_time: '2026-10-01T12:00:00Z' }); });
  await t('describe_item by id_uri resolves vault name + title into uri/field_uris, keeps id_uri', async () => {
    const r = await s.call('describe_item', { id_uri: 'pass://shMUSE3/itBF' }); assert.ok(!r.isError, r.text);
    assert.equal(r.data.vault, 'Dev'); assert.equal(r.data.title, 'Bifrost Virtual Key'); assert.equal(r.data.type, 'custom');
    assert.deepEqual(r.data.fields, ['Secret']); assert.equal(r.data.uri, 'pass://Dev/Bifrost Virtual Key');
    assert.equal(r.data.id_uri, 'pass://shMUSE3/itBF'); assert.deepEqual(r.data.field_uris, { Secret: 'pass://Dev/Bifrost Virtual Key/Secret' });
    assert.ok(!r.text.includes('bifrost-SEED-key'));
    const g = await s.call('get_secret', { uri: r.data.field_uris.Secret }); assert.equal(g.data.value, 'bifrost-SEED-key'); });
  await t('describe_item: unsafe title (contains /) falls back to item id in uri', async () => {
    const r = await s.call('describe_item', { id_uri: 'pass://shMUSE3/itCI' }); assert.ok(!r.isError, r.text);
    assert.equal(r.data.title, 'CI/CD Token'); assert.equal(r.data.uri, 'pass://Dev/itCI'); assert.equal(r.data.field_uris.password, 'pass://Dev/itCI/password');
    assert.ok(!r.text.includes('cicd-SEED-pw'));
    const g = await s.call('get_secret', { uri: r.data.field_uris.password }); assert.equal(g.data.value, 'cicd-SEED-pw'); });
  await t('describe_item by names also returns id_uri', async () => {
    const r = await s.call('describe_item', { vault: 'Dev', item: 'Bifrost Virtual Key' }); assert.equal(r.data.id_uri, 'pass://shMUSE3/itBF'); assert.equal(r.data.uri, 'pass://Dev/Bifrost Virtual Key'); });
  await t('search_items all vaults + limit', async () => { const r = await s.call('search_items', { limit: 2 });
    assert.equal(r.data.total, 6); assert.equal(r.data.items.length, 2);
    const t2 = await s.call('search_items', { query: 'custom' }); assert.equal(t2.data.items[0].title, 'Deploy Targets');
    assert.ok((await s.call('search_items', { limit: 0 })).isError); });
  const SEEDS = ['gh-S3CRET-pw', 'ghp_TOKENVALUE123', 'jdoe', 'a@example.com', 'github.com', 'db-pass-XYZ', 'admin',
                 'stg-pw-SEED', 'prd-pw-SEED', 'stg.host.SEED', 'deploy-note-SEED', 'wifi-pw-777', 'home'];
  await t('describe_item by id_uri: names only, per-field uris, no values', async () => {
    const r = await s.call('describe_item', { id_uri: 'pass://shWORK1/itGH' }); assert.ok(!r.isError, r.text);
    assert.equal(r.data.title, 'GitHub'); assert.equal(r.data.type, 'login'); assert.equal(r.data.uri, 'pass://Work/GitHub'); assert.equal(r.data.vault, 'Work');
    assert.deepEqual([...r.data.fields].sort(), ['api_token', 'email', 'password', 'url', 'username']);
    assert.equal(r.data.field_uris.api_token, 'pass://Work/GitHub/api_token');
    for (const x of SEEDS) assert.ok(!r.text.includes(x), `leaked ${x}`); });
  await t('describe_item by names: section fields, note', async () => {
    const r = await s.call('describe_item', { vault: 'Work', item: 'Deploy Targets' }); assert.ok(!r.isError, r.text);
    assert.equal(r.data.type, 'custom');
    assert.deepEqual([...r.data.fields].sort(), ['Production.password', 'Staging.host', 'Staging.password', 'note']);
    assert.equal(r.data.field_uris['Staging.password'], 'pass://Work/Deploy Targets/Staging.password');
    for (const x of SEEDS) assert.ok(!r.text.includes(x), `leaked ${x}`); });
  await t('describe_item field uri works with get_secret', async () => {
    const r = await s.call('describe_item', { vault: 'Personal', item: 'Home WiFi' });
    assert.deepEqual([...r.data.fields].sort(), ['password', 'ssid']); for (const x of SEEDS) assert.ok(!r.text.includes(x), `leaked ${x}`);
    const g = await s.call('get_secret', { uri: r.data.field_uris.password }); assert.equal(g.data.value, 'wifi-pw-777'); });
  for (const bad of [{}, { id_uri: 'pass://a/b/c' }, { vault: 'Work' }, { vault: 'Work', item: '--help' }, { vault: 'W/x', item: 'a' }, { id_uri: 'pass://a/b', vault: 'x' }])
    await t(`describe_item bad args ${JSON.stringify(bad)}`, async () => assert.ok((await s.call('describe_item', bad)).isError));
  await t('run_with_secrets resolves in child, masked output', async () => {
    const r = await s.call('run_with_secrets', { command: ['sh', '-c', 'echo "len=${#GH_PW} pw=$GH_PW"; echo err >&2; exit 3'], env: { GH_PW: 'pass://Work/GitHub/password' } });
    assert.ok(!r.isError, r.text); assert.equal(r.data.exit_code, 3);
    assert.match(r.data.stdout, /len=12 pw=<concealed by Proton Pass>/); assert.equal(r.data.stderr.trim(), 'err');
    assert.ok(!r.text.includes('gh-S3CRET-pw')); });
  await t('run_with_secrets rejects literal secret in env', async () => {
    const r = await s.call('run_with_secrets', { command: ['true'], env: { X: 'hunter2' } }); assert.ok(r.isError); });
  await t('run_with_secrets no shell injection (argv passed literally)', async () => {
    const r = await s.call('run_with_secrets', { command: ['echo', '$(id); rm -rf /tmp/nope'] });
    assert.equal(r.data.stdout.trim(), '$(id); rm -rf /tmp/nope'); });
  await t('run_with_secrets truncates large output', async () => {
    const r = await s.call('run_with_secrets', { command: ['sh', '-c', 'head -c 100000 /dev/zero | tr "\\0" a'] });
    assert.match(r.data.stdout, /truncated 83616 chars/); });
  await t('get_secret', async () => { const r = await s.call('get_secret', { uri: 'pass://Work/GitHub/api_token' });
    assert.ok(!r.isError, r.text); assert.equal(r.data.value, 'ghp_TOKENVALUE123'); });
  for (const bad of ['pass://Work/GitHub', 'pass://Work/GitHub/', 'pass://Work/GitHub/password/x', 'pass://', 'http://Work/GitHub/password',
                     '--help', 'pass://Work/GitHub/password?x=1', 'pass://Work/ /password', 'pass://Work/Git\nHub/password', 42])
    await t(`get_secret bad uri ${JSON.stringify(bad)}`, async () => { const r = await s.call('get_secret', { uri: bad });
      assert.ok(r.isError); assert.match(r.text, /Invalid secret reference|must be a string/); });
  await t('unknown method -> -32601', async () => { const m = await s.rpc('foo/bar', {}); assert.equal(m.error.code, -32601); });

  // ---- agent auth / reason / isolation checks (on server s) ----
  await t('auto-login on first call, then agent session verified via info', async () => {
    const L = readLog(s.log); assert.deepEqual(L.slice(0, 3).map((x) => x.args[0]), ['info', 'login', 'info']);
    assert.ok(fs.existsSync(path.join(s.sessionDir, 'session.json'))); });
  await t('every pass-cli call: isolated session dir + reason; token only on login', async () => {
    const L = readLog(s.log); assert.ok(L.length > 10);
    for (const x of L) { assert.equal(x.session_dir, s.sessionDir); assert.equal(x.reason, REASON); assert.equal(x.agentTokenVar, false);
      assert.equal(x.token, x.args[0] === 'login', `token presence wrong on ${x.args}`); } });
  await t('run_with_secrets child env has no token vars', async () => {
    const r = await s.call('run_with_secrets', { command: ['env'], env: { DB: 'pass://Work/Prod DB/password' } });
    assert.equal(r.data.exit_code, 0); assert.match(r.data.stdout, /^DB=<concealed by Proton Pass>$/m);
    for (const x of ['PROTON_PASS_PERSONAL_ACCESS_TOKEN', 'PROTON_PASS_AGENT_TOKEN', TOKEN, 'TOKENKEY']) assert.ok(!r.data.stdout.includes(x), `child saw ${x}`); });
  await t('run_with_secrets rejects reserved env names', async () =>
    assert.ok((await s.call('run_with_secrets', { command: ['true'], env: { PROTON_PASS_SESSION_DIR: 'pass://a/b/c' } })).isError));
  const before = readLog(s.log).length;
  for (const [label, reason] of [['missing', undefined], ['empty', '   '], ['301 chars', 'x'.repeat(301)], ['newline', 'a\nb'], ['non-string', 7]])
    for (const tool of ['list_vaults', 'search_items', 'describe_item', 'run_with_secrets', 'get_secret'])
      await t(`reason ${label} rejected: ${tool}`, async () => { const r = await s.call(tool, { uri: 'pass://Work/GitHub/password', command: ['true'], id_uri: 'pass://shWORK1/itGH' }, reason);
        assert.ok(r.isError); assert.match(r.text, /reason/); });
  await t('invalid reasons never invoked pass-cli', async () => assert.equal(readLog(s.log).length, before));
  await t('reason of exactly 300 chars accepted', async () => { const r = await s.call('list_vaults', {}, 'y'.repeat(300)); assert.ok(!r.isError, r.text); });
  await t('expired session -> transparent re-login', async () => {
    fs.unlinkSync(path.join(s.sessionDir, 'session.json')); const n0 = readLog(s.log).length;
    const r = await s.call('get_secret', { uri: 'pass://Work/GitHub/password' }); assert.ok(!r.isError, r.text); assert.equal(r.data.value, 'gh-S3CRET-pw');
    assert.ok(readLog(s.log).slice(n0).some((x) => x.args[0] === 'login')); });
  s.p.stdin.end();

  for (const [label, envx] of [['absent', { PROTON_PASS_AGENT_TOKEN: undefined, PROTON_PASS_AGENT_TOKEN_FILE: path.join(TMP, 'nope') }], ['unexpanded placeholder', { PROTON_PASS_AGENT_TOKEN: '${PROTON_PASS_AGENT_TOKEN}', PROTON_PASS_AGENT_TOKEN_FILE: path.join(TMP, 'nope') }]]) {
    const o = startServer(envx);
    for (const [tool, args] of [['list_vaults', {}], ['search_items', {}], ['describe_item', { id_uri: 'pass://shWORK1/itGH' }], ['get_secret', { uri: 'pass://Work/GitHub/password' }],
                                ['run_with_secrets', { command: ['true'], env: { A: 'pass://Work/GitHub/password' } }]])
      await t(`token ${label}: ${tool} refused with setup help`, async () => { const r = await o.call(tool, args); assert.ok(r.isError, r.text); assert.match(r.text, /agent create/); });
    await t(`token ${label}: pass-cli never invoked`, async () => assert.equal(readLog(o.log).length, 0));
    o.p.stdin.end();
  }
  { const f = path.join(TMP, 'tokfile'); fs.writeFileSync(f, `PROTON_PASS_PERSONAL_ACCESS_TOKEN=${TOKEN}\n`, { mode: 0o600 });
    const o = startServer({ PROTON_PASS_AGENT_TOKEN: '${PROTON_PASS_AGENT_TOKEN}', PROTON_PASS_AGENT_TOKEN_FILE: f });
    await t('token via _FILE (raw `agent create` string) works', async () => { const r = await o.call('list_vaults', {}); assert.ok(!r.isError, r.text); });
    o.p.stdin.end(); }
  { const home = path.join(TMP, 'home'); fs.mkdirSync(path.join(home, '.config/proton-pass-agent'), { recursive: true });
    fs.writeFileSync(path.join(home, '.config/proton-pass-agent/token'), TOKEN + '\n', { mode: 0o600 });
    const o = startServer({ HOME: home, PROTON_PASS_AGENT_TOKEN: undefined, PROTON_PASS_AGENT_TOKEN_FILE: undefined });
    await t('default token file ~/.config/proton-pass-agent/token works', async () => { const r = await o.call('list_vaults', {}); assert.ok(!r.isError, r.text); });
    o.p.stdin.end(); }
  { const o = startServer({ STUB_VALID_TOKEN: 'pst_other::KEY' });
    await t('bad/expired token -> clear login error, token not echoed', async () => { const r = await o.call('list_vaults', {});
      assert.ok(r.isError); assert.match(r.text, /agent renew/); assert.ok(!r.text.includes('TOKENKEY')); });
    o.p.stdin.end(); }
  { const o = startServer({ STUB_PLAIN_PAT: '1' });
    await t('non-agent (plain PAT) session refused', async () => { const r = await o.call('list_vaults', {}); assert.ok(r.isError); assert.match(r.text, /not an agent session/); });
    o.p.stdin.end(); }
  { const o = startServer({ PROTON_PASS_PLUGIN_SESSION_DIR: path.join(os.homedir(), '.local/share/proton-pass-cli/.session') });
    await t('personal session dir refused', async () => { const r = await o.call('list_vaults', {}); assert.ok(r.isError); assert.match(r.text, /personal pass-cli session/);
      assert.equal(readLog(o.log).length, 0); });
    o.p.stdin.end(); }

  const n = startServer({ PATH: '/usr/bin:/bin', PASS_CLI_BIN: 'pass-cli-does-not-exist' });
  await t('pass-cli missing', async () => { const r = await n.call('list_vaults', {}); assert.ok(r.isError); assert.match(r.text, /not found on PATH/); });
  n.p.stdin.end();

  console.log(`\n${pass} passed, ${failN} failed`); process.exit(failN ? 1 : 0);
})();
