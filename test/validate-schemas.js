// Optional: validates manifests with ajv (dev-only; install with `npm i --no-save ajv@8` in a scratch dir and set NODE_PATH).
const Ajv = require('ajv/dist/2020'); const fs = require('fs'); const p = require('path'); const R = p.join(__dirname, '..');
let bad = 0;
for (const [f, s] of [['plugin.json', 'plugin.schema.json'], ['mcp.json', 'mcp.schema.json']]) {
  const v = new Ajv({ strict: false }).compile(JSON.parse(fs.readFileSync(p.join(__dirname, s))));
  const ok = v(JSON.parse(fs.readFileSync(p.join(R, f)))); if (!ok) bad++; console.log(f, ok ? 'VALID' : JSON.stringify(v.errors));
}
process.exit(bad ? 1 : 0);
