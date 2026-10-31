import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createAssert, finish, requireExe, run } from './commons.mjs';

const checks = requireExe(createAssert());
const dir = mkdtempSync(join(tmpdir(), 'pm-acl-file-'));
const store = join(dir, 'nested', 'acl.json');
const grant = join(dir, 'grant.json');
const ask = join(dir, 'ask.json');

writeFileSync(grant, JSON.stringify([
  { op: 'addUserRoles', user: 'u1', roles: 'editor' },
  { op: 'allow', roles: 'editor', resources: 'posts', permissions: ['read', 'write'] },
]));
writeFileSync(ask, JSON.stringify([
  { op: 'isAllowed', user: 'u1', resource: 'posts', permissions: 'write' },
  { op: 'userRoles', user: 'u1' },
]));

const first = run(['run', grant, '--store', store]);
checks.assert(first.status === 0 && first.json && first.json.ok === true, 'save store');
const second = run(['run', ask, '--store', store]);
checks.assert(second.status === 0 && second.json && second.json.results[0].data === true, 'reloaded grant still allows write');
checks.assert(second.json && second.json.results[1].data.includes('editor'), 'reloaded user role');

writeFileSync(store, '{not json');
const reset = run(['run', ask, '--store', store]);
checks.assert(reset.status === 0 && reset.json && reset.json.results[0].data === false, 'bad JSON resets the store');

const fresh = join(dir, 'missing', 'acl.json');
const empty = run(['run', ask, '--store', fresh]);
checks.assert(empty.status === 0 && empty.json && empty.json.results[0].data === false, 'missing store starts empty');

finish(checks);
