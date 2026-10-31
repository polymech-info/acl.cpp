import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PKG, createAssert, finish, requireExe, run } from './commons.mjs';

const checks = requireExe(createAssert());
const scratch = mkdtempSync(join(tmpdir(), 'pm-acl-vfs-'));

const OWNER = '3bb4cfbf-318b-44d3-a9d3-35680e738421';
const TEAM_A = 'aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb';
const TEAM_C = 'cccccccc-4444-5555-6666-dddddddddddd';
const VIEW_D = 'dddddddd-7777-8888-9999-eeeeeeeeeeee';
const VIEW_F = 'ffffffff-aaaa-bbbb-cccc-111111111111';
const NOBODY = '99999999-0000-0000-0000-ffffffffffff';

function load(dir, checksAfter) {
  const file = join(scratch, `steps-${dir.replace(/[\\/:]/g, '_')}.json`);
  const steps = [{ op: 'loadVfs', dir }, ...checksAfter];
  writeFileSync(file, JSON.stringify(steps));
  const r = run(['run', file]);
  checks.assert(r.status === 0 && r.json && r.json.ok === true, `load ${dir}`);
  if (!r.json) console.error(r.stdout, r.stderr, r.spawnError);
  return r.json ? r.json.results : [];
}

function allow(results, index, label) {
  const row = results[index];
  checks.assert(row && row.ok === true && row.data === true, label);
}

function deny(results, index, label) {
  const row = results[index];
  checks.assert(row && row.ok === true && row.data === false, label);
}

const groupsDir = join(PKG, 'fixtures', 'groups-test');
const groups = load(groupsDir, [
  { op: 'isAllowed', user: OWNER, resource: `vfs:${OWNER}:/`, permissions: 'read' },
  { op: 'isAllowed', user: OWNER, resource: `vfs:${OWNER}:/`, permissions: 'some-future-perm' },
  { op: 'vfsAllowed', user: OWNER, path: '/private/secret.txt', permissions: 'delete' },
  { op: 'isAllowed', user: TEAM_A, resource: `vfs:${OWNER}:/shared`, permissions: 'write' },
  { op: 'isAllowed', user: TEAM_A, resource: `vfs:${OWNER}:/shared`, permissions: 'delete' },
  { op: 'isAllowed', user: TEAM_A, resource: `vfs:${OWNER}:/docs`, permissions: 'read' },
  { op: 'isAllowed', user: TEAM_A, resource: `vfs:${OWNER}:/docs`, permissions: 'write' },
  { op: 'isAllowed', user: TEAM_A, resource: `vfs:${OWNER}:/private`, permissions: 'read' },
  { op: 'vfsAllowed', user: TEAM_A, path: '/shared/reports/q1.pdf', permissions: 'read' },
  { op: 'vfsAllowed', user: TEAM_A, path: 'docs\\notes.txt', permissions: 'list' },
  { op: 'vfsAllowed', user: TEAM_A, path: '/docs/notes.txt', permissions: 'write' },
  { op: 'isAllowed', user: TEAM_C, resource: `vfs:${OWNER}:/shared`, permissions: 'mkdir' },
  { op: 'isAllowed', user: TEAM_C, resource: `vfs:${OWNER}:/private`, permissions: 'read' },
  { op: 'isAllowed', user: VIEW_D, resource: `vfs:${OWNER}:/docs`, permissions: 'list' },
  { op: 'isAllowed', user: VIEW_D, resource: `vfs:${OWNER}:/docs`, permissions: 'write' },
  { op: 'isAllowed', user: VIEW_D, resource: `vfs:${OWNER}:/shared`, permissions: 'read' },
  { op: 'isAllowed', user: VIEW_F, resource: `vfs:${OWNER}:/docs`, permissions: 'read' },
  { op: 'isAllowed', user: VIEW_F, resource: `vfs:${OWNER}:/shared`, permissions: 'list' },
  { op: 'isAllowed', user: VIEW_F, resource: `vfs:${OWNER}:/shared`, permissions: 'write' },
  { op: 'isAllowed', user: NOBODY, resource: `vfs:${OWNER}:/`, permissions: 'read' },
  { op: 'vfsAllowed', user: NOBODY, path: '/docs', permissions: 'list' },
]);
checks.assert(groups[0] && groups[0].ok && groups[0].data.owner === OWNER, 'owner id from settings');
allow(groups, 1, 'owner wildcard read');
allow(groups, 2, 'owner wildcard future permission');
allow(groups, 3, 'owner reaches a nested path');
allow(groups, 4, 'team write on /shared');
allow(groups, 5, 'team delete on /shared');
allow(groups, 6, 'team read on /docs');
deny(groups, 7, 'team write on /docs denied');
deny(groups, 8, 'team read on /private denied');
allow(groups, 9, 'grant on /shared covers a nested file');
allow(groups, 10, 'backslash path walks up to /docs');
deny(groups, 11, 'nested /docs write still denied');
allow(groups, 12, 'second team member');
deny(groups, 13, 'second team member denied on /private');
allow(groups, 14, 'viewer list on /docs');
deny(groups, 15, 'viewer write on /docs denied');
deny(groups, 16, 'viewer read on /shared denied');
allow(groups, 17, 'viewer group still covers /docs');
allow(groups, 18, 'direct grant covers /shared list');
deny(groups, 19, 'direct grant does not add write');
deny(groups, 20, 'stranger denied at root');
deny(groups, 21, 'stranger denied on a path');

const anonDir = join(PKG, 'fixtures', 'anon-test');
const anon = load(anonDir, [
  { op: 'vfsAllowed', user: 'anonymous', path: '/', permissions: 'read' },
  { op: 'vfsAllowed', user: 'anonymous', path: '/docs/a.txt', permissions: 'list' },
  { op: 'vfsAllowed', user: 'anonymous', path: '/docs/a.txt', permissions: 'write' },
  { op: 'vfsAllowed', user: TEAM_A, path: '/shared', permissions: 'read' },
  { op: 'vfsAllowed', user: 'Anonymous', path: '/', permissions: 'read' },
]);
allow(anon, 1, 'anonymous read at root');
allow(anon, 2, 'anonymous inherits root onto a nested path');
deny(anon, 3, 'anonymous write denied');
allow(anon, 4, 'named user with a root grant');
deny(anon, 5, 'id match is case-sensitive after clean');

const badDir = join(scratch, 'bad');
writeFileSync(join(scratch, 'skip'), '');
const { mkdirSync } = await import('node:fs');
mkdirSync(badDir);
writeFileSync(join(badDir, 'vfs-settings.json'), JSON.stringify({
  owner: OWNER,
  acl: [{ userId: 'not-a-uuid', path: '/', permissions: ['read'] }],
}));
const badFile = join(scratch, 'bad-steps.json');
writeFileSync(badFile, JSON.stringify([
  { op: 'loadVfs', dir: badDir },
  { op: 'isAllowed', user: OWNER, resource: `vfs:${OWNER}:/`, permissions: 'read' },
]));
const bad = run(['run', badFile]);
checks.assert(bad.status === 0 && bad.json && bad.json.results[0].ok === false, 'bad user id fails the load');
checks.assert(bad.json && bad.json.results[0].code === 'INVALID_INPUT', 'bad user id is INVALID_INPUT');
checks.assert(bad.json && bad.json.results[1].data === false, 'failed load does not grant the owner');

const missing = run(['run', join(scratch, 'nope.json')]);
checks.assert(missing.status === 1 && missing.json && missing.json.code === 'NOT_FOUND', 'missing script exits 1');

finish(checks);
