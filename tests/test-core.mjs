import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PKG, createAssert, finish, requireExe, run } from './commons.mjs';

const checks = requireExe(createAssert());
const dir = mkdtempSync(join(tmpdir(), 'pm-acl-'));
let n = 0;

function has(list, item) {
  return Array.isArray(list) && list.includes(item);
}

function apply(steps) {
  const file = join(dir, `steps-${n++}.json`);
  writeFileSync(file, JSON.stringify(steps));
  const r = run(['run', file]);
  checks.assert(r.status === 0 && r.json && r.json.ok === true, `run exits 0 (${steps.map(s => s.op).join(',')})`);
  if (!r.json) console.error(r.stdout, r.stderr, r.spawnError);
  return r.json ? r.json.results : [];
}

function data(results, index) {
  const row = results[index];
  checks.assert(row && row.ok === true, `step ${index} ok`);
  return row ? row.data : undefined;
}

const roles = apply([
  { op: 'addUserRoles', user: 'user1', roles: 'admin' },
  { op: 'userRoles', user: 'user1' },
  { op: 'addUserRoles', user: 'user2', roles: ['editor', 'viewer'] },
  { op: 'userRoles', user: 'user2' },
  { op: 'addUserRoles', user: 'user1', roles: ['admin', 'editor'] },
  { op: 'removeUserRoles', user: 'user1', roles: 'admin' },
  { op: 'userRoles', user: 'user1' },
  { op: 'addUserRoles', user: 'u1', roles: 'admin' },
  { op: 'addUserRoles', user: 'u2', roles: 'admin' },
  { op: 'roleUsers', role: 'admin' },
  { op: 'hasRole', user: 'u1', role: 'admin' },
  { op: 'hasRole', user: 'u1', role: 'missing' },
]);
checks.assert(has(data(roles, 1), 'admin'), 'single role assigned');
checks.assert(has(data(roles, 3), 'editor') && has(data(roles, 3), 'viewer'), 'multiple roles assigned');
const afterRemove = data(roles, 6);
checks.assert(!has(afterRemove, 'admin') && has(afterRemove, 'editor'), 'role removed, other kept');
const admins = data(roles, 9);
checks.assert(has(admins, 'u1') && has(admins, 'u2'), 'roleUsers lists both');
checks.assert(data(roles, 10) === true, 'hasRole true');
checks.assert(data(roles, 11) === false, 'hasRole false');

const perms = apply([
  { op: 'addUserRoles', user: 'u1', roles: 'editor' },
  { op: 'allow', roles: 'editor', resources: 'posts', permissions: 'edit' },
  { op: 'isAllowed', user: 'u1', resource: 'posts', permissions: 'edit' },
  { op: 'isAllowed', user: 'u1', resource: 'posts', permissions: 'delete' },
  { op: 'addUserRoles', user: 'u1', roles: 'admin' },
  { op: 'allow', roles: 'admin', resources: 'posts', permissions: ['create', 'edit', 'delete'] },
  { op: 'isAllowed', user: 'u1', resource: 'posts', permissions: 'create' },
  { op: 'isAllowed', user: 'u1', resource: 'posts', permissions: 'delete' },
  { op: 'addUserRoles', user: 'u1', roles: 'superadmin' },
  { op: 'allow', roles: 'superadmin', resources: 'everything', permissions: '*' },
  { op: 'isAllowed', user: 'u1', resource: 'everything', permissions: 'anything' },
  { op: 'isAllowed', user: 'u1', resource: 'everything', permissions: 'whatever' },
  { op: 'isAllowed', user: 'u1', resource: 'posts', permissions: ['edit', 'delete'] },
]);
checks.assert(data(perms, 2) === true, 'simple grant allows edit');
checks.assert(data(perms, 3) === false, 'ungranted delete denied');
checks.assert(data(perms, 6) === true && data(perms, 7) === true, 'multiple permissions granted');
checks.assert(data(perms, 10) === true && data(perms, 11) === true, 'wildcard allows any permission');
checks.assert(data(perms, 12) === true, 'all requested permissions must be held');

const batch = apply([
  { op: 'addUserRoles', user: 'u1', roles: 'member' },
  {
    op: 'allow',
    grants: [{
      roles: 'member',
      allows: [
        { resources: 'profile', permissions: ['read', 'update'] },
        { resources: 'feed', permissions: 'read' },
      ],
    }],
  },
  { op: 'isAllowed', user: 'u1', resource: 'profile', permissions: 'read' },
  { op: 'isAllowed', user: 'u1', resource: 'profile', permissions: 'update' },
  { op: 'isAllowed', user: 'u1', resource: 'feed', permissions: 'read' },
  { op: 'isAllowed', user: 'u1', resource: 'feed', permissions: 'write' },
]);
checks.assert(data(batch, 2) === true && data(batch, 3) === true, 'batch grant on profile');
checks.assert(data(batch, 4) === true && data(batch, 5) === false, 'batch grant on feed');

const tree = apply([
  { op: 'allow', roles: 'viewer', resources: 'docs', permissions: 'read' },
  { op: 'allow', roles: 'editor', resources: 'docs', permissions: 'write' },
  { op: 'addRoleParents', role: 'editor', parents: 'viewer' },
  { op: 'addUserRoles', user: 'u1', roles: 'editor' },
  { op: 'isAllowed', user: 'u1', resource: 'docs', permissions: 'write' },
  { op: 'isAllowed', user: 'u1', resource: 'docs', permissions: 'read' },
  { op: 'isAllowed', user: 'u1', resource: 'docs', permissions: ['read', 'write'] },
  { op: 'allow', roles: 'base', resources: 'res', permissions: 'read' },
  { op: 'allow', roles: 'mid', resources: 'res', permissions: 'write' },
  { op: 'allow', roles: 'top', resources: 'res', permissions: 'admin' },
  { op: 'addRoleParents', role: 'mid', parents: 'base' },
  { op: 'addRoleParents', role: 'top', parents: 'mid' },
  { op: 'addUserRoles', user: 'u1', roles: 'top' },
  { op: 'isAllowed', user: 'u1', resource: 'res', permissions: 'admin' },
  { op: 'isAllowed', user: 'u1', resource: 'res', permissions: 'write' },
  { op: 'isAllowed', user: 'u1', resource: 'res', permissions: 'read' },
  { op: 'removeRoleParents', role: 'editor', parents: 'viewer' },
  { op: 'isAllowed', user: 'u1', resource: 'docs', permissions: 'read' },
  { op: 'isAllowed', user: 'u1', resource: 'docs', permissions: 'write' },
]);
checks.assert(data(tree, 4) === true && data(tree, 5) === true, 'child inherits parent permission');
checks.assert(data(tree, 6) === true, 'split grant satisfies the full set');
checks.assert(data(tree, 13) === true && data(tree, 14) === true && data(tree, 15) === true, 'multi-level parents');
checks.assert(data(tree, 17) === false && data(tree, 18) === true, 'removing a parent cuts inheritance');

const removal = apply([
  { op: 'allow', roles: 'temp', resources: 'stuff', permissions: 'do' },
  { op: 'addUserRoles', user: 'u1', roles: 'temp' },
  { op: 'isAllowed', user: 'u1', resource: 'stuff', permissions: 'do' },
  { op: 'removeRole', role: 'temp' },
  { op: 'areAnyRolesAllowed', roles: 'temp', resource: 'stuff', permissions: 'do' },
  { op: 'allow', roles: 'editor', resources: 'posts', permissions: ['read', 'write', 'delete'] },
  { op: 'addUserRoles', user: 'u1', roles: 'editor' },
  { op: 'removeAllow', role: 'editor', resources: 'posts', permissions: 'delete' },
  { op: 'isAllowed', user: 'u1', resource: 'posts', permissions: 'delete' },
  { op: 'isAllowed', user: 'u1', resource: 'posts', permissions: 'read' },
  { op: 'removeAllow', role: 'editor', resources: 'posts' },
  { op: 'isAllowed', user: 'u1', resource: 'posts', permissions: 'read' },
  { op: 'isAllowed', user: 'u1', resource: 'posts', permissions: 'write' },
  { op: 'allow', roles: 'admin', resources: 'secrets', permissions: 'read' },
  { op: 'addUserRoles', user: 'u1', roles: 'admin' },
  { op: 'isAllowed', user: 'u1', resource: 'secrets', permissions: 'read' },
  { op: 'removeResource', resource: 'secrets' },
  { op: 'isAllowed', user: 'u1', resource: 'secrets', permissions: 'read' },
]);
checks.assert(data(removal, 2) === true, 'role can act before removal');
checks.assert(data(removal, 4) === false, 'removeRole drops the permission');
checks.assert(data(removal, 8) === false && data(removal, 9) === true, 'removeAllow drops one permission');
checks.assert(data(removal, 11) === false && data(removal, 12) === false, 'removeAllow drops the resource');
checks.assert(data(removal, 15) === true && data(removal, 17) === false, 'removeResource drops every role');

const queries = apply([
  { op: 'addUserRoles', user: 'u1', roles: 'editor' },
  { op: 'allow', roles: 'editor', resources: 'posts', permissions: ['read', 'write'] },
  { op: 'allow', roles: 'editor', resources: 'comments', permissions: 'moderate' },
  { op: 'allowedPermissions', user: 'u1', resources: ['posts', 'comments', 'settings'] },
  { op: 'allowedPermissions', user: '', resources: ['posts'] },
  { op: 'allow', roles: 'a', resources: 'res', permissions: 'read' },
  { op: 'areAnyRolesAllowed', roles: ['a', 'b'], resource: 'res', permissions: 'read' },
  { op: 'areAnyRolesAllowed', roles: [], resource: 'res', permissions: 'read' },
  { op: 'allow', roles: 'editor', resources: 'pages', permissions: 'read' },
  { op: 'whatResources', roles: 'editor' },
  { op: 'whatResources', roles: 'editor', permissions: 'write' },
  { op: 'isAllowed', user: 'nobody', resource: 'posts', permissions: 'read' },
]);
const map = data(queries, 3);
checks.assert(map && has(map.posts, 'read') && has(map.posts, 'write'), 'allowedPermissions lists posts');
checks.assert(map && has(map.comments, 'moderate') && Array.isArray(map.settings) && map.settings.length === 0, 'missing resource is an empty list');
checks.assert(data(queries, 4) && Object.keys(data(queries, 4)).length === 0, 'empty user yields {}');
checks.assert(data(queries, 6) === true, 'any matching role is enough');
checks.assert(data(queries, 7) === false, 'empty role list is denied');
const resources = data(queries, 9);
checks.assert(resources && has(resources.posts, 'read') && has(resources.pages, 'read'), 'whatResources map');
checks.assert(has(data(queries, 10), 'posts') && !has(data(queries, 10), 'pages'), 'whatResources filters by permission');
checks.assert(data(queries, 11) === false, 'unknown user is denied');

const bad = apply([
  { op: 'allow', roles: [], resources: ['posts'], permissions: ['read'] },
  { op: 'isAllowed', user: '', resource: 'posts', permissions: 'read' },
  { op: 'nope' },
]);
checks.assert(bad[0] && bad[0].ok === false && bad[0].code === 'INVALID_INPUT', 'empty role is INVALID_INPUT');
checks.assert(bad[1] && bad[1].ok === false && bad[1].code === 'INVALID_INPUT', 'empty user is INVALID_INPUT');
checks.assert(bad[2] && bad[2].ok === false, 'unknown op is recorded and the process still exits');

if (checks.failed) console.error('workdir', dir);
else console.log('core scripts', PKG);
finish(checks);
