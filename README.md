# pm-acl

A portable access-control list. One C++ library answers "may this user do this?" for roles, resources, and the `vfs-settings.json` files a folder owner writes. Desktop, the VFS jail, and a future Android build can call the same code.

The library has no sockets and no user directory. A host already knows who is calling. This package only stores grants and evaluates them.

| host | how it calls the list |
| --- | --- |
| this package's CLI | `pm-acl run steps.json`, JSON on stdout |
| Tanit or `packages/vfs.cpp`, later | `add_subdirectory` and `pm::acl::VfsAcl` |
| a process that must survive restart | `save_store` / `load_store` on a JSON file |

`pm-vfs` does not link this library yet. Until a host turns that on, the jail stays open to whoever can run the process. Quota in `pm-vfs` is a separate limit.

## Why a separate layer

The TypeScript package `@polymech/acl` already defines the rules: Zend-style roles, parent roles, a `*` permission, and folder settings that name an owner, groups, and path grants. That package sits on Node. The same rules need to run where Node does not, and the VFS jail should be able to leave them out of a build.

No third-party ACL library. The algorithm is small and has to match the TypeScript tests. JSON uses nlohmann. The CLI uses CLI11. Both are the same versions the VFS package already fetches.

## Rules

A **user** holds **roles**. A role holds **permissions** on **resources**. A role can name parent roles. A check walks parents until every requested permission is found, or a parent holds `*`.

`is_allowed` requires the full set. `read` plus `write` is true only when both are granted, on the role or on a parent. An unknown user is denied. An empty user, resource, or permission is `INVALID_INPUT`. An empty user passed to `allowed_permissions` returns an empty map.

Resource names are plain strings. The VFS loader uses `vfs:<ownerId>:<path>`, with the path in slash form and `/` for the folder root. A check on `docs/a.txt` walks `vfs:<owner>:/docs/a.txt`, then `vfs:<owner>:/docs`, then `vfs:<owner>:/`. The first level that grants the permission wins. The owner's role is `owner:<id>` with `*` on `/`, so the owner is allowed on every path.

`anonymous` and `authenticated` are valid user ids. Every other id is a UUID. Group names are lowercase and cannot contain `:`. Ids are checked before any grant is written, so a bad member does not leave a half-applied file.

## vfs-settings.json

```json
{
  "owner": "3bb4cfbf-318b-44d3-a9d3-35680e738421",
  "groups": [
    { "name": "team", "members": ["aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"] }
  ],
  "acl": [
    { "group": "team", "path": "/shared", "permissions": ["read", "write", "list"] },
    { "userId": "anonymous", "path": "/", "permissions": ["read", "list"] }
  ]
}
```

Permissions used by the VFS host are `read`, `list`, `write`, `mkdir`, `delete`, `rename`, and `copy`. The engine does not hard-code that list. `*` means every name.

```cpp
pm::acl::VfsAcl acl;
if (auto bad = acl.load(user_dir)) { /* bad.code, bad.message */ }
if (acl.allowed(user_id, "shared/a.txt", "read")) { /* serve the file */ }
```

`load` reads `user_dir/vfs-settings.json`. A missing file is `NOT_FOUND`.

## CLI

`pm-acl run steps.json [--store state.json]`

`steps.json` is an array. Each object has `op` plus the fields of that call. Strings and arrays are both accepted for roles, resources, and permissions. A failed step is recorded and the process still exits 0, so a test can assert `INVALID_INPUT`. A missing script exits 1.

| op | fields |
| --- | --- |
| `allow` | `roles`, `resources`, `permissions`, or `grants: [{roles, allows:[{resources, permissions}]}]` |
| `addUserRoles` / `removeUserRoles` | `user`, `roles` |
| `userRoles` | `user` |
| `roleUsers` | `role` |
| `hasRole` | `user`, `role` |
| `addRoleParents` | `role`, `parents` |
| `removeRoleParents` | `role`, optional `parents` (omit to drop every parent) |
| `removeRole` | `role` |
| `removeAllow` | `role`, `resources`, optional `permissions` |
| `removeResource` | `resource` |
| `allowedPermissions` | `user`, `resources` |
| `isAllowed` | `user`, `resource`, `permissions` |
| `areAnyRolesAllowed` | `roles`, `resource`, `permissions` |
| `whatResources` | `roles`, optional `permissions` |
| `loadVfs` | `dir` (the folder that contains `vfs-settings.json`) |
| `vfsAllowed` | `user`, `path`, `permissions` (owner comes from the last `loadVfs`) |

`--store` loads a JSON dump of the buckets when the file exists, and writes it back at the end. A file that is not JSON is treated as empty and then overwritten. The dump is the memory backend: buckets `meta`, `users`, `roles`, `parents`, `resources`, and `allows_<resource>`.

```text
pm-acl run steps.json
{"ok":true,"results":[{"ok":true,"code":"OK"},{"ok":true,"code":"OK","data":true}]}
```

## Build and test

From `packages/acl.cpp`:

```text
npm run build:cpp
npm test
```

`npm test` spawns `pm-acl` (`PM_ACL_CLI` overrides the path). Suites:

- `test:core` — roles, grants, parents, removal, queries
- `test:vfs` — `fixtures/groups-test` and `fixtures/anon-test`, plus a rejected id
- `test:file` — store round-trip and a bad JSON reset

From the Tanit repo: `npm run test:pm-acl`, `npm run build:cpp:acl`, `npm run configure:acl`.

Configure uses the repo's `scripts/cmake.mjs` so the MSVC environment is set. Presets are `dev` (`build/dev`, RelWithDebInfo) and `release`. This package does not change the Tanit root presets.

## Linking

```cmake
add_subdirectory(packages/acl.cpp)
target_link_libraries(your_target PRIVATE pm-acl-lib)
```

Public header: `include/pm/acl/acl.hpp`, namespace `pm::acl`.

`Acl` is the role engine (`MemoryBackend` underneath). `load_vfs_settings`, `resource_chain`, and `vfs_allowed` are the folder model. `VfsAcl` is the small type a host keeps: `load`, `allowed`, `owner`. `save_store` and `load_store` persist the buckets.

The static library is `pm-acl-lib`. The executable is `pm-acl`. Wire `pm-vfs` with `PM_VFS_WITH_ACL` only when a call site should start denying paths. Until then the two packages build and test on their own.
