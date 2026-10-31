#pragma once

#include <filesystem>
#include <map>
#include <string>
#include <vector>

namespace pm::acl {

struct Result {
    bool ok = true;
    std::string code = "OK";
    std::string message;

    static Result success();
    static Result failure(std::string code, std::string message);
    /// True when the call failed, so `if (auto bad = fn()) return bad;` works.
    explicit operator bool() const { return !ok; }
};

/// In-memory bucket store. Keys and values are strings. A transaction is a
/// list of deferred mutations applied by `end`.
class MemoryBackend {
public:
    using Row = std::vector<std::string>;
    using Bucket = std::map<std::string, Row>;
    using Store = std::map<std::string, Bucket>;

    struct Op {
        enum class Kind { Add, Del, Remove };
        Kind kind = Kind::Add;
        std::string bucket;
        std::string key;
        Row values;
    };

    Store& buckets() { return buckets_; }
    const Store& buckets() const { return buckets_; }

    std::vector<Op> begin() const;
    void end(std::vector<Op>& transaction);
    void clean();

    Row get(const std::string& bucket, const std::string& key) const;
    Row unite(const std::string& bucket, const std::vector<std::string>& keys) const;

    void add(std::vector<Op>& transaction, const std::string& bucket, const std::string& key, const Row& values);
    void del(std::vector<Op>& transaction, const std::string& bucket, const Row& keys);
    void remove(std::vector<Op>& transaction, const std::string& bucket, const std::string& key, const Row& values);

private:
    Store buckets_;
};

/// Zend-style RBAC: users, roles, parent roles, and permissions on resources.
/// A permission of `*` on a resource allows every action on that resource.
class Acl {
public:
    explicit Acl(MemoryBackend backend = {});

    MemoryBackend& backend() { return backend_; }
    const MemoryBackend& backend() const { return backend_; }

    Result allow(const std::vector<std::string>& roles,
                 const std::vector<std::string>& resources,
                 const std::vector<std::string>& permissions);
    Result add_user_roles(const std::string& user, const std::vector<std::string>& roles);
    Result remove_user_roles(const std::string& user, const std::vector<std::string>& roles);
    Result user_roles(const std::string& user, std::vector<std::string>& out) const;
    Result role_users(const std::string& role, std::vector<std::string>& out) const;
    Result has_role(const std::string& user, const std::string& role, bool& out) const;
    Result add_role_parents(const std::string& role, const std::vector<std::string>& parents);
    /// `parents == nullptr` drops every parent of `role`.
    Result remove_role_parents(const std::string& role, const std::vector<std::string>* parents);
    Result remove_role(const std::string& role);
    Result remove_resource(const std::string& resource);
    /// `permissions == nullptr` drops the resource from the role.
    Result remove_allow(const std::string& role,
                        const std::vector<std::string>& resources,
                        const std::vector<std::string>* permissions);
    Result allowed_permissions(const std::string& user,
                               const std::vector<std::string>& resources,
                               std::map<std::string, std::vector<std::string>>& out) const;
    Result is_allowed(const std::string& user,
                      const std::string& resource,
                      const std::vector<std::string>& permissions,
                      bool& out) const;
    Result are_any_roles_allowed(const std::vector<std::string>& roles,
                                 const std::string& resource,
                                 const std::vector<std::string>& permissions,
                                 bool& out) const;
    /// Without `permissions`, fills `map_out`. With it, fills `list_out`.
    Result what_resources(const std::vector<std::string>& roles,
                          const std::vector<std::string>* permissions,
                          std::map<std::string, std::vector<std::string>>& map_out,
                          std::vector<std::string>& list_out) const;

private:
    std::vector<std::string> all_roles(const std::vector<std::string>& roles) const;
    std::vector<std::string> resource_permissions(const std::vector<std::string>& roles,
                                                  const std::string& resource) const;
    bool check_permissions(const std::vector<std::string>& roles,
                           const std::string& resource,
                           const std::vector<std::string>& permissions) const;

    MemoryBackend backend_;
};

struct VfsSettings {
    std::string owner;
};

/// Read `vfs-settings.json` in `user_dir` and grant the owner, groups, and
/// direct users onto `Acl`. Resource names are `vfs:<owner>:<path>`.
Result load_vfs_settings(Acl& acl, const std::filesystem::path& user_dir, VfsSettings& out);

std::string vfs_resource(const std::string& owner, const std::string& resource_path = "/");
std::vector<std::string> resource_chain(const std::string& owner, const std::string& subpath);

/// True when any resource from the path up to `/` allows every permission.
Result vfs_allowed(const Acl& acl,
                   const std::string& owner,
                   const std::string& user,
                   const std::string& subpath,
                   const std::vector<std::string>& permissions,
                   bool& out);

/// One folder's settings, ready for a VFS host to ask "may this user do this?".
class VfsAcl {
public:
    Result load(const std::filesystem::path& user_dir);
    bool allowed(const std::string& user, const std::string& subpath, const std::string& permission) const;
    const std::string& owner() const { return owner_; }
    Acl& acl() { return acl_; }
    const Acl& acl() const { return acl_; }

private:
    Acl acl_;
    std::string owner_;
};

Result save_store(const MemoryBackend& backend, const std::filesystem::path& path);
Result load_store(MemoryBackend& backend, const std::filesystem::path& path);

} // namespace pm::acl
