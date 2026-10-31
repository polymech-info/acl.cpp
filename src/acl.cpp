#include "pm/acl/acl.hpp"

#include <algorithm>

namespace pm::acl {
namespace {

std::vector<std::string> set_union(std::vector<std::string> a, const std::vector<std::string>& b) {
    for (const auto& item : b) {
        if (std::find(a.begin(), a.end(), item) == a.end()) a.push_back(item);
    }
    return a;
}

std::vector<std::string> set_difference(const std::vector<std::string>& a, const std::vector<std::string>& b) {
    std::vector<std::string> out;
    for (const auto& item : a) {
        if (std::find(b.begin(), b.end(), item) == b.end()) out.push_back(item);
    }
    return out;
}

std::vector<std::string> set_intersect(const std::vector<std::string>& a, const std::vector<std::string>& b) {
    std::vector<std::string> out;
    for (const auto& item : a) {
        if (std::find(b.begin(), b.end(), item) != b.end()) out.push_back(item);
    }
    return out;
}

std::string trimmed(std::string s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r' || s.front() == '\n'))
        s.erase(s.begin());
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r' || s.back() == '\n'))
        s.pop_back();
    return s;
}

Result require_non_empty(const std::vector<std::string>& values, const char* label) {
    if (values.empty()) return Result::failure("INVALID_INPUT", std::string(label) + " cannot be empty");
    for (const auto& value : values) {
        if (trimmed(value).empty()) return Result::failure("INVALID_INPUT", std::string(label) + " cannot be empty");
    }
    return Result::success();
}

Result require_non_empty(const std::string& value, const char* label) {
    return require_non_empty(std::vector<std::string>{value}, label);
}

std::string allows_bucket(const std::string& resource) { return "allows_" + resource; }

} // namespace

Result Result::success() { return {}; }

Result Result::failure(std::string code, std::string message) {
    Result r;
    r.ok = false;
    r.code = std::move(code);
    r.message = std::move(message);
    return r;
}

std::vector<MemoryBackend::Op> MemoryBackend::begin() const { return {}; }

void MemoryBackend::end(std::vector<Op>& transaction) {
    for (const auto& op : transaction) {
        if (op.kind == Op::Kind::Add) {
            auto& row = buckets_[op.bucket][op.key];
            row = set_union(std::move(row), op.values);
        } else if (op.kind == Op::Kind::Del) {
            auto bit = buckets_.find(op.bucket);
            if (bit == buckets_.end()) continue;
            for (const auto& key : op.values) bit->second.erase(key);
        } else {
            auto bit = buckets_.find(op.bucket);
            if (bit == buckets_.end()) continue;
            auto kit = bit->second.find(op.key);
            if (kit == bit->second.end()) continue;
            kit->second = set_difference(kit->second, op.values);
        }
    }
    transaction.clear();
}

void MemoryBackend::clean() { buckets_.clear(); }

MemoryBackend::Row MemoryBackend::get(const std::string& bucket, const std::string& key) const {
    auto bit = buckets_.find(bucket);
    if (bit == buckets_.end()) return {};
    auto kit = bit->second.find(key);
    if (kit == bit->second.end()) return {};
    return kit->second;
}

MemoryBackend::Row MemoryBackend::unite(const std::string& bucket, const std::vector<std::string>& keys) const {
    Row out;
    auto bit = buckets_.find(bucket);
    if (bit == buckets_.end()) return out;
    for (const auto& key : keys) {
        auto kit = bit->second.find(key);
        if (kit != bit->second.end()) out = set_union(std::move(out), kit->second);
    }
    return out;
}

void MemoryBackend::add(std::vector<Op>& transaction, const std::string& bucket, const std::string& key, const Row& values) {
    transaction.push_back(Op{Op::Kind::Add, bucket, key, values});
}

void MemoryBackend::del(std::vector<Op>& transaction, const std::string& bucket, const Row& keys) {
    transaction.push_back(Op{Op::Kind::Del, bucket, {}, keys});
}

void MemoryBackend::remove(std::vector<Op>& transaction, const std::string& bucket, const std::string& key, const Row& values) {
    transaction.push_back(Op{Op::Kind::Remove, bucket, key, values});
}

Acl::Acl(MemoryBackend backend) : backend_(std::move(backend)) {}

Result Acl::allow(const std::vector<std::string>& roles,
                  const std::vector<std::string>& resources,
                  const std::vector<std::string>& permissions) {
    if (auto bad = require_non_empty(roles, "Role")) return bad;
    if (auto bad = require_non_empty(resources, "Resource")) return bad;
    if (auto bad = require_non_empty(permissions, "Permission")) return bad;
    auto tx = backend_.begin();
    backend_.add(tx, "meta", "roles", roles);
    for (const auto& resource : resources) {
        for (const auto& role : roles) backend_.add(tx, allows_bucket(resource), role, permissions);
    }
    for (const auto& role : roles) backend_.add(tx, "resources", role, resources);
    backend_.end(tx);
    return Result::success();
}

Result Acl::add_user_roles(const std::string& user, const std::vector<std::string>& roles) {
    if (auto bad = require_non_empty(user, "User ID")) return bad;
    if (auto bad = require_non_empty(roles, "Role")) return bad;
    auto tx = backend_.begin();
    backend_.add(tx, "meta", "users", {user});
    backend_.add(tx, "users", user, roles);
    for (const auto& role : roles) backend_.add(tx, "roles", role, {user});
    backend_.end(tx);
    return Result::success();
}

Result Acl::remove_user_roles(const std::string& user, const std::vector<std::string>& roles) {
    if (auto bad = require_non_empty(user, "User ID")) return bad;
    if (auto bad = require_non_empty(roles, "Role")) return bad;
    auto tx = backend_.begin();
    backend_.remove(tx, "users", user, roles);
    for (const auto& role : roles) backend_.remove(tx, "roles", role, {user});
    backend_.end(tx);
    return Result::success();
}

Result Acl::user_roles(const std::string& user, std::vector<std::string>& out) const {
    out = backend_.get("users", user);
    return Result::success();
}

Result Acl::role_users(const std::string& role, std::vector<std::string>& out) const {
    out = backend_.get("roles", role);
    return Result::success();
}

Result Acl::has_role(const std::string& user, const std::string& role, bool& out) const {
    const auto roles = backend_.get("users", user);
    out = std::find(roles.begin(), roles.end(), role) != roles.end();
    return Result::success();
}

Result Acl::add_role_parents(const std::string& role, const std::vector<std::string>& parents) {
    if (auto bad = require_non_empty(role, "Role")) return bad;
    if (auto bad = require_non_empty(parents, "Parent role")) return bad;
    auto tx = backend_.begin();
    backend_.add(tx, "meta", "roles", {role});
    backend_.add(tx, "parents", role, parents);
    backend_.end(tx);
    return Result::success();
}

Result Acl::remove_role_parents(const std::string& role, const std::vector<std::string>* parents) {
    auto tx = backend_.begin();
    if (parents) backend_.remove(tx, "parents", role, *parents);
    else backend_.del(tx, "parents", {role});
    backend_.end(tx);
    return Result::success();
}

Result Acl::remove_role(const std::string& role) {
    if (auto bad = require_non_empty(role, "Role")) return bad;
    const auto resources = backend_.get("resources", role);
    auto tx = backend_.begin();
    for (const auto& resource : resources) backend_.del(tx, allows_bucket(resource), {role});
    backend_.del(tx, "resources", {role});
    backend_.del(tx, "parents", {role});
    backend_.del(tx, "roles", {role});
    backend_.remove(tx, "meta", "roles", {role});
    backend_.end(tx);
    return Result::success();
}

Result Acl::remove_resource(const std::string& resource) {
    if (auto bad = require_non_empty(resource, "Resource")) return bad;
    const auto roles = backend_.get("meta", "roles");
    auto tx = backend_.begin();
    backend_.del(tx, allows_bucket(resource), roles);
    for (const auto& role : roles) backend_.remove(tx, "resources", role, {resource});
    backend_.end(tx);
    return Result::success();
}

Result Acl::remove_allow(const std::string& role,
                         const std::vector<std::string>& resources,
                         const std::vector<std::string>* permissions) {
    if (auto bad = require_non_empty(role, "Role")) return bad;
    if (auto bad = require_non_empty(resources, "Resource")) return bad;
    auto tx = backend_.begin();
    for (const auto& resource : resources) {
        if (permissions) backend_.remove(tx, allows_bucket(resource), role, *permissions);
        else {
            backend_.del(tx, allows_bucket(resource), {role});
            backend_.remove(tx, "resources", role, {resource});
        }
    }
    backend_.end(tx);
    auto tx2 = backend_.begin();
    for (const auto& resource : resources) {
        if (backend_.get(allows_bucket(resource), role).empty())
            backend_.remove(tx2, "resources", role, {resource});
    }
    backend_.end(tx2);
    return Result::success();
}

std::vector<std::string> Acl::all_roles(const std::vector<std::string>& roles) const {
    const auto parents = backend_.unite("parents", roles);
    if (parents.empty()) return roles;
    return set_union(roles, all_roles(parents));
}

std::vector<std::string> Acl::resource_permissions(const std::vector<std::string>& roles,
                                                   const std::string& resource) const {
    if (roles.empty()) return {};
    auto perms = backend_.unite(allows_bucket(resource), roles);
    const auto parents = backend_.unite("parents", roles);
    if (!parents.empty()) perms = set_union(std::move(perms), resource_permissions(parents, resource));
    return perms;
}

bool Acl::check_permissions(const std::vector<std::string>& roles,
                            const std::string& resource,
                            const std::vector<std::string>& permissions) const {
    const auto have = backend_.unite(allows_bucket(resource), roles);
    if (std::find(have.begin(), have.end(), "*") != have.end()) return true;
    const auto remaining = set_difference(permissions, have);
    if (remaining.empty()) return true;
    const auto parents = backend_.unite("parents", roles);
    if (parents.empty()) return false;
    return check_permissions(parents, resource, remaining);
}

Result Acl::allowed_permissions(const std::string& user,
                                const std::vector<std::string>& resources,
                                std::map<std::string, std::vector<std::string>>& out) const {
    out.clear();
    if (user.empty()) return Result::success();
    std::vector<std::string> roles;
    user_roles(user, roles);
    for (const auto& resource : resources) out[resource] = resource_permissions(roles, resource);
    return Result::success();
}

Result Acl::is_allowed(const std::string& user,
                       const std::string& resource,
                       const std::vector<std::string>& permissions,
                       bool& out) const {
    if (auto bad = require_non_empty(user, "User ID")) return bad;
    if (auto bad = require_non_empty(resource, "Resource")) return bad;
    if (auto bad = require_non_empty(permissions, "Permission")) return bad;
    const auto roles = backend_.get("users", user);
    if (roles.empty()) {
        out = false;
        return Result::success();
    }
    return are_any_roles_allowed(roles, resource, permissions, out);
}

Result Acl::are_any_roles_allowed(const std::vector<std::string>& roles,
                                  const std::string& resource,
                                  const std::vector<std::string>& permissions,
                                  bool& out) const {
    if (roles.empty()) {
        out = false;
        return Result::success();
    }
    out = check_permissions(roles, resource, permissions);
    return Result::success();
}

Result Acl::what_resources(const std::vector<std::string>& roles,
                           const std::vector<std::string>* permissions,
                           std::map<std::string, std::vector<std::string>>& map_out,
                           std::vector<std::string>& list_out) const {
    map_out.clear();
    list_out.clear();
    const auto expanded = all_roles(roles);
    std::vector<std::string> resources;
    for (const auto& role : expanded) resources = set_union(std::move(resources), backend_.get("resources", role));
    if (!permissions) {
        for (const auto& resource : resources) map_out[resource] = resource_permissions(roles, resource);
        return Result::success();
    }
    for (const auto& resource : resources) {
        const auto perms = resource_permissions(roles, resource);
        if (!set_intersect(*permissions, perms).empty()) list_out.push_back(resource);
    }
    return Result::success();
}

} // namespace pm::acl
