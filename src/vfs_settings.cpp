#include "pm/acl/acl.hpp"

#include <nlohmann/json.hpp>

#include <cctype>
#include <fstream>

namespace pm::acl {
namespace {

bool is_hex(char c) {
    const auto u = static_cast<unsigned char>(c);
    return std::isxdigit(u) != 0;
}

bool is_uuid(const std::string& id) {
    if (id.size() != 36) return false;
    for (std::size_t i = 0; i < id.size(); ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (id[i] != '-') return false;
            continue;
        }
        if (!is_hex(id[i])) return false;
    }
    return true;
}

std::string lower_trim(std::string s) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();
    for (char& c : s)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return s;
}

Result clean_id(const std::string& raw, std::string& out) {
    const auto id = lower_trim(raw);
    if (id == "anonymous" || id == "authenticated") {
        out = id;
        return Result::success();
    }
    if (!is_uuid(id)) return Result::failure("INVALID_INPUT", "Invalid UUID: '" + raw + "'");
    out = id;
    return Result::success();
}

Result clean_group(const std::string& raw, std::string& out) {
    out = lower_trim(raw);
    if (out.empty()) return Result::failure("INVALID_INPUT", "Group name cannot be empty");
    if (out.find(':') != std::string::npos)
        return Result::failure("INVALID_INPUT", "Group name cannot contain ':': " + out);
    return Result::success();
}

std::string clean_path(std::string raw) {
    for (char& c : raw)
        if (c == '\\') c = '/';
    std::string collapsed;
    for (char c : raw) {
        if (c == '/' && !collapsed.empty() && collapsed.back() == '/') continue;
        collapsed.push_back(c);
    }
    while (!collapsed.empty() && collapsed.front() == '/') collapsed.erase(collapsed.begin());
    while (!collapsed.empty() && collapsed.back() == '/') collapsed.pop_back();
    return collapsed;
}

std::string normalise_path(const std::string& raw) {
    const auto clean = clean_path(raw);
    return clean.empty() ? "/" : "/" + clean;
}

std::vector<std::string> path_segments(const std::string& raw) {
    const auto clean = clean_path(raw);
    std::vector<std::string> out;
    if (clean.empty()) return out;
    std::string seg;
    for (char c : clean) {
        if (c == '/') {
            if (!seg.empty()) out.push_back(seg);
            seg.clear();
        } else {
            seg.push_back(c);
        }
    }
    if (!seg.empty()) out.push_back(seg);
    return out;
}

} // namespace

std::string vfs_resource(const std::string& owner, const std::string& resource_path) {
    return "vfs:" + owner + ":" + normalise_path(resource_path);
}

std::vector<std::string> resource_chain(const std::string& owner, const std::string& subpath) {
    const auto segments = path_segments(subpath);
    std::vector<std::string> chain;
    for (std::size_t i = segments.size(); i > 0; --i) {
        std::string path;
        for (std::size_t n = 0; n < i; ++n) {
            path.push_back('/');
            path += segments[n];
        }
        chain.push_back(vfs_resource(owner, path));
    }
    chain.push_back(vfs_resource(owner, "/"));
    return chain;
}

Result load_vfs_settings(Acl& acl, const std::filesystem::path& user_dir, VfsSettings& out) {
    const auto settings_path = user_dir / "vfs-settings.json";
    std::error_code ec;
    if (!std::filesystem::exists(settings_path, ec)) return Result::failure("NOT_FOUND", "vfs-settings.json not found");
    std::ifstream in(settings_path);
    if (!in) return Result::failure("BACKEND_ERROR", "cannot read vfs-settings.json");
    std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (raw.find_first_not_of(" \t\r\n") == std::string::npos) return Result::failure("NOT_FOUND", "empty vfs-settings.json");
    nlohmann::json body;
    try {
        body = nlohmann::json::parse(raw);
    } catch (const std::exception& ex) {
        return Result::failure("INVALID_INPUT", ex.what());
    }
    if (!body.is_object() || !body.contains("owner") || !body["owner"].is_string())
        return Result::failure("INVALID_INPUT", "owner is required");
    std::string owner;
    if (auto bad = clean_id(body["owner"].get<std::string>(), owner)) return bad;

    struct Grant {
        bool group = false;
        std::string id;
        std::string path;
        std::vector<std::string> permissions;
        std::vector<std::string> members;
    };
    std::map<std::string, std::vector<std::string>> groups;
    if (body.contains("groups") && body["groups"].is_array()) {
        for (const auto& group : body["groups"]) {
            if (!group.is_object()) return Result::failure("INVALID_INPUT", "group must be an object");
            std::string name;
            if (auto bad = clean_group(group.value("name", std::string{}), name)) return bad;
            std::vector<std::string> members;
            if (group.contains("members") && group["members"].is_array()) {
                for (const auto& member : group["members"]) {
                    if (!member.is_string()) return Result::failure("INVALID_INPUT", "group member must be a string");
                    std::string id;
                    if (auto bad = clean_id(member.get<std::string>(), id)) return bad;
                    members.push_back(id);
                }
            }
            groups[name] = std::move(members);
        }
    }
    std::vector<Grant> grants;
    if (!body.contains("acl") || !body["acl"].is_array())
        return Result::failure("INVALID_INPUT", "acl must be an array");
    for (const auto& entry : body["acl"]) {
        if (!entry.is_object()) return Result::failure("INVALID_INPUT", "acl entry must be an object");
        Grant grant;
        grant.path = normalise_path(entry.value("path", std::string{"/"}));
        if (!entry.contains("permissions") || !entry["permissions"].is_array())
            return Result::failure("INVALID_INPUT", "permissions must be an array");
        for (const auto& perm : entry["permissions"]) {
            if (!perm.is_string()) return Result::failure("INVALID_INPUT", "permission must be a string");
            auto name = lower_trim(perm.get<std::string>());
            if (name.empty()) return Result::failure("INVALID_INPUT", "Permission name cannot be empty");
            grant.permissions.push_back(name);
        }
        if (entry.contains("group") && entry["group"].is_string()) {
            grant.group = true;
            if (auto bad = clean_group(entry["group"].get<std::string>(), grant.id)) return bad;
            auto it = groups.find(grant.id);
            if (it != groups.end()) grant.members = it->second;
        } else if (entry.contains("userId") && entry["userId"].is_string()) {
            if (auto bad = clean_id(entry["userId"].get<std::string>(), grant.id)) return bad;
        } else {
            return Result::failure("INVALID_INPUT", "acl entry needs group or userId");
        }
        grants.push_back(std::move(grant));
    }

    const auto owner_role = "owner:" + owner;
    if (auto bad = acl.allow({owner_role}, {vfs_resource(owner, "/")}, {"*"})) return bad;
    if (auto bad = acl.add_user_roles(owner, {owner_role})) return bad;
    for (const auto& grant : grants) {
        const auto resource = vfs_resource(owner, grant.path);
        if (grant.group) {
            const auto role = "group:" + owner + ":" + grant.id;
            if (auto bad = acl.allow({role}, {resource}, grant.permissions)) return bad;
            for (const auto& member : grant.members) {
                if (auto bad = acl.add_user_roles(member, {role})) return bad;
            }
        } else {
            const auto role = "vfs-grant:" + owner + ":" + grant.id + ":" + grant.path;
            if (auto bad = acl.allow({role}, {resource}, grant.permissions)) return bad;
            if (auto bad = acl.add_user_roles(grant.id, {role})) return bad;
        }
    }
    out.owner = owner;
    return Result::success();
}

Result vfs_allowed(const Acl& acl,
                   const std::string& owner,
                   const std::string& user,
                   const std::string& subpath,
                   const std::vector<std::string>& permissions,
                   bool& out) {
    out = false;
    for (const auto& resource : resource_chain(owner, subpath)) {
        bool allowed = false;
        if (auto bad = acl.is_allowed(user, resource, permissions, allowed)) return bad;
        if (allowed) {
            out = true;
            return Result::success();
        }
    }
    return Result::success();
}

Result VfsAcl::load(const std::filesystem::path& user_dir) {
    VfsSettings settings;
    if (auto bad = load_vfs_settings(acl_, user_dir, settings)) return bad;
    owner_ = settings.owner;
    return Result::success();
}

bool VfsAcl::allowed(const std::string& user, const std::string& subpath, const std::string& permission) const {
    bool out = false;
    if (auto bad = vfs_allowed(acl_, owner_, user, subpath, {permission}, out)) return false;
    return out;
}

} // namespace pm::acl
