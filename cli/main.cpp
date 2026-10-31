#include "pm/acl/acl.hpp"

#include <CLI/CLI.hpp>
#include <nlohmann/json.hpp>

#include <fstream>
#include <iostream>

namespace {

nlohmann::json result_json(const pm::acl::Result& result) {
    nlohmann::json j = {{"ok", result.ok}, {"code", result.code}};
    if (!result.message.empty()) j["message"] = result.message;
    return j;
}

nlohmann::json with_data(const pm::acl::Result& result, nlohmann::json data) {
    auto j = result_json(result);
    if (result.ok) j["data"] = std::move(data);
    return j;
}

std::vector<std::string> as_list(const nlohmann::json& value) {
    std::vector<std::string> out;
    if (value.is_array()) {
        for (const auto& item : value) {
            if (item.is_string()) out.push_back(item.get<std::string>());
            else if (item.is_number()) out.push_back(item.dump());
        }
        return out;
    }
    if (value.is_string()) return {value.get<std::string>()};
    if (value.is_number()) return {value.dump()};
    return out;
}

nlohmann::json run_step(pm::acl::Acl& acl, std::string& owner, const nlohmann::json& step) {
    const auto op = step.value("op", std::string{});
    if (op == "allow" && step.contains("grants")) {
        for (const auto& grant : step["grants"]) {
            for (const auto& allow : grant["allows"]) {
                auto applied = acl.allow(as_list(grant["roles"]), as_list(allow["resources"]), as_list(allow["permissions"]));
                if (!applied.ok) return result_json(applied);
            }
        }
        return result_json(pm::acl::Result::success());
    }
    if (op == "allow")
        return result_json(acl.allow(as_list(step["roles"]), as_list(step["resources"]), as_list(step["permissions"])));
    if (op == "addUserRoles") return result_json(acl.add_user_roles(step.value("user", std::string{}), as_list(step["roles"])));
    if (op == "removeUserRoles")
        return result_json(acl.remove_user_roles(step.value("user", std::string{}), as_list(step["roles"])));
    if (op == "userRoles") {
        std::vector<std::string> roles;
        auto result = acl.user_roles(step.value("user", std::string{}), roles);
        return with_data(result, roles);
    }
    if (op == "roleUsers") {
        std::vector<std::string> users;
        auto result = acl.role_users(step.value("role", std::string{}), users);
        return with_data(result, users);
    }
    if (op == "hasRole") {
        bool yes = false;
        auto result = acl.has_role(step.value("user", std::string{}), step.value("role", std::string{}), yes);
        return with_data(result, yes);
    }
    if (op == "addRoleParents")
        return result_json(acl.add_role_parents(step.value("role", std::string{}), as_list(step["parents"])));
    if (op == "removeRoleParents") {
        if (step.contains("parents")) {
            auto parents = as_list(step["parents"]);
            return result_json(acl.remove_role_parents(step.value("role", std::string{}), &parents));
        }
        return result_json(acl.remove_role_parents(step.value("role", std::string{}), nullptr));
    }
    if (op == "removeRole") return result_json(acl.remove_role(step.value("role", std::string{})));
    if (op == "removeResource") return result_json(acl.remove_resource(step.value("resource", std::string{})));
    if (op == "removeAllow") {
        if (step.contains("permissions")) {
            auto perms = as_list(step["permissions"]);
            return result_json(acl.remove_allow(step.value("role", std::string{}), as_list(step["resources"]), &perms));
        }
        return result_json(acl.remove_allow(step.value("role", std::string{}), as_list(step["resources"]), nullptr));
    }
    if (op == "allowedPermissions") {
        std::map<std::string, std::vector<std::string>> perms;
        auto result = acl.allowed_permissions(step.value("user", std::string{}), as_list(step["resources"]), perms);
        return with_data(result, perms);
    }
    if (op == "isAllowed") {
        bool yes = false;
        auto result = acl.is_allowed(step.value("user", std::string{}), step.value("resource", std::string{}),
                                     as_list(step["permissions"]), yes);
        return with_data(result, yes);
    }
    if (op == "areAnyRolesAllowed") {
        bool yes = false;
        auto result = acl.are_any_roles_allowed(as_list(step["roles"]), step.value("resource", std::string{}),
                                                as_list(step["permissions"]), yes);
        return with_data(result, yes);
    }
    if (op == "whatResources") {
        std::map<std::string, std::vector<std::string>> map_out;
        std::vector<std::string> list_out;
        if (step.contains("permissions")) {
            auto perms = as_list(step["permissions"]);
            auto result = acl.what_resources(as_list(step["roles"]), &perms, map_out, list_out);
            return with_data(result, list_out);
        }
        auto result = acl.what_resources(as_list(step["roles"]), nullptr, map_out, list_out);
        return with_data(result, map_out);
    }
    if (op == "loadVfs") {
        pm::acl::VfsSettings settings;
        auto result = pm::acl::load_vfs_settings(acl, step.value("dir", std::string{}), settings);
        if (result.ok) owner = settings.owner;
        auto j = result_json(result);
        if (result.ok) j["data"] = {{"owner", settings.owner}};
        return j;
    }
    if (op == "vfsAllowed") {
        bool yes = false;
        const auto who = owner.empty() ? step.value("owner", std::string{}) : owner;
        auto result = pm::acl::vfs_allowed(acl, who, step.value("user", std::string{}), step.value("path", std::string{}),
                                           as_list(step["permissions"]), yes);
        return with_data(result, yes);
    }
    return result_json(pm::acl::Result::failure("INVALID_INPUT", "unknown op: " + op));
}

} // namespace

int main(int argc, char** argv) {
    CLI::App app{"pm-acl"};
    app.require_subcommand(1);
    std::string script;
    std::string store;
    auto* run = app.add_subcommand("run", "Apply a JSON list of ACL operations");
    run->add_option("script", script, "Steps JSON file")->required();
    run->add_option("--store", store, "Load and save the bucket file");

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        return app.exit(e);
    }

    pm::acl::MemoryBackend backend;
    if (!store.empty()) {
        auto loaded = pm::acl::load_store(backend, store);
        if (!loaded.ok) {
            std::cout << result_json(loaded).dump() << "\n";
            return 1;
        }
    }
    pm::acl::Acl acl(std::move(backend));
    std::ifstream in(script);
    if (!in) {
        std::cout << result_json(pm::acl::Result::failure("NOT_FOUND", "script not found")).dump() << "\n";
        return 1;
    }
    nlohmann::json steps;
    try {
        steps = nlohmann::json::parse(std::string(std::istreambuf_iterator<char>(in), {}));
    } catch (const std::exception& ex) {
        std::cout << result_json(pm::acl::Result::failure("INVALID_INPUT", ex.what())).dump() << "\n";
        return 1;
    }
    if (!steps.is_array()) {
        std::cout << result_json(pm::acl::Result::failure("INVALID_INPUT", "script must be an array")).dump() << "\n";
        return 1;
    }
    std::string owner;
    nlohmann::json results = nlohmann::json::array();
    for (const auto& step : steps) results.push_back(run_step(acl, owner, step));
    if (!store.empty()) {
        auto saved = pm::acl::save_store(acl.backend(), store);
        if (!saved.ok) {
            std::cout << result_json(saved).dump() << "\n";
            return 1;
        }
    }
    std::cout << nlohmann::json{{"ok", true}, {"results", results}}.dump() << "\n";
    return 0;
}
