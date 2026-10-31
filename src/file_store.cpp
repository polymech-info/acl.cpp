#include "pm/acl/acl.hpp"

#include <nlohmann/json.hpp>

#include <fstream>

namespace pm::acl {

Result save_store(const MemoryBackend& backend, const std::filesystem::path& path) {
    nlohmann::json body = nlohmann::json::object();
    for (const auto& [bucket, rows] : backend.buckets()) {
        nlohmann::json obj = nlohmann::json::object();
        for (const auto& [key, values] : rows) obj[key] = values;
        body[bucket] = std::move(obj);
    }
    std::error_code ec;
    if (path.has_parent_path()) std::filesystem::create_directories(path.parent_path(), ec);
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return Result::failure("BACKEND_ERROR", "cannot write acl store");
    out << body.dump(2);
    if (!out) return Result::failure("BACKEND_ERROR", "cannot write acl store");
    return Result::success();
}

Result load_store(MemoryBackend& backend, const std::filesystem::path& path) {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) return Result::success();
    std::ifstream in(path, std::ios::binary);
    if (!in) return Result::failure("BACKEND_ERROR", "cannot read acl store");
    std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (raw.empty()) return Result::success();
    nlohmann::json body;
    try {
        body = nlohmann::json::parse(raw);
    } catch (const std::exception&) {
        backend.clean();
        return Result::success();
    }
    if (!body.is_object()) return Result::failure("INVALID_INPUT", "acl store must be an object");
    MemoryBackend::Store store;
    for (auto bit = body.begin(); bit != body.end(); ++bit) {
        if (!bit.value().is_object()) continue;
        MemoryBackend::Bucket bucket;
        for (auto kit = bit.value().begin(); kit != bit.value().end(); ++kit) {
            MemoryBackend::Row row;
            if (kit.value().is_array()) {
                for (const auto& item : kit.value())
                    if (item.is_string()) row.push_back(item.get<std::string>());
            }
            bucket[kit.key()] = std::move(row);
        }
        store[bit.key()] = std::move(bucket);
    }
    backend.buckets() = std::move(store);
    return Result::success();
}

} // namespace pm::acl
