cmake_minimum_required(VERSION 3.20)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  project(pm-acl
    VERSION 0.1.0
    DESCRIPTION "PolyMech ACL and vfs-settings loader"
    LANGUAGES CXX)
endif()

if(NOT TARGET CLI11::CLI11 OR NOT TARGET nlohmann_json::nlohmann_json)
  include(FetchContent)
  set(_pm_acl_deps "${CMAKE_CURRENT_SOURCE_DIR}/../../build/release-debug/_deps")
  if(NOT TARGET CLI11::CLI11)
    if(NOT DEFINED FETCHCONTENT_SOURCE_DIR_CLI11
       AND EXISTS "${_pm_acl_deps}/cli11-src/CMakeLists.txt")
      set(FETCHCONTENT_SOURCE_DIR_CLI11 "${_pm_acl_deps}/cli11-src" CACHE PATH "" FORCE)
    endif()
    set(CLI11_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(CLI11_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(cli11
      GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
      GIT_TAG v2.4.2
      GIT_SHALLOW TRUE)
    FetchContent_MakeAvailable(cli11)
  endif()
  if(NOT TARGET nlohmann_json::nlohmann_json)
    if(NOT DEFINED FETCHCONTENT_SOURCE_DIR_NLOHMANN_JSON
       AND EXISTS "${_pm_acl_deps}/nlohmann_json-src/CMakeLists.txt")
      set(FETCHCONTENT_SOURCE_DIR_NLOHMANN_JSON "${_pm_acl_deps}/nlohmann_json-src" CACHE PATH "" FORCE)
    endif()
    set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(nlohmann_json
      GIT_REPOSITORY https://github.com/nlohmann/json.git
      GIT_TAG v3.11.3
      GIT_SHALLOW TRUE)
    FetchContent_MakeAvailable(nlohmann_json)
  endif()
endif()

add_library(pm-acl-lib STATIC
  src/acl.cpp
  src/vfs_settings.cpp
  src/file_store.cpp)
target_include_directories(pm-acl-lib PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_compile_features(pm-acl-lib PUBLIC cxx_std_20)
target_link_libraries(pm-acl-lib PUBLIC nlohmann_json::nlohmann_json)
if(MSVC)
  target_compile_definitions(pm-acl-lib PRIVATE _CRT_SECURE_NO_WARNINGS)
  target_compile_options(pm-acl-lib PRIVATE /W3 /utf-8 /EHsc)
else()
  target_compile_options(pm-acl-lib PRIVATE -Wall -Wextra)
endif()

add_executable(pm-acl cli/main.cpp)
target_compile_features(pm-acl PRIVATE cxx_std_20)
target_link_libraries(pm-acl PRIVATE pm-acl-lib CLI11::CLI11)
if(MSVC)
  target_compile_definitions(pm-acl PRIVATE _CRT_SECURE_NO_WARNINGS)
  target_compile_options(pm-acl PRIVATE /W3 /utf-8 /EHsc)
else()
  target_compile_options(pm-acl PRIVATE -Wall -Wextra)
endif()
