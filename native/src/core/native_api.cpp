#include "core/native_api.h"

#include <sys/mman.h>

#include <algorithm>
#include <functional>
#include <memory>
#include <mutex>
#include <unordered_map>

#include "common/logging.h"
#include "core/native_module_registry.h"
#include "elf/elf_image.h"
#include "elf/symbol_cache.h"

/**
 * @file native_api.cpp
 * @brief Implementation of the native module loading and API provisioning system.
 */

using lsplant::operator""_sym;
/*
 * ===========================================================================================
 * LSPLANT HOOKING DSL (DOMAIN SPECIFIC LANGUAGE) DOCUMENTATION
 * ===========================================================================================
 *
 * This source file utilizes the 'lsplant' library, which implements a C++20 Hooking DSL.
 * Unlike traditional C-style hooking (which relies on void* casting, manual trampolines,
 * and global function pointers), this DSL uses compile-time metaprogramming to ensure
 * type safety and encapsulate hooking logic.
 *
 * -------------------------------------------------------------------------------------------
 * 1. SYNTAX ANATOMY
 * -------------------------------------------------------------------------------------------
 * The hooking syntax follows this pattern:
 *    "SYMBOL_NAME"_sym .hook ->* [] <auto backup> (args...) { ...body... };
 *
 *  A. "SYMBOL_NAME"_sym
 *     - This is a C++ User-Defined Literal (UDL). It converts the string literal into a
 *       compile-time 'Symbol' type.
 *     - For C++ mangled names (common in Android system libs), you must provide the full
 *       mangled signature (e.g., "__dl__Z9do_dlopen...").
 *
 *  B. Multi-Architecture Support (| Operator)
 *     - Android often requires different symbol names for 32-bit (ARM) and 64-bit (ARM64).
 *     - The DSL supports the pipe operator '|' to select the correct symbol at compile time:
 *       ("Sym32"_sym | "Sym64"_sym)
 *
 *  C. .hook ->*
 *     - '.hook' accesses the hook injection mechanism.
 *     - '->*' (Member Pointer Operator) is overloaded to bind the symbol to the lambda.
 *
 *  D. The Template Lambda (The Replacement)
 *     - Syntax: [] <lsplant::Backup auto backup> (Type arg1, Type arg2...) { ... }
 *     - This is a C++20 Template Lambda.
 *     - 'backup': Represents the ORIGINAL function (trampoline).
 *                 You call this to execute the original system logic.
 *     - 'args...': Must match the signature of the target function exactly.
 *
 * -------------------------------------------------------------------------------------------
 * 2. EXAMPLE USAGE
 * -------------------------------------------------------------------------------------------
 * inline static auto my_hook =
 *     "__open"_sym.hook ->* []<auto backup>(const char* path, int flags) {
 *         // 1. Pre-processing (Before original)
 *         LOGD("Opening file: %s", path);
 *
 *         // 2. Call Original (The "Backup")
 *         int result = backup(path, flags);
 *
 *         // 3. Post-processing (After original)
 *         return result;
 *     };
 *
 * -------------------------------------------------------------------------------------------
 * 3. REGISTRATION
 * -------------------------------------------------------------------------------------------
 * Defining the hook variable does not apply it.
 * You must pass the variable to the HookHandler to modify memory: handler(my_hook).
 * ===========================================================================================
 */

namespace vector::native {

namespace {
NativeModuleRegistry<NativeOnModuleLoaded> g_module_registry;
#if defined(DOBBY_HOOK_TRANSACTION_API_VERSION)
std::mutex g_dobby_ownership_mutex;
std::unordered_map<void *, DobbyHookOwnership> g_dobby_ownership;
#endif

struct NativeApiStorage {
    NativeAPIEntries v2;
    NativeAPIEntriesV3 v3;
};

// A smart pointer to a memory page that will hold the NativeAPIEntries struct.
std::unique_ptr<void, std::function<void(void *)>> g_api_page(
    mmap(nullptr, 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0), [](void *ptr) {
        if (ptr != MAP_FAILED) {
            munmap(ptr, 4096);
        }
    });
}  // namespace

#if defined(DOBBY_HOOK_TRANSACTION_API_VERSION)
bool LookupDobbyHookOwnership(void *target, DobbyHookOwnership *ownership) {
    if (target == nullptr || ownership == nullptr) return false;
    std::lock_guard<std::mutex> lock(g_dobby_ownership_mutex);
    const auto it = g_dobby_ownership.find(target);
    if (it == g_dobby_ownership.end()) return false;
    *ownership = it->second;
    return true;
}

void StoreDobbyHookOwnership(void *target, DobbyHookHandle handle, DobbyHookOwnershipState state) {
    if (target == nullptr || handle == 0) return;
    std::lock_guard<std::mutex> lock(g_dobby_ownership_mutex);
    g_dobby_ownership[target] = DobbyHookOwnership{handle, state};
}

void ForgetDobbyHookOwnership(void *target, DobbyHookHandle handle) {
    std::lock_guard<std::mutex> lock(g_dobby_ownership_mutex);
    const auto it = g_dobby_ownership.find(target);
    if (it != g_dobby_ownership.end() && it->second.handle == handle)
        g_dobby_ownership.erase(it);
}
#endif

// The read-only, statically available Native API entry points for modules.
const NativeAPIEntries *g_native_api_entries = nullptr;
const NativeAPIEntriesV3 *g_native_api_entries_v3 = nullptr;

/**
 * @brief Initializes the Native API entries struct and makes it read-only.
 */
void InitializeApiEntries() {
    if (g_api_page.get() == MAP_FAILED) {
        LOGF("Failed to allocate memory for native API entries.");
        LOGD("Release the memory page pointer %p", g_api_page.release());
        return;
    }
    auto *storage = new (g_api_page.get()) NativeApiStorage{
        .v2 = {.version = 2, .hookFunc = &HookInline, .unhookFunc = &UnhookInline},
        .v3 = {
            .base = {.version = 3, .hookFunc = &HookInline, .unhookFunc = &UnhookInline},
            .struct_size = sizeof(NativeAPIEntriesV3),
            .reserved = 0,
            .hookWithPublication = &HookInlineWithPublication,
        },
    };
    if (mprotect(g_api_page.get(), 4096, PROT_READ) != 0) {
        PLOGE("Failed to mprotect API page to read-only");
        return; // Do not publish a mutable or incompletely initialized ABI page.
    }
    g_native_api_entries = &storage->v2;
    g_native_api_entries_v3 = &storage->v3;
    LOGI("Native API entries initialized and protected.");
}

void RegisterNativeLib(const std::string &library_name) {
    static bool is_initialized = []() {
        InitializeApiEntries();
        if (g_native_api_entries == nullptr) {
            LOGE("Cannot initialize Native API without a protected entries page.");
            return false;
        }
        return InstallNativeAPI(lsplant::InitInfo{
            .inline_hooker =
                [](void *target, void *replacement) {
                    void *backup = nullptr;
                    return HookInline(target, replacement, &backup) == 0 ? backup : nullptr;
                },
            .art_symbol_resolver =
                [](auto symbol) { return ElfSymbolCache::GetLinker()->getSymbAddress(symbol); },
        });
    }();

    if (!is_initialized) {
        LOGE("Cannot register module '{}' because native API failed to initialize.",
             library_name.c_str());
        return;
    }

    // Native API v2 has no unregister operation. Deduplicate names so repeated
    // Java registration cannot grow loader work without bound.
    if (!g_module_registry.RegisterLibrary(library_name)) {
        LOGD("Native module library '{}' is already registered.", library_name.c_str());
        return;
    }
    LOGD("Native module library '{}' has been registered.", library_name.c_str());
}

bool HasEnding(std::string_view fullString, std::string_view ending) {
    if (fullString.length() >= ending.length()) {
        return (fullString.compare(fullString.length() - ending.length(), std::string_view::npos,
                                   ending) == 0);
    }
    return false;
}

inline static auto do_dlopen_hook =
    "__dl__Z9do_dlopenPKciPK17android_dlextinfoPKv"_sym.hook->*
    []<lsplant::Backup auto backup>(const char *name, int flags, const void *extinfo,
                                    const void *caller_addr) static -> void * {
    void *handle = backup(name, flags, extinfo, caller_addr);
    const std::string lib_name = (name != nullptr) ? name : "null";
    LOGV("do_dlopen hook triggered for library: '{}'", lib_name.c_str());

    if (handle == nullptr) return nullptr;

    // Never call code from an external native module under the registry
    // mutex: native_init/onModuleLoaded can register modules, resolve symbols,
    // or dlopen dependencies, and any nested loader callback would reenter us.
    const auto registered_modules = g_module_registry.SnapshotLibraries();

    NativeOnModuleLoaded newly_initialized = nullptr;
    for (std::string_view module_lib : registered_modules) {
        if (HasEnding(lib_name, module_lib)) {
            LOGI("Detected registered native module being loaded: '{}'", lib_name.c_str());
            void *init_sym = nullptr;
#if defined(DOBBY_HOOK_TRANSACTION_API_VERSION) && \
    (defined(__aarch64__) || defined(__x86_64__))
            init_sym = dlsym(handle, "native_init_v3");
            if (init_sym != nullptr && g_native_api_entries_v3 != nullptr) {
                auto native_init_v3 = reinterpret_cast<NativeInitV3>(init_sym);
                newly_initialized = native_init_v3(g_native_api_entries_v3);
                LOGD("Initialized native module '{}' through strict Native API v3.",
                     lib_name.c_str());
                break;
            }
#endif
            init_sym = dlsym(handle, "native_init");
            if (init_sym == nullptr) {
                LOGW("Library '{}' matches a module name but exports neither usable native_init_v3 nor native_init.",
                     lib_name.c_str());
                break;
            }
            auto native_init = reinterpret_cast<NativeInit>(init_sym);
            newly_initialized = native_init(g_native_api_entries);
            break;
        }
    }

    if (newly_initialized != nullptr) {
        // This prevents repeated dlopen of one resident module from
        // accumulating the same callback. It does NOT unregister callbacks or
        // make an old module safe to unload.
        if (g_module_registry.RegisterCallback(newly_initialized)) {
            LOGI("Initialized native module '{}' and registered its callback.",
                 lib_name.c_str());
        } else {
            LOGD("Native module '{}' returned an already registered callback.",
                 lib_name.c_str());
        }
    }
    const auto callbacks = g_module_registry.SnapshotCallbacks();
    for (const auto &callback : callbacks) {
        callback(name, handle);
    }

    return handle;
};

bool InstallNativeAPI(const lsplant::HookHandler &handler) { return handler(do_dlopen_hook); }

}  // namespace vector::native
