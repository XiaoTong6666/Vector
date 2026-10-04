#pragma once

#include <dlfcn.h>
#include <dobby.h>

#include <cstddef>
#include <string>
#include <type_traits>
#include <utils/hook_helper.hpp>

#include "common/config.h"
#include "common/logging.h"
#include "core/art_quiescence.h"

/**
 * @file native_api.h
 * @brief Manages the native module ecosystem and provides a stable API for them.
 *
 * This component is responsible for hooking the dynamic library loader (`dlopen`) to
 * detect when registered native modules are loaded.
 * It then provides these modules with a set of function pointers for
 * interacting with the Vector core, primarily for creating native hooks.
 */

// NOTE: The following type definitions form a public ABI for native modules.
// Do not change them without careful consideration for backward compatibility.

/*
 * =========================================================================================
 *  Vector Native API Interface
 * =========================================================================================
 *
 * This following function types and data structures allow a native library (your module) to
 * interface with the Vector framework.
 * The core idea is that Vector provides a set of powerful tools (like function hooking),
 * and your module consumes these tools through a well-defined entry point.
 *
 * The interaction flow is as follows:
 *
 *   1. Vector intercepts the loading of your native library (e.g., libnative.so).
 *   2. Vector looks for and calls the `native_init` function within your library.
 *   3. Vector passes a `NativeAPIEntries` struct to your `native_init`,
 *      which contains function pointers to Vector's hooking
 *      and unhooking implementations (powered by Dobby).
 *   4. Your `native_init` function saves these function pointers for later use
 *      and returns a callback function (`NativeOnModuleLoaded`).
 *   5. Vector will then invoke your returned callback every time
 *      a new native library is loaded into the target process,
 *      allowing you to perform "late" hooks on specific libraries.
 *
 *
 * Initialization Flow
 *
 *   Vector Framework                    Your Native Module (e.g., libnative.so)
 *   -----------------                    -------------------------------------
 *
 *        |                                            |
 * [ Intercepts dlopen("libnative.so") ]               |
 *        |                                            |
 *        |----------> [ Finds & Calls native_init() ] |
 *        |                                            |
 *   [ Passes NativeAPIEntries* ]  ---> [ Stores function pointers ]
 *   (Contains hook/unhook funcs)                      |
 *        |                                            |
 *        |                                            |
 *        |             <-----------[ Returns `NativeOnModuleLoaded` callback ]
 *        |                                            |
 *        |                                            |
 *   [ Stores your callback ]                          |
 *        |                                            |
 *
 */

// Function pointer type for a native hooking implementation.
using HookFunType = int (*)(void *func, void *replace, void **backup);

// Function pointer type for a native unhooking implementation.
using UnhookFunType = int (*)(void *func);

using HookBackupPublisher = void (*)(void *user_data, void *original);
using StrictHookFunType = int (*)(void *target, void *replacement, void *user_data,
                                  HookBackupPublisher publish);

enum NativeHookResult : int {
    NATIVE_HOOK_OK = 0,
    NATIVE_HOOK_FAILED_NEVER_PUBLISHED = -1,
    NATIVE_HOOK_FAILED_AFTER_PUBLISHED = -2,
    NATIVE_HOOK_RECOVERY_REQUIRED = -3,
};

// Callback function pointer that modules receive, invoked when any library is loaded.
//
// Native API v2 has no callback-unregister operation. Vector retains this
// function pointer for the process lifetime, including after the original
// dlopen handle's owner calls dlclose. A module returning a non-null callback
// MUST keep its text mapped for that lifetime (e.g. link with -Wl,-z,nodelete)
// and may close logical admission / drain entrants without unmapping itself.
// unhookFunc only restores a physical entry; it is NOT a module-unload token.
// True unload requires a separate generation-scoped registration/unregistration
// protocol plus callback and instruction-fetch grace.
using NativeOnModuleLoaded = void (*)(const char *name, void *handle);

/**
 * @struct NativeAPIEntries
 * @brief A struct containing function pointers exposed to native modules.
 */
struct NativeAPIEntries {
    uint32_t version;          // The version of this API struct.
    HookFunType hookFunc;      // Pointer to the function for inline  hooking.
    UnhookFunType unhookFunc;  // Pointer to the function for unhooking.
};

struct NativeAPIEntriesV3 {
    NativeAPIEntries base;
    uint32_t struct_size;
    uint32_t reserved;
    StrictHookFunType hookWithPublication;
};
static_assert(std::is_standard_layout_v<NativeAPIEntriesV3>);
static_assert(offsetof(NativeAPIEntriesV3, base) == 0);
static_assert(sizeof(NativeAPIEntriesV3::base) == sizeof(NativeAPIEntries));

// NOTE: Module developers should not include the following INTERNAL definitions.

namespace vector::native {

inline const char *DobbyHookStatusName(uint32_t status) {
    switch (status) {
    case DOBBY_HOOK_OK: return "OK";
    case DOBBY_HOOK_INVALID_ARGUMENT: return "INVALID_ARGUMENT";
    case DOBBY_HOOK_TARGET_BUSY: return "TARGET_BUSY";
    case DOBBY_HOOK_NEAR_UNAVAILABLE: return "NEAR_UNAVAILABLE";
    case DOBBY_HOOK_RELOCATION_FAILED: return "RELOCATION_FAILED";
    case DOBBY_HOOK_CONCURRENCY_UNSUPPORTED: return "CONCURRENCY_UNSUPPORTED";
    case DOBBY_HOOK_SYNC_UNAVAILABLE: return "SYNC_UNAVAILABLE";
    case DOBBY_HOOK_SYNC_FAILED: return "SYNC_FAILED";
    case DOBBY_HOOK_PATCH_FAILED: return "PATCH_FAILED";
    case DOBBY_HOOK_RECOVERY_REQUIRED: return "RECOVERY_REQUIRED";
    case DOBBY_HOOK_INVALID_HANDLE: return "INVALID_HANDLE";
    case DOBBY_HOOK_INVALID_STATE: return "INVALID_STATE";
    case DOBBY_HOOK_TARGET_CHANGED: return "TARGET_CHANGED";
    default: return "UNKNOWN";
    }
}

#if defined(DOBBY_HOOK_TRANSACTION_API_VERSION)
enum class DobbyHookOwnershipState : uint8_t {
    Prepared,
    Active,
    RecoveryRequired,
};

struct DobbyHookOwnership {
    DobbyHookHandle handle = 0;
    DobbyHookOwnershipState state = DobbyHookOwnershipState::Prepared;
};

bool LookupDobbyHookOwnership(void *target, DobbyHookOwnership *ownership);
void StoreDobbyHookOwnership(void *target, DobbyHookHandle handle, DobbyHookOwnershipState state);
void ForgetDobbyHookOwnership(void *target, DobbyHookHandle handle);
#endif

// The entry point function that native modules must export (`native_init`).
using NativeInit = NativeOnModuleLoaded (*)(const NativeAPIEntries *entries);
using NativeInitV3 = NativeOnModuleLoaded (*)(const NativeAPIEntriesV3 *entries);

/**
 * @brief Installs the hooks required for the native API to function.
 * @param handler The LSPlant hook handler.
 * @return True on success, false on failure.
 */
bool InstallNativeAPI(const lsplant::HookHandler &handler);

/**
 * @brief Registers a native library by its filename for module initialization.
 *
 * When a library with a matching filename is loaded via `dlopen`, the runtime will attempt to
 * initialize it as a native module by calling its `native_init` function.
 *
 * @param library_name The filename of the native module's .so file (e.g., "libmymodule.so").
 */
void RegisterNativeLib(const std::string &library_name);

/**
 * @brief A wrapper around DobbyHook.
 */
inline int HookInlineTransaction(void *original, void *replace, void **backup,
                                 void *publish_user_data, HookBackupPublisher publish) {
    if constexpr (kIsDebugBuild) {
        Dl_info info;
        if (dladdr(original, &info)) {
            LOGD("Dobby hooking {} ({}) from {} ({})",
                 info.dli_sname ? info.dli_sname : "(unknown symbol)",
                 info.dli_saddr ? info.dli_saddr : original,
                 info.dli_fname ? info.dli_fname : "(unknown file)", info.dli_fbase);
        }
    }
#if defined(DOBBY_HOOK_TRANSACTION_API_VERSION) && \
    (defined(__aarch64__) || defined(__x86_64__))
    // All ART/linker/Native API targets may be executed by other threads.
    // ARM64 can satisfy that contract with one aligned near branch plus
    // sync-core. x86_64 needs an explicit stop-the-world lease. Vector can
    // provide that lease for libart targets through ART's ScopedSuspendAll;
    // non-ART targets continue to fail closed instead of pretending that an
    // ART-only suspension primitive covers arbitrary native execution.
    if (backup != nullptr) *backup = nullptr;

    DobbyHookOwnership existing{};
    if (LookupDobbyHookOwnership(original, &existing)) {
        if (existing.state != DobbyHookOwnershipState::RecoveryRequired) {
            LOGE("Dobby target already owned target={} handle={}", original, existing.handle);
            return NATIVE_HOOK_FAILED_NEVER_PUBLISHED;
        }
        DobbyHookResult recovered{};
        recovered.struct_size = sizeof(recovered);
        if (DobbyRecoverHook(existing.handle, &recovered) != RS_SUCCESS) {
            LOGE("Dobby retained hook recovery failed target={} handle={} status={} cause={}",
                 original, existing.handle, recovered.status, recovered.cause);
            return NATIVE_HOOK_RECOVERY_REQUIRED;
        }
        ForgetDobbyHookOwnership(original, existing.handle);
    }

    #if defined(__x86_64__)
    if (!SupportsArtQuiescenceTarget(original)) {
        LOGE("Dobby x86_64 concurrent-safe hook rejected target={}: ART quiescence is only "
             "available for libart targets", original);
        return NATIVE_HOOK_FAILED_NEVER_PUBLISHED;
    }
    DobbyHookOptionsQuiescentV2 options{};
    options.base = {
        sizeof(options),
        DOBBY_BRANCH_FORCE_LONG,
        DOBBY_HOOK_REQUIRE_CONCURRENT_SAFE,
        0,
        original,
        reinterpret_cast<dobby_dummy_func_t>(replace),
    };
    options.user_data = nullptr;
    options.acquire = &AcquireArtQuiescence;
    options.release = &ReleaseArtQuiescence;
    const auto *prepare_options = reinterpret_cast<const DobbyHookOptions *>(&options);
    #else
    DobbyHookOptions options{
        sizeof(DobbyHookOptions),
        DOBBY_BRANCH_REQUIRE_NEAR,
        DOBBY_HOOK_REQUIRE_CONCURRENT_SAFE,
        0,
        original,
        reinterpret_cast<dobby_dummy_func_t>(replace),
    };
    const auto *prepare_options = &options;
    #endif
    DobbyHookResult result{};
    result.struct_size = sizeof(result);
    if (DobbyPrepareHook(prepare_options, &result) != RS_SUCCESS) {
        LOGE("Dobby Prepare failed target={} status={}({}) cause={}({})", original,
             result.status, DobbyHookStatusName(result.status), result.cause,
             DobbyHookStatusName(result.cause));
        return NATIVE_HOOK_FAILED_NEVER_PUBLISHED;
    }
    const DobbyHookHandle prepared_handle = result.handle;
    StoreDobbyHookOwnership(original, prepared_handle, DobbyHookOwnershipState::Prepared);
    if (publish != nullptr)
        publish(publish_user_data, reinterpret_cast<void *>(result.original));
    else if (backup != nullptr)
        *backup = reinterpret_cast<void *>(result.original);
    if (DobbyCommitHook(prepared_handle, &result) != RS_SUCCESS) {
        LOGE("Dobby Commit failed target={} status={}({}) cause={}({}) retained={} published={}",
             original, result.status, DobbyHookStatusName(result.status), result.cause,
             DobbyHookStatusName(result.cause), result.handle != 0,
             result.ever_published != 0);
        if (result.status == DOBBY_HOOK_RECOVERY_REQUIRED && result.handle != 0) {
            StoreDobbyHookOwnership(original, result.handle,
                                    DobbyHookOwnershipState::RecoveryRequired);
            DobbyHookResult recovered{};
            recovered.struct_size = sizeof(recovered);
            if (DobbyRecoverHook(result.handle, &recovered) == RS_SUCCESS) {
                ForgetDobbyHookOwnership(original, result.handle);
                return NATIVE_HOOK_FAILED_AFTER_PUBLISHED;
            } else {
                LOGE("Dobby recovery retained target={} handle={} status={} cause={}",
                     original, result.handle, recovered.status, recovered.cause);
                return NATIVE_HOOK_RECOVERY_REQUIRED;
            }
        } else {
            bool reservation_retained = false;
            if (result.handle != 0) {
                DobbyHookResult aborted{};
                aborted.struct_size = sizeof(aborted);
                if (DobbyAbortHook(result.handle, &aborted) == RS_SUCCESS) {
                    ForgetDobbyHookOwnership(original, prepared_handle);
                } else {
                    LOGE("Dobby Abort failed target={} handle={} status={} cause={}", original,
                         prepared_handle, aborted.status, aborted.cause);
                    reservation_retained = true;
                }
            } else {
                ForgetDobbyHookOwnership(original, prepared_handle);
            }
            if (reservation_retained)
                return NATIVE_HOOK_RECOVERY_REQUIRED;
            if (!result.ever_published) {
                if (publish != nullptr)
                    publish(publish_user_data, nullptr);
                else if (backup != nullptr)
                    *backup = nullptr;
            }
        }
        return result.ever_published ? NATIVE_HOOK_FAILED_AFTER_PUBLISHED
                                     : NATIVE_HOOK_FAILED_NEVER_PUBLISHED;
    }
    StoreDobbyHookOwnership(original, prepared_handle, DobbyHookOwnershipState::Active);
    return NATIVE_HOOK_OK;
#else
    (void) publish_user_data;
    (void) publish;
    return DobbyHook(original, reinterpret_cast<dobby_dummy_func_t>(replace),
                     reinterpret_cast<dobby_dummy_func_t *>(backup)) == RS_SUCCESS
               ? NATIVE_HOOK_OK
               : NATIVE_HOOK_FAILED_NEVER_PUBLISHED;
#endif
}

inline int HookInline(void *original, void *replace, void **backup) {
    const int status = HookInlineTransaction(original, replace, backup, nullptr, nullptr);
    return status == NATIVE_HOOK_OK ? RS_SUCCESS : RS_FAILED;
}

inline int HookInlineWithPublication(void *original, void *replace, void *user_data,
                                     HookBackupPublisher publish) {
    if (publish == nullptr) return NATIVE_HOOK_FAILED_NEVER_PUBLISHED;
#if defined(DOBBY_HOOK_TRANSACTION_API_VERSION) && \
    (defined(__aarch64__) || defined(__x86_64__))
    return HookInlineTransaction(original, replace, nullptr, user_data, publish);
#else
    (void) original;
    (void) replace;
    (void) user_data;
    return NATIVE_HOOK_FAILED_NEVER_PUBLISHED;
#endif
}

/**
 * @brief A wrapper around DobbyDestroy.
 */
inline int UnhookInline(void *original) {
    if constexpr (kIsDebugBuild) {
        Dl_info info;
        if (dladdr(original, &info)) {
            LOGD("Dobby unhooking {} ({}) from {} ({})",
                 info.dli_sname ? info.dli_sname : "(unknown symbol)",
                 info.dli_saddr ? info.dli_saddr : original,
                 info.dli_fname ? info.dli_fname : "(unknown file)", info.dli_fbase);
        }
    }
#if defined(DOBBY_HOOK_TRANSACTION_API_VERSION) && \
    (defined(__aarch64__) || defined(__x86_64__))
    DobbyHookOwnership ownership{};
    if (LookupDobbyHookOwnership(original, &ownership)) {
        DobbyHookResult result{};
        result.struct_size = sizeof(result);
        int rc = RS_FAILED;
        switch (ownership.state) {
        case DobbyHookOwnershipState::Prepared:
            rc = DobbyAbortHook(ownership.handle, &result);
            break;
        case DobbyHookOwnershipState::Active:
            rc = DobbyDestroyHook(ownership.handle, &result);
            break;
        case DobbyHookOwnershipState::RecoveryRequired:
            rc = DobbyRecoverHook(ownership.handle, &result);
            break;
        }
        if (rc == RS_SUCCESS) {
            ForgetDobbyHookOwnership(original, ownership.handle);
            return RS_SUCCESS;
        }
        if (result.status == DOBBY_HOOK_RECOVERY_REQUIRED)
            StoreDobbyHookOwnership(original, ownership.handle,
                                    DobbyHookOwnershipState::RecoveryRequired);
        LOGE("Dobby unhook failed target={} handle={} status={} cause={}", original,
             ownership.handle, result.status, result.cause);
        return RS_FAILED;
    }
#endif
    return DobbyDestroy(original);
}

}  // namespace vector::native
