#include "core/art_quiescence.h"

#include <dlfcn.h>

#include <array>
#include <cstddef>
#include <mutex>
#include <string_view>

#include "elf/elf_image.h"
#include "elf/symbol_cache.h"

namespace vector::native {
namespace {

#if defined(__x86_64__)
using ScopedSuspendAllCtor = void (*)(void *, const char *, bool);
using ScopedSuspendAllDtor = void (*)(void *);
using SuspendVm = void (*)();
using ResumeVm = void (*)();

struct ArtSuspendBackend {
    ScopedSuspendAllCtor ctor = nullptr;
    ScopedSuspendAllDtor dtor = nullptr;
    SuspendVm suspend_vm = nullptr;
    ResumeVm resume_vm = nullptr;

    bool available() const {
        return (ctor != nullptr && dtor != nullptr) ||
               (suspend_vm != nullptr && resume_vm != nullptr);
    }
};

const ArtSuspendBackend &GetBackend() {
    static const ArtSuspendBackend backend = [] {
        ArtSuspendBackend out{};
        const auto *art = ElfSymbolCache::GetArt();
        if (art == nullptr) return out;

        // Match the same symbols LSPlant uses for ScopedSuspendAll, but resolve
        // them directly so the very first LSPlant ART hook can already acquire
        // the lease before ScopedSuspendAll::Init() itself has run.
        out.ctor = art->getSymbAddress<ScopedSuspendAllCtor>(
            "_ZN3art16ScopedSuspendAllC2EPKcb");
        out.dtor = art->getSymbAddress<ScopedSuspendAllDtor>(
            "_ZN3art16ScopedSuspendAllD2Ev");
        out.suspend_vm = art->getSymbAddress<SuspendVm>("_ZN3art3Dbg9SuspendVMEv");
        out.resume_vm = art->getSymbAddress<ResumeVm>("_ZN3art3Dbg8ResumeVMEv");
        return out;
    }();
    return backend;
}

bool IsLibArtAddress(void *target) {
    if (target == nullptr) return false;
    Dl_info info{};
    if (dladdr(target, &info) == 0 || info.dli_fname == nullptr) return false;
    const std::string_view path(info.dli_fname);
    return path.ends_with("/libart.so") || path.ends_with("/libartd.so") ||
           path == "libart.so" || path == "libartd.so";
}

enum class SuspendMode : uint8_t { None, ScopedSuspendAll, DebugVm };

struct ArtLeaseState {
    std::mutex mutex;
    // art::ScopedSuspendAll is intentionally stateless in ART and LSPlant also
    // models it as an empty class. Keep conservative aligned storage here so
    // the Itanium constructor ABI still receives a valid object address.
    alignas(std::max_align_t) std::array<std::byte, 64> storage{};
    SuspendMode mode = SuspendMode::None;
};

ArtLeaseState g_lease;
#endif

}  // namespace

bool SupportsArtQuiescenceTarget(void *target) {
#if defined(__x86_64__)
    return IsLibArtAddress(target) && GetBackend().available();
#else
    (void) target;
    return false;
#endif
}

int AcquireArtQuiescence(void *, void *target, uint32_t patch_size) {
#if defined(__x86_64__)
    if (patch_size < 5 || !SupportsArtQuiescenceTarget(target)) return 0;
    if (!g_lease.mutex.try_lock()) return 0;

    const auto &backend = GetBackend();
    if (backend.ctor != nullptr && backend.dtor != nullptr) {
        backend.ctor(g_lease.storage.data(), "Vector x86_64 inline hook", false);
        g_lease.mode = SuspendMode::ScopedSuspendAll;
        return 1;
    }
    if (backend.suspend_vm != nullptr && backend.resume_vm != nullptr) {
        backend.suspend_vm();
        g_lease.mode = SuspendMode::DebugVm;
        return 1;
    }

    g_lease.mutex.unlock();
    return 0;
#else
    (void) target;
    (void) patch_size;
    return 0;
#endif
}

void ReleaseArtQuiescence(void *) {
#if defined(__x86_64__)
    const auto &backend = GetBackend();
    switch (g_lease.mode) {
    case SuspendMode::ScopedSuspendAll:
        backend.dtor(g_lease.storage.data());
        break;
    case SuspendMode::DebugVm:
        backend.resume_vm();
        break;
    case SuspendMode::None:
        return;
    }
    g_lease.mode = SuspendMode::None;
    g_lease.mutex.unlock();
#endif
}

}  // namespace vector::native
