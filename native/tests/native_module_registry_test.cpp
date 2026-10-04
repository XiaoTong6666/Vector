#include "core/native_module_registry.h"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <vector>

namespace {
using Callback = void (*)(const char *, void *);
using Registry = vector::native::NativeModuleRegistry<Callback>;

Registry *g_registry = nullptr;
std::atomic_uint32_t g_calls{0};

void ReentrantCallback(const char *, void *) {
  g_calls.fetch_add(1, std::memory_order_relaxed);
  // Production takes a callback snapshot before invoking external code.
  // If it ever called this under the registry mutex, this would deadlock.
  g_registry->RegisterLibrary("nested.so");
  g_registry->RegisterCallback(ReentrantCallback);
}

void SecondCallback(const char *, void *) {
  g_calls.fetch_add(1, std::memory_order_relaxed);
}

bool Check(bool value, const char *label) {
  if (!value)
    std::fprintf(stderr, "native-registry FAIL: %s\n", label);
  return value;
}
} // namespace

int main() {
  Registry registry;
  g_registry = &registry;
  bool ok = Check(registry.RegisterLibrary("module.so"),
                  "initial library registration");
  ok &= Check(!registry.RegisterLibrary("module.so") &&
                  registry.LibraryCountForTesting() == 1,
              "library registration deduplicated");
  ok &= Check(registry.RegisterCallback(ReentrantCallback) &&
                  !registry.RegisterCallback(ReentrantCallback) &&
                  registry.CallbackCountForTesting() == 1,
              "callback registration deduplicated");

  std::vector<std::thread> workers;
  for (int i = 0; i < 8; ++i) {
    workers.emplace_back([&] {
      for (int n = 0; n < 2000; ++n) {
        registry.RegisterLibrary("module.so");
        registry.RegisterCallback(ReentrantCallback);
        if (registry.SnapshotCallbacks().empty())
          std::abort();
      }
    });
  }
  for (auto &worker : workers)
    worker.join();
  ok &= Check(registry.LibraryCountForTesting() == 1 &&
                  registry.CallbackCountForTesting() == 1,
              "concurrent duplicate registration remains bounded");

  registry.RegisterCallback(SecondCallback);
  const auto callbacks = registry.SnapshotCallbacks();
  for (const auto callback : callbacks)
    callback("libx.so", nullptr);
  ok &= Check(g_calls.load(std::memory_order_relaxed) == 2,
              "snapshot callbacks execute and may reenter registry");
  ok &= Check(registry.LibraryCountForTesting() == 2 &&
                  registry.CallbackCountForTesting() == 2,
              "reentrant callback mutates registry after snapshot");
  std::printf(
      "native-registry libraries=%zu callbacks=%zu calls=%u result=%s\n",
      registry.LibraryCountForTesting(), registry.CallbackCountForTesting(),
      g_calls.load(std::memory_order_relaxed), ok ? "PASS" : "FAIL");
  return ok ? 0 : 1;
}
