#include "core/native_module_registry.h"

#include <dlfcn.h>

#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {
using Callback = void (*)(const char *, void *);
using Hook = int (*)(void *, void *, void **);
using Unhook = int (*)(void *);
using BackupPublisher = void (*)(void *, void *);
using StrictHook = int (*)(void *, void *, void *, BackupPublisher);
struct NativeAPIEntries {
  uint32_t version;
  Hook hookFunc;
  Unhook unhookFunc;
};
struct NativeAPIEntriesV3 {
  NativeAPIEntries base;
  uint32_t struct_size;
  uint32_t reserved;
  StrictHook hookWithPublication;
};
using NativeInit = Callback (*)(const NativeAPIEntries *);
using NativeInitV3 = Callback (*)(const NativeAPIEntriesV3 *);
using Registry = vector::native::NativeModuleRegistry<Callback>;

int FakeHook(void *, void *, void **) { return -1; }
int FakeUnhook(void *) { return -1; }
int FakeStrictHook(void *, void *, void *, BackupPublisher) { return -1; }

bool CallbackMapped(Callback callback, const char *needle) {
  FILE *maps = std::fopen("/proc/self/maps", "r");
  if (!maps)
    return false;
  const auto pc = reinterpret_cast<uintptr_t>(callback);
  char line[2048];
  bool found = false;
  while (std::fgets(line, sizeof(line), maps)) {
    unsigned long long start = 0;
    unsigned long long end = 0;
    char permissions[5]{};
    if (std::sscanf(line, "%llx-%llx %4s", &start, &end, permissions) != 3)
      continue;
    if (pc >= start && pc < end && permissions[2] == 'x' &&
        std::strstr(line, needle)) {
      found = true;
      break;
    }
  }
  std::fclose(maps);
  return found;
}

bool Check(bool value, const char *label) {
  if (!value)
    std::fprintf(stderr, "native-dso-registry FAIL: %s\n", label);
  return value;
}
} // namespace

int main(int argc, char **argv) {
  if (argc != 2) {
    std::fprintf(stderr, "Usage: %s /absolute/path/libfusehide.so\n", argv[0]);
    return 2;
  }
  Registry registry;
  bool ok =
      Check(registry.RegisterLibrary("libfusehide.so"), "register module name");
  void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!handle) {
    std::fprintf(stderr, "native-dso-registry FAIL: dlopen: %s\n", dlerror());
    return 1;
  }
  const auto init = reinterpret_cast<NativeInit>(dlsym(handle, "native_init"));
  const auto init_v3 = reinterpret_cast<NativeInitV3>(dlsym(handle, "native_init_v3"));
  ok &= Check(init != nullptr, "native_init exported");
  const NativeAPIEntries api{2, FakeHook, FakeUnhook};
  const NativeAPIEntriesV3 api_v3{{3, FakeHook, FakeUnhook}, sizeof(api_v3), 0,
                                  FakeStrictHook};
  const bool strict = init_v3 != nullptr;
  const Callback callback = strict ? init_v3(&api_v3) : (init ? init(&api) : nullptr);
  ok &= Check(callback != nullptr && registry.RegisterCallback(callback),
              "first callback registered");
  const Callback repeated = strict ? init_v3(&api_v3) : init(&api);
  ok &= Check(repeated == nullptr &&
                  registry.CallbackCountForTesting() == 1,
              "repeat init cannot duplicate callback");
  if (!ok)
    return 1;

  dlclose(handle);
  const auto callbacks = registry.SnapshotCallbacks();
  const bool mapped = CallbackMapped(callback, "libfusehide.so");
  ok &= Check(
      callbacks.size() == 1 && mapped,
      "process-lifetime registry callback remains executable after dlclose");
  if (mapped) {
    callbacks.front()("libnot_fuse_jni.so", nullptr);
    callbacks.front()("libnot_fuse_jni.so", nullptr);
  }
  ok &= Check(registry.CallbackCountForTesting() == 1,
              "late callback calls do not mutate registry ownership");
  std::printf("native-dso-registry api=%s callbacks=%zu mapped=%u result=%s\n",
              strict ? "v3" : "v2", registry.CallbackCountForTesting(), mapped,
              ok ? "PASS" : "FAIL");
  return ok ? 0 : 1;
}
