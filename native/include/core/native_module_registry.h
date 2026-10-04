#pragma once

#include <algorithm>
#include <cstddef>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace vector::native {

// A snapshot registry used by the native loader path. Callbacks are never
// invoked while the registry mutex is held: callers copy a snapshot and then
// execute external module code after releasing the lock.
//
// Native API v2 has no unregister operation. Callback addresses therefore
// remain process-lifetime entries and their DSOs must remain mapped.
template <typename Callback> class NativeModuleRegistry final {
public:
  bool RegisterLibrary(std::string library_name) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (std::find(libraries_.begin(), libraries_.end(), library_name) !=
        libraries_.end()) {
      return false;
    }
    libraries_.push_back(std::move(library_name));
    return true;
  }

  bool RegisterCallback(Callback callback) {
    if (callback == nullptr)
      return false;
    std::lock_guard<std::mutex> lock(mutex_);
    if (std::find(callbacks_.begin(), callbacks_.end(), callback) !=
        callbacks_.end()) {
      return false;
    }
    callbacks_.push_back(callback);
    return true;
  }

  std::vector<std::string> SnapshotLibraries() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return libraries_;
  }

  std::vector<Callback> SnapshotCallbacks() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return callbacks_;
  }

  size_t LibraryCountForTesting() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return libraries_.size();
  }

  size_t CallbackCountForTesting() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return callbacks_.size();
  }

private:
  mutable std::mutex mutex_;
  std::vector<std::string> libraries_;
  std::vector<Callback> callbacks_;
};

} // namespace vector::native
