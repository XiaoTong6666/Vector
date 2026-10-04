#pragma once

#include <cstdint>

namespace vector::native {

// x86_64 inline entry patches span multiple bytes. For ART targets Vector can
// borrow ART's own stop-the-world primitive while Dobby owns the physical text
// transaction. The callbacks are process-lifetime functions because Dobby may
// retain them with a recovery ticket until a later Destroy/Recover.
bool SupportsArtQuiescenceTarget(void *target);
int AcquireArtQuiescence(void *user_data, void *target, uint32_t patch_size);
void ReleaseArtQuiescence(void *user_data);

}  // namespace vector::native
