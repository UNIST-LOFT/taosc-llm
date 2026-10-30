/* Fixed candidate: reuse exactly the selector's descriptor evaluator and
 * allocator tracker, but do not run its environment-reading initializer.
 * predicate.h contains only validated descriptor/address data, never C input. */
#define init binradar_selector_init
#include "predicate.h"
#include "brpatch.c"
#undef init

const void *llm_dest(const struct STATE *state)
{
    /* No PATCH_ID, shared memory, or environment can disable this artifact. */
    env_patch_id = 1;
    return dest(state);
}
