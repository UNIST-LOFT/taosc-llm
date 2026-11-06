/* Fixed candidate: reuse exactly the selector's descriptor evaluator and
 * allocator tracker, but never read selector or shared-memory settings.
 * predicate.h contains only validated descriptor/address data, never C input. */
#define init binradar_selector_init
#include "predicate.h"
#include "brpatch.c"
#undef init

void init(int argc, const char *const *argv, char **envp)
{
    /* Logging is observable without allowing PATCH_ID to disable the guard. */
    environ = envp;
    uint32_t fd = getenvul("PATCH_FD");
    if (fd > 2) {
        patch_fd = (int)fd;
    }
}

const void *llm_dest(const struct STATE *state)
{
    /* No PATCH_ID, shared memory, or environment can disable this artifact. */
    env_patch_id = 1;
    return dest(state);
}
