/* Reuse BinRadar's signed-i64 evaluator, without its environment selector.
 * The generated predicate.h contains only validated prefix tokens/addresses.
 * E9 must not call the included selector initializer for a fixed patch. */
#define BINRADAR_EVAL_ONLY
#define init binradar_selector_init
#include "brpatch.c"
#undef init
#include "predicate.h"

const void *llm_dest(const struct STATE *state)
{
    int64_t values[16];
    state_to_env(state, values);
    const char *cursor = TAOSC_LLM_BRANCH;
    int invalid = 0;
    const int jump = eval(&cursor, values, &invalid) != 0;
    if (invalid) {
        /* Match BinRadar's br=2 failure: do not jump on arithmetic traps. */
        log_patch(1, 2, 0);
        return NULL;
    }
    return jump ? (const void *)TAOSC_DEST : NULL;
}
