#include "random.h"

#include <stdlib.h>
#include <stdint.h>
#include <threads.h>
#include <time.h>
#include <stdbool.h>

#define XORSHIFT_FALLBACK_STATE 123456789u

static thread_local uint32_t state = 0;

static void init_state();

uint32_t random_u32()
{
    uint32_t x;

    if (state == 0) {
        init_state();
    }
    x = state;

    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;

    return state = x;
}

uint16_t random_u16()
{
    return (uint16_t)(random_u32() >> 16);
}

bool random_bool()
{
    return (random_u32() >> 31) & 1;
}

void init_state()
{
    struct timespec tp;
    if (clock_gettime(CLOCK_REALTIME, &tp) != 0) {
        abort();
    }

    state = tp.tv_nsec;
    if (state == 0) {
        state = XORSHIFT_FALLBACK_STATE;
    }
}