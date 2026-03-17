#include <stdint.h>
#include <stdlib.h>
#include <time.h>

uint64_t timestamp_mono()
{
    struct timespec tp;

    if (clock_gettime(CLOCK_MONOTONIC_COARSE, &tp) != 0) {
        abort();
    }
    return (uint64_t)tp.tv_sec * 1000 + tp.tv_nsec / 1000000;
}
