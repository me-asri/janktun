#pragma once

#include <stdint.h>

#if !__has_builtin(__builtin_ctzg)
#error "Your compiler is too old and does not support __builtin_ctzg, use GCC 14+"
#endif

typedef uint64_t bitset64_t;

#define BITSET64_ZERO_INIT(var) \
    do {                        \
        (var) = 0ULL;           \
    } while (0)
#define BITSET64_SET_BIT(var, pos) ((var) |= (1ULL << (pos)))
#define BITSET64_CLEAR_BIT(var, pos) ((var) &= ~(1ULL << (pos)))
#define BITSET64_TEST_BIT(var, pos) (((var) & (1ULL << (pos))) != 0)
#define BITSET64_TEST_SEQ(var, start, n) \
    (((var) & (((1ULL << (n)) - 1) << (start))) == ((1ULL << (n)) - 1) << (start))

typedef __uint128_t bitset512_t[4];

/* clang-format off */
#define BITSET512_ZERO_INIT(var)   \
    do {                           \
        (var)[0] = (__uint128_t)0; \
        (var)[1] = (__uint128_t)0; \
        (var)[2] = (__uint128_t)0; \
        (var)[3] = (__uint128_t)0; \
    } while (0)
#define BITSET512_SET_BIT(var, pos) \
    ((var)[(pos) / 128] |= ((__uint128_t)1 << ((pos) % 128)))
#define BITSET512_CLEAR_BIT(var, pos) \
    ((var)[(pos) / 128] &= ~((__uint128_t)1 << ((pos) % 128)))
#define BITSET512_TEST_BIT(var, pos) \
    (((var)[(pos) / 128] & ((__uint128_t)1 << ((pos) % 128))) != 0)
#define BITSET512_FIRST_SET(var)                 \
    (                                            \
        (var)[0] != 0                            \
            ? __builtin_ctzg((var)[0], -1)       \
            : (var)[1] != 0                      \
            ? 128 + __builtin_ctzg((var)[1], -1) \
            : (var)[2] != 0                      \
            ? 256 + __builtin_ctzg((var)[2], -1) \
            : (var)[3] != 0                      \
            ? 384 + __builtin_ctzg((var)[3], -1) \
            : -1                                 \
    )
#define BITSET512_FIRST_UNSET(var)                \
    (                                             \
        ~(var)[0] != 0                            \
            ? __builtin_ctzg(~(var)[0], -1)       \
            : ~(var)[1] != 0                      \
            ? 128 + __builtin_ctzg(~(var)[1], -1) \
            : ~(var)[2] != 0                      \
            ? 256 + __builtin_ctzg(~(var)[2], -1) \
            : ~(var)[3] != 0                      \
            ? 384 + __builtin_ctzg(~(var)[3], -1) \
            : -1                                  \
    )
#define BITSET512_FOR_EACH_SET(var, pos)                                 \
    for (int _i = 0; _i < 4; ++_i)                                       \
        for (__uint128_t _temp = (var)[_i];                              \
             _temp && ((pos) = _i * 128 + __builtin_ctzg(_temp, -1), 1); \
             _temp &= (_temp - 1))
/* clang-format on */