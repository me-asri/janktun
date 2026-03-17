#pragma once

typedef __uint128_t u256_bits_t[2];

#define U64_BIT_SET(var, pos) ((var) |= (1ULL << (pos)))
#define U64_BIT_CLEAR(var, pos) ((var) &= ~(1ULL << (pos)))
#define U64_BIT_TEST(var, pos) (((var) & (1ULL << (pos))) != 0)
#define U64_BIT_TEST_SEQ(var, start, n) \
    (((var) & (((1ULL << (n)) - 1) << (start))) == ((1ULL << (n)) - 1) << (start))

#define U128_BIT_SET(var, pos) ((var) |= ((__uint128_t)1 << (pos)))
#define U128_BIT_CLEAR(var, pos) ((var) &= ~((__uint128_t)1 << (pos)))
#define U128_BIT_TEST(var, pos) (((var) & ((__uint128_t)1 << (pos))) != 0)
#define U128_BIT_TEST_SEQ(var, start, n) \
    (((var) & ((((__uint128_t)1 << (n)) - 1) << (start))) == (((__uint128_t)1 << (n)) - 1) << (start))
#define U128_BIT_FIRST_SET(var) __builtin_ctzg((__uint128_t)var, -1)
#define U128_BIT_FIRST_UNSET(var) U128_BIT_FIRST_SET(~(var))
#define U128_FOR_EACH_BIT_SET(var, pos) \
    for (__uint128_t _temp = (var); _temp && (pos = __builtin_ctzg(_temp), 1); _temp &= (_temp - 1))

#define U256_BIT_ZERO_INITIALIZE(var) \
    do {                              \
        (var)[0] = (__uint128_t)0;    \
        (var)[1] = (__uint128_t)0;    \
    } while (0)
#define U256_BIT_SET(var, pos) \
    ((var)[(pos) / 128] |= ((__uint128_t)1 << ((pos) % 128)))
#define U256_BIT_CLEAR(var, pos) \
    ((var)[(pos) / 128] &= ~((__uint128_t)1 << ((pos) % 128)))
#define U256_BIT_TEST(var, pos) \
    (((var)[(pos) / 128] & ((__uint128_t)1 << ((pos) % 128))) != 0)
#define U256_BIT_FIRST_SET(var)                  \
    ((var)[0] != 0                               \
            ? __builtin_ctzg((var)[0], -1)       \
            : (var)[1] != 0                      \
            ? 128 + __builtin_ctzg((var)[1], -1) \
            : -1)
#define U256_BIT_FIRST_UNSET(var)                 \
    (~(var)[0] != 0                               \
            ? __builtin_ctzg(~(var)[0], -1)       \
            : ~(var)[1] != 0                      \
            ? 128 + __builtin_ctzg(~(var)[1], -1) \
            : -1)
#define U256_FOR_EACH_BIT_SET(var, pos) \
    for (struct { int i; __uint128_t temp; } _s = { 0, (var)[0] }; (_s.temp || (_s.i == 0 && (++_s.i, _s.temp = (var)[1], _s.temp))) && ((pos) = _s.i * 128 + __builtin_ctzg(_s.temp, -1), 1); _s.temp &= (_s.temp - 1))
