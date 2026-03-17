#pragma once

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
