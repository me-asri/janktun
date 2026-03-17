#pragma once

#include <stdint.h>
#include <stdbool.h>

/* Generate a pseudo-random unsigned 32-bit integer */
uint32_t random_u32();

/* Generate a pseudo-random unsigned 16-bit integer */
uint16_t random_u16();

/* Generate a pseudo-random boolean */
bool random_bool();
