#pragma once

#include <stdint.h>

/* Create a timerfd expiring after specified milliseconds */
int timerfd_open(uint64_t millis, bool repeating);

/* Read number of expirations from timerfd */
int timerfd_get_expire(int fd, uint64_t* expirations);
