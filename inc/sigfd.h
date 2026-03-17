#pragma once

#include <stdint.h>
#include <sys/types.h>

/* Setup a signalfd for specified signals and block them on current thread until `sigfd_close` is called */
int sigfd_create(unsigned int count, ...);

/* Destroy singalfd created by `sigfd_create` and unblock signals blocked by `sigfd_create` */
int sigfd_close(int fd);

/* Read all signals from signalfd, returning last one */
ssize_t sigfd_read(int fd, uint32_t* signo);

/* Get signal name */
const char* sigfd_sig_name(uint32_t signo);
