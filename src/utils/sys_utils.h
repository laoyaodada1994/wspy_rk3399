#ifndef _COMMON_H
#define _COMMON_H

#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys_log.h>
#include <unistd.h>
#ifdef DEBUG
extern void Assert(const uint8_t *file, const uint8_t *func, uint32_t line);
#define ASSERT(condition)                         \
    do {                                          \
        if (condition)                            \
            NULL;                                 \
        else                                      \
            Assert(__FILE__, __func__, __LINE__); \
    } while (0)
#else
#define ASSERT(condition) NULL
#endif

extern int32_t Run_Shell_Read(const uint8_t *cmd, uint8_t *result);
extern int8_t *Get_Cur_Path(void);
#endif
