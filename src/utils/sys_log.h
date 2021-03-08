#ifndef _SYS_LOG_H
#define _SYS_LOG_H

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

extern void Log_Degug(const uint8_t *fmt, ...);
extern void Log_Warning(const uint8_t *fmt, ...);
extern void Log_Err(const uint8_t *fmt, ...);
extern void Log_Emerg(const uint8_t *fmt, ...);

#endif
