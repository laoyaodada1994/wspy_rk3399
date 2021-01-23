/*****************************************************************************
 * @file: serialport.h
 * @author: andy.zhang
 * @email: zhangt@sinux.com.cn
 * @version: v0.1
 */
#ifndef __SERIALPORT_H
#define __SERIALPORT_H

#ifdef __cplusplus
 extern "C" {
#endif
#include <ctype.h>
#include<unistd.h>
#include "common.h"
/*****************************************************************************
 * Macro
 */

/*****************************************************************************
 * Type
 */
/*****************************************************************************
 * Declare
 */
int serial_open(const char * dev, 
                uint32_t baudrate, 
                uint32_t databit,
                uint32_t stopbit,
                uint32_t parity,
                uint8_t  ucmode);
void serial_close(uint8_t fd);
int serial_read(uint8_t * buffer, size_t maxsize,uint8_t fd);
int serial_write(uint8_t * pdata, size_t size,uint8_t ucchl);
void serial_flush(uint8_t fd);
int serial_readline(int fd, char * buffer, size_t maxsize, int timeout_ms);
#ifdef __cplusplus
 }
#endif

#endif //__SERIALPORT_H
