/******************************************************************************
 *  File:    common.c
 *
 *  Author:  Andy.Zhang
 *
 *  Data:    2019-5-24
 *
 *  Version: v1.0
 *
 *  Describe:
 *
 * ****************************************************************************
 *   All rights reserved by the Sinuc co.,Ltd.
 ******************************************************************************/
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <stdarg.h>
#include "common.h"

uint8_t zk_dev_log_level=_ZK_DEBUG;
/******************************************************************************
 *                              Variable
 ******************************************************************************/

/******************************************************************************
 *                              Function
 ******************************************************************************/
void strcpyl(char * dest, const char * src, size_t len)
{
    while (*src != 0 && len--) 
        *dest++ = *src++;
    *dest = 0;
}

char * itoa(int value, char * string, int radix)
{
	char tmp[11];
	int mod, sign, i;
	unsigned v;

    if (string == NULL)
        return NULL;

	if (radix > 36 || radix <= 1) 
		return 0;
	
	sign = (radix == 10 && value < 0);
	if (sign) {
		v = -value;
        *string++ = '-';
    }
	else
		v = (unsigned)value;

    for (i=0;v || !i;i++) {
		mod = v % radix;
		v = v / radix;
		if (mod< 10)
			tmp[i] = mod + '0';
		else
			tmp[i] = mod + 'a' - 10;
    }
	
    while (i)
        *string++ = tmp[--i];
    *string = 0;

	return string;
}

// int itoa_s
void sys_get(const char * cmd, char * output, size_t out_sz)
{
    FILE * fp;

    output[0] = 0;
    fp = popen(cmd, "r");
    if (fp != NULL) 
        fgets(output, out_sz, fp);
    while (out_sz--) {
        if (*output == '\n')
            *output = 0;
        else
            output++;
    }
    
    pclose(fp);
}

void sys_set(const char * cmd, ...)
{
    char * buffer = (char *)malloc(128);
    char * ptr = buffer;
    va_list args;
    va_start(args, cmd);

    while (*cmd) {
        if (*cmd != '%') {
            *ptr++ = *cmd++;
            continue;
        }

        switch (*++cmd) {
        case 'd': {
            int n = va_arg(args, int);
            ptr = itoa(n, ptr, 10);
            break;
        }

        case 'c':
            *(ptr++) = va_arg(args, char);
            break;
        default:break;
        }
        cmd++;
    }
    *ptr = 0;
    puts(buffer);
}
