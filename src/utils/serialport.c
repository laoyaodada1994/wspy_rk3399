/*************************************************************************
 *  File:       heartbeat.c
 * 
 *  Author:     Andy.Zhang
 * 
 *  Date:       2019-7-3
 *  
 *  Version:    v1.0
 * 
 *  Describe:
 ************************************************************************
 *   All rights reserved by the Sinux Co.,Ltd
 ************************************************************************/
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <termios.h>
#include <time.h>
#include "common.h"
#include "serialport.h"
/***********************************************************************
 *                              Declare
 ***********************************************************************/
#define SERIAL_RD_TIMEOUT       30
/***********************************************************************
 *                              Variable
 ***********************************************************************/

#define MAXSERIALNUM	5
static int SerialFd[MAXSERIALNUM];
static int serialcount=0;
/***********************************************************************
 *                              Variable
 ***********************************************************************/

int serial_open(const char * dev, 
                 uint32_t baudrate, 
                 uint32_t databit,
                 uint32_t stopbit,
                 uint32_t parity,
                 uint8_t  ucmode)
{
    speed_t spd;
    struct termios opt;
    if(serialcount >MAXSERIALNUM){
    	return -1;
    }
    int idx = serialcount;
    if(ucmode !=1){
    	SerialFd[serialcount++]= open(dev, O_RDWR | O_NOCTTY);
    }
    else{
    	SerialFd[serialcount++]= open(dev, O_RDWR);
    }
    if (SerialFd[idx] < 0) {
        perror("open serial port failed\n");
        return -1;
    }

    tcgetattr(SerialFd[idx], &opt);

    switch (baudrate) {
    case 115200:
        spd = B115200;
        break;
    case 57600:
        spd = B57600;
        break;
    case 38400:
        spd = B38400;
        break;
    case 9600:
        spd = B9600;
        break;
    }
    cfsetispeed(&opt, spd);

    opt.c_cflag &= ~CSIZE;
    opt.c_oflag = 0;
    switch (stopbit) {
    default:
    case 8:
        opt.c_cflag |= CS8;
        break;
    case 7:
        opt.c_cflag |= CS7;
        break;
    }

    switch (parity) {
    default:
    case 'N':
    case 'n':
        opt.c_cflag &= ~PARENB;
        opt.c_iflag &= ~INPCK;
        break;
    case 'E':
        opt.c_cflag &= ~PARENB;
        opt.c_cflag &= ~PARODD;
        break;
    case 'O':
        opt.c_cflag |= (PARENB | PARODD);
        break;
    case ' ':
        opt.c_cflag &= ~PARENB;
        opt.c_cflag &= ~CSTOPB;
        break;
    }

    switch (stopbit) {
    default:
    case 1:
        opt.c_cflag &= ~ CSTOPB;
        break;
    case 2:
        opt.c_cflag |= CSTOPB;
        break;
    }
    if(ucmode == 1){
#if 0
    	opt.c_cflag |=CREAD;
    	opt.c_cflag |=CLOCAL;
    	opt.c_cc[VMIN] = 40;
    	opt.c_cc[VTIME] = 1;
    	//opt.c_oflag &= ~OPOST;
    	opt.c_lflag &= ~(ICANON|ECHO|ECHOE|ISIG);
#else
    	opt.c_cc[VTIME] = 150; // 15 seconds
    	opt.c_cc[VMIN] = 0;
    	opt.c_lflag &= ~(ECHO | ICANON);

#endif
    }
    else{
    	opt.c_cc[VMIN] = 0;
		opt.c_cc[VTIME] = SERIAL_RD_TIMEOUT;
    }
    tcflush(SerialFd[idx], TCIFLUSH);
    tcsetattr(SerialFd[idx], TCSANOW, &opt);

    return SerialFd[idx];
}

void serial_close(uint8_t fd)
{
    close(fd);
}

void serial_flush(uint8_t fd)
{
    tcflush(fd, TCIOFLUSH);
}

int serial_read(uint8_t * buffer, size_t maxsize,uint8_t fd)
{
    return read(fd, buffer, maxsize);
}

int serial_write(uint8_t * pdata, size_t size,uint8_t fd)
{
    return write(fd, pdata, size);
}
int serial_readline(int fd, char * buffer, size_t maxsize, int timeout_ms)
{
    size_t len;

    while (timeout_ms) {
        timeout_ms--;
        if (read(fd, buffer, 1) < 1) {
            usleep(1000);
           // printf("%s %d \n",__func__,__LINE__);
            continue;
        }
        else if (buffer[0] == '\n' || buffer[0] == '\r') {
        	usleep(1000);
        	//  printf("%s %d \n",__func__,__LINE__);
        	continue;
        }
        else
            break;
    }

    len = 1;

    while (timeout_ms--) {
        if (len >= maxsize)
            break;
        else if (read(fd, buffer+len, 1) < 1) {
            usleep(1000);
          //  printf("%s %d \n",__func__,__LINE__);
            continue;
        }
        else if (buffer[len] == '\n' || buffer[len] == '\r') {
            len++;
            break;
        }
        else if (isprint(buffer[len]) == false) {
            return 0;
        }
        len++;
    }
    buffer[len] = 0;

    return len;
}
