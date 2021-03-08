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
#include "serialport.h"

#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <time.h>

#include "common.h"
/***********************************************************************
 *                              Declare
 ***********************************************************************/
#define SERIAL_RD_TIMEOUT 30
/***********************************************************************
 *                              Variable
 ***********************************************************************/

#define MAXSERIALNUM 5
static int SerialFd[MAXSERIALNUM];
static int serialcount = 0;
/***********************************************************************
 *                              Variable
 ***********************************************************************/
int speed_arr[] = {
    B921600, B460800, B230400, B115200, B57600, B38400, B19200, B9600, B4800, B2400, B1200, B300,
};
int name_arr[] = {
    921600, 460800, 230400, 115200, 57600, 38400, 19200, 9600, 4800, 2400, 1200, 300,
};
void set_speed(int fd, int speed) {
    int            i;
    int            status;
    struct termios Opt;

    tcgetattr(fd, &Opt);

    cfmakeraw(&Opt);
    for (i = 0; i < sizeof(speed_arr) / sizeof(int); i++) {
        if (speed == name_arr[i]) {
            tcflush(fd, TCIOFLUSH);
            cfsetispeed(&Opt, speed_arr[i]);
            cfsetospeed(&Opt, speed_arr[i]);
            status = tcsetattr(fd, TCSANOW, &Opt);
            if (status != 0) perror("tcsetattr fd1");
            return;
        }
        tcflush(fd, TCIOFLUSH);
    }

    if (i == 12) { printf("\tSorry, please set the correct baud rate!\n\n"); }
}
/*
 *@brief   设置串口数据位，停止位和效验位
 *@param  fd     类型  int  打开的串口文件句柄*
 *@param  databits 类型  int 数据位   取值 为 7 或者8*
 *@param  stopbits 类型  int 停止位   取值为 1 或者2*
 *@param  parity  类型  int  效验类型 取值为N,E,O,,S
 */
int set_Parity(int fd, int databits, int stopbits, int parity) {
    struct termios options;

    if (tcgetattr(fd, &options) != 0) {
        perror("SetupSerial 1");
        return (FALSE);
    }

    options.c_cflag &= ~CSIZE;
    options.c_oflag = 0;
    switch (databits) /*设置数据位数*/ {
        case 7: options.c_cflag |= CS7; break;
        case 8: options.c_cflag |= CS8; break;
        default: fprintf(stderr, "Unsupported data size\n"); return (FALSE);
    }

    switch (parity) {
        case 'n':
        case 'N':
            options.c_cflag &= ~PARENB; /* Clear parity enable */
            options.c_iflag &= ~INPCK;  /* Enable parity checking */
            break;
        case 'o':
        case 'O':
            options.c_cflag |= (PARODD | PARENB); /* 设置为奇效验*/
            options.c_iflag |= INPCK;             /* Disnable parity checking */
            break;
        case 'e':
        case 'E':
            options.c_cflag |= PARENB;  /* Enable parity */
            options.c_cflag &= ~PARODD; /* 转换为偶效验*/
            options.c_iflag |= INPCK;   /* Disnable parity checking */
            break;
        case 'S':
        case 's': /*as no parity*/
            options.c_cflag &= ~PARENB;
            options.c_cflag &= ~CSTOPB;
            break;
        default: fprintf(stderr, "Unsupported parity\n"); return (FALSE);
    }
    /* 设置停止位*/
    switch (stopbits) {
        case 1: options.c_cflag &= ~CSTOPB; break;
        case 2: options.c_cflag |= CSTOPB; break;
        default: fprintf(stderr, "Unsupported stop bits\n"); return (FALSE);
    }
    /* Set input parity option */
    if (parity != 'n') options.c_iflag |= INPCK;

    options.c_cc[VTIME] = 150;  // 15 seconds
    options.c_cc[VMIN]  = 0;

    options.c_lflag &= ~(ECHO | ICANON);

    tcflush(fd, TCIFLUSH); /* Update the options and do it NOW */
    if (tcsetattr(fd, TCSANOW, &options) != 0) {
        perror("SetupSerial 3");
        return (FALSE);
    }
    return (TRUE);
}
#if 0
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
#else
int serial_open(const char* dev, uint32_t baudrate, uint32_t databit, uint32_t stopbit, uint32_t parity,
                uint8_t ucmode) {
    speed_t        spd;
    struct termios opt;
    if (serialcount > MAXSERIALNUM) { return -1; }
    int idx                 = serialcount;
    SerialFd[serialcount++] = open(dev, O_RDWR);
    if (SerialFd[idx] < 0) {
        perror("open serial port failed\n");
        return -1;
    }
    set_speed(SerialFd[idx], baudrate);
    if (set_Parity(SerialFd[idx], 8, 1, 'N') == FALSE) {
        fprintf(stderr, "Set Parity Error\n");
        close(SerialFd[idx]);
        return -1;
    }
    return SerialFd[idx];
}
#endif
void serial_close(uint8_t fd) { close(fd); }

void serial_flush(uint8_t fd) { tcflush(fd, TCIOFLUSH); }

int serial_read(uint8_t* buffer, size_t maxsize, uint8_t fd) { return read(fd, buffer, maxsize); }

int serial_write(uint8_t* pdata, size_t size, uint8_t fd) { return write(fd, pdata, size); }
int serial_readline(int fd, char* buffer, size_t maxsize, int timeout_ms) {
    size_t len;

    while (timeout_ms) {
        timeout_ms--;
        if (read(fd, buffer, 1) < 1) {
            usleep(1000);
            // printf("%s %d \n",__func__,__LINE__);
            continue;
        } else if (buffer[0] == '\n' || buffer[0] == '\r') {
            usleep(1000);
            //  printf("%s %d \n",__func__,__LINE__);
            continue;
        } else
            break;
    }

    len = 1;

    while (timeout_ms--) {
        if (len >= maxsize)
            break;
        else if (read(fd, buffer + len, 1) < 1) {
            usleep(1000);
            //  printf("%s %d \n",__func__,__LINE__);
            continue;
        } else if (buffer[len] == '\n' || buffer[len] == '\r') {
            len++;
            break;
        } else if (isprint(buffer[len]) == false) {
            return 0;
        }
        len++;
    }
    buffer[len] = 0;

    return len;
}
