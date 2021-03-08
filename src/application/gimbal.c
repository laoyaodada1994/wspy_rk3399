/*************************************************************************
 *  File:       gimbal.c
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
#include "gimbal.h"

#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "MqttProcess.h"
#include "cJSON.h"
#include "common.h"
#include "serialport.h"

CHTOFREQ g_charry[] = {
    {.channel = 36, .ffreq = 5.180, .lfreq = 5180},  {.channel = 38, .ffreq = 5.190, .lfreq = 5190},
    {.channel = 40, .ffreq = 5.200, .lfreq = 5200},  {.channel = 44, .ffreq = 5.220, .lfreq = 5220},
    {.channel = 46, .ffreq = 5.230, .lfreq = 5230},  {.channel = 48, .ffreq = 5.240, .lfreq = 5240},
    {.channel = 50, .ffreq = 5.250, .lfreq = 5250},  {.channel = 52, .ffreq = 5.260, .lfreq = 5260},
    {.channel = 54, .ffreq = 5.270, .lfreq = 5270},  {.channel = 56, .ffreq = 5.280, .lfreq = 5280},
    {.channel = 58, .ffreq = 5.290, .lfreq = 5290},  {.channel = 60, .ffreq = 5.300, .lfreq = 5300},
    {.channel = 62, .ffreq = 5.310, .lfreq = 5310},  {.channel = 64, .ffreq = 5.320, .lfreq = 5320},
    {.channel = 100, .ffreq = 5.500, .lfreq = 5500}, {.channel = 102, .ffreq = 5.510, .lfreq = 5510},
    {.channel = 104, .ffreq = 5.520, .lfreq = 5520}, {.channel = 106, .ffreq = 5.530, .lfreq = 5530},
    {.channel = 108, .ffreq = 5.540, .lfreq = 5540}, {.channel = 110, .ffreq = 5.550, .lfreq = 5550},
    {.channel = 112, .ffreq = 5.560, .lfreq = 5560}, {.channel = 114, .ffreq = 5.570, .lfreq = 5570},
    {.channel = 116, .ffreq = 5.580, .lfreq = 5580}, {.channel = 118, .ffreq = 5.590, .lfreq = 5590},
    {.channel = 120, .ffreq = 5.600, .lfreq = 5600}, {.channel = 122, .ffreq = 5.610, .lfreq = 5610},
    {.channel = 124, .ffreq = 5.620, .lfreq = 5620}, {.channel = 126, .ffreq = 5.630, .lfreq = 5630},
    {.channel = 128, .ffreq = 5.640, .lfreq = 5640}, {.channel = 132, .ffreq = 5.660, .lfreq = 5660},
    {.channel = 134, .ffreq = 5.670, .lfreq = 5670}, {.channel = 136, .ffreq = 5.680, .lfreq = 5680},
    {.channel = 138, .ffreq = 5.690, .lfreq = 5690}, {.channel = 140, .ffreq = 5.700, .lfreq = 5700},
    {.channel = 142, .ffreq = 5.710, .lfreq = 5710}, {.channel = 144, .ffreq = 5.720, .lfreq = 5720},
    {.channel = 149, .ffreq = 5.745, .lfreq = 5745}, {.channel = 151, .ffreq = 5.755, .lfreq = 5755},
    {.channel = 153, .ffreq = 5.765, .lfreq = 5765}, {.channel = 155, .ffreq = 5.775, .lfreq = 5775},
    {.channel = 157, .ffreq = 5.785, .lfreq = 5785}, {.channel = 159, .ffreq = 5.795, .lfreq = 5795},
    {.channel = 161, .ffreq = 5.805, .lfreq = 5805}, {.channel = 165, .ffreq = 5.825, .lfreq = 5825},
};
int g_chl5g_num = sizeof(g_charry) / sizeof(g_charry[0]);
//
//									(info->frequency == 5785)? 157:
//									(info->frequency == 5795)? 159:
//									(info->frequency == 5805)? 161:
//									(info->frequency == 5825)? 165:
//									(info->frequency == 4915)? 183:
//									(info->frequency == 4920)? 184:
//									(info->frequency == 4925)? 185:
//									(info->frequency == 4935)? 187:
//									(info->frequency == 4940)? 188:
//									(info->frequency == 4945)? 189:
//									(info->frequency == 4960)? 192:
//									(info->frequency == 4980)? 196:
int lsin_array[] = {
    0,       146401,  292758,  439026,  585160,  731115,  876848,  1022314, 1167469, 1312267, 1456666, 1600622, 1744090,
    1887026, 2029388, 2171132, 2312214, 2452592, 2592222, 2731064, 2869073, 3006208, 3142428, 3277690, 3411954, 3545179,
    3677324, 3808348, 3938213, 4066878, 4194304, 4320453, 4445285, 4568763, 4690850, 4811508, 4930700, 5048390, 5164543,
    5279122, 5392093, 5503422, 5613074, 5721017, 5827217, 5931642, 6034260, 6135040, 6233951, 6330963, 6426047,
};
#define CHNAN_24FLAG 0x52
#define CHNAN_58FLAG 0x55
#define FREQ24BASE 2.412
int gim_fd = 0;

GIM_SET_RES gim_set_res;  //转台状态查询结构
/***********************************************************************
 *                              Declare
 ***********************************************************************/

/***********************************************************************
 *                              Function
 ***********************************************************************/
/*****************************************************************
 * 函数描述：转台校验和计算
 * 参数：const gimbal_packet_t * pkt 转台数据缓存指针
 * 返回值：uint8_t 校验和数值
 * ***************************************************************/
uint8_t gimbal_cal_chk(const gimbal_packet_t *pkt) {
    uint8_t chk = pkt->buffer[0];
    uint8_t len = pkt->length + GIMBAL_FRAME_HEADER_SIZE;
    for (int i = 1; i < len; i++) chk ^= pkt->buffer[i];
    return chk;
}

int gimbal_rsponse_chk(const gimbal_packet_t *resp) {
    if (resp->head != GIMBAL_FRAME_HEAD) return -1;
    if (resp->payload[resp->length] != gimbal_cal_chk(resp)) return -2;
    return 0;
}
#if 0
void gimbal_check()
{
	float angle=0;
	int timeout = 100;
    gimbal_packet_t cmd;
    cmd.head = GIMBAL_FRAME_HEAD;
    *(uint32_t *)cmd.ctrl = GIMBAL_FRAME_CTRL_VAL;
    cmd.type = GIMBAL_FRAME_TYPE_CHK;
    cmd.length = 0;
    cmd.payload[0] = gimbal_cal_chk(&cmd);
    GIMBAL_PORT_WRITE(cmd.buffer, cmd.length + GIMBAL_FRAME_MIN_SIZE,gim_fd);
    for(int i=0;i<cmd.length + GIMBAL_FRAME_MIN_SIZE;i++){
    	printf("%#02x,",cmd.buffer[i]);
    }
    printf("end\n");
}
#endif
/*****************************************************************
 * 函数描述：车载转台复位操作
 * 参数：无
 * 返回值： 无
 * ***************************************************************/
void gimbal_reset() {
    gimbal_packet_t cmd;
    cmd.head               = GIMBAL_FRAME_HEAD;
    *(uint32_t *) cmd.ctrl = GIMBAL_FRAME_CTRL_VAL;
    cmd.type               = GIMBAL_FRAME_TYPE_RST;
    cmd.length             = 0;
    cmd.payload[0]         = gimbal_cal_chk(&cmd);
    GIMBAL_PORT_WRITE(cmd.buffer, cmd.length + GIMBAL_FRAME_MIN_SIZE, gim_fd);
    printf("reset begin\n");
    return;
}
#if 0
uint8_t gimbal_query_status()
{
    gimbal_packet_t cmd;
    cmd.head = GIMBAL_FRAME_HEAD;
    *(uint32_t *)cmd.ctrl = GIMBAL_FRAME_CTRL_VAL;
    cmd.type = GIMBAL_FRAME_TYPE_QUERY;
    cmd.length = 1;
    cmd.payload[0] = GIMBAL_CMD_QUERY_STATUS;
    cmd.payload[1] = gimbal_cal_chk(&cmd);
    serial_write(cmd.payload, 11,gim_fd);
    return 0;
}

float gimbal_read_angle(void)
{
    uint8_t buffer[128];
    const gimbal_packet_t * pkt;
    int len;

//    serial_flush(gim_fd);
//
//    gimbal_query_status();
    len = serial_read(buffer, 40, gim_fd);
    for(int i=0;i<len;i++){
    	printf("%#02x,",buffer[i]);
    }
  //  printf("serial: %d\n", len);
    return 1;
    for (int i=0;i<len-1;i++) {
        if (buffer[i] != 0xFE)
            continue;
        if (buffer[i+1] != 0xFE)
            continue;
        pkt = (const gimbal_packet_t *)(buffer + i);
        if (gimbal_rsponse_chk(pkt) != 0)
            continue;
        if (pkt->type == GIMBAL_FRAME_TYPE_QUERY
        &&  pkt->payload[0] == GIMBAL_CMD_QUERY_STATUS) {
            return *(float *)(pkt->payload + 7);
        }
        printf("serial: %d\n", pkt->type);
    }

    return -1;
}
#endif
/*************************************************************************
 *函数描述：计算公式1 sina*cosb
 *参数：	 int theta θ参数
 *		 int *out 计算结果输出指针
 *返回值：  计算是否正确
 *					-1  参数错误
 *					 0  计算完成
 *************************************************************************/
int calformula1(int theta, int *out) {
    if (theta > 50 || theta < -50 || out == NULL) { return -1; }
    if (theta < 0) {
        theta = abs(theta);
        *out  = -lsin_array[theta];
    } else {
        *out = lsin_array[theta];
    }
    return 0;
}
#ifdef WSPY_CAR
/***************************************************************
 * 函数描述：转台角度设置
 * 参数：	  int angle  转台角度值
 * 返回值：  无
 ****************************************************************/
void gimbal_set_angle(float fangle) {
    int             res = 0;
    gimbal_packet_t cmd;
    float           angle        = 180 + fangle;
    cmd.head                     = GIMBAL_FRAME_HEAD;
    *(uint32_t *) cmd.ctrl       = GIMBAL_FRAME_CTRL_VAL;
    cmd.type                     = GIMBAL_FRAME_TYPE_CTRL;
    cmd.length                   = 6;
    cmd.sequence                 = 0;
    cmd.payload[0]               = 0x0;
    cmd.payload[1]               = GIMBAL_CMD_SET_ANGLE;
    *(float *) (cmd.payload + 2) = angle;
    cmd.payload[6]               = gimbal_cal_chk(&cmd);
    printf("%s :", __func__);
    for (int i = 0; i < cmd.length + GIMBAL_FRAME_MIN_SIZE; i++) { printf("%#02x,", cmd.buffer[i]); }
    // tcflush(gim_fd, TCOFLUSH);
    res = GIMBAL_PORT_WRITE(cmd.buffer, cmd.length + GIMBAL_FRAME_MIN_SIZE, gim_fd);
    printf("set angle: %f res :%d\n", angle, res);
}
#else
/*****************************************************************
 * 函数描述：波控角度和信道设置
 * 参数：	  int angle  波控角度值
 * 		  uint8_t channel	信道
 * 返回值：  设置结果 	0 设置正确
 * 					其他 设置失败
 ****************************************************************/
int gimbal_set_angle(int angle, uint8_t channel) {
    uint8_t sendbuf[128];
    int     res = 0, calres = 0, num = 0;
    float   curfreq = 0;
    DBFARG  tdbf;
    if (channel > 14)  // 5G
    {
        tdbf.channel = CHNAN_58FLAG;
    } else {
        tdbf.channel = CHNAN_24FLAG;
    }
    tdbf.synflag = 0xaa;
    res          = calformula1(angle, &calres);
    if (res < 0) return -1;
    tdbf.calformula1[2] = calres & 0xff;
    tdbf.calformula1[1] = calres >> 8 & 0xff;
    tdbf.calformula1[0] = calres >> 16 & 0xff;
    printf("send %#x %#x %f\n", calres, (calres >> 24 & 0xff), 2.45 * (2 << 12));
    tdbf.calformula2[0] = 0;
    tdbf.calformula2[1] = 0;
    tdbf.calformula2[2] = 0;
    if (tdbf.channel == CHNAN_24FLAG) {
        curfreq = FREQ24BASE + (channel - 1) * 0.005;
    } else if (tdbf.channel == CHNAN_58FLAG) {
        num = sizeof(g_charry) / sizeof(g_charry[0]);
        for (int i = 0; i < num; i++) {
            if (channel == g_charry[i].channel) {
                curfreq = g_charry[i].ffreq;
                break;
            }
        }
        if (curfreq == 0) return -1;
    }
    tdbf.freq[0] = ((int) (curfreq * (2 << 11)) >> 8) & 0xff;
    tdbf.freq[1] = (int) (curfreq * (2 << 11)) & 0xff;
    tdbf.status  = 0;
    // res=GIMBAL_PORT_WRITE((uint8_t*)&tdbf, sizeof(tdbf),gim_fd);
    sendbuf[0] = 0xf2;
    memcpy(sendbuf + 1, (uint8_t *) &tdbf, sizeof(tdbf));
    for (int i = 0; i < sizeof(tdbf) + 1; i++) { printf("%#02x,", sendbuf[i]); }
    printf("\n");
    res = write(gim_fd, sendbuf, sizeof(tdbf) + 1);
    printf("set angle: %d freq %f send len %d fd %d\n", angle, curfreq, res, gim_fd);
    return res;
}
#endif
/*****************************************************************
 * 函数描述：波束控制异常处理报告
 * 参数： float angle	转台角度
 * 		int chl
 * 返回值：   无
 ****************************************************************/
void gimbal_bsabort_send(float angle, int chl) {
    char souree_buf[256];
    memset(souree_buf, 0, sizeof(souree_buf));
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "type", "CtrlAborted");
    cJSON_AddNumberToObject(resp, "sn", DeviceSN);
    cJSON_AddStringToObject(resp, "source", "波束控制");
    cJSON_AddStringToObject(resp, "name", "波束控制异常");
    sprintf(souree_buf, "波束控制%d度,信道%d异常，未收到应答，请检查", (int) angle, chl);
    cJSON_AddStringToObject(resp, "detail", souree_buf);
    cJSON_AddNumberToObject(resp, "alertLevelNo", Abort_Level2);
    char *pdata = cJSON_Print(resp);
    mqtt_publish_msg(MQTT_TOPIC_FAIL, (uint8_t *) pdata, strlen(pdata));
    cJSON_Delete(resp);
}

/*****************************************************************
 * 函数描述：转台速率设置
 * 参数：	  uint8_t speed 转台速率值
 * 返回值：  无
 ****************************************************************/
void gimbal_set_speed(uint8_t speed) {
    gimbal_packet_t cmd;

    serial_flush(gim_fd);
    cmd.head               = GIMBAL_FRAME_HEAD;
    *(uint32_t *) cmd.ctrl = GIMBAL_FRAME_CTRL_VAL;
    cmd.type               = GIMBAL_FRAME_TYPE_CONF;
    cmd.length             = 3;
    cmd.payload[0]         = GIMBAL_CMD_SET_SPEED;
    cmd.payload[1]         = GIMBAL_CMD_SET_HORIZON;
    cmd.payload[2]         = speed;
    cmd.payload[3]         = gimbal_cal_chk(&cmd);
    GIMBAL_PORT_WRITE(cmd.buffer, 3 + GIMBAL_FRAME_MIN_SIZE, gim_fd);
    printf("set speed: %d\n", speed);
}
/*****************************************************************
 * 函数描述：转台状态设置
 * 参数：	  gimbal_packet_t * 转台数据结构指针
 * 返回值：  无
 ****************************************************************/
void gimabl_status_set(gimbal_packet_t *packet) {
    float cur_angel;
    if (!packet) {
        printf("packet is NULL\n");
        return;
    }
    uint8_t ucchk = packet->payload[packet->length];
    if (ucchk != gimbal_cal_chk(packet)) {
        printf("gimbal crc is error %#02x %#02x\n", ucchk, gimbal_cal_chk(packet));
        return;
    }
    if (gim_set_res.settype != packet->type) {
        // printf("gimbal type is %#02x, but packet type is %#02x\n",gim_set_res.settype,packet->type);
        return;
    }
    switch (packet->type) {
        case GIMBAL_FRAME_TYPE_CTRL:
            if (packet->payload[1] == GIMBAL_CTRL_OK) { gim_set_res.recflag = 1; }
            break;
        case GIMBAL_FRAME_TYPE_CONF:
            if (packet->payload[1] == GIMBAL_SPEED_OK) { gim_set_res.recflag = 1; }
            printf("gimbal type payload is %d\n", packet->payload[1]);
            break;
        case GIMBAL_FRAME_TYPE_RST:
            if (packet->payload[0] == GIMBAL_CTRL_OK) { gim_set_res.recflag = 1; }
            break;
        case GIMBAL_FRAME_TYPE_QUERY:
            if (gim_set_res.setflag == 1) {
                cur_angel = *((float *) (packet->payload + 7));
                cur_angel -= gim_set_res.angle;
                if (cur_angel < 1 && cur_angel > -1) {
                    gim_set_res.recflag = 1;
                    gim_set_res.setflag = 0;
                }
                printf("cur angle %f flag %d\n", cur_angel, gim_set_res.recflag);
            }
            break;
        default: break;
    }
}
/*****************************************************************
 * 函数描述：转台状态查询
 * 参数：	  uint8_t uctype  查询类型
 * 		  int count 等待超时次数
 * 		  int timeout 超时时间 ms
 * 返回值：  状态查询结果
 * 		   0    状态查询完成
 * 		  -1    状态查询未完成
 * 		  -2	状态查询异常
 ****************************************************************/
int gimabl_status_parse(uint8_t uctype, int count, int timeout) {
    int mstime = timeout * 1000;
    count += 1;
    while (count--) {
        if (gim_set_res.settype == uctype) {
            switch (uctype) {
                case GIMBAL_FRAME_TYPE_CTRL:
                case GIMBAL_FRAME_TYPE_CONF:
                case GIMBAL_FRAME_TYPE_RST:
                case GIMBAL_FRAME_TYPE_QUERY:
                    if (gim_set_res.recflag == 1) {
                        printf("recv status is ok %d\n", count);
                        return 0;
                    }
                    break;
                default: return -2; break;
            }
        } else {
            return -2;
        }
        if (count > 0) { usleep(mstime); }
    }
    return -1;
}
/*****************************************************************
 * 函数描述：串口初始化函数
 * 参数：	  无
 * 返回值：  无
 ****************************************************************/
void gimbal_init() {
#ifndef WSPY_CAR
    gim_fd = open("/dev/sx7045-i2c-4", O_RDWR);
    if (gim_fd < 0) {
        printf("can't i2c4 dev \r\n");
        return;
    }
#else
    gim_fd = serial_open("/dev/ttyS0", 9600, 8, 1, 'N', 1);
#endif
}
/*****************************************************************
 * 函数描述：转台异常处理报告
 * 参数：	   int type  转台控制类型
 * 		   float angle	转台角度
 * 返回值：   无
 ****************************************************************/
void gimbal_abort_send(int type, float angle) {
    char souree_buf[256];

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "type", "CtrlAborted");
    cJSON_AddNumberToObject(resp, "sn", DeviceSN);
    cJSON_AddStringToObject(resp, "source", "转台控制");
    switch (type) {
        case GIMBAL_FRAME_TYPE_CONF: {
            cJSON_AddStringToObject(resp, "name", "转台速率设置异常");
            cJSON_AddStringToObject(resp, "detail", "转台速率设置，未收到设置应答，请检查");
            cJSON_AddNumberToObject(resp, "alertLevelNo", Abort_Level4);
        } break;
        case GIMBAL_FRAME_TYPE_RST: {
            cJSON_AddStringToObject(resp, "name", "转台复位控制异常");
            cJSON_AddStringToObject(resp, "detail", "控制转台复位，未接收到复位应答，请检查");
            cJSON_AddNumberToObject(resp, "alertLevelNo", Abort_Level2);
        } break;
        case GIMBAL_FRAME_TYPE_CTRL: {
            cJSON_AddStringToObject(resp, "name", "转台角度控制异常");
            memset(souree_buf, 0, sizeof(souree_buf));
            sprintf(souree_buf, "控制转台转动%d度失败，未接收到转动应答，请检查", (int) angle);
            cJSON_AddStringToObject(resp, "detail", souree_buf);
            cJSON_AddNumberToObject(resp, "alertLevelNo", Abort_Level2);
        } break;
        default: {
            cJSON_AddStringToObject(resp, "name", "转台未知控制异常");
            cJSON_AddStringToObject(resp, "detail", "转台控制未知异常，请检查");
            cJSON_AddNumberToObject(resp, "alertLevelNo", Abort_Level3);
            break;
        }
    }
    char *pdata = cJSON_Print(resp);
    printf("%s\n", pdata);
    mqtt_publish_msg(MQTT_TOPIC_FAIL, (uint8_t *) pdata, strlen(pdata));
    cJSON_Delete(resp);
}
/*****************************************************************
 * 函数描述：转台初始化设置函数，设置转台转动速率及复位角度
 * 参数：	  无
 * 返回值：  无
 ****************************************************************/
void gimbal_init_set() {
    int res = 0;
    memset(&gim_set_res, 0, sizeof(gim_set_res));
    gim_set_res.settype = GIMBAL_FRAME_TYPE_CONF;
    gimbal_set_speed(2);
    res = gimabl_status_parse(GIMBAL_FRAME_TYPE_CONF, 3, 500);
    if (res != 0) { gimbal_abort_send(GIMBAL_FRAME_TYPE_CONF, 0); }
    //	gimbal_set_angle(150);
    //	sleep(20);
    memset(&gim_set_res, 0, sizeof(gim_set_res));
    gim_set_res.setflag = 1;
    gim_set_res.settype = GIMBAL_FRAME_TYPE_QUERY;
    gim_set_res.angle   = 180;
    sleep(2);
    res = gimabl_status_parse(GIMBAL_FRAME_TYPE_QUERY, 3, 500);
    memset(&gim_set_res, 0, sizeof(gim_set_res));
    printf("que sta %d\n", res);
    if (res != 0) {
        gim_set_res.settype = GIMBAL_FRAME_TYPE_RST;
        gim_set_res.angle   = 180;
        gimbal_reset();
        res = gimabl_status_parse(GIMBAL_FRAME_TYPE_RST, 30, 1000);
        if (res != 0) { gimbal_abort_send(GIMBAL_FRAME_TYPE_RST, 0); }
    }
#if 0
	while(1){
		for(int i=0;i<50;i+=10){
			gimbal_set_angle((float)i);
			sleep(5);
		}
		for(int i=50;i>-50;i-=10){
			gimbal_set_angle((float)i);
			sleep(5);
		}
		for(int i=-50;i<0;i+=10){
			gimbal_set_angle((float)i);
			sleep(5);
		}
	}
#endif
}
/*****************************************************************
 * 函数描述：串口线程读取函数
 * 参数：	  void *  线程参数
 * 返回值：  void *  线程运行返回结果
 ****************************************************************/
void *gimbal_thread(void *argv) {
    int              retval = 0, readsize = 0, alread = 0, packetlen = 0;
    fd_set           read_fds;
    gimbal_packet_t *read_packet = NULL;
    struct timeval   tv;
    uint8_t          readbuf[128];
    serial_flush(gim_fd);
    while (1) {
        memset(readbuf, 0, sizeof(readbuf));
        readsize   = 0;
        alread     = 9;
        tv.tv_sec  = 10;
        tv.tv_usec = 0;
        FD_ZERO(&read_fds);
        FD_SET(gim_fd, &read_fds);
        retval = select(gim_fd + 1, &read_fds, NULL, NULL, &tv);
        if (retval == -1) {
            printf("select error:\n");
            break;
        } else if (retval == 0) {
            // printf("select error2:\n");
            continue;
        } else {
            if (FD_ISSET(gim_fd, &read_fds)) {
#if 1
                readsize = read(gim_fd, readbuf, 9);
                if (readsize < 0) {
                    close(gim_fd);
                    FD_CLR(gim_fd, &read_fds);
                    printf("recv error:\n");
                    break;
                }
                if (readsize != 9) {
                    for (int i = 0; i < readsize; i++) { printf("%#02x,", read_packet->buffer[i]); }
                    printf("\n");
                    printf("read size not enough %d\n", readsize);
                    continue;
                }
                read_packet = (gimbal_packet_t *) (readbuf);
                if (read_packet->head != GIMBAL_FRAME_HEAD) {
                    printf("head error \n");
                    for (int i = 0; i < 9; i++) { printf("%#02x,", read_packet->buffer[i]); }
                    printf("\n");
                    continue;
                }
                if (read_packet->length > 0x23) {
                    printf("frame len too long %d \n", read_packet->length);
                    continue;
                }
                packetlen = read_packet->length + 1;
                while (packetlen > 0) {
                    readsize = read(gim_fd, readbuf + alread, packetlen);
                    alread += readsize;
                    packetlen -= readsize;
                }
                //				for(int i=0;i<read_packet->length+GIMBAL_FRAME_MIN_SIZE;i++){
                //					printf("%#02x,",read_packet->buffer[i]);
                //				}
                //				printf("\n");
                gimabl_status_set(read_packet);  //帧处理
//					if(readsize <9 &&frame_head==0){
//						printf("read size not %d\n",readsize);
//						break;
//					}
//					read_packet=(gimbal_packet_t *)(readbuf+alread);
//					if(read_packet->head !=GIMBAL_FRAME_HEAD && frame_head==0){
//						printf("head error \n");
//						for(int i=0;i<9;i++){
//							printf("%#02x,",read_packet->buffer[i]);
//						}
//						break;
//					}
//					if(read_packet->length > 0x23){
//						printf("body size error \n");
//						break;
//					}
//					gimabl_status_set(read_packet);
//					printf("recv size %d :",readsize);
//					for(int i=0;i<readsize;i++){
//						printf("%#02x,",read_packet->buffer[i]);
//					}
//					printf("\n");
//					alread+=(read_packet->length+GIMBAL_FRAME_MIN_SIZE);
//					readsize=readsize-read_packet->length-GIMBAL_FRAME_MIN_SIZE;
#endif
            }
        }
    }
    return NULL;
}
void gimbal_test(void) {
    int i;
    int j = 0;
    gimbal_init();
    for (;;) {
        for (i = 0; i <= 36; i++) {

            //        gimbal_set_angle((float)j);
            j += i * 10;
            //     gimbal_read_angle();
            sleep(2);
        }
        //        for (;i>-30;i--) {
        //            gimbal_set_angle((float)i);
        //        //    gimbal_read_angle();
        //            sleep(2);
        //        }
    }
}
