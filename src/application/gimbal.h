/*****************************************************************************
 * @file: gimbal.h
 * @author: andy.zhang
 * @email: zhangt@sinux.com.cn
 * @version: v0.1
 */
#ifndef __SNIFFER_H
#define __SNIFFER_H

#ifdef __cplusplus

#include
extern "C" {
#endif
#define MAX_SEC_ANGLE 10  //每秒转动最大角度
/*****************************************************************************
 * Macro
 */
#include <stdint.h>
/***************转台运动控制回传状态****************/
#define GIMBAL_CTRL_OK 0x2
#define GIMBAL_CTRL_RUN 0x1
#define GIMBAL_CTRL_ERR 0x3

/***************转台速度控制回传状态****************/
#define GIMBAL_SPEED_OK 0x1
#define GIMBAL_SPEED_FAIL 0x0

#define GIMBAL_BODY_MAXLEN 0x23
#define GIMBAL_FRAME_HEAD 0xFEFE
#define GIMBAL_FRAME_HEADER_SIZE (9)
#define GIMBAL_FRAME_MIN_SIZE (10)
#define GIMBAL_FRAME_CTRL_VAL (0x20000000)

#define GIMBAL_FRAME_TYPE_QUERY 0x01
#define GIMBAL_FRAME_TYPE_CTRL 0x02
#define GIMBAL_FRAME_TYPE_CONF 0x03
#define GIMBAL_FRAME_TYPE_CHK 0x04
#define GIMBAL_FRAME_TYPE_RST 0x05

#define GIMBAL_CMD_QUERY_STATUS 0x02
#define GIMBAL_CMD_SET_HORIZON 0x00
#define GIMBAL_CMD_SET_SPEED 0x01
#define GIMBAL_CMD_SET_ANGLE 0x03

#define GIMBAL_PORT_WRITE(pdata, len, fd) serial_write((pdata), (len), (fd))
#define GIMBAL_PORT_READ(buffer, len, fd) serial_read(buffer, len, (fd))
/*****************************************************************************
 * Type
 */
typedef union {
    uint8_t buffer[73];
    struct {
        uint16_t head;
        uint8_t  ctrl[4];
        uint8_t  sequence;
        uint8_t  type;
        uint8_t  length;
        uint8_t  payload[64];
    };
} gimbal_packet_t;

#pragma pack(push, 1)
typedef struct dbfarg {
    uint8_t synflag;
    uint8_t channel;
    int8_t  calformula1[3];
    int8_t  calformula2[3];
    uint8_t freq[2];
    uint8_t status;
} DBFARG;
#pragma pack(pop)

typedef struct {
    uint8_t  channel;
    float    ffreq;
    uint16_t lfreq;
} CHTOFREQ;

typedef struct gimbal_set {
    uint8_t setflag;
    uint8_t recflag;
    uint8_t settype;
    float   angle;
} GIM_SET_RES;
extern CHTOFREQ    g_charry[];
extern int         g_chl5g_num;
extern GIM_SET_RES gim_set_res;
/*****************************************************************************
 * Decalre
 */
/*****************************************************************
 * 函数描述：车载转台复位操作
 * 参数：无
 * 返回值： 无
 * ***************************************************************/
void gimbal_reset();
#ifdef WSPY_CAR
void gimbal_set_angle(float angle);
#else
/*****************************************************************
 * 函数描述：波控角度和信道设置
 * 参数：	  int angle  波控角度值
 * 		  uint8_t channel	信道
 * 返回值：  设置结果 	0 设置正确
 * 					其他 设置失败
 ****************************************************************/
int gimbal_set_angle(int angle, uint8_t channel);
#endif
float gimbal_read_angle(void);
void  gimbal_test(void);
/*****************************************************************
 * 函数描述：转台速率设置
 * 参数：	  uint8_t speed 转台速率值
 * 返回值：  无
 ****************************************************************/
void gimbal_set_speed(uint8_t speed);

/*****************************************************************
 * 函数描述：串口初始化函数
 * 参数：	  无
 * 返回值：  无
 ****************************************************************/
void gimbal_init();
/*****************************************************************
 * 函数描述：串口线程读取函数
 * 参数：	  void *  线程参数
 * 返回值：  void *  线程运行返回结果
 ****************************************************************/
void *gimbal_thread(void *argv);
void  gimbal_check();
/*****************************************************************
 * 函数描述：转台状态设置
 * 参数：	  gimbal_packet_t * 转台数据结构指针
 * 返回值：  无
 ****************************************************************/
void gimabl_status_set(gimbal_packet_t *packet);
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
int gimabl_status_parse(uint8_t uctype, int count, int timeout);
/*****************************************************************
 * 函数描述：转台初始化设置函数，设置转台转动速率及复位角度
 * 参数：	  无
 * 返回值：  无
 ****************************************************************/
void gimbal_init_set();
/*****************************************************************
 * 函数描述：转台异常处理报告
 * 参数：	   int type  转台控制类型
 * 		   float angle	转台角度
 * 返回值：   无
 ****************************************************************/
void gimbal_abort_send(int type, float angle);
/*****************************************************************
 * 函数描述：波束控制异常处理报告
 * 参数： float angle	转台角度
 * 		int chl
 * 返回值：   无
 ****************************************************************/
void gimbal_bsabort_send(float angle, int chl);
#ifdef __cplusplus
}
#endif
#endif  //__SNIFFER_H
