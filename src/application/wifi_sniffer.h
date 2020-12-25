/*****************************************************************************
 * @file: wlan_list.h
 * @author: andy.zhang
 * @email: zhangt@sinux.com.cn
 * @version: v0.1
 */
#ifndef __WIFI_CAPTURE_H
#define __WIFI_CAPTURE_H

#ifdef __cplusplus
 extern "C" {
#endif
#include <pthread.h>
#include "mac80211_fmt.h"
#include "common.h"

#define MAX_ANGLE	50  //最大探测角度
#define MIN_ANGLE 	-50	//最小探测角度
#define FIX_SCAN_TIME	2//固定角度扫描时间 20201124 modify by lpz
extern bool PcapOn[];
extern pthread_mutex_t g_tscanpolicy_mutex;
extern pthread_mutex_t g_tchl_mutex[];
extern pthread_mutex_t g_wlanlist_mutex;
extern char PcapInterface[IEEE80211BANDS][WDEVNAME_LEN];

#define NET2G4MAJIDX	0 //2.4G主网卡序号
#define NET5G8MAJIDX	1 //5.8G主网卡序号

 /*****************************************************************************
 * Macro
 */
typedef struct {
    uint8_t it_version;
    uint8_t it_pad;
    uint16_t it_len;
    uint32_t it_present;
}__attribute__((packed)) radiotap_head_t;

typedef struct {
    uint32_t timestamp;
    uint32_t timestamp_us;
    uint8_t radio_flags;
    uint8_t data_rate;
    uint16_t frequency;
    uint16_t chann_flags;
    int8_t signal;
    int8_t noise;
    uint16_t rx_flags;
    uint8_t vendor[12];
}__attribute__((packed)) radiotap_data_t;
typedef struct {
	uint32_t magic;
	uint16_t major;
	uint16_t minor;
	uint32_t thiszone;
	uint32_t sigfig;
	uint32_t snaplen;
	uint32_t linktype;
}__attribute__((packed)) pcapfilehead_t;
/*****************************************************************************
 * Type
 */

#if 1
struct scan_policy {
	struct{
		int16_t start;
		int16_t end;
		int16_t step;
	} angle;
	struct {
		uint8_t cnt;
		uint8_t table[36];
	} channel[IEEE80211BANDS];
	uint8_t cycle_period;
	bool repeat[IEEE80211BANDS];
	bool enable[IEEE80211BANDS];
};
#else
struct scan_policy {
    struct {
        struct {
            int8_t start;
            int8_t end;
            uint8_t step;
        } angle;

        struct {
            uint8_t cnt;
            uint8_t table[14];
        } channel;
    
        uint8_t cycle_period;
        bool repeat;
        bool enable;
    } band_2_4g;

    struct {
        struct {
            uint8_t start;
            uint8_t end;
            uint8_t step;
        } angle;

        struct {
            uint8_t cnt;
            uint8_t table[36];
        } channel;
    
        uint8_t cycle_period;
        bool repeat;
        bool enable;
    } band_5_8g;
};
#endif

typedef struct {									//统计错包率
	uint32_t totalcount;
	uint32_t  errcount;
}MACPACK_COUNT;
//加密方式
#define STD_OPN	0x1
#define STD_WEP	0x2
#define STD_WPA	0x4
#define STD_WPA2 0x8
//协议类型
#define IEEE80211B	0x1
#define IEEE80211G	0x2
#define IEEE80211N	0x4
#define IEEE80211A	0x8
#define IEEE80211AC	0x10

//可选字段
#define TAG_VENDOR		0xdd
#define TAG_RSN			0x30
#define TAG_SUPPORT		0x01
#define TAG_SUPPORTEXT  0x32
#define TAG_HTCAP		0x2d
#define TAG_VHTCAP		0xbf
#define TAG_CHAN		0x3

//有效信道 起始
#define CHANNEL2G4_START	1
#define CHANNEL2G4_STOP		14
#define CHANNEL5G8_START	36
#define CHANNEL5G8_STOP		196
#define FREQ2G4_START		2412 //2.4g信道起始
//自定义帧类型
typedef enum{
	MACINFO_INVALID_TYPE=0,
	MACINFO_BEACORRES, //
	MACINFO_DATA
}MACINFOENUM;

#ifdef WSPY_CAR
#define MIN_SCAN_PERIOD 4
#else
#define MIN_SCAN_PERIOD	2//最小扫描周期
#endif
/*****************************************************************************
 * Declare
 */
//extern bool PcapOn[IEEE80211BANDS];
extern struct scan_policy ScanPolicy;
extern MACPACK_COUNT PacketCount[IEEE80211BANDS];
void start_sniffer(void);
void stop_sniffer(void);
extern uint8_t g_curchl[IEEE80211BANDS];
/*****************************************************************
 * 函数描述：扫描策略执行函数
 * 参数：	  void *arg 扫描通道
 * 返回值： 无
 * ***************************************************************/
void wifi_scan_policy(void *arg);
/*****************************************************************
 * 函数描述：循环抓包处理函数
 * 参数： void *arg 抓包通道
 * 返回值： 无
 * ***************************************************************/
void capture_loop(void *arg);
/*****************************************************************
 * 函数描述：探测信息上传函数，用于将链表格式化后的信息上传到上位机
 * 参数： uint32_t timeout 延时时间
 * 		 uint8_t ucchl 通道
 * 返回值： 无
 * ***************************************************************/
void sniffer_msg_push(uint32_t timeout,uint8_t ucchl);
void sniffer_upload_test(void);
/*****************************************************************
 * 函数描述：检查mac地址函数，用于检查mac地址有效性
 * 参数：	  const uint8_t * addr 输入检查
 * 返回值： bool false mac 地址无效
 * 			    true  mac 地址有效
 * ***************************************************************/
bool is_phy_addr_availible(const uint8_t * addr);
#ifdef __cplusplus
 }
#endif

#endif //__WIFI_CAPTURE_H
