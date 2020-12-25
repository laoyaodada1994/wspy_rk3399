/*****************************************************************************
 * @file: mac80211_atk.h
 * @author: andy.zhang
 * @email: zhangt@sinux.com.cn
 * @version: v0.1
 */
#ifndef __MAC80211_ATK_H
#define __MAC80211_ATK_H

#ifdef __cplusplus
 extern "C" {
#endif
#include "cJSON.h"
#include "gimbal.h"
#define MUL_GR
/*****************************************************************************
 * Macro
 */
#define BROADCAST           ((uint8_t *)"\xFF\xFF\xFF\xFF\xFF\xFF")
#define ETH_P_ALL           0x0003
 struct DC_device
 {
     //char *iface_out;
 	char iface[64];
 	int iface_len;

     unsigned char s_bssid[6];
 	unsigned char a_bssid[6];
     int fd_out, arptype_out;

     unsigned char mac_in[6];
     unsigned char mac_out[6];

     int channel;
     int freq;
     int rate;
     int tx_power;

     unsigned char pl_mac[6];
 };
/*****************************************************************************
 * Type
 */
/*****************************************************************************
 * Declare
 */
int make_mac80211_deauth(const char * iface, uint8_t bssid[6], uint8_t sta[6]);
void mac80211_atk(void);

int deauth_atk(int argc, char** argv );

#define ATK24DEVCHL	2 //2.4G攻击网卡号
#define ATK58DEVCHL	3 //5.8G攻击网卡号

extern bool ApInter;
extern bool StaInter;
extern struct Atk_Info AtkInfo;
#define MAX_GZ_NUM 4 //最大攻击sta数目
enum{
	ATK_TAGET_NONE,
	ATK_TAGET_AP,
	ATK_TAGET_STA,
};

struct Atk_Info {
	uint8_t taget;
	uint16_t channel;
	int16_t	angle;
	uint8_t band;
	uint8_t sta_num; //攻击数目
#ifndef ZRRJ
	uint8_t ap_mac[6];
	uint8_t sta_mac[6];
#else
	char ap_mac[32];
#ifndef MUL_GR
	char sta_mac[32];
#else
	char sta_mac[MAX_GZ_NUM][32];
#endif
#endif
}zkinfo_str;
/*****************************************************************
 * 函数描述：开启ap广播压制线程
 * 参数：	   无
 * 返回值： 无
 * ***************************************************************/
void start_ap_inter(void);
/*****************************************************************
 * 函数描述：关闭ap广播压制线程
 * 参数：	   无
 * 返回值： 无
 * ***************************************************************/
void stop_ap_inter(void);
/*****************************************************************
 * 函数描述：压制、干扰策略解析函数，用于解析上位机发下来的策略并执行
 * 参数：	   cJSON* param_ap ap 信息json字串
 * 		   cJSON* param_sta sta信息json字串
 * 返回值： 解析结果  -1 错误
 * 					0 解析成功
 * ***************************************************************/
int wifi_atkpolicy_parse(cJSON* param_ap,cJSON* param_sta);
/*****************************************************************
 * 函数描述：deauth攻击包发送线程回调处理函数，用于发送deauth数据包
 * 参数：	   void *argv 发包参数
 * 返回值： 无
 * ***************************************************************/
void *do_deauth_atk(void *argv);
/*****************************************************************
 * 函数描述：开启sta压制线程
 * 参数：	   无
 * 返回值： 无
 * ***************************************************************/
void start_sta_inter(void);
/*****************************************************************
 * 函数描述：关闭sta压制线程
 * 参数：	   无
 * 返回值： 无
 * ***************************************************************/
void stop_sta_inter(void);
/*****************************************************************
* 函数描述：mac格式转换函数
* 参数：	  char * macAddress
*		  int strict 检查mac个数参数
*		  unsigned char * mac 输出的mac数值
* 返回值：  无
****************************************************************/
int getmac(char * macAddress, int strict, unsigned char * mac);
#ifdef __cplusplus
 }
#endif

#endif //__MAC80211_ATK_H
