/*****************************************************************************
 * @file: wifi_access.h
 * @author: andy.zhang
 * @email: zhangt@sinux.com.cn
 * @version: v0.1
 */
#ifndef __WIFI_ACCESS_H
#define __WIFI_ACCESS_H

#ifdef __cplusplus
 extern "C" {
#endif

/*****************************************************************************
 * Macro
 */


 enum{
 	ACCESS_MODE_INVALID=0,
 	ACCESS_MODE_AP,
 	ACCESS_MODE_STA,
 	ACCESS_MODE_EXIT,
 	ACCESS_MODE_AP_SUCC,
 	ACCESS_MODE_STA_SUCC,
	ACCESS_MODE_MONITOR
 };


/*****************************************************************************
 * Type
 */

 struct wifi_access{
	uint8_t mode;	//ap or station
	uint8_t hwmode;	//protocol type
	uint8_t band;
	uint16_t channel;
	int16_t angle;
	uint8_t ap_mac[6];
	uint8_t sta_mac[6];
};
 typedef struct {
	 char cdev[10];
	 char amac[20];
 }WSPY_ACESS;
extern WSPY_ACESS g_acess_node;
extern struct wifi_access WifiAccess;
extern int g_acesstimeout;
extern char default_gw_ip[32];
/*****************************************************************
 * 函数描述：作为ap吸附状态检测函数
 * 参数：	  无
 * 返回值： 0：吸附成功
 * 		   1：吸附失败
 * ***************************************************************/
int  ap_acess_report();
/*****************************************************************************
 * Declare
 */
/*****************************************************************
* 函数描述：接入字段解析函数，JSON字串解析
* 参数：cJSON* param JSON格式串缓存指针
* 		char* runmode 运行模式 "sta","ap"
* 返回值： 解析结果
* ***************************************************************/
int wifi_access_ap_policy_parse(cJSON* param,char * runmode);
/*****************************************************************
 * 函数描述：停止接入及吸附
 * 参数：cJSON* param JSON格式串缓存指针
 * 		char* runmode 运行模式 "sta","ap"
 * 返回值： 无
 * ***************************************************************/
void wifi_stop_acess();
/*****************************************************************
 * 函数描述：接入状态检测函数
 * 参数：int sockfd 网卡套接字描述符
 *
 * 返回值： 0 ：接入成功
 * 		   1：接入失败
 * ***************************************************************/
int  sta_acess_report(int);
#ifdef __cplusplus
 }
#endif

#endif //__WIFI_ACCESS_H
