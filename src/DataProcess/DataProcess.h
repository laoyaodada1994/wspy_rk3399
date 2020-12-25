/*
 * DataProcess.h
 *
 *  Created on: Jan 8, 2019
 *      Author: lpz
 */

#ifndef SRC_DATAPROCESS_DATAPROCESS_H_
#define SRC_DATAPROCESS_DATAPROCESS_H_
#include "cJSON.h"
#include "common.h"
typedef struct {
	char    clinet_id[32];
	char	ip[32];
	int 	port;
	uint32_t sn;
	float   longitude;
	float   latitude;
	char	user[32];
	char	password[32];
	char	localpath[128];
	char	applocalpath[128];
	uint8_t gps_disable;
	char	wlan_dev[4][64];
} json_rcv_config;

struct system_cfg {
	int 	sn;
	char 	svr_ip[32];
	char 	svr_port[32];
	char	usr_nm[32];
	char 	password[32];
};

extern json_rcv_config UserCfgJson;
/*****************************************************************
* 函数描述：文件存储，将缓存的json串写入本地文件
* 参数：	  cJSON* param json缓存指针
* 返回值：无
* ***************************************************************/
int save_configfile();
/*****************************************************************
* 函数描述：设置参数文件的经纬度
* 参数：	  cJSON* param json指针
* 		  char *setstr	需要修改的字符串
*		  float ftitude 需要修改的经纬度
* 返回值：无
****************************************************************/
void set_device(cJSON* param,char *setstr,float ftitude);
/*****************************************************************
* 函数描述：获取用户参数配置的json指针缓存
* 参数：	  无
* 返回值：	cJSON * json串配置
* ***************************************************************/
cJSON * get_json_config();
/*****************************************************************
* 函数描述：用户配置参数读取函数，读取需要设置的参数
* 参数：	  无
* 返回值：	0 读取正确
* 			其他 读取失败
* ***************************************************************/
int read_user_config();
/*****************************************************************
* 函数描述：server 参数解析函数，解析json文本中上位记通信参数
* 参数：	  cJSON* param json缓存指针
* 返回值：无
* ***************************************************************/
void parse_server(cJSON* param);
/*****************************************************************
* 函数描述：ftp 服务器参数解析函数，解析json文本中ftp通信参数
* 参数：	  cJSON* param json缓存指针
* 返回值：无
* ***************************************************************/
void parse_ftp(cJSON* param);
/*****************************************************************
* 函数描述：device 参数解析函数，解析json文本中设备信息参数
* 参数：	  cJSON* param json缓存指针
* 返回值：无
* ***************************************************************/
void parse_device(cJSON* param);
/*****************************************************************
* 函数描述：gps 参数解析函数
* 参数：	  cJSON* param json缓存指针
* 返回值：无
* ***************************************************************/
void parse_gps(cJSON* param);
/*****************************************************************
* 函数描述：wlan 网口参数解析函数
* 参数：	  cJSON* param json缓存指针
* 返回值：无
* ***************************************************************/
void parse_wlan(cJSON* param);
int ftpsget(char *cServerip ,char *user,char *password,char *ftpurl);
// void mqtt_publish_msg(const char * topic, const char * message);

#endif /* SRC_DATAPROCESS_DATAPROCESS_H_ */
