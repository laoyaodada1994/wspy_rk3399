/*
 * wifi_trojan.h
 *
 *  Created on: 2020-7-12
 *      Author: andy
 */

#ifndef WIFI_TROJAN_H_
#define WIFI_TROJAN_H_
#include <stdint.h>
#include <stdio.h>
#include "common.h"
#include "cJSON.h"
#include "wifi_sniffer.h"
typedef struct url_data{
	uint8_t uc_urlsniffer_flag;
	char id_str[128];
}Url_Sniffer_Data;
extern Url_Sniffer_Data g_turl_data;

struct intercept_info {
    char staMac[128];
    char imei[128];
    char imsi[128];
    char tel[128];
    char os[128];
    char ver[128];
};
/*****************************************************************
 * 函数描述: 植入操作
 * 参数：    cJSON* ap ap植入的参数，
 * 			cJSON* sta sta植入的参数
 * 			CJSON* para 植入文件的参数
 * 			uint8_t op_code 1 开始植入
 * 							其他 停止植入
 * 返回值：  无
 * ***************************************************************/
void start_stojan(cJSON* ap,cJSON* sta,cJSON* para,uint8_t op_code);
/*****************************************************************
* 函数描述: 截获操作
* 参数：    无
* 返回值：  无
****************************************************************/
void url_sniffer_parse();
/*****************************************************************
* 函数描述: arp欺骗操作
* 参数：    cJSON* ap ap json 参数
* 		   cJSON* sta  sta json 参数
* 		   uint8_t op_code 1 开始植入
* 							其他 停止植入
* 返回值：  无
****************************************************************/
void start_arp_op(cJSON* ap,cJSON* sta,uint8_t op_code);
/*****************************************************************
* 函数描述: 截获操作
* 参数：     cJSON* ap ap截获的参数，
* 			cJSON* sta sta截获的参数
* 			CJSON* para 截获id的参数
* 			uint8_t op_code 1 开始截获
* 							其他 停止截获
* 返回值：  无
****************************************************************/
void start_url_sniffer(cJSON* ap,cJSON* sta,cJSON* id,uint8_t op_code);
#endif /* WIFI_TROJAN_H_ */
