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
#include <pthread.h>
#include <time.h>
#include <malloc.h>
#include <MQTTAsync.h>
#include "cJSON.h"
#include "common.h"
#include "gps.h"
#include "status.h"
#include "MqttProcess.h"
#include "host_query.h"
#include "script.h"
#include "wifi_sniffer.h"
#include "DataProcess.h"
//#include "./DataProcess/DataProcess.h"
WSPY_GPS wspy_gps;
pthread_mutex_t gps_staus_mutex;//扫描策略线程互斥锁
/***********************************************************************
 *                              Declare
 ***********************************************************************/
#define STATUS_STR_SIZE            512

struct sys_status {
    struct sys_status * pre;
    struct sys_status * next;
    struct sys_status * parent;
    struct sys_status * child;
    char  operate[512];
    char  status[512];
};

static struct sys_status * ListHead = NULL;
static int ListSize = 0;

static char Last_Status[512];
char Last_Json[512];
/***********************************************************************
 *                              Variable
 ***********************************************************************/
bool StatusQueryEvtOn = false;

/***********************************************************************
 *                              Function
 ***********************************************************************/
/*****************************************************************
* 函数描述：状态节点获取函数，根据输入操作字串，筛选出对应节点
* 参数：	  const char * operate 状态操作字串
* 返回值： struct sys_status * 状态结构缓存指针
****************************************************************/
struct sys_status * status_node(const char * operate)
{
    struct sys_status * walk = ListHead;

    while (walk != NULL) {
        if (strcmp(walk->operate, operate) == 0) 
            return walk;
        walk = walk->next;
    }

    return NULL;
}
/*****************************************************************
* 函数描述：状态更新函数，用于更新指定操作的节点状态
* 参数：	  const char * operate 状态操作字串
* 		  const char * status  要更新的状态值
* 		  const char * parent_status 父节点状态
* 返回值：  int  			0 更新成功
* 						其他 更新失败
****************************************************************/
int update_status(const char * operate, const char * status, const char * parent_status)
{
    struct sys_status ** walk;
    struct sys_status * parent = NULL;

    if (parent_status != NULL) {
        parent = status_node(parent_status);
        if (parent == NULL) {
            fprintf(stderr, "can not find the parent status\n");
            return -1;
        }
    }

    walk = &ListHead;
    while ((*walk) != NULL) {
        if (strcmp((*walk)->operate, operate) == 0) {
           // (*walk)->status = status;
            strcpy((*walk)->status,status);
            if (parent != NULL) {
                (*walk)->parent = parent;
                (*walk)->parent->child = (*walk);
            }
            printf("update status: %s-%s\n", (*walk)->operate, (*walk)->status);
            return 0;
        }
        walk = &(*walk)->next;
    }
    
    *walk = (struct sys_status *)malloc(sizeof(struct sys_status));
   // (*walk)->operate = operate;
  //  (*walk)->status = status;
    strcpy((*walk)->operate,operate);
    strcpy((*walk)->status,status);
    (*walk)->next = NULL;
    (*walk)->pre = container_of(walk, struct sys_status, next);
    (*walk)->child = NULL;
    if (parent != NULL) {
        (*walk)->parent = parent;
        (*walk)->parent->child = (*walk);
    }
    else {
        (*walk)->parent = NULL;
    }
    ListSize++;
    printf("update status: %s-%s\n", (*walk)->operate, (*walk)->status);

    return 0;
}
/*****************************************************************
* 函数描述：状态节点删除函数，删除状态链表中指定的节点
* 参数：	  struct sys_status * node 要删除的节点
* 返回值：  无
****************************************************************/
static void remove_node(struct sys_status * node)
{
    if (node == ListHead) {
        ListHead = ListHead->next;
    }
    else {
        node->pre->next = node->next;
        if (node->next != NULL)
            node->next->pre = node->pre;
    }
    
    struct sys_status * walk = node;
    while (walk->child != NULL) {
    	//walk->child->status = "result-exit";
    	strcpy(walk->child->status,"result-exit");
        walk = node->child;
    }
    if (node->parent != NULL) {
        node->parent->child = node->child;
    }
    free(node);
    node = NULL;
    ListSize--;
}
/*****************************************************************
* 函数描述：链表状态读取函数，用于读取状态值，并生成json数据
* 参数：	  cJSON * parent json 缓存指针
* 返回值：  无
****************************************************************/
void traverse_status_list(cJSON * parent)//状态链表里面取出数据组成json数据
{
    cJSON * status;
    struct sys_status * node = ListHead;
    int size = ListSize;
    char coldsta[512];
    char *cstatus=NULL;
    if (node == NULL) {
//        const char * pstr[1];
//        pstr[0] = "null-status-idle";
//        status = cJSON_CreateStringArray(pstr, 1);
//        if(strcmp(pstr[0],Last_Status)){ //状态发生变化
//        	strcpy(Last_Status,pstr[0]);
//        	save_lasted_status(Last_Status,NULL);
//        }
    	return ;
    }
    else {
        char * pstr[size];
        for (int i=0;i<size;i++) {
            pstr[i] = (char *)malloc(STATUS_STR_SIZE);
            strcpy(pstr[i], node->operate);
            strcat(pstr[i], "-");
            if(strstr(node->status,"detail") != NULL){//是否有文件名细节
            	strcpy(coldsta,node->status);
            	cstatus=strtok(coldsta,"/");
            	strcat(pstr[i], cstatus);
            	cstatus=strtok(NULL,":");
            	cstatus=strtok(NULL,":");
            	cJSON_AddStringToObject(parent, "detail", cstatus);
            	printf("%s %d %s\n",__func__,__LINE__,cstatus);
            }
            else{
            	strcat(pstr[i], node->status);
            }
            if (strstr(node->status, "result") != NULL) {
                struct sys_status * next = node->next;
                remove_node(node);
                node = next;
            }
            else
                node = node->next;
        }
        if(strcmp(pstr[size -1],Last_Status)){
        	strcpy(Last_Status,pstr[size -1]);
        	save_lasted_status(Last_Status,Last_Json);
        }
        status = cJSON_CreateStringArray((const char **)pstr, size);
        for (int i=0;i<size;i++) {
        	printf("%s %d %s\n",__func__,__LINE__,pstr[i]);
        	free(pstr[i]);
        }

    }
	cJSON_AddItemToObject(parent, "status", status);
}


/*****************************************************************
* 函数描述：程序状态初始化配置，通过读取程序初始化的状态文件和参数，恢复上次程序运行的状态
* 参数： 无
* 返回值： int 0 初始成功
* 		   其他  初始状态恢复失败
* ***************************************************************/
int init_status()
{
	char *oprate = NULL;
	char tmp[64];
	memset(tmp,0,sizeof(tmp));

	get_lasted_status(Last_Status,Last_Json);
	if(strstr(Last_Status,"status-run") == NULL){
		return -1;
	}
	strncpy(tmp,Last_Status,strlen(Last_Status));
	oprate = strtok(tmp,"-");
	strcpy(tmp,oprate);
	if(strstr(oprate,"wifiScan") !=NULL && strstr(Last_Status,"wifiScan")!=NULL){
	}
	else if(strstr(oprate,"apAcess") !=NULL && strstr(Last_Status,"apAcess")!=NULL){
	}
	else if(strstr(oprate,"apInter") !=NULL && strstr(Last_Status,"apInter")!=NULL){
	}
	else if(strstr(oprate,"staInter") !=NULL && strstr(Last_Status,"staInter")!=NULL){
	}
	else {
		return -1;
	}
	rxmsg_json_parse("controlDown",Last_Json);
	return 0;
}
/*****************************************************************
* 函数描述：gps 状态上报函数，用于获取gps位置及组帧上报给mqtt服务器
* 参数： 无
* 返回值： 无
* ***************************************************************/
void gps_report(void)
{
	uint8_t ucmodify_flag=0;
	char cgpsbuf[128];
	float ftude=0.0;
	char cmd[64];
	cJSON *user_params=NULL;
	memset(cgpsbuf,0,sizeof(cgpsbuf));
	cJSON * root = cJSON_CreateObject();
	cJSON * use_conf=get_json_config();
    cJSON_AddNumberToObject(root, "sn", DeviceSN);

    //sys_get("uci get wspy.gps.disabled", cmd, sizeof(cmd));
    user_params = cJSON_GetObjectItem(use_conf, "device");
    if(user_params == NULL){
    	printf("conf parse error\n");
    }
	if (UserCfgJson.gps_disable == 1) {
		cJSON_AddStringToObject(root, LONGITUDE, "103.916529");//"103.916529")南京"118.792156";
		cJSON_AddStringToObject(root, LATITUDE, "30.763128");//"30.763128");南京"30.763128"
	}
	else {
		pthread_mutex_lock(&gps_staus_mutex);
		ftude =GPS_Data.longitude/100;
		if(ftude < 1){
			ftude = wspy_gps.longtitude;
		}
		else{
			if((ftude -1)> wspy_gps.longtitude ||(wspy_gps.longtitude -1) >ftude)
			{
				wspy_gps.longtitude=ftude;
				set_device(user_params,LONGITUDE,ftude);
				ucmodify_flag=1;
			}
		}
		sprintf(cgpsbuf,"%f",ftude);
		cJSON_AddStringToObject(root, LONGITUDE, cgpsbuf);//"103.916529");
		memset(cgpsbuf,0,sizeof(cgpsbuf));
		ftude=GPS_Data.latitude/100;
		if(ftude < 1){
				ftude = wspy_gps.latitude;
		}
		else{
			if((ftude -1)> wspy_gps.latitude ||(wspy_gps.latitude -1) >ftude)
			{
				wspy_gps.latitude=ftude;
				set_device(user_params,LATITUDE,ftude);
				ucmodify_flag=1;
			}
		}
		sprintf(cgpsbuf,"%f",ftude);
		cJSON_AddStringToObject(root,LATITUDE,cgpsbuf);//"30.763128");
		pthread_mutex_unlock(&gps_staus_mutex);
		if(ucmodify_flag == 1){
			save_configfile(); //修改后的精度写回文件
		}
	}
    cJSON_AddNumberToObject(root, "heading", 0);//head是啥
    char *pdata=cJSON_Print(root);
    mqtt_publish_msg("gps", (uint8_t *)pdata,strlen(pdata));
    cJSON_Delete(root);
}
/*****************************************************************
* 函数描述：状态上报函数，用于组帧上报设备状态
* 参数： 无
* 返回值： 无
* ***************************************************************/
void status_report(void)
{
	cJSON * root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "sn", DeviceSN);
    cJSON_AddStringToObject(root, "mode", "monitor");
    // get_system_status(root);
    traverse_status_list(root);
    char *pdata= cJSON_Print(root);
    mqtt_publish_msg("status", (uint8_t *)pdata,strlen(pdata));
	//printf("%s\n",cJSON_Print(root));
    cJSON_Delete(root);
}
/*****************************************************************
* 函数描述：文件传输函数，用于传输握手包数据到mqtt服务器
* 参数： uint8_t *data	数据缓存指针
* 		uint16_t data_len 数据缓存长度
* 返回值： 无
* ***************************************************************/
void trans_file( uint8_t *data, uint16_t data_len)
{
	if ((data == NULL) && (data_len > 5000))
		return;
	mqtt_publish_msg("decrypt", data, data_len);
}
/*****************************************************************
* 函数描述：打开红色led灯
* 参数： 无
* 返回值： 无
* ***************************************************************/
void red_led_on(void)
{
    system("echo 1 > /sys/class/leds/sata_led/brightness");
}
/*****************************************************************
* 函数描述：关闭红色led灯
* 参数： 无
* 返回值： 无
* ***************************************************************/
void red_led_off(void)
{
    system("echo 0 > /sys/class/leds/sata_led/brightness");
}
/*****************************************************************
* 函数描述：打开绿色led灯
* 参数： 无
* 返回值： 无
* ***************************************************************/
void green_led_on(void)
{
    system("echo 1 > /sys/class/leds/led_usb1/brightness");
}
/*****************************************************************
* 函数描述：led绿灯关闭函数，控制关闭车载机箱led灯
* 参数： 		无
* 返回值： 	无
* ***************************************************************/
void green_led_off(void)
{
    system("echo 0 > /sys/class/leds/led_usb1/brightness");
}
