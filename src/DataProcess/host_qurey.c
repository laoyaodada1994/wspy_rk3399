#include <stdio.h>
#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <MQTTAsync.h>
#include "cJSON.h"
#include "MqttProcess.h"
#include "script.h"
#include "status.h"
#include "wifi_sniffer.h"
/***********************************************************************************
 *                                  Declare
 ***********************************************************************************/
/*****************************************************************
* 函数描述：控制下发主题协议解析函数，解析上位机的下发的控制协议并执行动作
* 参数：cJSON * root json 缓存指针
* 返回值： int	0 解析成功
* 				其他 解析失败
****************************************************************/
extern int topic_controldown_handle(cJSON * root);
extern uint32_t DeviceSN;
extern const char * FirmwareVersion;
/***********************************************************************************
 *                                  Variable
 ***********************************************************************************/


/***********************************************************************************
 *                                  Function
 ***********************************************************************************/

void print_json(cJSON * root)
{
    if (!root)
        return;
    char * str;
    str = cJSON_Print(root);
	printf("%s\n", str);
}
/*****************************************************************
* 函数描述：查询主题协议解析函数，解析上位机的下发的查询协议并执行动作
* 参数：cJSON * root json 缓存指针
* 返回值： int	0 解析成功
* 				其他 解析失败
****************************************************************/
int topic_querydown_handle(cJSON * root)
{
	cJSON * params=NULL, * obj=NULL;
    char tmp_str[32];
    // PublishFlag = 1;
    char publish_msg[1024];
    char *strtail = publish_msg;
#if 0
    print_json(root);
    resp = cJSON_CreateObject();
    cJSON_AddNumberToObject(resp, "sn", DeviceSN);
    params = cJSON_GetObjectItem(root, "params");
    if (params == NULL) 
        goto query_resp;

    obj = cJSON_GetObjectItem(root, "sid");
    if (obj != NULL) 
        cJSON_AddNumberToObject(resp, "sid", obj->valueint);

    resp_param = cJSON_CreateObject();
    cJSON_AddItemToObject(resp, "params", resp_param);
    if (cJSON_GetObjectItem(params, "ver") != NULL) {
        cJSON_AddStringToObject(resp_param, "ver", FirmwareVersion);
    }

    if (cJSON_GetObjectItem(params, "ip") != NULL) {
        get_local_ip(tmp_str);
        cJSON_AddStringToObject(resp_param, "ip", tmp_str);
    }
    if (cJSON_GetObjectItem(params, "net") != NULL) {
        cJSON_AddStringToObject(resp_param, "net", "以太网");
    }
    if (cJSON_GetObjectItem(params, "status") != NULL) {
    	get_dev_status(tmp_str);
        cJSON_AddStringToObject(resp_param, "status", tmp_str);
    }

    if (cJSON_GetObjectItem(params, "channel") != NULL) {
    	get_dev_channel(tmp_str);
        cJSON_AddStringToObject(resp_param, "channel", tmp_str);
    }

    if (cJSON_GetObjectItem(params, "protocol") != NULL) {
    	get_dev_hwmode(tmp_str);
        cJSON_AddStringToObject(resp_param, "protocol", tmp_str);
    }
    if (cJSON_GetObjectItem(params, "bandwidth") != NULL) {
    	get_dev_htmode(tmp_str);
        cJSON_AddStringToObject(resp_param, "bandwidth", tmp_str);
    }
    if (cJSON_GetObjectItem(params, "mode") != NULL) {
    	get_dev_mode(tmp_str);
        cJSON_AddStringToObject(resp_param, "mode", tmp_str);
    }
    if (cJSON_GetObjectItem(params, "cpu") != NULL) {
        get_cpu_occupy(tmp_str);
        cJSON_AddStringToObject(resp_param, "cpu", tmp_str);
    }
    if (cJSON_GetObjectItem(params, "mem") != NULL) {
    	get_mem_occupy(tmp_str);
        cJSON_AddStringToObject(resp_param, "mem", tmp_str);
    }
    if (cJSON_GetObjectItem(params, "disk") != NULL) {
       // get_mem_occupy(tmp_str);
    	get_disk_occupy(tmp_str);
        cJSON_AddStringToObject(resp_param, "disk", tmp_str);
    }

query_resp:
	pdata=cJSON_Print(resp);
	printf("%s\n",pdata);
    mqtt_publish_msg(MQTT_TOPIC_QUERYUP,(uint8_t *)pdata,strlen(pdata) );
    printf("free resp--------1\n");
    cJSON_Delete(resp);
    printf("free resp--------2\n");
    resp=NULL;
    return 0;
#else
	params = cJSON_GetObjectItem(root, "params");
	if (params == NULL)
		return  -1;

	obj = cJSON_GetObjectItem(root, "sid");
	if (obj == NULL)
		return -1;
	strtail += sprintf(strtail, "{\"sn\": %u,", DeviceSN);
	strtail += sprintf(strtail, "\"sid\": %u,", (uint32_t)obj->valueint);
	strtail += sprintf(strtail, "\"params\": {");

	if (cJSON_GetObjectItem(params, "ver") != NULL)
	{
		strtail += sprintf(strtail, "\"ver\":\"%s\",", FirmwareVersion);
	}
	if (cJSON_GetObjectItem(params, "ip") != NULL)
	{
		get_local_ip(tmp_str);
		strtail += sprintf(strtail, "\"ip\":\"%s\",", tmp_str);
	}
	if (cJSON_GetObjectItem(params, "net") != NULL)
	{
		strtail += sprintf(strtail, "\"net\":\"%s\",", "以太网");
	}
    if (cJSON_GetObjectItem(params, "status") != NULL)
	{
    	get_dev_status(tmp_str);
		strtail += sprintf(strtail, "\"status\":\"%s\",", tmp_str);
	}
    if (cJSON_GetObjectItem(params, "channel") != NULL)
	{
    	get_dev_channel(tmp_str);
    	strtail += sprintf(strtail, "\"channel\":\"%s\",", tmp_str);
	}
    if (cJSON_GetObjectItem(params, "protocol") != NULL)
    {
	   strtail += sprintf(strtail, "\"protocol\":\"b/g/n,a/n/ac\",");
    }
    if (cJSON_GetObjectItem(params, "bandwidth") != NULL)
	{
    	get_dev_htmode(tmp_str);
    	strtail += sprintf(strtail, "\"bandwidth\":\"20,20\",");
	}
    if (cJSON_GetObjectItem(params, "mode") != NULL)
	{
    	get_dev_mode(tmp_str);
		strtail += sprintf(strtail, "\"mode\":\"%s\",", tmp_str);
	}
	if (cJSON_GetObjectItem(params, "cpu") != NULL) {
		get_cpu_occupy(tmp_str);
		strtail += sprintf(strtail, "\"cpu\":\"%s\",", tmp_str);
	}
	if (cJSON_GetObjectItem(params, "mem") != NULL) {
		get_mem_occupy(tmp_str);
		strtail += sprintf(strtail, "\"mem\":\"%s\",", tmp_str);
	}
	if (cJSON_GetObjectItem(params, "disk") != NULL) {
	   // get_mem_occupy(tmp_str);
		get_disk_occupy(tmp_str);
		strtail += sprintf(strtail, "\"disk\":\"%s\",", tmp_str);
	}
	if (*(strtail - 1) == ',')
		strtail--;
	*strtail++ = '}'; // remove the last ","
	*strtail++ = '}';
	*strtail++ = '\0';
	printf("%s\n",publish_msg);
	mqtt_publish_msg(MQTT_TOPIC_QUERYUP,(uint8_t*) publish_msg,strlen(publish_msg));
#endif
	return 0;
}


/*************************************************************************
*函数描述：mqtt客户端连接函数，用于消息发布
*参数：	 char *json_string     接收的json数据
            
*返回值： int
*			 MQTTCLIENT_SUCCESS 0
*			 MQTTCLIENT_FAILURE -1
*************************************************************************/
int rxmsg_json_parse(const char * topic, const char * json)
{
	cJSON * obj, * rxroot=NULL;
	
    rxroot = cJSON_Parse(json);

	if (rxroot == NULL) {
		fprintf(stderr, "rx json msg parse error\n");
		return -1;
	}

    obj = cJSON_GetObjectItem(rxroot, "sn");
    if (obj == NULL
    ||  obj->valueint != DeviceSN
    ) {
        cJSON_Delete(rxroot);
        fprintf(stderr, "sn number is missing or incorrect\n");
        return -1;
    }

    if (!strcmp(topic, "queryDown")) {
    	if(Last_Json != json){
    		memset(Last_Json,0,strlen(Last_Json));
    		strcpy(Last_Json,json);
    	}
        topic_querydown_handle(rxroot);
    } 
    else if (!strcmp(topic, "controlDown")) {
    	//memset(Last_Json,0,strlen(Last_Json));
    	if(Last_Json != json){
    		memset(Last_Json,0,strlen(Last_Json));
    		strcpy(Last_Json,json);
    	}
        topic_controldown_handle(rxroot);
    } 
    printf("rxroot111\n");
    cJSON_Delete(rxroot);
    rxroot=NULL;
    printf("rxroot222\n");
   return 0;
}





