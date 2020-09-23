#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include "common.h"
#include "cJSON.h"
#include "wifi_sniffer.h"
#include "wifi_access.h"
#include "mac80211_atk.h"
#include "status.h"
#include "DataProcess.h"
#include "script.h"
/***********************************************************************************
 *                                  Declare
 ***********************************************************************************/
struct wifi_access WifiAccess;

WSPY_ACESS g_acess_node;
int g_acesstimeout=0;

/***********************************************************************************
 *                                  Variable
 ***********************************************************************************/


/***********************************************************************************
 *                                  Function
 ***********************************************************************************/


/*****************************************************************
 * 函数描述：作为ap吸附状态检测函数
 * 参数：	  无
 * 返回值： 0 ：吸附成功
 * 		   1：吸附失败
 * ***************************************************************/
int  ap_acess_report()
{
	 char iwinfo[256];
	 char cmdinfo[1024];
#if 0
	 char client_mac[64];
	 sprintf(client_mac,"%02x:%02x:%02x:%02x:%02x:%02x",WifiAccess.sta_mac[0],
			 WifiAccess.sta_mac[1],WifiAccess.sta_mac[2],WifiAccess.sta_mac[3],
			 WifiAccess.sta_mac[4],WifiAccess.sta_mac[5]);
	 printf("%s %d %s\n",__func__,__LINE__,client_mac);
	 sprintf(cmdinfo,"cat /tmp/dhcp.leases |grep -i \"%s\"",client_mac);
	 sys_get(cmdinfo, iwinfo, sizeof(iwinfo));
	 printf("%s\n",iwinfo);
	 if(strstr(iwinfo,client_mac) == NULL){
		 return 1;
	 }
	 else{
#endif
#ifdef ZRRJ
		 sprintf(cmdinfo,"connect_sta_status %s %02x-%02x-%02x-%02x-%02x-%02x",UserCfgJson.wlan_dev[WifiAccess.band],WifiAccess.sta_mac[0],
				 WifiAccess.sta_mac[1],WifiAccess.sta_mac[2],WifiAccess.sta_mac[3],
				 WifiAccess.sta_mac[4],WifiAccess.sta_mac[5]);
		 system(cmdinfo);
		 sprintf(cmdinfo,"cat /tmp/connect_sta_status.res");
		 sys_get(cmdinfo, iwinfo, sizeof(iwinfo));
		 if(strstr(iwinfo,"0400") == NULL){
			 return 1;
		 }
		 else{
			 return 0;
		 }
#else
		 return 0;
#endif
	// }
	 return 0;
}
/*****************************************************************
 * 函数描述：作为客户端接入状态检测函数
 * 参数：int sockfd 网卡套接字描述符
 *
 * 返回值： 0 ：接入成功
 * 		   1 ：接入失败
 * ***************************************************************/
int  sta_acess_report(int sockfd)
{
	char cmdbuf[128];
	char ip[32];
#if 0
	 char iwinfo[256];
	 char cmdinfo[128];

	 memset(iwinfo,0,sizeof(iwinfo));
	 memset(cmdinfo,0,sizeof(cmdinfo));
	 sprintf(cmdinfo,"ifconfig %s|grep \"inet addr\"",g_acess_node.cdev);
	 printf("%s %d %s\n",__func__,__LINE__,cmdinfo);
//	 sprintf(cmdinfo,"iwconfig %s|grep -i %02x:%02x:%02x:%02x:02x:02x",g_acess_node.cdev,
//			 g_acess_node.amac[0], g_acess_node.amac[1], g_acess_node.amac[2],
//			 g_acess_node.amac[3],g_acess_node.amac[4],g_acess_node.amac[5]);
	 sys_get(cmdinfo, iwinfo, sizeof(iwinfo));
	 printf("%s %d %s\n",__func__,__LINE__,iwinfo);
	 if(strstr(iwinfo,"inet addr") == NULL){
		 return 1;
	 }
	 else{
		 return 0;
	 }
#else
	 struct sockaddr_in sin;
	 struct ifreq ifr;
	 int err=0;
#if 0
	 strncpy(ifr.ifr_name, g_acess_node.cdev,IFNAMSIZ);
#else
	 sprintf(ifr.ifr_name,"%s",UserCfgJson.wlan_dev[WifiAccess.band]);
#endif

	 printf("ifrname %s\n",ifr.ifr_name);
	 if(ioctl(sockfd,SIOCGIFADDR,&ifr) <0){
		 printf("ioctl  error :%s\n",strerror(err));
		 return 1;
	 }


	 memset(cmdbuf,0,sizeof(cmdbuf));
	 sprintf(cmdbuf,"route add -host %s gw %s",UserCfgJson.ip,default_gw_ip);
	 printf("%s\n",cmdbuf);
	 system(cmdbuf);

	 memcpy(&sin,&ifr.ifr_addr,sizeof(sin));
	 printf("ip %s\n",inet_ntoa(sin.sin_addr));
	 return 0;
#endif
}
/*****************************************************************
 * 函数描述：停止接入及吸附
 * 参数：cJSON* param JSON格式串缓存指针
 * 		char* runmode 运行模式 "sta","ap"
 * 返回值： 无
 * ***************************************************************/
void wifi_stop_acess()
{
	char cmd[128];
#ifndef ZRRJ
	snprintf(cmd, sizeof(cmd),"uci set wireless.@wifi-iface[%d].mode=monitor",WifiAccess.band);
	WifiAccess.mode=ACCESS_MODE_INVALID;
	printf("%s\n",cmd);
	system(cmd);
	system("uci commit wireless");
	system("wifi &");
#else
	printf("%s mode:%d\n",__func__,WifiAccess.mode);
	if(WifiAccess.mode == ACCESS_MODE_AP_SUCC){
		snprintf(cmd, sizeof(cmd),"pseudo_ap_server stop %s &",UserCfgJson.wlan_dev[WifiAccess.band]);
		system(cmd);
	}
	else if(WifiAccess.mode == ACCESS_MODE_STA_SUCC){
		snprintf(cmd, sizeof(cmd),"pseudo_sta_server stop  &");
		system(cmd);
	}
	else{
		snprintf(cmd, sizeof(cmd),"pseudo_ap_server stop  %s &",UserCfgJson.wlan_dev[WifiAccess.band]);
		system(cmd);
		snprintf(cmd, sizeof(cmd),"pseudo_sta_server stop  &");
		system(cmd);
	}
#endif
	memset(cmd,0,sizeof(cmd));
	sprintf(cmd,"route add default gw %s",default_gw_ip);
	printf("%s\n",cmd);
	system(cmd);
	WifiAccess.mode=ACCESS_MODE_INVALID;
}
/*****************************************************************
 * 函数描述：接入及吸附字段解析函数，JSON字串解析
 * 参数：cJSON* param JSON格式串缓存指针
 * 		char* runmode 运行模式 "sta","ap"
 * 返回值： 解析结果
 * ***************************************************************/
int wifi_access_ap_policy_parse(cJSON* param,char * runmode)
{
	uint8_t uc_zrglag=0xff;
	char *zr_encry=NULL;
    if (param == NULL) {
    	WifiAccess.mode = ACCESS_MODE_INVALID;
    	return -1;
    }
#ifdef ZRRJ
    uc_zrglag = 1;
#else
    uc_zrglag = 0;
#endif
	char json_type;
	int array_size;
	char data[64],cmd[128];
	char *mac = NULL;
	char *key = NULL;
	char *ssid= NULL;
	char *encryption = NULL;
	char *band =NULL;
	memset(data, 0, sizeof(data));
	uint8_t ucchl;

	const char *protocol = NULL;
	cJSON* array=NULL;
	cJSON* array_item=NULL;



	int size = cJSON_GetArraySize(param);
	for (int i=0;i<size;i++){
		json_type = cJSON_GetArrayItem(param, i)->type;

		if (json_type == cJSON_Array){
			array = cJSON_GetArrayItem(param, i);

			if (strcmp(array->string,"ssid") == 0){//解析SSID
				array_size = cJSON_GetArraySize(array);

				for (int cnt=0;cnt<array_size;cnt++){
					array_item = cJSON_GetArrayItem(array, cnt);
					if (array_item != NULL){
						data[cnt] = (int)array_item->valueint;
					}
				}

				data[array_size] = 0;
				ssid = data;
				printf("ssid:%s\n", ssid);
			}
		}else if (json_type == cJSON_String){
			if (strcmp(cJSON_GetArrayItem(param, i)->string,"mac") == 0){//解析bssid
				mac = cJSON_GetArrayItem(param, i)->valuestring;
				getmac(mac, 1, WifiAccess.ap_mac);
				printf ("mac:%s\n", mac);
			}else if (strcmp(cJSON_GetArrayItem(param, i)->string,"ch") == 0){//解析获取信道值
				WifiAccess.channel = atoi((const char *)cJSON_GetArrayItem(param, i)->valuestring);
				printf ("channel:%d\n", WifiAccess.channel);
			}else if (strcmp(cJSON_GetArrayItem(param, i)->string,"pro") == 0){ //解析协议
				protocol = cJSON_GetArrayItem(param, i)->valuestring;
#if 0
				if (strcmp(protocol,"11a") == 0){
					WifiAccess.hwmode = IEEE80211A;
				}else if (strcmp(protocol,"11b") == 0){
					WifiAccess.hwmode = IEEE80211G;
				}else if (strcmp(protocol,"11g") == 0){
					WifiAccess.hwmode = IEEE80211B;
				}else if (strcmp(protocol,"11n") == 0){
					WifiAccess.hwmode = IEEE80211N;
				}
#else
				if(strchr(protocol,'a') != NULL){//协议
					 if(strchr(protocol,'c') != NULL){
						 WifiAccess.hwmode = IEEE80211AC;
					 }
					 else{
						 WifiAccess.hwmode =IEEE80211A;
					 }
				}
				else if(strchr(protocol,'n') != NULL){
					WifiAccess.hwmode = IEEE80211N;
				}
				else if(strchr(protocol,'g')!= NULL){
					WifiAccess.hwmode = IEEE80211G;
				}
				else if(strchr(protocol,'b')!= NULL){
					WifiAccess.hwmode = IEEE80211B;
				}
#endif
				printf ("protocol:%s\n", protocol);
			}else if (strcmp(cJSON_GetArrayItem(param, i)->string,"pwd") == 0){
				key = cJSON_GetArrayItem(param, i)->valuestring;
				printf ("key:%s\n", key);
			}else if (strcmp(cJSON_GetArrayItem(param, i)->string,"encrypt") == 0){
				encryption = cJSON_GetArrayItem(param, i)->valuestring;
				printf ("encryption:%s\n", encryption);
			}
			else if (strcmp(cJSON_GetArrayItem(param, i)->string,"band") == 0){
				band = cJSON_GetArrayItem(param, i)->valuestring;
				if(strcmp(band,"2.4") ==0){
					WifiAccess.band=ucchl = 0 ;
				}
				else if(strcmp(band,"5.8") ==0){
					WifiAccess.band=ucchl = 1;
				}
				//printf ("encryption:%s\n", encryption);
			}
		}
		else if(json_type == cJSON_Number){
			WifiAccess.angle = cJSON_GetArrayItem(param, i)->valueint;
			if(WifiAccess.angle <MIN_ANGLE){
				WifiAccess.angle=MIN_ANGLE;
			}
			else if(WifiAccess.angle >MAX_ANGLE){
				WifiAccess.angle=MAX_ANGLE;
			}
			printf ("angle:%d\n", WifiAccess.angle);
		}
	}

	if ((mac == NULL) || (ssid == NULL) || (protocol == NULL) || (encryption == NULL)){
		printf("ap_mac=%s ssid=%s protocol=%s encryption=%s\n",mac,ssid,protocol,encryption);
		return -1;
	}



	memset(cmd, 0, sizeof(cmd));
	if(strcmp(runmode,"sta") == 0){
		snprintf(cmd, sizeof(cmd),"uci set wireless.@wifi-device[%d].channel=%d", ucchl,WifiAccess.channel);
	}
	else if(strcmp(runmode,"ap") == 0){

#if 0
		switch(WifiAccess.band){
			case 0:{
				//if(WifiAccess.channel != 1){
					snprintf(cmd, sizeof(cmd),"uci set wireless.@wifi-device[%d].channel=%d", ucchl,1);
//				}
//				else{
//					snprintf(cmd, sizeof(cmd),"uci set wireless.@wifi-device[%d].channel=%d", ucchl,11);
//				}
			}
			break;
			case 1:{
				//if(WifiAccess.channel != 153){
					snprintf(cmd, sizeof(cmd),"uci set wireless.@wifi-device[%d].channel=%d", ucchl,36);
				//}
//				else{
//					snprintf(cmd, sizeof(cmd),"uci set wireless.@wifi-device[%d].channel=%d", ucchl,165);
//				}
			}
		}

#else
		snprintf(cmd, sizeof(cmd),"uci set wireless.@wifi-device[%d].channel=%d", ucchl,WifiAccess.channel);
#endif
		if(uc_zrglag == 0){
			printf("%s\n",cmd);
			system(cmd);
			memset(cmd, 0, sizeof(cmd));
			snprintf(cmd, sizeof(cmd),"uci set wireless.@wifi-device[%d].channel=%d", 3-ucchl,WifiAccess.channel);
			system(cmd);
		}
	}
	if(uc_zrglag == 0){
		printf("%s\n",cmd);
		system(cmd);
	}


#ifdef WSPY_CAR //设置前端的角度和信道
    gimbal_set_angle(WifiAccess.angle);
#else
	gimbal_set_angle(WifiAccess.angle,WifiAccess.channel);
#endif
	memset(cmd, 0, sizeof(cmd));
	if(ucchl == 0){//如果是2.4G
		switch(WifiAccess.hwmode){
			case IEEE80211N:{
				snprintf(cmd, sizeof(cmd),"uci set wireless.@wifi-device[%d].hwmode=%s", ucchl,"11n");//设置11n
				printf("%s\n",cmd);
				//system(cmd);

				memset(cmd, 0, sizeof(cmd));
				snprintf(cmd, sizeof(cmd),"uci set wireless.@wifi-device[%d].htmode=%s", ucchl,"HT20");//设置带宽
				printf("%s\n",cmd);
				//system(cmd);
			}break;
			case IEEE80211G:{
				snprintf(cmd, sizeof(cmd),"uci set wireless.@wifi-device[%d].hwmode=%s", ucchl,"11ng");
				printf("%s\n",cmd);
				//system(cmd);
			}break;
			case IEEE80211B:{
				snprintf(cmd, sizeof(cmd),"uci set wireless.@wifi-device[%d].hwmode=%s", ucchl,"11b");
				printf("%s\n",cmd);
				//system(cmd);
			}break;
			default:break;
		}
	}
	else if(ucchl == 1){
		switch(WifiAccess.hwmode){
			case IEEE80211N:{
				snprintf(cmd, sizeof(cmd),"uci set wireless.@wifi-device[%d].hwmode=%s", ucchl,"11a");
				printf("%s\n",cmd);
				//system(cmd);

				memset(cmd, 0, sizeof(cmd));
				snprintf(cmd, sizeof(cmd),"uci set wireless.@wifi-device[%d].htmode=%s", ucchl,"HT20");
				printf("%s\n",cmd);
			//	system(cmd);
			}break;
			case IEEE80211A:{
				snprintf(cmd, sizeof(cmd),"uci set wireless.@wifi-device[%d].hwmode=%s", ucchl,"11na");
				printf("%s\n",cmd);
				//system(cmd);
			}break;
			case IEEE80211AC:{
				snprintf(cmd, sizeof(cmd),"uci set wireless.@wifi-device[%d].hwmode=%s", ucchl,"11ac");
				printf("%s\n",cmd);
			//	system(cmd);

				memset(cmd, 0, sizeof(cmd));
				snprintf(cmd, sizeof(cmd),"uci set wireless.@wifi-device[%d].htmode=%s", ucchl,"VHT20");
				printf("%s\n",cmd);
				//system(cmd);
			}break;
			default:break;
		}
	}
	memset(cmd, 0, sizeof(cmd));//删除bssid
	snprintf(cmd,sizeof(cmd),"uci delete  wireless.@wifi-iface[%d].bssid",ucchl);
	printf("%s\n",cmd);
	if(uc_zrglag == 0){
		system(cmd);
	}

	memset(cmd, 0, sizeof(cmd));//设置extap
	snprintf(cmd,sizeof(cmd),"uci set  wireless.@wifi-iface[%d].extap=1",ucchl);
	printf("%s\n",cmd);
	if(uc_zrglag == 0){
		system(cmd);
	}

	if (strcmp(encryption, "No Encryption") != 0){//设置加密方式
		if (strstr(encryption, "WPA2") != NULL){
			zr_encry=encryption = "psk2";
		}else if (strstr(encryption, "WPA") != NULL){
			zr_encry=encryption = "psk";
		}else if (strstr(encryption, "WEP") != NULL){
			encryption = "wep-shared";
			zr_encry="wep";
		}
		snprintf(cmd, sizeof(cmd),"uci set wireless.@wifi-iface[%d].encryption=%s",ucchl, encryption);
	}else{
		zr_encry="none";
		snprintf(cmd, sizeof(cmd),"uci set wireless.@wifi-iface[%d].encryption=none",ucchl);
	}
	printf("%s\n",cmd);
	if(uc_zrglag == 0){
		system(cmd);
	}

	if (strcmp(encryption, "No Encryption") != 0){//设置密钥
		if (key == NULL)
			return -1;

		memset(cmd, 0, sizeof(cmd));
		if(strcmp(encryption, "wep-shared") == 0){//wep密钥
			snprintf(cmd, sizeof(cmd),"uci set wireless.@wifi-iface[%d].key1=%s;"
					"uci set wireless.@wifi-iface[%d].key=1",ucchl, key,ucchl);
		}
		else{
			snprintf(cmd, sizeof(cmd),"uci set wireless.@wifi-iface[%d].key=%s",ucchl, key);
		}
		printf("%s\n",cmd);
		if(uc_zrglag == 0){
			system(cmd);
		}
	}


	memset(cmd, 0, sizeof(cmd));
	if(strcmp(runmode,"ap") == 0){//设置接口类型
		snprintf(cmd, sizeof(cmd),"uci set wireless.@wifi-iface[%d].network=%s", ucchl,"lan");
	}
	else{
		if(ucchl == 0){
			snprintf(cmd, sizeof(cmd),"uci set wireless.@wifi-iface[%d].network=%s", ucchl,"wwan1");
		}
		else if(ucchl == 1){
			snprintf(cmd, sizeof(cmd),"uci set wireless.@wifi-iface[%d].network=%s", ucchl,"wwan2");
		}
		else {
			printf("sta channel error %d\n",ucchl);
		}
	}
	printf("%s\n",cmd);
	if(uc_zrglag == 0){
		system(cmd);
	}

	memset(cmd, 0, sizeof(cmd));
	snprintf(cmd, sizeof(cmd),"uci set wireless.@wifi-iface[%d].ssid=%s", ucchl,ssid);//设置ssid
	printf("%s\n",cmd);
	if(uc_zrglag == 0){
		system(cmd);
	}

	if(uc_zrglag == 0){
		for (int i=0; i<strlen(mac)-1;i++){
			if (mac[i] == '-')
				mac[i] = ':';
		}
		printf("mac:%s\n",mac);
		strcpy(g_acess_node.amac,mac);				//获取mac
		sprintf(g_acess_node.cdev,"ath%d",ucchl);	//获取网卡名称
		memset(cmd, 0, sizeof(cmd));//设置bssid
		snprintf(cmd, sizeof(cmd),"uci set wireless.@wifi-iface[%d].bssid=%s", ucchl,mac);
		printf("%s\n",cmd);
		system(cmd);
	}

	memset(cmd, 0, sizeof(cmd));

	snprintf(cmd, sizeof(cmd),"uci set wireless.@wifi-iface[%d].mode=%s",ucchl,runmode);//运行模式
	printf("%s\n",cmd);
	if(uc_zrglag == 0){
		system(cmd);
	}

	memset(cmd, 0, sizeof(cmd));
	snprintf(cmd, sizeof(cmd),"uci set wireless.@wifi-iface[%d].bintval=%d",3-ucchl,100);//设置wifi3的beacon时间
	printf("%s\n",cmd);
	if(uc_zrglag == 0){
		system(cmd);
		system("uci commit wireless");
	}


	system("cat /dev/null > /tmp/dhcp.leases");//清空dhcp的缓存


	if(uc_zrglag == 0){
		if(strcmp(runmode,"ap") == 0){//先重启网卡再修改模式
				WifiAccess.mode = ACCESS_MODE_AP;
				printf("Wifi mode1 %d \n",WifiAccess.mode);
		}
		else if(strcmp(runmode,"sta") == 0){
			WifiAccess.mode = ACCESS_MODE_STA;
			printf("Wifi mode1 %d \n",WifiAccess.mode);
			system("wifi&");
		}
	}
	else if(uc_zrglag == 1){
		char *htmode = NULL;
		if(ucchl == 0)
		{
			htmode="ht20";
		}
		else{
			htmode="vht40";
		}
		if(strcmp(runmode,"ap") == 0){//先重启网卡再修改模式
			WifiAccess.mode = ACCESS_MODE_AP;
			strobe_wifi_sta(ucchl);
			strobe_wifi_monitor(ucchl+2,1);
			snprintf(cmd, sizeof(cmd),"pseudo_ap_server %s %d %d %s %s &",UserCfgJson.wlan_dev[ucchl],3,WifiAccess.channel,ssid,key);
			printf("%s\n",cmd);
			system(cmd);
		}
		else if(strcmp(runmode,"sta") == 0){
			WifiAccess.mode = ACCESS_MODE_STA;
			strobe_wifi_sta(ucchl);
			strobe_wifi_sta(ucchl+2);
			memset(cmd, 0, sizeof(cmd));
			snprintf(cmd, sizeof(cmd),"pseudo_sta_server %s  %s %s &",UserCfgJson.wlan_dev[ucchl],ssid,key);
			printf("%s\n",cmd);
			system(cmd);
		}
	}
	printf("Wifi mode2 %d \n",WifiAccess.mode);
	//system("/mnt/mmc/ssl/reset.sh");
    return 0;
}


//int wifi_attch_sta_policy_parse(cJSON* param_ap,cJSON* param_sta)
//{
//
//}

