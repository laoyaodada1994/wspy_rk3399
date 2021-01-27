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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "script.h"
#include "DataProcess.h"
#include "common.h"
#include "status.h"
#include "wifi_sniffer.h"
#include "wifi_access.h"
#define PROCESS_STATUS_NAME "lasted_status.conf"	//程序状态文件
/***********************************************************************
 *                              Declare
 ***********************************************************************/
/***********************************************************************
 *                              Variable
 ***********************************************************************/

/***********************************************************************
 *                              Function
 ***********************************************************************/
/*****************************************************************
* 函数描述: 获取设备本机与上位机通信的ip的欧洲就哦
* 参数：    char *ip_str ip信息输出字串
* 返回值：  无
****************************************************************/
void get_local_ip(char ip_str[32])
{
    FILE * fp;
    char resbuf[512],cmdbuf[512],local_ip[512];
    uint16_t usport =0 ;
#if 0
    memset(resbuf,0,sizeof(resbuf));
    sys_get("uci get wspy.server.port",resbuf,sizeof(resbuf));
    usport=atoi(resbuf);
    memset(cmdbuf,0,sizeof(cmdbuf));
    memset(resbuf,0,sizeof(resbuf));
    sprintf(cmdbuf,"netstat |grep %d|awk '{print $4}'|awk -F':' '{print $1}'",usport);//获取与上位机建立连接的ip
    sys_get(cmdbuf,local_ip,sizeof(local_ip));

    memset(cmdbuf,0,sizeof(cmdbuf));
    sys_get("uci get network.wan.ifname",resbuf,sizeof(resbuf));
    sprintf(cmdbuf,"ifconfig %s | grep \"inet addr\" | awk '{print $2}' | awk -F: '{print $2}'",resbuf);
    memset(resbuf,0,sizeof(resbuf));
    printf("%s\n",cmdbuf);
    sys_get(cmdbuf,resbuf,sizeof(resbuf));
    if(strcmp(local_ip,resbuf) ==0 ){//如果ip地址相同，则是wan口通信
    	strcpy(ip_str,resbuf);
    }
    else { //如果ip地址不同,则用lan口通信
		fp = popen("ifconfig br-lan | grep \"inet addr\" | awk '{print $2}' | awk -F: '{print $2}'", "r");
		fgets(ip_str, 16, fp);
		ip_str[strlen(ip_str)-1] = '\0';
		pclose(fp);
    }
#else
    sprintf(cmdbuf,"ifconfig %s | grep \"inet addr\" | awk '{print $2}' | awk -F: '{print $2}'","eth0");
	memset(resbuf,0,sizeof(resbuf));
	printf("%s\n",cmdbuf);
	sys_get(cmdbuf,ip_str,sizeof(resbuf));
#endif
}
const char * cover_to_chinese(const char *str){
	if(strstr(str,"wifiScan")){
		return "探测";
	}
	else if(strstr(str,"apDecrypt")){
		return "破解";
	}
	else if(strstr(str,"staArp")){
		return "Arp";
	}
	else if(strstr(str,"staCapture")){
		return "JH";
	}
	else if(strstr(str,"staTrojan")){
		return "ZR";
	}
	else if(strstr(str,"apInter")){
		return "压制";
	}
	else if(strstr(str,"staInter")){
		return "干扰";
	}
	else if(strstr(str,"staAttach")){
		return "吸附";
	}
	else if(strstr(str,"apAccess")){
		return "接入";
	}
	else {
		return "空闲";
	}
}
/*****************************************************************
* 函数描述: 获取设备工作状态
* 参数：    char *cdev_sta 工作状态输出字串
* 返回值：  无
****************************************************************/
void get_dev_status(char *cdev_sta)
{
	cJSON * root = cJSON_CreateObject();
	traverse_status_list(root);
	char *pdata= cJSON_Print(root);
	const char *pstr=cover_to_chinese(pdata);
	strcpy(cdev_sta,pstr);
	printf("%s %s\n",pdata,cdev_sta );
	cJSON_Delete(root);
}
/*****************************************************************
* 函数描述: 获取设备网卡的信道，包括2.4G和5.8G网卡的工作信道
* 参数：    char *cdev_mode 工作信道输出字串
* 返回值：  无
****************************************************************/
void get_dev_channel(char *cdev_mode)
{
	char cmdbuf[256];
	char buffer[16],buffer2[16];
	float fdev=0.0;
	int dev_channel[2];
	memset(buffer,0,sizeof(buffer));
	for(int i=0 ;i <2;i++){
		sprintf(cmdbuf,"iwlist %s channel |grep Cur|awk '{print $2}'|awk -F':' '{print $2}'",UserCfgJson.wlan_dev[i]);
		sys_get(cmdbuf,buffer,sizeof(buffer));
		fdev = atof(buffer);
		printf("fdev %f\n",fdev);
		if(((fdev - 2.484 <0.00001)&&(fdev >2.484)) ||((fdev - 2.484 >-0.00001)&&(fdev<2.484 ))){
			dev_channel[i]=14;
		}
		else if(fdev <2.484){
			dev_channel[i]=((fdev-2.412)*1000+0.5)/5+1;
		}
		else if(fdev >5.170){
			dev_channel[i] = ((fdev-5.180)*1000+0.5)/5+36;
			printf("%f\n",(fdev-5.180)*1000);
		}
		else{
			dev_channel[i]=-1;//err
		}
	}
	sprintf(cdev_mode,"%d,%d",dev_channel[0],dev_channel[1]);
	printf("%s\n",cdev_mode);
}

/*****************************************************************
* 函数描述: 获取设备网卡的协议，包括2.4G和5.8G网卡的工作协议
* 参数：    char *cdev_mode 工作协议输出字串
* 返回值：  无
****************************************************************/
void get_dev_hwmode(char *cdev_mode)
{
	char buffer1[16],buffer2[16];
//	sys_get("uci get wireless.@wifi-device[0].hwmode",buffer1,sizeof(buffer1));
	//sys_get("uci get wireless.@wifi-device[1].hwmode",buffer2,sizeof(buffer2));
	sprintf(cdev_mode,"%s,%s","b/g/n","a/n/ac");
	printf("%s\n",cdev_mode);
}

/*****************************************************************
* 函数描述: 获取设备网卡的带宽 ，包括2.4G和5.8G网卡的带宽s
* 参数：    char *cdev_mode 工作带宽输出字串
* 返回值：  无
****************************************************************/
void get_dev_htmode(char *cdev_mode)
{
	char buffer1[16],buffer2[16];
	memset(buffer1,0,sizeof(buffer1));
	memset(buffer2,0,sizeof(buffer2));
//	sys_get("uci get wireless.@wifi-device[0].htmode",buffer1,sizeof(buffer1));
	//sys_get("uci get wireless.@wifi-device[1].htmode",buffer2,sizeof(buffer2));
	if(strstr(buffer1,"ht") == NULL){
		strcpy(buffer1,"ht20");
	}
	if(strstr(buffer2,"ht") == NULL){
		strcpy(buffer2,"ht40");
	}
	sprintf(cdev_mode,"%s,%s",buffer1,buffer2);
	printf("%s\n",cdev_mode);
}

/*****************************************************************
* 函数描述: 获取设备网卡的工作模式 ，包括2.4G和5.8G网卡工作模式
* 参数：    char *cdev_mode 工作模式输出字串
* 返回值：  无
****************************************************************/
void get_dev_mode(char *cdev_mode)
{
	char cmdbuf[256];
	char buffer[16];
	char res[2][16];
	for(int i=0 ;i <2;i++){
		sprintf(cmdbuf,"iwconfig %s|grep Mode |awk '{print $1}' |awk -F':' '{printf $2}'",UserCfgJson.wlan_dev[i]);
		sys_get(cmdbuf,buffer,sizeof(buffer));
		if(strcmp(buffer,"Monitor")== 0){
			strcpy(res[i],"monitor");
		}
		else if(strcmp(buffer,"Managed")== 0){
			strcpy(res[i],"sta");
		}
		else if(strcmp(buffer,"Master")== 0){
			strcpy(res[i],"ap");
		}
	}
	sprintf(cdev_mode,"%s,%s",res[0],res[1]);
	printf("%s\n",cdev_mode);
}
void get_cpu_occupy(char oc_str[5])
{
    int  oc_sys;
    char buffer[64];

    sys_get("top -n 1|grep CPU:|grep -v grep |awk '{print $8}'|awk -F'%' '{print $1}'",buffer,sizeof(buffer));
    oc_sys=atoi(buffer);
    sprintf(oc_str, "%d", 100-oc_sys);
}
int get_disk_occupy(char oc_str[5])
{
	float fused;
	int iused;
    char buffer[256];
	FILE * fp;
	fp = popen("df -h|grep mmcblk1p5|awk '{print $5}'","r");
	fgets(buffer, sizeof(buffer), fp);

	fused=atof(buffer);
	sprintf(oc_str, "%.1f", fused);
	pclose(fp);

	fp = popen("df -m|grep mmcblk1p5|awk '{print $4}'","r");
	fgets(buffer, sizeof(buffer), fp);

	iused=atoi(buffer);
	pclose(fp);
	return iused;
}

void get_mem_occupy(char oc_str[5])
{
    int mem_total, mem_free;
    float fused;
    char buffer[256];
    FILE * fp;
#if 0
    fp = popen("top -n 1 | grep KiB | awk -F '  ' '{print $2 $3}' | sed -r \"s:([\\x1B(B])*(\\x1B\\[[0-9;]*[mK])*::g\"", "r");
#else
    fp = popen("cat /proc/meminfo |grep -i memtotal|awk '{print $2}'","r");
    fgets(buffer, sizeof(buffer), fp);
    pclose(fp);
    mem_total = atoi(buffer);
    fp = popen("cat /proc/meminfo |grep -i memfree|awk '{print $2}'","r");
    fgets(buffer, sizeof(buffer), fp);
    mem_free = atoi(buffer);
    pclose(fp);
#endif

#if 0
    int ret = sscanf(buffer, "%d total, %d free,", &mem_total, &mem_free);
    if (ret != 2) {
        used = 0;
    }
    else
        used = (mem_total - mem_free) / (mem_total / 100);
#else
    fused = ((float)(mem_total-mem_free)/mem_total)*100;
#endif
    sprintf(oc_str, "%.1f", fused);
}
/*****************************************************************
 * 函数描述：设置wifi为sta模式
 * 参数： uint8_t ucchl 设置通道
 * 返回值： 无
 * ***************************************************************/
void strobe_wifi_sta(uint8_t ucchl)
{
	char getbuf[128];
	char cmdbuf[128];
	memset(cmdbuf,0,sizeof(cmdbuf));
	sprintf(cmdbuf,"ifconfig %s down;iwconfig %s mode manager;ifconfig %s up",UserCfgJson.wlan_dev[ucchl],UserCfgJson.wlan_dev[ucchl],UserCfgJson.wlan_dev[ucchl]);
	system(cmdbuf);

	usleep(100000);
	memset(cmdbuf,0,sizeof(cmdbuf));
	sprintf(cmdbuf,"ifconfig |grep %s",UserCfgJson.wlan_dev[ucchl]);
	if(strstr(getbuf,UserCfgJson.wlan_dev[ucchl]) == NULL){
		wlan_abort(UserCfgJson.wlan_dev[ucchl],1,ACCESS_MODE_STA);
	}
	else{
		memset(cmdbuf,0,sizeof(cmdbuf));
		sprintf(cmdbuf,"iwconfig  %s|grep Mode",UserCfgJson.wlan_dev[ucchl]);
		sys_get(cmdbuf,getbuf,sizeof(getbuf));
		if(strstr(getbuf,"Managed") == NULL){
			wlan_abort(UserCfgJson.wlan_dev[ucchl],0,ACCESS_MODE_STA);
		}
	}
}
/*****************************************************************
 * 函数描述：设置wifi为monitor模式
 * 参数： uint8_t ucchl 设置通道
 * 		 uint8_t ifup  网卡重启标识
 * 返回值： 无
 * ***************************************************************/
void strobe_wifi_monitor(uint8_t ucchl,uint8_t ifup)
{
    // system("wifi down");
    // usleep(500000);
	char cmdbuf[128];
	char getbuf[128];
	int res = 0;
#ifndef ZRRJ
	if(ucchl &0x1){ //设置wifi0为monitor
		system("uci set wireless.@wifi-iface[0].mode=monitor && uci set wireless.wifi0.disabled=0");
		system("uci set wireless.@wifi-iface[3].mode=ap && uci set wireless.wifi3.disabled=0");
	}
	if((ucchl &0x2) == 0x2){ //设置wifi1为monitor
		system("uci set wireless.@wifi-iface[1].mode=monitor && uci set wireless.wifi1.disabled=0");
		system("uci set wireless.@wifi-iface[2].mode=ap && uci set wireless.wifi2.disabled=0");
	}
    system("uci commit wireless");
    if(ifup == 1){
    	system("wifi");
    }
#else
	sprintf(cmdbuf,"set_monitor %s",UserCfgJson.wlan_dev[ucchl]);
	system(cmdbuf);
#endif
    usleep(500000);

    memset(cmdbuf,0,sizeof(cmdbuf));
    sprintf(cmdbuf,"ifconfig |grep %s",UserCfgJson.wlan_dev[ucchl]);
    sys_get(cmdbuf,getbuf,sizeof(getbuf));

    if(strstr(getbuf,UserCfgJson.wlan_dev[ucchl]) == NULL){
    	wlan_abort(UserCfgJson.wlan_dev[ucchl],1,ACCESS_MODE_MONITOR);
    }
    else{
        memset(cmdbuf,0,sizeof(cmdbuf));
        sprintf(cmdbuf,"iwconfig %s|grep Mode",UserCfgJson.wlan_dev[ucchl]);
        sys_get(cmdbuf,getbuf,sizeof(getbuf));
        printf("%s\n",getbuf);
        if(strstr(getbuf,"Monitor")!= NULL){
        	wlan_abort(UserCfgJson.wlan_dev[ucchl],0,ACCESS_MODE_MONITOR);
        }
    }
}
/*****************************************************************
 * 函数描述：设置wifi为ap模式
 * 参数： uint8_t ucchl 设置通道
 * 		 uint8_t ifup  网卡重启标识
 * 返回值： 无
 * ***************************************************************/
void strobe_wifi_ap(uint8_t ucchl,uint8_t ifup)
{
	char cbuf[256];
	memset(cbuf,0,sizeof(cbuf));
	sprintf(cbuf,"uci set wireless.@wifi-iface[%d].mode=ap",ucchl);
	system(cbuf);
	sprintf(cbuf,"uci set wireless.wifi%d.disabled=0",ucchl);
	system(cbuf);
	system("uci commit wireless");
	if(ifup == 1){
		system("wifi");
	}
	usleep(500000);
}
/*****************************************************************
 * 函数描述：获取默认网关
 * 参数： char *default_gw 网关地址缓存
 * 		 int gw_len		  获取网关长度
 * 返回值： 无
 * ***************************************************************/
void get_default_gw(char *default_gw,int gw_len)
{
	char cbuf[256],cmdbuf[256];
	char local_ip[64];
	uint16_t usport =0 ;
	memset(cbuf,0,sizeof(cbuf));
	memset(local_ip,0,sizeof(local_ip));
	//sys_get("uci get wspy.server.port",cbuf,sizeof(cbuf));
	usport=UserCfgJson.port;
	memset(cbuf,0,sizeof(cbuf));
	memset(cmdbuf,0,sizeof(cmdbuf));
	sprintf(cmdbuf,"netstat -an|grep %d|grep ESTABLISHED|awk '{print $4}'|awk -F':' '{print $1}'|awk -F'.' '{print $1\".\"$2\".\"$3}'",usport);//获取与上位机建立连接的ip
	sys_get(cmdbuf,local_ip,sizeof(local_ip));

	sprintf(cbuf,"route -n|grep %s|grep G|awk '{print $2}'",local_ip);
	sys_get(cbuf,default_gw,gw_len);
}
/*****************************************************************
 * 函数描述：读取当前程序状态及执行参数
 * 参数： const char *status 当前程序状态
 * 		 const char *json	执行参数json缓存
 * 返回值： int 0 读取成功
 * 		   其他  读取失败
 * ***************************************************************/
int get_lasted_status(char *status,char *json)
{
	int ret = -1;
	char cmd[512];
	FILE *fp = NULL;
	const char *filename = PROCESS_STATUS_NAME;
	if(status == NULL ||json == NULL){
		printf("%s: status is NULL \n",__func__);
		return ret;
	}
	fp = fopen(filename,"r");
	if(fp == NULL){
		printf("can't find file %s\n",filename);
		return ret;
	}
	memset(cmd,0,sizeof(cmd));
	fgets(cmd,sizeof(cmd),fp);
	strcpy(status,cmd);
	printf("%s : %s \n",__func__,status);

	memset(cmd,0,sizeof(cmd));
	fgets(cmd,sizeof(cmd),fp);
	strcpy(json,cmd);
	printf("%s : %s \n",__func__,json);
	ret = 0 ;
	fclose(fp);
	return ret;
}
/*****************************************************************
 * 函数描述：存储当前程序状态及执行参数
 * 参数： const char *status 当前程序状态
 * 		 const char *json	执行参数json缓存
 * 返回值： int 0 存储成功
 * 		   其他  存储失败
 * ***************************************************************/
int save_lasted_status(const char *status,const char *json)
{
	int ret = -1;
	char cmd[512];
	FILE *fp = NULL;
	const char *filename = PROCESS_STATUS_NAME;
	if(status == NULL){
		printf("%s: status is NULL",__func__);
		return -1;
	}


	fp =fopen(filename,"wt+");
	if(fp == NULL){
		printf("can't find file %s\n",filename);
		return ret;
	}
	memset(cmd,0,sizeof(cmd));
	sprintf(cmd,"%s\r\n",status);
	fputs(cmd,fp);
	printf("%s : %s %d\n",__func__,cmd,__LINE__);

	memset(cmd,0,sizeof(cmd));
	sprintf(cmd,"%s\r\n",json);
	fputs(cmd,fp);
	printf("%s : %s %d\n",__func__,cmd,__LINE__);
	ret = 0;
	fclose(fp);
	return ret;
}
/*****************************************************************
* 函数描述：ssh 关闭函数，关闭设备的ssh网络服务
* 参数：	无
* 返回值：无
****************************************************************/
void ssh_close(void)
{
	system("/etc/init.d/dropbear stop");
	system("/etc/init.d/dropbear disable");
	system("kill -9 $(ps | grep dropbear | grep -v 'grep' | awk '{print $1}')");
}
/*****************************************************************
* 函数描述：ssh 打开函数，打开设备的ssh网络服务
* 参数：	无
* 返回值：无
****************************************************************/
void ssh_open(void)
{
	system("/etc/init.d/dropbear enable");
	system("/etc/init.d/dropbear start");
}
/*****************************************************************
* 函数描述：设置自毁标志,向指定文件写入自毁标志
* 参数：	无
* 返回值：无
****************************************************************/
void set_destroy_flag(void)
{
	system("echo 1 > /root/wspy/reset_flag");
}
