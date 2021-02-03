/*
 * DataProcess.c
 *
 *  Created on: Jan 8, 2019
 *      Author: lpz
 */
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "cJSON.h"
#include "DataProcess.h"
#include "mac80211_fmt.h"

extern char PcapInterface[4][WDEVNAME_LEN];

json_rcv_config UserCfgJson;

static cJSON *root_config=NULL;


/*****************************************************************
* 函数描述：获取用户参数配置的json指针缓存
* 参数：	  无
* 返回值：	cJSON * json串配置
* ***************************************************************/
cJSON * get_json_config()
{
	return root_config;
}
/*****************************************************************
* 函数描述：用户配置参数读取函数，读取需要设置的参数
* 参数：	  无
* 返回值：	0 读取正确
* 			其他 读取失败
* ***************************************************************/
int read_user_config()
{
    FILE * fp;
    char buf[1048];
    char wlan_buf[128],cmdbuf[128];
    cJSON * root = NULL;
    cJSON * params = NULL;
    //json路径
    if ((fp = fopen("./config.json", "r")) == NULL) {
        if ((fp = fopen("/etc/config/wspy", "r")) == NULL) {
            perror("not found configuration file\n");
            return -1;
        }
    }
    
    fread(buf, sizeof(char), sizeof(buf), fp);
    fclose(fp);
    root_config=root = cJSON_Parse(buf);
    if (!root) {
        perror("configuration parse error\n");
        return -2;
    }
    else
    	params = cJSON_GetObjectItem(root, "server");
    if (params == NULL) {
        fprintf(stderr, "error: not found server configuration\n");
        cJSON_Delete(root);
        return -3;
    }
    parse_server(params);
    params = cJSON_GetObjectItem(root, "device");
    if (params == NULL) {
		fprintf(stderr, "error: not found device configuration\n");
		cJSON_Delete(root);
		return -3;
	}
    parse_device(params);
    params = cJSON_GetObjectItem(root, "ftp");
	if (params == NULL) {
		fprintf(stderr, "error: not found device configuration\n");
		cJSON_Delete(root);
		return -3;
	}
	parse_ftp(params);
	params = cJSON_GetObjectItem(root, "gps");
	if (params == NULL) {
		fprintf(stderr, "error: not found device configuration\n");
		cJSON_Delete(root);
		return -3;
	}
	parse_gps(params);

	float fusb[2]={0.0,0.0};
	for(int i=0; i <2;i++){
		memset(cmdbuf,0,sizeof(cmdbuf));
		memset(wlan_buf,0,sizeof(wlan_buf));
		sprintf(cmdbuf,"cat /wspy/dmesg.log |grep \"usb %d-1\" |grep Sinux |awk '{print $2}'|awk -F']' '{print $1}'",i+1);
		sys_get(cmdbuf,wlan_buf,sizeof(wlan_buf));
		fusb[i] = atof(wlan_buf);
		printf("usb time %d %f\n",i,fusb[i]);
	}
#ifdef WSPY_CAR
char wlan_name[2][6]={"wlan2","wlan1"};
#else
char wlan_name[2][6]={"wlan1","wlan2"};
#endif
	if(fusb[0] > fusb[1]){
		params = cJSON_GetObjectItem(root, wlan_name[0]);
		if (params == NULL) {
			fprintf(stderr, "error: not found device configuration\n");
			cJSON_Delete(root);
			return -3;
		}
	}
	else{
		params = cJSON_GetObjectItem(root, wlan_name[1]);
		if (params == NULL) {
			fprintf(stderr, "error: not found device configuration\n");
			cJSON_Delete(root);
			return -3;
		}
	}
	parse_wlan(params);
    return 0;
}
/*****************************************************************
* 函数描述：server 参数解析函数，解析json文本中上位记通信参数
* 参数：	  cJSON* param json缓存指针
* 返回值：无
* ***************************************************************/
void parse_server(cJSON* param)
{

	int size = cJSON_GetArraySize(param);
	for (int i=0;i<size;i++){
		if (strcmp(cJSON_GetArrayItem(param, i)->string,"port") == 0){//获取port
			UserCfgJson.port=cJSON_GetArrayItem(param, i)->valueint;
			printf("server port %d\n",UserCfgJson.port);
		}
		else if(strcmp(cJSON_GetArrayItem(param, i)->string,"user") == 0){ //获取user
			strcpy(UserCfgJson.clinet_id,cJSON_GetArrayItem(param, i)->valuestring);
			printf("client id  %s\n",UserCfgJson.clinet_id);
		}
		else if(strcmp(cJSON_GetArrayItem(param, i)->string,"ip") == 0){//获取ip
			strcpy(UserCfgJson.ip,cJSON_GetArrayItem(param, i)->valuestring);
		}
	}
}
/*****************************************************************
* 函数描述：device 参数解析函数，解析json文本中设备信息参数
* 参数：	  cJSON* param json缓存指针
* 返回值：无
* ***************************************************************/
void parse_device(cJSON* param)
{
	char *p;
	int size = cJSON_GetArraySize(param);
	for (int i=0;i<size;i++){
		if (strcmp(cJSON_GetArrayItem(param, i)->string,"sn") == 0){//获取port
			DeviceSN=UserCfgJson.sn=strtol(cJSON_GetArrayItem(param, i)->valuestring,&p,16);
			printf("%x %s\n",DeviceSN,cJSON_GetArrayItem(param, i)->valuestring);
		}
		else if(strcmp(cJSON_GetArrayItem(param, i)->string,LONGITUDE) == 0){ //获取精度
			UserCfgJson.longitude=atof(cJSON_GetArrayItem(param, i)->valuestring);
			printf("longtitude %f\n",UserCfgJson.longitude);
		}
		else if(strcmp(cJSON_GetArrayItem(param, i)->string,LATITUDE) == 0){//获取ip
			UserCfgJson.latitude=atof(cJSON_GetArrayItem(param, i)->valuestring);
		}
	}
}
/*****************************************************************
* 函数描述：文件存储，将缓存的json串写入本地文件
* 参数：	  cJSON* param json缓存指针
* 返回值：无
* ***************************************************************/
int save_configfile()
{
	FILE * fp;
	char *pchar=NULL;
	if ((fp = fopen("./config.json", "w")) == NULL) {
	        if ((fp = fopen("/etc/config/wspy", "r")) == NULL) {
	            perror("not found configuration file\n");
	            return -1;
		}
	}
	pchar= cJSON_Print(root_config);
	fwrite(pchar,strlen(pchar),1,fp);
	fclose(fp);
	return 0;
}
/*****************************************************************
* 函数描述：设置参数文件的经纬度
* 参数：	  cJSON* param json指针
* 		  char *setstr	需要修改的字符串
*		  float ftitude 需要修改的经纬度
* 返回值：无
****************************************************************/
void set_device(cJSON* param,char *setstr,float ftitude)
{
	int size = cJSON_GetArraySize(param);
	for (int i=0;i<size;i++){
		if (strcmp(cJSON_GetArrayItem(param, i)->string,setstr) == 0){//获取port
			sprintf(cJSON_GetArrayItem(param, i)->valuestring,"%.2f",ftitude);
			printf("longtitude %s\n",cJSON_GetArrayItem(param, i)->valuestring);
		}
	}
}
/*****************************************************************
* 函数描述：ftp 服务器参数解析函数，解析json文本中ftp通信参数
* 参数：	  cJSON* param json缓存指针
* 返回值：无
* ***************************************************************/
void parse_ftp(cJSON* param)
{
	int size = cJSON_GetArraySize(param);
	for (int i=0;i<size;i++){
		if (strcmp(cJSON_GetArrayItem(param, i)->string,"user") == 0){//获取port
			strcpy(UserCfgJson.user,cJSON_GetArrayItem(param, i)->valuestring);
		}
		else if (strcmp(cJSON_GetArrayItem(param, i)->string,"passwd") == 0){//获取port
			strcpy(UserCfgJson.password,cJSON_GetArrayItem(param, i)->valuestring);
		}
		else if (strcmp(cJSON_GetArrayItem(param, i)->string,"localpath") == 0){//获取port
			strcpy(UserCfgJson.localpath,cJSON_GetArrayItem(param, i)->valuestring);
		}
		else if (strcmp(cJSON_GetArrayItem(param, i)->string,"applocalpath") == 0){//获取port
			strcpy(UserCfgJson.applocalpath,cJSON_GetArrayItem(param, i)->valuestring);
		}
	}
}
/*****************************************************************
* 函数描述：gps 参数解析函数
* 参数：	  cJSON* param json缓存指针
* 返回值：无
* ***************************************************************/
void parse_gps(cJSON* param)
{
	int size = cJSON_GetArraySize(param);
	for (int i=0;i<size;i++){
		if (strcmp(cJSON_GetArrayItem(param, i)->string,"disabled") == 0){//获取gps开关
			UserCfgJson.gps_disable=cJSON_GetArrayItem(param, i)->valueint;
		}
	}
}
/*****************************************************************
* 函数描述：wlan 网口参数解析函数
* 参数：	  cJSON* param json缓存指针
* 返回值：无
* ***************************************************************/
void parse_wlan(cJSON* param)
{
	char dev_name[10];
	int size = cJSON_GetArraySize(param);
	for (int i=0;i<size;i++){
		sprintf(dev_name,"dev%d",i);
		if (strcmp(cJSON_GetArrayItem(param, i)->string,dev_name) == 0){//获取网卡名称
			strcpy(UserCfgJson.wlan_dev[i],cJSON_GetArrayItem(param, i)->valuestring);
			strcpy(PcapInterface[i],UserCfgJson.wlan_dev[i]);
			printf("%s\n",UserCfgJson.wlan_dev[i]);
		}
	}
}
