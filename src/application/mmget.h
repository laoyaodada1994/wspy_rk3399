/*
 * mmget.h
 *
 *  Created on: 2019-12-30
 *      Author: andy
 */

#ifndef MMGET_H_
#define MMGET_H_
#include <stdint.h>
#include <unistd.h>
#include <sched.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "cJSON.h"
#define MAX_MM_NUM	128	//最大支持同时下载128个木马
typedef struct mm_file{
	char md5string[512];
	char ftpfile[512];
	char filename[512];
	char filetype[16];
}MM_FILE_DATA;
/*****************************************************************
 * 函数描述：木马下发初始化，主要实现lftp所需参数的配置读取等初始化
 * 参数：无
 * 返回值： 无
 * ***************************************************************/
void mmget_init();
/*****************************************************************
 * 函数描述：木马文件获取，用于从服务器下发木马文件
 * 参数：	   JSON 格式缓存指针
 * 返回值： 无
 * ***************************************************************/
void *mmget_file(void *param_mm);
/*****************************************************************
 * 函数描述：创建木马下发线程
 * 参数：  cJSON* param_mm JSON 木马参数缓存指针
 * 		  int settype  设置参数
 * 		  				0  删除文件
 * 		  				1 下发文件
 * 返回值： 无
 * ***************************************************************/
void mmget_thread_start(cJSON* param_mm,int settype);
/*****************************************************************
* 函数描述：文件读取函数
* 参数：	   char *basePath 文件目录缓存指针
* 返回值： int
****************************************************************/
int readFileList(char *basePath,cJSON* filesarray);
#endif /* MMGET_H_ */
