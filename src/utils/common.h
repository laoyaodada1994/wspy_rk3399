/*****************************************************************************
 * @file: common.h
 */
#ifndef __COMMON_H
#define __COMMON_H


////typedef unsigned int bool;
//typedef enum{
//	false =0,
//	true
//};
#ifdef __cplusplus
 extern "C" {
#endif
//#include"../userheader.h"
/*****************************************************************************
 * Macro
 */
//typedef unsigned int bool;
#include<string.h>

#define LONGITUDE	"longitude"
#define LATITUDE	"latitude"

#undef bool
#define bool unsigned int
#ifndef offsetof
 #define offsetof(type, member)          ((size_t) &(((type *)0)->member))
#endif

#ifndef container_of
 #define container_of(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type,member)))
#endif
/**Debug Information*/
#define DEV_PREFIX "WIFI_ZK_INFO:"
enum {
	_ZK_NONE_=0,
	_ZK_ALWAYS_,
	_ZK_INFO,
	_ZK_DEBUG,
	_ZK_MAX_
};
extern uint8_t zk_dev_log_level;
#define ZK_DEV_PRINT(fmt,arg...)\
	do{\
		if(_ZK_ALWAYS_< zk_dev_log_level){\
			printf(DEV_PREFIX fmt,##arg);\
		}\
	}while(0)


/*****************************************************************************
 * Type
 */
 
/*****************************************************************************
 * Declare
 */
extern uint32_t DeviceSN;

void strcpyl(char * dest, const char * src, size_t len);
void sys_get(const char * cmd, char * output, size_t out_sz);
void sys_set(const char * cmd, ...);

#ifdef __cplusplus
 }
#endif

#endif //__COMMON_H
