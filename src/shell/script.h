/*****************************************************************
 * @file: script.h
 */
#ifndef __SCRIPT_H
#define __SCRIPT_H
#include<stdint.h>
/*****************************************************************
 *  Decalre
 */
/*****************************************************************
* 函数描述: 获取设备工作状态
* 参数：    char *cdev_sta 工作状态输出字串
* 返回值：  无
****************************************************************/
void get_dev_status(char *cdev_sta);
/*****************************************************************
* 函数描述: 获取设备网卡的信道，包括2.4G和5.8G网卡的工作信道
* 参数：    char *cdev_mode 工作信道输出字串
* 返回值：  无
****************************************************************/
void get_dev_channel(char *cdev_mode);
/*****************************************************************
* 函数描述: 获取设备网卡的协议，包括2.4G和5.8G网卡的工作协议
* 参数：    char *cdev_mode 工作协议输出字串
* 返回值：  无
****************************************************************/
void get_dev_hwmode(char *cdev_mode);
/*****************************************************************
* 函数描述: 获取设备网卡的带宽 ，包括2.4G和5.8G网卡的带宽s
* 参数：    char *cdev_mode 工作带宽输出字串
* 返回值：  无
****************************************************************/
void get_dev_htmode(char *cdev_mode);
/*****************************************************************
* 函数描述: 获取设备网卡的工作模式 ，包括2.4G和5.8G网卡工作模式
* 参数：    char *cdev_mode 工作模式输出字串
* 返回值：  无
****************************************************************/
void get_dev_mode(char *cdev_mode);
void get_local_ip(char buffer[16]);
void get_cpu_occupy(char buffer[4]);
void get_mem_occupy(char oc_str[5]);
void get_disk_occupy(char oc_str[5]);
/*****************************************************************
 * 函数描述：设置wifi为sta模式
 * 参数： uint8_t ucchl 设置通道
 * 返回值： 无
 * ***************************************************************/
void strobe_wifi_sta(uint8_t ucchl);
/*****************************************************************
 * 函数描述：设置wifi为monitor模式
 * 参数： uint8_t ucchl 设置通道
 * 		 uint8_t ifup  网卡重启标识
 * 返回值： 无
 * ***************************************************************/
void strobe_wifi_monitor(uint8_t ucchl,uint8_t ifup);
/*****************************************************************
 * 函数描述：设置wifi为ap模式
 * 参数： uint8_t ucchl 设置通道
 * 		 uint8_t ifup  网卡重启标识
 * 返回值： 无
 * ***************************************************************/
void strobe_wifi_ap(uint8_t ucchl,uint8_t ifup);
/*****************************************************************
 * 函数描述：获取默认网关
 * 参数： char *default_gw 网关地址缓存
 * 		 int gw_len		  获取网关长度
 * 返回值： 无
 * ***************************************************************/
void get_default_gw(char *default_gw,int gw_len);
/*****************************************************************
 * 函数描述：读取当前程序状态及执行参数
 * 参数： const char *status 当前程序状态
 * 		 const char *json	执行参数json缓存
 * 返回值： int 0 读取成功
 * 		   其他  读取失败
 * ***************************************************************/
int get_lasted_status(char *status,char *json);
/*****************************************************************
 * 函数描述：存储当前程序状态及执行参数
 * 参数： const char *status 当前程序状态
 * 		 const char *json	执行参数json缓存
 * 返回值： int 0 存储成功
 * 		   其他  存储失败
 * ***************************************************************/
int save_lasted_status(const char *status,const char *json);
/*****************************************************************
* 函数描述：ssh 关闭函数，关闭设备的ssh网络服务
* 参数：	无
* 返回值：无
****************************************************************/
void ssh_close(void);
/*****************************************************************
* 函数描述：ssh 打开函数，打开设备的ssh网络服务
* 参数：	无
* 返回值：无
****************************************************************/
void ssh_open(void);

#endif //__SCRIPT_H
