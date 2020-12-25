/*
 * scan_hided_ssid.h
 *
 *  Created on: 2019-11-28
 *      Author: andy
 */

#ifndef SCAN_HIDED_SSID_H_
#define SCAN_HIDED_SSID_H_

/*****************************************************************
* 函数描述：隐藏节点线程处理函数
* 参数：	  void *arg 通道号 0 2.4G
* 						  1 5.8G
* 返回值： 无
****************************************************************/
void deauth_process(void *arg);
/*****************************************************************
* 函数描述：deauth 数据发送函数，用于调用无线网卡发送deauth数据
* 参数：	  uint8_t * bssid bssid mac
* 		  uint8_t ucchl  通道号  0 2.4G
* 		  						1 5.8G
* 		  uint8_t ucworkchl 工作信道
* 返回值： 无
****************************************************************/
void * send_deauth(uint8_t *bssid,uint8_t ucchl,uint8_t ucworkchl);
#endif /* SCAN_HIDED_SSID_H_ */
