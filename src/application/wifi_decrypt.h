/*****************************************************************************
 * @file: wifi_decrypt.h
 * @author: andy.zhang
 * @email: zhangt@sinux.com.cn
 * @version: v0.1
 */
#ifndef __WIFI_DECRYPT_H
#define __WIFI_DECRYPT_H

#ifdef __cplusplus
 extern "C" {
#endif
#include "pcap.h"
/*****************************************************************************
 * Macro
 */


#define WEP_KEY_OFFSET	24 //WEP偏移
#define WPA_EAPOL_HEAD_OFFSET	32
#define WPA_EAPOL_KEYTYPE_OFFSET 35
#define WPA_EAPOL_KEYDEC_OFFSET	 38
#define WPA_KEY_OFFSET		39
#define WPA_KEYLEN_OFFSET	131


#define WEP_KEY1_STRING	"\x01\x00\x01\x00\x00\x00" //wep key1字串
#define WEP_KEY2_STRING	"\x01\x00\x02\x00\x00\x00" //wep key2字串
#define WEP_KEY4_STRING	"\x01\x00\x04\x00\x00\x00" //wep key4字串
#define WPA_EAPOLHEAD_STRING "\x88\x8e"
#define WPA_EAPOL_KEY_TYPE 0x03
#define WPA_EAPOL_KEY_DEC  0xfe
#define WPA2_EAPOL_KEY_DEC  0x02

#define KEY_MESSAGE_NONE (0<<0)
#define KEY_MESSAGE_1 (1<<0)
#define KEY_MESSAGE_2 (1<<1)
#define KEY_MESSAGE_3 (1<<2)
#define KEY_MESSAGE_4 (1<<3)

#define MAX_CAP_STA_NUM 5

struct eapol_info_t {
	uint8_t msg_id; //message sn, 4
    uint8_t ap_mac[6];
    uint8_t sta_mac[6];
} ;

struct pcap_pkthdr_32bit {
    uint32_t tv_sec; /* time stamp */
    uint32_t tv_usec;
    uint32_t caplen; /* length of portion present */
    uint32_t len;    /* length this packet (off wire) */
};
/*****************************************************************************
 * Type
 */
#define DEV_SN_LEN	4//设备号长度
#define DEV_ID_LEN	32 //ID号字符长度
 struct wifi_decrypt{
	uint8_t encrypt;
	char decr_id[32];
	uint8_t hwmode;	//protocol type
	uint8_t resp_flag; //response帧接收标识
	uint16_t channel;
	uint8_t bssid[6];
	FILE* pcap_fp;
};

/*****************************************************************************
 * Declare
 */

 extern bool DecryptOn;
 extern struct wifi_decrypt WifiDecrypt;
 /*****************************************************************
  * 函数描述：解密操作退出函数
  * 参数：	   无
  * 返回值： 无
  * ***************************************************************/
 void wifi_decrypt_exit(void);
 /*****************************************************************
  * 函数描述：握手包解析函数，用于解析存储交互的握手数据包
  * 参数：		const struct pcap_pkthdr * pkthdr  pcap缓存指针
  * 			const uint8_t * packet	数据帧缓存
  * 			uint8_t *bssid bssid
  *			uint8_t *src	源mac
  *			uint8_t *dst    目的mac
  * 返回值： 0 ：解析成功
  * 		   1：解析失败
  * ***************************************************************/
 int do_wifi_decypt(const struct pcap_pkthdr * pkthdr, const uint8_t * packet, uint8_t *bssid, uint8_t *src, uint8_t *dst);
 /*****************************************************************
  * 函数描述：解密信道设置
  * 参数：	  uint8_t ucch 设置网卡的通道号
  * 返回值： 无
  * ***************************************************************/
 void wifi_decrypt_setchl(uint8_t ucchl);
 /*****************************************************************
  * 函数描述：解密策略解析函数函数
  * 参数：	  cJSON* param json参数缓存
  * 返回值： 解析结果  0 解析正常
  * 				   其他解析 异常
  * ***************************************************************/
 int wifi_decrypt_policy_parse(cJSON* param);
 #ifdef __cplusplus
 }
#endif

#endif //__WIFI_DECRYPT_H
