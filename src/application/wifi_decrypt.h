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
#define WEP_FILE_OPEN 1 //wep抓包文件

#define ETHER_ADDR_LEN 6 /* length of an Ethernet address */
#define ETHER_TYPE_LEN 2 /* length of the Ethernet type field */
#define ETHER_CRC_LEN 4	 /* length of the Ethernet CRC */
#define ETHER_HDR_LEN (ETHER_ADDR_LEN * 2 + ETHER_TYPE_LEN)
#define ETHER_MIN_LEN 64		 /* minimum frame len, including CRC */
#define ETHER_MAX_LEN 1518		 /* maximum frame len, including CRC */
#define ETHER_MAX_LEN_JUMBO 9018 /* max jumbo frame len, including CRC */

#define RTC_RESOLUTION 8192
#define NULL_MAC (unsigned char *)"\x00\x00\x00\x00\x00\x00"

#define IEEE80211_FC1_DIR_MASK 0x03
#define IEEE80211_FC1_DIR_NODS 0x00	  /* STA->STA */
#define IEEE80211_FC1_DIR_TODS 0x01	  /* STA->AP  */
#define IEEE80211_FC1_DIR_FROMDS 0x02 /* AP ->STA */
#define IEEE80211_FC1_DIR_DSTODS 0x03 /* AP ->AP  */

#define IEEE80211_FC1_MORE_FRAG 0x04
#define IEEE80211_FC1_RETRY 0x08
#define IEEE80211_FC1_PWR_MGT 0x10
#define IEEE80211_FC1_MORE_DATA 0x20
#define IEEE80211_FC1_PROTECTED 0x40
#define IEEE80211_FC1_WEP 0x40 /* pre-RSNA compat */
#define IEEE80211_FC1_ORDER 0x80

#define IEEE80211_SEQ_FRAG_MASK 0x000f
#define IEEE80211_SEQ_FRAG_SHIFT 0
#define IEEE80211_SEQ_SEQ_MASK 0xfff0
#define IEEE80211_SEQ_SEQ_SHIFT 4
#define IEEE80211_FC0_VERSION_MASK 0x03
#define IEEE80211_FC0_VERSION_SHIFT 0
#define IEEE80211_FC0_VERSION_0 0x00
#define IEEE80211_FC0_TYPE_MASK 0x0c
#define IEEE80211_FC0_TYPE_SHIFT 2
#define IEEE80211_FC0_TYPE_MGT 0x00
#define IEEE80211_FC0_TYPE_CTL 0x04
#define IEEE80211_FC0_TYPE_DATA 0x08
#define IEEE80211_FC0_SUBTYPE_BEACON 0x80
#define IEEE80211_NWID_LEN 32
#define IEEE80211_FC0_SUBTYPE_CF_ACK_CF_ACK 0x70

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
struct arp_control
{
	uint8_t arp_packet[8][1024];
	int arp_packet_len[8];
	int hdrlen[8];
	unsigned int nb_arp;
	int arp_off1;
	int arp_off2;
	int arp_send_status;
	unsigned long nb_pkt_sent;
	unsigned int arp_save_count;
	uint32_t arp_count;
	uint32_t ack_count;
};
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
	uint8_t sta[6]; //modify by lpz  2021 0115 wep破解 需要sta mac地址
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
 int arp_filter_packet(unsigned char *h80211, int caplen, int f_minlen, int f_maxlen, uint8_t *ap_mac, uint8_t *sta_mac, uint8_t *dst_mac);
 void *send_buffer_thread(void *);
 /*****************************************************************
 * 函数描述：破密初始化函数，用于初始化wep数据缓存
 * 参数：	  无
 * 返回值：  0 初始化成功
 * 		  其他 初始化失败
 ****************************************************************/
 int wifi_decrypt_init();
 #ifdef __cplusplus
 }
#endif

#endif //__WIFI_DECRYPT_H
