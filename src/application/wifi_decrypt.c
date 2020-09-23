#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <fcntl.h>
#include "common.h"
#include "cJSON.h"
#include "script.h"
#include "pcap.h"
#include "status.h"
#include "wifi_sniffer.h"
#include "wifi_access.h"
#include "mac80211_atk.h"
#include "mac80211_fmt.h"
#include "wifi_decrypt.h"
/***********************************************************************************
 *                                  Declare
 ***********************************************************************************/

bool DecryptOn = false;
struct wifi_decrypt WifiDecrypt;
struct eapol_info_t EapolInfo[MAX_CAP_STA_NUM];

char file_name[128];
uint16_t packet_data_len[MAX_CAP_STA_NUM];			// key message packet data lenth
static uint8_t packet_data[MAX_CAP_STA_NUM][2048];  // key message packet data buffer
extern int wifi_atk_ap_policy_parse(cJSON* param_ap);

/***********************************************************************************
 *                                  Variable
 ***********************************************************************************/


/***********************************************************************************
 *                                  Function
 ***********************************************************************************/

/*****************************************************************
 * 函数描述：解密信道设置
 * 参数：	  uint8_t ucch 设置网卡的通道号
 * 返回值： 无
 * ***************************************************************/
void wifi_decrypt_setchl(uint8_t ucchl)
{
	char cmdbuf[128];
	memset(cmdbuf,0,sizeof(cmdbuf));
#ifdef WSPY_CAR //设置前端的角度和信道
    gimbal_set_angle(ScanPolicy[ucchl].angle.start);
#else
	gimbal_set_angle(ScanPolicy[ucchl].angle.start,WifiDecrypt.channel);
#endif
	sprintf(cmdbuf,"iwconfig %s channel %d",PcapInterface[ucchl],WifiDecrypt.channel);//控制网卡信道切换
	system(cmdbuf);

	usleep(1000);
}
/*****************************************************************
 * 函数描述：解密策略解析函数函数
 * 参数：	  cJSON* param json参数缓存
 * 返回值： 解析结果  0 解析正常
 * 				   其他解析 异常
 * ***************************************************************/
int wifi_decrypt_policy_parse(cJSON* param)
{
    if (param == NULL) {
    	return -1;
    }

	char data[64],cbuf[64];
	char *mac = NULL;
	char *key = NULL;
	char *encryption = NULL;

	memset(data, 0, sizeof(data));
	memset(&WifiDecrypt, 0, sizeof(WifiDecrypt));

	const char *protocol = NULL;
	uint8_t ucchl;
	int size = cJSON_GetArraySize(param);
	for (int i=0;i<size;i++){
		if (strcmp(cJSON_GetArrayItem(param, i)->string,"mac") == 0){//获取bssid
			mac = cJSON_GetArrayItem(param, i)->valuestring;
			getmac(mac, 1, WifiDecrypt.bssid);
			printf ("mac:%s\n", mac);
		}else if (strcmp(cJSON_GetArrayItem(param, i)->string,"ch") == 0){//获取信道
			WifiDecrypt.channel = atoi((const char *)cJSON_GetArrayItem(param, i)->valuestring);
			printf ("channel:%d\n", WifiDecrypt.channel);
		}else if (strcmp(cJSON_GetArrayItem(param, i)->string,"pro") == 0){//获取协议
			protocol = cJSON_GetArrayItem(param, i)->valuestring;
			if (strcmp(protocol,"a") == 0){
				WifiDecrypt.hwmode = IEEE80211A;
			}else if (strcmp(protocol,"b") == 0){
				WifiDecrypt.hwmode = IEEE80211G;
			}else if (strcmp(protocol,"g") == 0){
				WifiDecrypt.hwmode = IEEE80211B;
			}else if (strcmp(protocol,"n") == 0){
				WifiDecrypt.hwmode = IEEE80211N;
			}
			else{
				printf("unknow protocol:\t");
			}
			printf ("protocol:%s\n", protocol);
		}else if (strcmp(cJSON_GetArrayItem(param, i)->string,"pwd") == 0){//获取密码
			key = cJSON_GetArrayItem(param, i)->valuestring;
			printf ("key:%s\n", key);
		}else if (strcmp(cJSON_GetArrayItem(param, i)->string,"encrypt") == 0){//加密类型
			encryption = cJSON_GetArrayItem(param, i)->valuestring;
			printf ("encryption:%s\n", encryption);

			if(strcmp(encryption,"WEP") == 0){  //wep加密
				WifiDecrypt.encrypt= STD_WEP;
			}else if(strcmp(encryption,"WPA-PSK") == 0){//wpa
				WifiDecrypt.encrypt= STD_WPA;
			}
			else if(strcmp(encryption,"WPA2-PSK") == 0){//wpa2
				WifiDecrypt.encrypt= STD_WPA2;
			}
			else if(strcmp(encryption,"WPA-PSK/WPA2-PSK") == 0){//wpa/wpa2
				WifiDecrypt.encrypt= STD_WPA2;
			}
			else{
				WifiDecrypt.encrypt = STD_OPN;//无加密
			}
		}

	}
	cJSON* band = cJSON_GetObjectItem(param, "band");
	if(band == NULL){
		printf ("band==NULL\n");
		return -2;
	}
	if(strcmp(band->valuestring,"2.4") == 0 ){
		ucchl =NET2G4MAJIDX;
	}
	else if(strcmp(band->valuestring,"5.8") ==0){
		ucchl=NET5G8MAJIDX;
	}
	else{
		printf("%s\n",band->valuestring);
		return -3;
	}
	if ((mac == NULL) || (protocol == NULL)||encryption == NULL){
		return -1;
	}

//	sprintf(cbuf,"uci get wspy.wlan.dev%d",ucchl);//获取设备名称
//	sys_get(cbuf,PcapInterface[ucchl],WDEVNAME_LEN);
	//printf("%s %d chl %d dev %s\n",__func__,__LINE__,ucchl,);
	PcapOn[ucchl]=true;
	printf("pcap %d %d \n",PcapOn[ucchl],ucchl);
	DecryptOn = true;
	wifi_atkpolicy_parse(param,NULL);
    start_ap_inter();


#if 0
	for(int i=0;i<MAX_CAP_STA_NUM;i++){
		for(int j=0;j<KEY_MESSAGE_NUM;j++){
			if (EapolInfo[i].packet[j] != NULL){
				free(EapolInfo[i].packet[j]);
				EapolInfo[i].packet[j] = NULL;
			}
		}
	}

	memset(EapolInfo, 0, sizeof(struct eapol_info_t) * MAX_CAP_STA_NUM);
#else
	memset(packet_data, 0, sizeof(packet_data));//初始化pcap文件头
	for(int i=0;i<MAX_CAP_STA_NUM;i++){
			packet_data_len[i] = 0;
	}

	memset(EapolInfo, 0, sizeof(struct eapol_info_t) * MAX_CAP_STA_NUM);
	uint32_t u32sn =0;
	u32sn =htonl(DeviceSN);
	for(int i=0;i<MAX_CAP_STA_NUM;i++){
		packet_data_len[i] = 0;

		memcpy(packet_data[i] , &u32sn, sizeof(u32sn));
		packet_data_len[i] = sizeof(u32sn);
		pcapfilehead_t *pcap=(pcapfilehead_t *)(packet_data[i]+packet_data_len[i]);
		pcap->magic=htonl(0xd4c3b2a1);
		pcap->major =0x0002;// htons(0x0002);
		pcap->minor = 0x0004;//htons(0x0004);
		pcap->thiszone =0;
		pcap->sigfig =0;
		pcap->snaplen=65535;//htonl(65535);
		pcap->linktype=0x7f;//htonl(0x7f);
		packet_data_len[i]+=sizeof(pcapfilehead_t);
//		for(int j=0;j<packet_data_len[i];j++){
//			printf("%#02x,",packet_data[i][j]);
//		}
		printf("DeviceSN 0x%02x%02x%02x%02x\n", packet_data[i][0], packet_data[i][1], packet_data[i][2], packet_data[i][3]);
	}
#endif
//	crc32_init(0x4C11DB7);
	return 0;
}
/*****************************************************************
 * 函数描述：解密操作退出函数
 * 参数：	   无
 * 返回值： 无
 * ***************************************************************/
void wifi_decrypt_exit(void)
{
	PcapOn[IEEE80211_2G4] =PcapOn[IEEE80211_5G8] = false;
	sleep(1);
	DecryptOn = false;
	stop_sniffer();
	stop_ap_inter();
#if 0
	for(int i=0;i<MAX_CAP_STA_NUM;i++){
		for(int j=0;j<KEY_MESSAGE_NUM;j++){
			if (EapolInfo[i].packet[j] != NULL){
				free(EapolInfo[i].packet[j]);
				EapolInfo[i].packet[j] = NULL;
			}
		}
	}

	memset(EapolInfo, 0, sizeof(struct eapol_info_t) * MAX_CAP_STA_NUM);
#else
	for(int i=0;i<MAX_CAP_STA_NUM;i++){
		packet_data_len[i] = 0;
	}

	memset(packet_data, 0, sizeof(packet_data));
	memset(EapolInfo, 0, sizeof(struct eapol_info_t) * MAX_CAP_STA_NUM);
#endif
}

#if 0
void add_eapol_packet(struct eapol_info_t * eapol, const struct pcap_pkthdr * pkthdr, const uint8_t * packet)
{
	uint8_t *bssid = WifiDecrypt.bssid;

	if(eapol == NULL)
		return;

	if(memcmp(eapol->ap_mac, bssid, sizeof(eapol->ap_mac)) != 0){
		printf("add_eapol_packet: eapol->ap_mac dosen't match\n");
		return;
	}

	uint8_t flag = 0;

	for(int n=0; n<MAX_CAP_STA_NUM; n++){
		if (is_phy_addr_availible(EapolInfo[n].sta_mac) == false){ // different key message packet
			flag = 0;
			for(int n=0; n<MAX_CAP_STA_NUM; n++){
				if(memcmp(EapolInfo[n].sta_mac, eapol->sta_mac, sizeof(EapolInfo[n].sta_mac)) == 0){ //match sta mac
					flag = 1;
					break;
				}
			}

			if(flag == 1)
				break;

			EapolInfo[n].msg_id = eapol->msg_id;
			memcpy(EapolInfo[n].sta_mac, eapol->sta_mac, sizeof(EapolInfo[n].sta_mac));
			printf("capture %d key message packet\n",eapol->msg_id);

			memcpy(packet_data + packet_data_len, (void*)pkthdr, sizeof(struct pcap_pkthdr)); // save pcap_pkthdr
			packet_data_len += sizeof(struct pcap_pkthdr);

			memcpy(packet_data + packet_data_len, packet,pkthdr->caplen); // save packet data
			packet_data_len += pkthdr->caplen;

#if 0
			fwrite((void*)pkthdr, sizeof(struct pcap_pkthdr), 1, WifiDecrypt.pcap_fp);
			fwrite(packet, pkthdr->caplen, 1, WifiDecrypt.pcap_fp);
#endif
			break;
		}
	}

	for(int i=0; i<MAX_CAP_STA_NUM; i++){
		if(memcmp(EapolInfo[i].sta_mac, eapol->sta_mac, sizeof(EapolInfo[i].sta_mac)) == 0){ //match sta mac
			if((EapolInfo[i].msg_id & eapol->msg_id) == 0){ // different key message packet
				EapolInfo[i].msg_id |= eapol->msg_id;
				printf("capture %d key message packet\n",eapol->msg_id);

				memcpy(packet_data + packet_data_len, (void*)pkthdr, sizeof(struct pcap_pkthdr)); // save pcap_pkthdr
				packet_data_len += sizeof(struct pcap_pkthdr);

				memcpy(packet_data + packet_data_len, packet,pkthdr->caplen); // save packet data
				packet_data_len += pkthdr->caplen;

#if 0
				fwrite((void*)pkthdr, sizeof(struct pcap_pkthdr), 1, WifiDecrypt.pcap_fp);
				fwrite(packet, pkthdr->caplen, 1, WifiDecrypt.pcap_fp);
#endif
				if(EapolInfo[i].msg_id == 0x0f){ // capture 4 key message packet
//					DecryptOn = false;
//					PcapOn = false;
					trans_file(packet_data, packet_data_len);
					printf("trans_file packet_data_len %d\n",packet_data_len);
					memset(&EapolInfo, 0, sizeof(EapolInfo));
					packet_data_len = 0;
#if 0
					fclose(WifiDecrypt.pcap_fp);

					char cmd[256];
					memset(cmd, 0, sizeof(cmd));
					snprintf(cmd, sizeof(cmd),"tftp -p -l %s 192.168.3.96 ",file_name);
					printf("%s\n",cmd);
					system(cmd);
					usleep(500000);
#endif
				}
			}
			break;
		}
	}
}
#else

/*****************************************************************
 * 函数描述：握手包组帧函数，将抓取的握手包组成pcap文件，发送到上位机
 * 参数：		struct eapol_info_t *  握手包帧信息缓存指针
 * 			const struct pcap_pkthdr * pkthdr  pcap文件数据缓存指针
 * 			const uint8_t * packet	数据帧缓存
 * 返回值：  无
 * ***************************************************************/
void add_eapol_packet(struct eapol_info_t * eapol, const struct pcap_pkthdr * pkthdr, const uint8_t * packet)
{
	uint8_t *bssid = WifiDecrypt.bssid;
	if(eapol == NULL)
		return;

	if(memcmp(eapol->ap_mac, bssid, sizeof(eapol->ap_mac)) != 0){
		printf("add_eapol_packet: eapol->ap_mac dosen't match\n");
		return;
	}

	uint8_t flag = 0;
//	int sn = get_message_sn(eapol->msg_id);
//	if(sn < 0)
//		return;

	for(int n=0; n<MAX_CAP_STA_NUM; n++){
		if (is_phy_addr_availible(EapolInfo[n].sta_mac) == false){ // different key message packet
			flag = 0;
			for(int n=0; n<MAX_CAP_STA_NUM; n++){
				if(memcmp(EapolInfo[n].sta_mac, eapol->sta_mac, sizeof(EapolInfo[n].sta_mac)) == 0){ //match sta mac
					flag = 1;
					break;
				}
			}

			if(flag == 1)
				break;

			EapolInfo[n].msg_id |= eapol->msg_id;
			memcpy(EapolInfo[n].sta_mac, eapol->sta_mac, sizeof(EapolInfo[n].sta_mac));
			memcpy(packet_data[n] + packet_data_len[n], (void*)pkthdr, sizeof(struct pcap_pkthdr)); // save pcap_pkthdr
//			tmppkthdr=(struct pcap_pkthdr *)(packet_data[n] + packet_data_len[n]);
//			tmppkthdr->len +=sizeof(crc_result);
//			tmppkthdr->caplen+=sizeof(crc_result);
//			printf("%s %d i %d len1 %d len2 \n",__func__,__LINE__,n, tmppkthdr->len,tmppkthdr->caplen);
			packet_data_len[n] += sizeof(struct pcap_pkthdr);

			memcpy(packet_data[n] + packet_data_len[n], packet,pkthdr->caplen); // save packet data
			packet_data_len[n] += pkthdr->caplen;

//			crc_result = crc32(0xffffffff, (uint8_t *)packet, pkthdr->caplen);
//			memcpy(packet_data[n] + packet_data_len[n], &crc_result,sizeof(crc_result)); // crc
//			packet_data_len[n] += sizeof(crc_result);
			break;
		}
	}

	for(int i=0; i<MAX_CAP_STA_NUM; i++){
		if(memcmp(EapolInfo[i].sta_mac, eapol->sta_mac, sizeof(EapolInfo[i].sta_mac)) == 0){ //match sta mac
			if((EapolInfo[i].msg_id & eapol->msg_id) == 0){ // different key message packet
				EapolInfo[i].msg_id |= eapol->msg_id;
				memcpy(packet_data[i] + packet_data_len[i], (void*)pkthdr, sizeof(struct pcap_pkthdr)); // save pcap_pkthdr
//				tmppkthdr=(struct pcap_pkthdr *)(packet_data[i] + packet_data_len[i]);
//				tmppkthdr->len +=sizeof(crc_result);
//				tmppkthdr->caplen+=sizeof(crc_result);
//
//				printf("%s %d i %d len1 %d len2 \n",__func__,__LINE__,i, tmppkthdr->len,tmppkthdr->caplen);
				packet_data_len[i] += sizeof(struct pcap_pkthdr);

				memcpy(packet_data[i] + packet_data_len[i], packet,pkthdr->caplen); // save packet data
				packet_data_len[i] += pkthdr->caplen;

//				crc_result = crc32(0xffffffff, (uint8_t *)packet, pkthdr->caplen);
//				memcpy(packet_data[i] + packet_data_len[i], (void *)&crc_result,sizeof(crc_result)); // crc
//				packet_data_len[i] += sizeof(crc_result);
				printf("%s %d i %d msg_id %#02x\n",__func__,__LINE__,i,EapolInfo[i].msg_id );
				if(EapolInfo[i].msg_id == 0x0f){ // capture 4 key message packet
//					DecryptOn = false;
//					PcapOn = false;
					printf("%s %d i %d msg_id %#02x\n",__func__,__LINE__,i,EapolInfo[i].msg_id );
					trans_file(packet_data[i], packet_data_len[i]);
					printf("trans_file packet_data_len %d\n",packet_data_len[i]);
					EapolInfo[i].msg_id=0;
					packet_data_len[i]=4+sizeof(pcapfilehead_t);
					WifiDecrypt.resp_flag=0;
//					for(int n=0;n<MAX_CAP_STA_NUM;n++){
//						packet_data_len[n] = 0;
//					}
//
//					memset(packet_data, 0, sizeof(packet_data));
//					memset(EapolInfo, 0, sizeof(struct eapol_info_t) * MAX_CAP_STA_NUM);
				}
			}
			break;
		}
	}
}
#endif
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
int do_wifi_decypt(const struct pcap_pkthdr * pkthdr, const uint8_t * packet, uint8_t *bssid, uint8_t *src, uint8_t *dst)
{
    const radiotap_head_t * radiotap = (const radiotap_head_t *)packet;
    const mac80211_pkt_t * mac80211 = (const mac80211_pkt_t *)(packet + radiotap->it_len);
    if (DecryptOn == false)
    	return -1;

	struct eapol_info_t eapol_info;
	memset(&eapol_info, 0, sizeof(eapol_info));

	if (is_phy_addr_availible(WifiDecrypt.bssid) == false)
		return -1;

	if (memcmp(WifiDecrypt.bssid, bssid, sizeof(WifiDecrypt.bssid)) != 0)
		return -1;

	const uint8_t *pdata = (packet + radiotap->it_len);
	uint8_t subType = (mac80211->FrameType >> 4) & 0xf;
	uint8_t Type = (mac80211->FrameType >> 2) & 0x3;
//	printf("%#02x   %d \n",subType,WifiDecrypt.resp_flag);
	if ((subType == ProbeResponse) && (WifiDecrypt.resp_flag == 0)){
			WifiDecrypt.resp_flag = 1;
			for(int i=0; i<MAX_CAP_STA_NUM; i++){
				memcpy(packet_data[i] + packet_data_len[i], (void*)pkthdr, sizeof(struct pcap_pkthdr)); // save pcap_pkthdr
				packet_data_len[i] += sizeof(struct pcap_pkthdr);

				memcpy(packet_data[i] + packet_data_len[i], packet, pkthdr->caplen); // save packet data
				packet_data_len[i] += pkthdr->caplen;
			}
	}
	if (WifiDecrypt.encrypt == STD_WEP){
			if ((subType == Authentication) && (WifiDecrypt.resp_flag == 1)){

				if(memcmp(pdata+WEP_KEY_OFFSET,WEP_KEY1_STRING,6)==0){
					eapol_info.msg_id = KEY_MESSAGE_1;
				}
				else if(memcmp(pdata+WEP_KEY_OFFSET,WEP_KEY2_STRING,6)==0){
					eapol_info.msg_id = KEY_MESSAGE_2;
				}
				else if(memcmp(pdata+WEP_KEY_OFFSET,WEP_KEY4_STRING,6)==0){
					eapol_info.msg_id = KEY_MESSAGE_4;
				}
				else{
					eapol_info.msg_id = KEY_MESSAGE_3;
				}

				printf("capture key message msg_id %d\n",eapol_info.msg_id);

				if (eapol_info.msg_id != KEY_MESSAGE_NONE){ // valid eapol packet
					if(memcmp(bssid, src, 6) == 0) {//ap mac
						memcpy(eapol_info.ap_mac, src, sizeof(eapol_info.ap_mac));
						memcpy(eapol_info.sta_mac, dst, sizeof(eapol_info.sta_mac));
					} else {
						memcpy(eapol_info.ap_mac, dst, sizeof(eapol_info.ap_mac));
						memcpy(eapol_info.sta_mac, src, sizeof(eapol_info.sta_mac));
					}

					add_eapol_packet(&eapol_info, pkthdr, packet);
				}
			}
	}
	else if ((WifiDecrypt.encrypt == STD_WPA) || (WifiDecrypt.encrypt == STD_WPA2)){
			if((subType == Beacon) && (Type == DataFrame) && (WifiDecrypt.resp_flag == 1)){ //qos data frame

				if(pkthdr->caplen <WPA_KEYLEN_OFFSET+2){
					return  -1;
				}
	//printf("%#02x  %#02x %#02x %#02x\n",pdata[WPA_EAPOL_HEAD_OFFSET],pdata[WPA_EAPOL_HEAD_OFFSET+1],pdata[WPA_EAPOL_KEYTYPE_OFFSET],pdata[WPA_EAPOL_KEYDEC_OFFSET]);
				if((memcmp(pdata+WPA_EAPOL_HEAD_OFFSET,WPA_EAPOLHEAD_STRING,2)==0)&&
						(pdata[WPA_EAPOL_KEYTYPE_OFFSET] == WPA_EAPOL_KEY_TYPE)){ //EAPOL
					uint16_t flag, type, key_len;

					memcpy(&flag, pdata+WPA_KEY_OFFSET, 2);
					flag=ntohs(flag);
					type = (flag>>6) & 0xf;


					memcpy(&key_len, pdata+WPA_KEYLEN_OFFSET, 2);
					key_len=ntohs(key_len);

					if (WifiDecrypt.encrypt == STD_WPA &&(pdata[WPA_EAPOL_KEYDEC_OFFSET] == WPA_EAPOL_KEY_DEC)){
						if (type == 0x02)
							eapol_info.msg_id = KEY_MESSAGE_1;
						else if ((type == 0x04) && (key_len != 0x00))
							eapol_info.msg_id = KEY_MESSAGE_2;
						else if (type == 0x07)
							eapol_info.msg_id = KEY_MESSAGE_3;
						else if ((type == 0x04) && (key_len == 0x00))
							eapol_info.msg_id = KEY_MESSAGE_4;
						else
							eapol_info.msg_id = KEY_MESSAGE_NONE;
					} else if (WifiDecrypt.encrypt == STD_WPA2
							&&(pdata[WPA_EAPOL_KEYDEC_OFFSET] == WPA2_EAPOL_KEY_DEC)){
						if (type == 0x04)
							eapol_info.msg_id = KEY_MESSAGE_1;
						else if (type == 0x02)
							eapol_info.msg_id = KEY_MESSAGE_2;
						else if (type == 0x0f)
							eapol_info.msg_id = KEY_MESSAGE_3;
						else if (type == 0x0c)
							eapol_info.msg_id = KEY_MESSAGE_4;
						else
							eapol_info.msg_id = KEY_MESSAGE_NONE;
					}

					printf("capture key message msg_id %d\n",eapol_info.msg_id);

					if (eapol_info.msg_id != KEY_MESSAGE_NONE){ // valid eapol packet
						if(memcmp(bssid, src, 6) == 0) {//ap mac
							memcpy(eapol_info.ap_mac, src, sizeof(eapol_info.ap_mac));
							memcpy(eapol_info.sta_mac, dst, sizeof(eapol_info.sta_mac));
						} else {
							memcpy(eapol_info.ap_mac, dst, sizeof(eapol_info.ap_mac));
							memcpy(eapol_info.sta_mac, src, sizeof(eapol_info.sta_mac));
						}

						add_eapol_packet(&eapol_info, pkthdr, packet);
					}
				}
			}
		}

	return 1;
#if 0
	if((subType== Beacon) && (Type == DataFrame)){ //qos data frame
		printf("%s %d\n",__func__,__LINE__);
//		for(int i=0;i<pkthdr->caplen;i++)
//		{
//			printf("%#02x,",packet[i]);
//		}
//		printf("\n");
		printf("%#02x,%#02x,%#02x,%#02x\n",pdata[32],pdata[33],pdata[35],pdata[38]);
		if((pdata[32] == 0x88) && (pdata[33] == 0x8e)
		&& (pdata[35] == 0x03) && (pdata[38] == 0x02)){ //EAPOL
			uint16_t flag, type;
			memcpy(&flag, pdata+39, 2);
			flag=ntohs(flag);
			type = (flag>>6) & 0xf;
			printf("flag %#02x fff %#02x type %#02x\n",flag,flag>>6,type);
			if (type == 0x04)
				eapol_info.msg_id = KEY_MESSAGE_1;
			else if (type == 0x02)
				eapol_info.msg_id = KEY_MESSAGE_2;
			else if (type == 0x0f)
				eapol_info.msg_id = KEY_MESSAGE_3;
			else if (type == 0x0c)
				eapol_info.msg_id = KEY_MESSAGE_4;
			else
				eapol_info.msg_id = KEY_MESSAGE_NONE;
			printf("capture key message msg_id %d\n",eapol_info.msg_id);

			if (eapol_info.msg_id != KEY_MESSAGE_NONE){ // valid eapol packet
				if(memcmp(bssid, src, 6) == 0) {//ap mac
					memcpy(eapol_info.ap_mac, src, sizeof(eapol_info.ap_mac));
					memcpy(eapol_info.sta_mac, dst, sizeof(eapol_info.sta_mac));
				} else {
					memcpy(eapol_info.ap_mac, dst, sizeof(eapol_info.ap_mac));
					memcpy(eapol_info.sta_mac, src, sizeof(eapol_info.sta_mac));
				}

				add_eapol_packet(&eapol_info, pkthdr, packet);
			}
		}
	}
	else if((subType== ProbeResponse) && (Type == ManagementFrame)){ //qos data frame
		for(int i=0; i<MAX_CAP_STA_NUM; i++){
			if((EapolInfo[i].msg_id &0x10)==0x0){ // capture 4 key message packet
				memcpy(packet_data[i] + packet_data_len[i], (void*)pkthdr, sizeof(struct pcap_pkthdr)); // save pcap_pkthdr
//				tmppkthdr=(struct pcap_pkthdr *)(packet_data[i] + packet_data_len[i]);
//				tmppkthdr->len +=sizeof(crc_result);
//				tmppkthdr->caplen+=sizeof(crc_result);

				packet_data_len[i] += sizeof(struct pcap_pkthdr);

				memcpy(packet_data[i] + packet_data_len[i], packet,pkthdr->caplen); // save packet data
				packet_data_len[i] += pkthdr->caplen;
//				crc_result = crc32(0xffffffff, (uint8_t *)packet, pkthdr->caplen);
//				memcpy(packet_data[i] + packet_data_len[i], (void *)&crc_result,sizeof(crc_result)); // crc
//				packet_data_len[i] += sizeof(crc_result);

				EapolInfo[i].msg_id |=0x10;
				printf("%s %d i %d msgid %#02x\n",__func__,__LINE__,i,EapolInfo[i].msg_id);
				if(EapolInfo[i].msg_id == 0x1f){
					printf("%s %d i %d\n",__func__,__LINE__,i);
					trans_file(packet_data[i], packet_data_len[i]);
					packet_data_len[i]=4+sizeof(pcapfilehead_t);
					EapolInfo[i].msg_id=0;
				}
			}
		}
	}
	return 1;
#endif
}
