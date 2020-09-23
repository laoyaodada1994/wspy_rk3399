/******************************************************************************
 *  File:    wlan_list.c
 *
 *  Author:  Andy.Zhang
 *
 *  Data:    2019-5-24
 *
 *  Version: v1.0
 *
 *  Describe:
 *
 * ****************************************************************************
 *   All rights reserved by the Sinuc co.,Ltd.
 ******************************************************************************/
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <time.h>
#include "mac80211_fmt.h"
#include "wlan_list.h"
#include "common.h"

/******************************************************************************
 *                              Variable
 ******************************************************************************/
static struct wlan_list * ListHead[2] = {NULL,NULL};
static uint32_t ListSize[2] = {0,0};
size_t PcapListMaxSize[2] = {10000,10000};

/******************************************************************************
 *                              Function
 ******************************************************************************/
/*****************************************************************
* 函数描述 : 链表头获取函数，返回对应通道的链表头指针
* 参数：   uint8_t ucchl	通道号
* 返回值： struct wlan_list * 链表指针缓存
****************************************************************/
struct wlan_list * get_wlan_list(uint8_t ucchl)
{
	return ListHead[ucchl];
}

bool is_bss_table_empty(void)
{
    return (ListHead == NULL);
}

uint32_t get_bss_table_len(uint8_t ucchl)
{
    return ListSize[ucchl];//TODO: add length
}
/*****************************************************************
* 函数描述 : 链表头获取函数，返回对应通道的链表头指针
* 参数：   const mac80211_pkt_t * packet mac80211 数据指针缓存
* 		  const uint8_t * bssid bssid mac 地址
* 		  const uint8_t * src 源地址
* 		  const uint8_t * dst 目的地址
* 返回值：  无
****************************************************************/
void parse_mac80211_addr(const mac80211_pkt_t * packet, 
                         const uint8_t * bssid, 
                         const uint8_t * src, 
                         const uint8_t * dst)
{
    switch (packet->DS) {
    case 0:  //To DS:0, From DS:0
        bssid = packet->Address3;
        src = packet->Address2;
        dst = packet->Address1;
        break;
    case 0x01:   //To DS:1, From DS:0
        bssid = packet->Address1;
        src = packet->Address2;
        dst = packet->Address3;
        break;
    case 0x02:   //To DS:0, From DS:1
        bssid = packet->Address2;
        src = packet->Address3;
        dst = packet->Address1;
        break;
    case 0x03:    //To
        //src = packet->Address4;
        dst = packet->Address3;
        //TODO: fix the WDS mode
        break;
    }
}
/*****************************************************************
 * 函数描述：链表添加及信息更新函数，用于插入新的数据节点或更新新的数据
 * 参数：   mac_link_info_t * link 节点信息缓存
 * 		   uint8_t ucchl	通道号
 * 返回值： 无
 * 修改时间： modify by lpz 20200116 修改加密类型及协议的更新条件
 * ***************************************************************/
void wlan_list_add_info(mac_link_info_t * link,uint8_t ucchl)
{
    struct wlan_list ** walk;
    struct wlan_list * first_bssid;
    time_t sec_time;
    bool ssid_valid = false;

    walk = &ListHead[ucchl];
    first_bssid = ListHead[ucchl];

//    printf("start:");
//    while ((*walk) != NULL){
//    	printf("%s %d %#02x:%#02x:%#02x:%#02x:%#02x:%#02x \n",__func__,__LINE__,
//    			(*walk)->info.bssid[0],(*walk)->info.bssid[1],(*walk)->info.bssid[2],
//    			(*walk)->info.bssid[3],(*walk)->info.bssid[4],(*walk)->info.bssid[5]);
//    	 walk = &(*walk)->next;
//    }
//    walk = &ListHead[ucchl];
    sec_time=time((time_t *) NULL);
    while ((*walk) != NULL) {
        if (memcmp((*walk)->info.bssid, link->bssid, 6) != 0) {
            walk = &(*walk)->next;
            continue;
        }

        first_bssid = *walk;//record the first item in the list what bssid is the same
//        printf("%s %d %#02x:%#02x:%#02x:%#02x:%#02x:%#02x %#02x:%#02x:%#02x:%#02x:%#02x:%#02x\n",__func__,__LINE__,
//        		first_bssid->info.bssid[0],first_bssid->info.bssid[1],first_bssid->info.bssid[2],
//        		first_bssid->info.bssid[3],first_bssid->info.bssid[4],first_bssid->info.bssid[5],
//        		link->bssid[0],link->bssid[1],link->bssid[2],
//        		link->bssid[3],link->bssid[4],link->bssid[5]);

        do {
        	if ((*walk)->info.ssid != NULL)
        	    ssid_valid = true;
            if ((!memcmp((*walk)->info.src, link->src, 6) && !memcmp((*walk)->info.dst, link->dst, 6))
              ||(!memcmp((*walk)->info.src, link->dst, 6) && !memcmp((*walk)->info.dst, link->src, 6))) { //同源同宿,只需更新一下内容
                if ((*walk)->info.rssi < link->rssi) {
                    (*walk)->info.rssi = link->rssi;
                    (*walk)->info.angle = link->angle;
                }
                if(link->ssid!=NULL){
                	if((*walk)->info.encrypt !=link->encrypt ||(*walk)->info.hwmode!=link->hwmode){
                		(*walk)->info.encrypt=link->encrypt;
						(*walk)->info.hwmode=link->hwmode;
                	}
                }
                (*walk)->upload_tm=sec_time;


                if (link->ssid != NULL&&ssid_valid==false) {
                        char * space = (char *)malloc(link->ssid_len + 1);
                        strcpyl(space, link->ssid, link->ssid_len);
                        (*walk)->info.ssid = space;
                        (*walk)->info.ssid[link->ssid_len]=0;
                        (*walk)->info.ssid_len=link->ssid_len;
                       // link->ssid_len+=1;
				}
//                if (link->ssid != NULL &&   (*walk)->info.ssid == NULL) {
//                		(*walk)->info.ssid  = (char *)malloc(link->ssid_len + 1);
//                        strcpyl((*walk)->info.ssid, link->ssid, link->ssid_len);
//                        //link->ssid = space;
//                        (*walk)->info.ssid_len=link->ssid_len+1;
//                        (*walk)->info.ssid[link->ssid_len]=0;
//
//                }
                return;
            }
            else 
                walk = &(*walk)->next;
        } while ((*walk) != NULL && !memcmp((*walk)->info.bssid, link->bssid, 6));
        //run to here means there is same bssid in the list, but no this link
        //walk = &(*walk)->pre;
        break;
    }
    if (link->Type == 2 && ssid_valid == false){
    	//printf("get packet type %#02x  ssid_valid %d\n",link->Type,ssid_valid);
    	return;
    }

    if (ListSize[ucchl] >= PcapListMaxSize[ucchl]){
    	printf("listsize %d PcapListMaxSize %d\n",ListSize[ucchl],PcapListMaxSize[ucchl]);
    	return;
    }
    if (link->ssid != NULL) {
        char * space = (char *)malloc(link->ssid_len + 1);
        strcpyl(space, link->ssid, link->ssid_len);
        link->ssid = space;
        link->ssid[link->ssid_len]=0;
       // link->ssid_len+=1;
    }

    struct wlan_list * insert = (struct wlan_list *)malloc(sizeof(struct wlan_list));
    memset(insert,0,sizeof( struct wlan_list));
	if (first_bssid != NULL) {
#if 0
		insert->next = first_bssid->next;
		insert->pre = first_bssid;
		if (first_bssid->next != NULL)
			first_bssid->next->pre = insert;
		first_bssid->next = insert;
#else
#if 0
		insert->next = first_bssid;
		if (first_bssid != ListHead[ucchl]){
				first_bssid->pre->next = insert;
				insert->pre=first_bssid->pre;
		}
		else{
			ListHead[ucchl] = insert;
		}
		first_bssid->pre=insert;
#else
		if(*walk == NULL){
			first_bssid = container_of(walk,struct wlan_list,next);
		}
		insert->next = first_bssid->next;
		insert->pre = first_bssid;
		if (first_bssid->next != NULL)
			first_bssid->next->pre = insert;
		first_bssid->next = insert;
#endif
#endif
	}
	else {
		ListHead[ucchl] = insert;
		insert->pre = NULL;
		insert->next = NULL;
	}

	memcpy(&insert->info, link, sizeof(mac_link_info_t));
	insert->upload_tm=sec_time;
	ListSize[ucchl]++;
}
/*****************************************************************
 * 函数描述：链表获取，用于从链表中返回节点
 * 参数：   mac_link_info_t * link 节点信息缓存
 * 		   uint8_t ucchl	通道号
 * 返回值： 无
 * ***************************************************************/
struct wlan_list * wlan_list_read_info(uint8_t ucchl)
{
    struct wlan_list * walk = ListHead[ucchl];
    while (walk != NULL) {
        if (walk->upload_tm <walk->cur_tm+10){ //TOGO: 如果小于10s
            walk = walk->next;
        }
        else{
        	walk->cur_tm = walk->upload_tm;
            break;
        }
    }
    return walk;
}
/*****************************************************************
 * 函数描述：链表销毁函数，用于删除链表上的所有节点，并释放缓存s
 * 参数：   uint8_t ucchl	通道号
 * 返回值： 无
 * ***************************************************************/
void destroy_wlan_list(uint8_t ucchl)
{
    struct wlan_list * walk = ListHead[ucchl];

    while (walk != NULL) {
        if (walk->info.ssid != NULL) 
            free(walk->info.ssid);
        ListHead[ucchl] = ListHead[ucchl]->next;
        // if (ListHead != NULL)
        //     ListHead->pre = NULL;
        free(walk);
        walk = ListHead[ucchl];
        ListSize[ucchl]--;
    }
    ListSize[ucchl]=0;
}

//void destroy_wlan_info(struct wlan_list * node)
//{
//    struct wlan_list * expire;
//
//    if (node == NULL)
//        return;
//    if (node->info.ssid != NULL)
//        free(node->info.ssid);
//    if (node == ListHead) {
//        expire = ListHead;
//        ListHead = ListHead->next;
//        ListHead->pre = NULL;
//        free(expire);
//        ListSize--;
//    }
//}

