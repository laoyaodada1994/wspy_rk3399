/*****************************************************************************
 * @file: wlan_list.h
 * @author: andy.zhang
 * @email: zhangt@sinux.com.cn
 * @version: v0.1
 */
#ifndef __WLAN_LIST_H
#define __WLAN_LIST_H

#ifdef __cplusplus
 extern "C" {
#endif
/*****************************************************************************
 * Macro
 */

/*****************************************************************************
 * Type
 */

typedef struct {
    uint8_t bssid[6];
    uint8_t src[6];
    uint8_t dst[6];
    int8_t rssi;
    uint8_t angle;
    uint8_t hwmode;
    uint8_t htmode;
    uint8_t encrypt;
    uint16_t frequency;
    uint8_t ssid_len;
    char  *ssid;
    uint32_t timestamp;
    uint16_t Type;
    uint8_t workchl;
} mac_link_info_t;

struct wlan_list {
    mac_link_info_t info;
    time_t upload_tm;
    time_t cur_tm;
    struct wlan_list * pre;
    struct wlan_list * next;
};
struct wlan_list * get_wlan_list(uint8_t ucchl);
/*****************************************************************************
 * Declare
 */
void wlan_list_init(void);
/*****************************************************************
 * 函数描述：链表添加及信息更新函数，用于插入新的数据节点或更新新的数据
 * 参数：   mac_link_info_t * link 节点信息缓存
 * 		   uint8_t ucchl	通道号
 * 返回值： 无
 * ***************************************************************/
void wlan_list_add_info(mac_link_info_t * link,uint8_t ucchl);
/*****************************************************************
 * 函数描述：链表获取，用于从链表中返回节点
 * 参数：   mac_link_info_t * link 节点信息缓存
 * 		   uint8_t ucchl	通道号
 * 返回值： 无
 * ***************************************************************/
struct wlan_list * wlan_list_read_info(uint8_t ucchl);
/*****************************************************************
 * 函数描述：链表销毁函数，用于删除链表上的所有节点，并释放缓存s
 * 参数：   uint8_t ucchl	通道号
 * 返回值： 无
 * ***************************************************************/
void destroy_wlan_list(uint8_t ucchl);
void destroy_wlan_info(struct wlan_list * node);
#ifdef __cplusplus
 }
#endif

#endif //__WLAN_LIST_H
