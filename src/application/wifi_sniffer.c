/*************************************************************************
 *  File:       heartbeat.c
 * 
 *  Author:     Andy.Zhang
 * 
 *  Date:       2019-7-3
 *  
 *  Version:    v1.0
 * 
 *  Describe:
 ************************************************************************
 *   All rights reserved by the Sinux Co.,Ltd
 ************************************************************************/
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <malloc.h>
#include <pthread.h>
#include "DataProcess.h"
#include "mac80211_fmt.h"
#include "wifi_sniffer.h"
#include "wlan_list.h"
#include "common.h"
#include "MQTTAsync.h"
#include "MqttProcess.h"
#include "pcap.h"
#include "cJSON.h"
#include "gimbal.h"
#include "common.h"
#include "radiotap_iter.h"
#include "wifi_decrypt.h"
/***********************************************************************
 *                              Declare
 ***********************************************************************/

/***********************************************************************
 *                              Variable
 ***********************************************************************/
enum{
	BSCTRL_INIT=0, //波束控制初始化状态
	BSCTRL_SETANG,//切角度状态
	BSCTRL_SETCHL//切信道状态
};
uint8_t g_curchl[IEEE80211BANDS];
pthread_mutex_t g_tscanpolicy_mutex;//扫描策略线程互斥锁
pthread_mutex_t g_tchl_mutex[IEEE80211BANDS];//信道获取互斥锁
pthread_mutex_t g_wlanlist_mutex;//wifi信息链表

pcap_dumper_t *out_pcap[IEEE80211BANDS];//抓包文件操作符指针
bool PcapOn[IEEE80211BANDS]= {false,false};//抓包标识
//uint32_t PcapMsgPushTm[IEEE80211BANDS] = {0,0};
int8_t AntennaAngle=0;
char PcapInterface[4][WDEVNAME_LEN]={"wlan0","wlan2","wlan1","wlan3"};//= {"ath0","ath1"};
static char UploadMsgBuf[IEEE80211BANDS][1024];
struct scan_policy ScanPolicy;
MACPACK_COUNT PacketCount[IEEE80211BANDS];
/***********************************************************************
 *                              Function
 ***********************************************************************/
/*****************************************************************
 * 函数描述：启动探测函数，根据解析结果置位对应通道接口
 * 参数： bscan
 * 返回值： 无
 * ***************************************************************/
void start_sniffer()
{
	char cbuf[100];
	memset(cbuf,0,sizeof(cbuf));
	memset(PacketCount,0,sizeof(PacketCount));
	pthread_mutex_lock(&g_tscanpolicy_mutex);//上锁防止被抓包线程打断
	memset(PcapInterface,0,sizeof(PcapInterface));
	for(int i=0 ; i<IEEE80211BANDS;i++){
		if(ScanPolicy.enable[i]){
		//	sprintf(cbuf,"uci get wspy.wlan.dev%d",i);//获取设备名称
			//sys_get(cbuf,PcapInterface[i],WDEVNAME_LEN);
			strcpy(PcapInterface[i],UserCfgJson.wlan_dev[i]);
			PcapOn[i]=true;
			printf("%s\n",PcapInterface[i]);
		}
	}
	pthread_mutex_unlock(&g_tscanpolicy_mutex);
    printf("start to scan\n");
}
/*****************************************************************
 * 函数描述：停止探测函数，根据解析结果置位对应通道接口，并清理回收缓存
 * 参数：无
 * 返回值： 无
 * ***************************************************************/
void stop_sniffer(void)
{
	//pthread_mutex_lock(&g_tscanpolicy_mutex);//上锁防止被抓包线程打断
	PcapOn[IEEE80211_2G4]= PcapOn[IEEE80211_5G8]= false;
	ScanPolicy.enable[0]=0;
	ScanPolicy.enable[1]=0;
	printf("%s\n",__func__);
}
/*****************************************************************
 * 函数描述：扫描策略解析函数，用于解析上位机传下来的策略参数
 * 参数：cJSON* root jason字串结构缓存
 * 返回值： int -1 解析错误
 * 			   0 解析成功
 * ***************************************************************/
int wifi_scan_policy_parse(cJSON* root)
{  
	cJSON *params, *band,*band_5_8g=NULL;

	memset(&ScanPolicy,0,sizeof(ScanPolicy));
	params = cJSON_GetObjectItem(root, "params");
	if (params == NULL) {
		perror("scan policy config file has no params\n");
		return -1;
	}
	cJSON * cycle = cJSON_GetObjectItem(params, "cycle");//获取角度值
	if(cycle != NULL){
	   ScanPolicy.cycle_period = (uint8_t)(cJSON_GetObjectItem(params, "cycle")->valueint);
	}

	cJSON * angle = cJSON_GetObjectItem(params, "angle");//获取角度值
	if (angle != NULL) {
		ScanPolicy.angle.start = cJSON_GetObjectItem(angle, "start")->valuedouble;
		if( ScanPolicy.angle.start <MIN_ANGLE){//便携设备角度范围为-50到50
			ScanPolicy.angle.start = MIN_ANGLE;
		}
		if(ScanPolicy.angle.start >MAX_ANGLE){
			ScanPolicy.angle.start = MAX_ANGLE;
		}
		ScanPolicy.angle.end = cJSON_GetObjectItem(angle, "end")->valuedouble;
		if( ScanPolicy.angle.end <MIN_ANGLE){//便携设备角度范围为-50到50
			ScanPolicy.angle.end = MIN_ANGLE;
		}
		if( ScanPolicy.angle.end >MAX_ANGLE){
			ScanPolicy.angle.end=MAX_ANGLE;
		}
		if(ScanPolicy.angle.end > ScanPolicy.angle.start){
			ScanPolicy.angle.step = cJSON_GetObjectItem(angle, "step")->valuedouble;
			if(ScanPolicy.angle.end<=0){
				if(ScanPolicy.angle.step > (abs(ScanPolicy.angle.start)-abs(ScanPolicy.angle.end))){
					ScanPolicy.angle.step =abs(ScanPolicy.angle.start)-abs(ScanPolicy.angle.end);
					printf(" %s %d start step is %d\n",__func__,__LINE__,ScanPolicy.angle.step);
				}
			}
			else if(ScanPolicy.angle.start <=0){
				if(ScanPolicy.angle.step > (abs(ScanPolicy.angle.start)+ScanPolicy.angle.end)){
					ScanPolicy.angle.step =abs(ScanPolicy.angle.start)+ScanPolicy.angle.end;
					printf("start step is %d\n",ScanPolicy.angle.step);
				}
				printf("%d start step is %d %d %d\n",__LINE__,ScanPolicy.angle.step,ScanPolicy.angle.start,ScanPolicy.angle.end);
			}
			else
			{
				if(ScanPolicy.angle.step > (ScanPolicy.angle.end-ScanPolicy.angle.start)){
					ScanPolicy.angle.step =ScanPolicy.angle.start-ScanPolicy.angle.end;
					printf(" %s %d start step is %d\n",__func__,__LINE__,ScanPolicy.angle.step);
				}
			}
		}
		else {
			ScanPolicy.angle.step = -(int)(cJSON_GetObjectItem(angle, "step")->valueint);
			if(ScanPolicy.angle.start<=0){
				if(abs(ScanPolicy.angle.step) > (abs(ScanPolicy.angle.end)-abs(ScanPolicy.angle.start))){
					ScanPolicy.angle.step =abs(ScanPolicy.angle.start)-abs(ScanPolicy.angle.end);
					printf(" %s %d start step is %d\n",__func__,__LINE__,ScanPolicy.angle.step);
				}
			}
			else if(ScanPolicy.angle.end <=0){
				if(ScanPolicy.angle.step < (-ScanPolicy.angle.start+ScanPolicy.angle.end)){
					ScanPolicy.angle.step =(-ScanPolicy.angle.start+ScanPolicy.angle.end);
					printf(" %s %d start step is %d\n",__func__,__LINE__,ScanPolicy.angle.step);
				}
			}
			else{
				if(ScanPolicy.angle.step < (ScanPolicy.angle.end-ScanPolicy.angle.start)){
					ScanPolicy.angle.step =ScanPolicy.angle.end-ScanPolicy.angle.start;
					printf(" %s %d start step is %d\n",__func__,__LINE__,ScanPolicy.angle.step);
				}
			}
		}
	}
	band = cJSON_GetObjectItem(params, "2.4");
	if (band != NULL) {
		ScanPolicy.repeat[0] = cJSON_GetObjectItem(band, "repeat")->valueint;
		ScanPolicy.enable[0]= true;

		cJSON * channel = cJSON_GetObjectItem(band, "channel");
		ScanPolicy.channel[0].cnt = cJSON_GetArraySize(channel);
		for (int i=0;i<ScanPolicy.channel[0].cnt;i++) {
			ScanPolicy.channel[0].table[i] = atoi((const char *)cJSON_GetArrayItem(channel, i)->valuestring);
		}
	}
	else
		ScanPolicy.enable[0] = false;

	band_5_8g = cJSON_GetObjectItem(params, "5.8");
	if (band_5_8g != NULL) {
		ScanPolicy.repeat[1] = cJSON_GetObjectItem(band_5_8g, "repeat")->valueint;
		ScanPolicy.enable[1] = true;

		cJSON * channel = cJSON_GetObjectItem(band_5_8g, "channel");
		ScanPolicy.channel[1].cnt = cJSON_GetArraySize(channel);
		for (int i=0;i<ScanPolicy.channel[1].cnt;i++) {
		   ScanPolicy.channel[1].table[i] = atoi((const char *)cJSON_GetArrayItem(channel, i)->valuestring);
		}
	}
	else
	   ScanPolicy.enable[1]= false;
	return 0;
}

/*****************************************************************
 * 函数描述：扫描策略执行函数
 * 参数：	  void *arg 扫描通道
 * 返回值： 无
 * 修改内容：修改车载扫描策略，包括扫描周期改为驻留时间，起始角度可以大于终止角度 modify by lpz 20200819
 * ***************************************************************/
void wifi_scan_policy(void *arg)
{  
	uint8_t ch_idx[IEEE80211BANDS] = {0,0},bsctrl_flag=BSCTRL_INIT;
    int angle=0,step=0,res=0;
    uint32_t tick,tick_count=0;
    uint8_t ucchl1=0,ucchl2=0,chlable[IEEE80211BANDS];
    int fix_flag=0;
    uint8_t ucchl=*((uint8_t *)arg);
    char cmdbuf[64];
    chlable[0]=ucchl&0x1;
	if(chlable[0] ==1){
		ucchl1=0;
	}
	chlable[1]=((ucchl&IEEE80211BANDS)>>1);
	if(chlable[1]==1){
		ucchl2=1;
	}
    memset(cmdbuf,0,64);
#ifdef WSPY_CAR
    gimbal_init_set();
#endif
    if(!ScanPolicy.enable[0]&&!ScanPolicy.enable[1]){//判断扫描策略是否使能，如果没有使能，则推出线程处理函数
   		pthread_exit(0);
   		return ;
    }
    step = ScanPolicy.angle.step;
	if (ScanPolicy.cycle_period > 0//判断获取动态角度和变换时间
    	    &&  ScanPolicy.angle.start != ScanPolicy.angle.end &&step !=0) {
//    	        float range = (ScanPolicy[ucchl].angle.end - ScanPolicy[ucchl].angle.start)/step;
//    	        float period = (float)(ScanPolicy[ucchl].cycle_period);
//    	        tick = (int)(period / range);
	}
    else{
		printf("scan fix angle: %d\n", ScanPolicy.angle.start);
    	      //  gimbal_set_angle(ScanPolicy.band_2_4g.angle.start,channel);
		fix_flag =1;//设置固定角度
	}
	tick = ScanPolicy.cycle_period;//驻留时间 modify by lpz 20200819
	if(tick == 0){
		tick=FIX_SCAN_TIME;
	}
	tick_count=tick*10;
	 printf("channel %d Dev %d scan channels: %d\t Dev %d scan channels: %d\n",ucchl,
	    		ucchl1 ,ScanPolicy.channel[ucchl1].cnt,
	    		ucchl2 ,ScanPolicy.channel[ucchl2].cnt);
	for (int i=0;i<ScanPolicy.channel[ucchl1].cnt;i++)
		printf("%d, ", ScanPolicy.channel[ucchl1].table[i]);
	printf("\n");
	for (int i=0;i<ScanPolicy.channel[ucchl2].cnt;i++)
		   printf("%d, ", ScanPolicy.channel[ucchl2].table[i]);
	printf("\n");
    angle=ScanPolicy.angle.start;//获取起始角度
#ifdef WSPY_CAR
    memset(&gim_set_res,0,sizeof(gim_set_res));
    if(angle<-2||angle >2){
		gim_set_res.settype=GIMBAL_FRAME_TYPE_QUERY;
		gim_set_res.angle = angle+180;
		gimbal_set_angle((float)angle); //如果是车载，则设置转台角度
		gim_set_res.setflag=1;
		res=gimabl_status_parse(GIMBAL_FRAME_TYPE_QUERY,ZT_MAX_SCANTIME,1000);
		if(res!=0){
			gimbal_abort_send(GIMBAL_FRAME_TYPE_CTRL,angle);
		}
    }
#else
    for(int i=0;i<IEEE80211BANDS;i++){
		if(chlable[i]){
			res=gimbal_set_angle(angle,ScanPolicy.channel[i].table[ch_idx[i]]);//，如果是便携，则先设置一次角度和信道
			if(res <=0){
				gimbal_bsabort_send(angle,ScanPolicy.channel[i].table[ch_idx[i]]);
			}
		}
	}
//    gimbal_set_angle(angle);
#endif


    for(int i=0;i<IEEE80211BANDS;i++){
       	if(chlable[i]){
   			sprintf(cmdbuf,"iwconfig %s channel %d",PcapInterface[i],ScanPolicy.channel[i].table[ch_idx[i]]);//控制网卡信道切换
   			printf("        buf %s angle %d step %d\n",cmdbuf,angle,step);
   			system(cmdbuf);
   			pthread_mutex_lock(&g_tchl_mutex[i]);//上锁防止被抓包线程打断
   			g_curchl[i]=ScanPolicy.channel[i].table[ch_idx[i]++];
   			pthread_mutex_unlock(&g_tchl_mutex[i]);//上锁防止被抓包线程打断
       	}
    }
//    if(ScanPolicy[ucchl].channel.cnt <= 1&&fix_flag ==1){
//	    pthread_exit(0);
//    	return ;
//    }
    printf("start capture policy\n");
    uint8_t channel[IEEE80211BANDS] ;
    bsctrl_flag=BSCTRL_SETCHL;//初始化为信号控制
    while ((PcapOn[ucchl1] == true||PcapOn[ucchl2] == true)&&DecryptOn == false) {
//    	channel[ucchl1]= ScanPolicy.channel[ucchl1].table[ch_idx[ucchl1]];
//		channel[ucchl2]= ScanPolicy.channel[ucchl2].table[ch_idx[ucchl2]];
		for(int i=0;i<IEEE80211BANDS;i++){
			if(chlable[i]){
				if ((ch_idx[i] != 0 &&bsctrl_flag == BSCTRL_SETCHL)&&ch_idx[i] >= ScanPolicy.channel[i].cnt){
					ch_idx[i]=0;
					printf("channel aready set \n");
					continue;
				}
				sleep(tick);//延时信道时间
				pthread_mutex_lock(&g_tchl_mutex[i]);//上锁防止被抓包线程打断
				g_curchl[i]=channel[i] =  ScanPolicy.channel[i].table[ch_idx[i]++];
				pthread_mutex_unlock(&g_tchl_mutex[i]);//上锁防止被抓包线程打断
				sprintf(cmdbuf,"iwconfig %s channel %d",PcapInterface[i],channel[i]);//控制网卡信道切换
				system(cmdbuf);
				printf("scan channel : %d\n", channel[i]);
#ifndef WSPY_CAR
				res=gimbal_set_angle(angle,channel[i]);
				if(res <=0){
					gimbal_bsabort_send(angle,channel[i]);
				}

#endif
			}
		}
		if(ch_idx[IEEE80211_2G4] == 0 &&ch_idx[IEEE80211_5G8] ==0){ //两个频段信道均扫描完成
			bsctrl_flag = BSCTRL_SETANG;//切换角度
		}
        if(bsctrl_flag ==BSCTRL_SETANG){
        	angle += step;
        	if ( ScanPolicy.angle.step!=0) {  //动态切换角度和信号
				if(ScanPolicy.angle.end >ScanPolicy.angle.start){
					if (angle >= ScanPolicy.angle.end) {
						angle = ScanPolicy.angle.end;
						step  = -ScanPolicy.angle.step;
					}
					else if (angle <= ScanPolicy.angle.start) {
						angle = ScanPolicy.angle.start;
						step = ScanPolicy.angle.step;
					}
				}
				else
				{
					if (angle <= ScanPolicy.angle.end) {
						angle = ScanPolicy.angle.end;
						step  = -ScanPolicy.angle.step;
					}
					else if (angle >= ScanPolicy.angle.start) {
						angle = ScanPolicy.angle.start;
						step = ScanPolicy.angle.step;
					}
				}
				AntennaAngle=angle;
#ifdef WSPY_CAR
				memset(&gim_set_res,0,sizeof(gim_set_res));
				gim_set_res.recflag=0;
				gim_set_res.settype=GIMBAL_FRAME_TYPE_QUERY;
				gim_set_res.angle =angle+180;
				gimbal_set_angle((float)angle);
				usleep(20000);
				gim_set_res.setflag=1;
				gimabl_status_parse(GIMBAL_FRAME_TYPE_QUERY,ZT_MAX_SCANTIME,1000);
				if(res!=0){
					gimbal_abort_send(GIMBAL_FRAME_TYPE_CTRL,angle);
				}
#else

				for(int i=0;i<IEEE80211BANDS;i++){
					if(chlable[i]){
						res=gimbal_set_angle(angle,channel[i]);
						if(res <=0){
							gimbal_bsabort_send(angle,channel[i]);
						}
						printf("turn set angle %d channel %d\n",angle,channel[i]);
					}
				}
#endif

        	}
        	else if(fix_flag ==1){//向波控固定角度，定时切换信道
        	//if (channel > 0 && channel < 15) {
        		AntennaAngle=ScanPolicy.angle.start;
#ifdef WSPY_CAR
        		gimbal_set_angle(ScanPolicy.angle.start);
#else
        		for(int i=0;i<IEEE80211BANDS;i++){
        			if(chlable[i]){
        				gimbal_set_angle(ScanPolicy.angle.start,channel[i]);
        				printf("set fix angle %d chnanel %d\n",ScanPolicy.angle.start,channel[i]);
        			}
        			printf("chlable %d %d\n",chlable[0],chlable[1]);
        		}
        		usleep(100000);//延时100ms，避免设置到信道设置阶段再次设置
#endif
        	}
        	bsctrl_flag =BSCTRL_SETCHL;
        }
    }
	printf("%s exit\n",__func__);
    pthread_exit(0);
}
/*****************************************************************
 * 函数描述：检查mac地址函数，用于检查mac地址有效性
 * 参数：	  const uint8_t * addr 输入检查
 * 返回值： bool false mac 地址无效
 * 			    true  mac 地址有效
 * ***************************************************************/
bool is_phy_addr_availible(const uint8_t * addr)
{
    uint32_t * bdy1 = (uint32_t *)addr;
    uint16_t * bdy2 = (uint16_t *)(addr + 4);

    if (addr == NULL)
        return false;
    else if (*bdy1 == 0xffffffff && *bdy2 == 0xffff)
        return false;
    else if (*bdy1 == 0 && *bdy2 == 0)
        return false;
    return true;
}
/*****************************************************************
* 函数描述：mac帧元素有效性判断
* 参数：	  const mac80211_element_t * element mac帧元素缓存指针
* 返回值： bool false  帧有效
* 			    true 帧无效
****************************************************************/
bool is_mac80211_element_availible(const mac80211_element_t * element)
{
    if (element == NULL)
        return false;
    else if (element->len == 0)
        return false;
    return true;
}
/*****************************************************************
 * 函数描述：mac帧解析函数，用于解析mac帧字段内容
 * 参数：uint8_t *pdata  数据包缓存指针
 * 		uint16_t ulen 	数据包缓存长度
 * 		mac_link_info_t *plinkinfo mac信息缓存指针
 *		uint8_t ucchl	通道号，2.4G 5.8G
 * 返回值： 无
 * ***************************************************************/
int tag_parse(uint8_t *pdata,uint16_t ulen,mac_link_info_t *plinkinfo, uint8_t ucchl)
{
	uint8_t *puch80211=NULL;
	uint16_t ustaglen=0,usoptlen=0;
	int type = 0,loffset=0,bflag=0,bhtflag=0,bvhtflag=0;
	if(ulen < 36){
		return -1;
	}
	if(pdata[0] ==MAC80211_BEACON || pdata[0] == MAC80211_PROBE_RESP){//只解析beacon帧和
	//	printf("becon -- resp \n");
		if((pdata[34] &0x10) == 0x10){
			plinkinfo->encrypt|=STD_WEP;  //WEP加密
		}
		else{
			plinkinfo->encrypt|=STD_OPN;  //opensysterm
		}
		if(ulen >38){
			puch80211 = pdata+36;
			usoptlen=ulen-36;
			while(loffset < usoptlen)	{
				type= puch80211[0];
				ustaglen = puch80211[1];
				loffset+=ustaglen+2;
			//	printf("taglen %d offset %d usoptlen %d\n",ustaglen,loffset,usoptlen);
				if((type == TAG_VENDOR &&(ustaglen >= 8) //加密类型
					&&(memcmp(puch80211+2,"\x00\x50\xF2\x01\x01\x00",6)==0))
					||(type == TAG_RSN )){

						if(type == TAG_VENDOR){
							plinkinfo->encrypt |=STD_WPA;
						}
						if(type == TAG_RSN){
							plinkinfo->encrypt |=STD_WPA2;
						}
				}
				if(type == TAG_SUPPORT||type == TAG_SUPPORTEXT){//速率
					for(int i=0;i<ustaglen && i<8;i++){
						int bout=0;
						if(bout ==1 )
							break;

						switch(puch80211[2+i]&0x7f){
							case 0x02:
							case 0x04:
							case 0x0b:
							case 0x16:{
								plinkinfo->hwmode|=IEEE80211B;break;
							}
							case 0x0c:
							case 0x12:
							case 0x18:
							case 0x24:
							case 0x30:
							case 0x48:
							case 0x60:
							case 0x6c:{
									bout=1;
									if(bhtflag ==1){
										plinkinfo->hwmode|=IEEE80211N;
									}
									if(bvhtflag ==1&&ucchl ==IEEE80211_5G8){
										plinkinfo->hwmode|=IEEE80211AC;
									}
										//bhtflag =1;
									if(ucchl ==IEEE80211_2G4){
										plinkinfo->hwmode |=IEEE80211G;
									}
									else{
										plinkinfo->hwmode |=IEEE80211A;
									}
									break;
							}
							default:break;
						}
					}
				}
				if(type ==TAG_HTCAP){//HT能力
					if((plinkinfo->hwmode &IEEE80211G)==IEEE80211G){
						plinkinfo->hwmode|=IEEE80211N;
					}
					else if((plinkinfo->hwmode &IEEE80211A)==IEEE80211A){
						plinkinfo->hwmode|=IEEE80211N;
					}
					else{
						bhtflag =1;
					}
				}
				if(type ==TAG_VHTCAP){//VHT能力
					if((plinkinfo->hwmode &IEEE80211G)==IEEE80211G){
						plinkinfo->hwmode|=IEEE80211AC;
					}
					else if((plinkinfo->hwmode &IEEE80211A)==IEEE80211A){
						plinkinfo->hwmode|=IEEE80211AC;
					}
					else{
						bvhtflag =1;
					}
				}
				if(type ==TAG_CHAN &&ustaglen==1){//信道
					//printf("chanel:%#02x\n",puch80211[2]);
					if(ucchl ==IEEE80211_2G4){
						if(puch80211[2]>CHANNEL2G4_STOP ||puch80211[2] <CHANNEL2G4_START){ //如果信道值大于14 ，改为默认值
							plinkinfo->workchl = 1;
						}
						else{
							plinkinfo->workchl = puch80211[2];
						}
					}
					else if(ucchl ==IEEE80211_5G8){
						if(puch80211[2]> CHANNEL5G8_STOP ||puch80211[2] < CHANNEL5G8_START){ //如果信道值大于14 ，改为默认值
							plinkinfo->workchl = 36;
						}
						else{
							plinkinfo->workchl = puch80211[2];
						}
					}
				}
				if(loffset == usoptlen){
					bflag =1;
				//	printf("right packet ..............\n");
				}
				puch80211 +=ustaglen+2;
			}
			if(bflag != 1)
			{
				return -1;
			}
		}
		else
		{
			return -1;
		}
	}
	return 0;
}
/*****************************************************************
 * 函数描述：mac帧解析函数，用于解析mac帧字段内容
 * 参数：char * buffer格式化后的数据缓存
 * 		const uint8_t ** bssid 获取的BSSID
 * 		const uint8_t ** src 	源mac地址
 *		const uint8_t *dst	目的mac地址
 * 		const mac_link_info_t * info 格式化前的数据缓存
 * 		uint16_t uscaplen	抓取数据包
 * 		uint8_t	 ucchl		通道号
 * 返回值： 无
 * ***************************************************************/
int mac80211_addr_parse( mac80211_pkt_t * packet,
                       const uint8_t ** bssid,
                       const uint8_t ** src,
					   const uint8_t ** dst,
                       mac80211_element_t ** ssid,
                       mac_link_info_t *plinkinfo,
                       uint16_t uscaplen,
                       uint8_t ucchl)
{
	int res=0,buse=0;
	uint8_t *dst_tmp=NULL;
	if(packet==NULL){
		printf("%s packet error\n",__func__);
	}
    if (packet->Type == ControlFrame 
    ||  packet->Type == Reserved) {
        return -1;
    }
    // printf("type: %02x\n", packet->FrameType);

    switch (packet->FrameType) {
    case MAC80211_BEACON:
    case MAC80211_PROBE_RESP:
        *ssid = ( mac80211_element_t *)(&packet->FrameBody[12]);
        if((*ssid)->id!= 0){
        	return -1;
        }
        if(memcmp(packet->Address2,packet->Address3,6)!=0){
        	return -1;
        }
        res=tag_parse((uint8_t *)packet,uscaplen,plinkinfo,ucchl);//解析beacon和response帧
        if(res == -7)
        {
        	return res;
        }
        buse=1;
       // memset(packet->Address1,0xff,6);//将应答帧的目的地址改为广播，避免上位机处理这些信息
      //  printf("ssid : %.*s  \t pack len%d enctype %#02x id: %d\n",(*ssid)->len,(*ssid)->body,uscaplen,plinkinfo->encrypt,(*ssid)->id);

        break;
    case MAC80211_AUTH:
    	break;
    default:
    	if (packet->Type == DataFrame)//如果是数据帧，就跳出解析头过程
    		break;
    	else
    		return -1;
    }

#if 1
    switch (packet->DS) {
    case 0x00:  //To DS:0, From DS:0
        *bssid = packet->Address3;
        *src = packet->Address2;
        *dst =dst_tmp= packet->Address1;
        break;
    case 0x01:   //To DS:1, From DS:0
        *bssid = packet->Address1;
        *src = packet->Address2;
        *dst =dst_tmp= packet->Address3;
        break;
    case 0x02:   //To DS:0, From DS:1
        *bssid = packet->Address2;
        *src = packet->Address3;
        *dst  =dst_tmp= packet->Address1;
        break;
    case 0x03:
    default:
    	return -1;
    	break;
    }
    if(buse ==1&&(dst_tmp[0] &0x1) == 0x1){
    	memset(dst_tmp,0xff,6);//将应答帧的目的地址改为广播，避免上位机处理组播信息
    }
#endif
    return 0;
}
/*****************************************************************
 * 函数描述：ssid信息json字串格式化函数，用于数据信息上报服务器前的格式化转换
 * 参数：		char * buffer格式化后的数据缓存
 * 		 	const mac_link_info_t * info 格式化前的数据缓存
 * 		 	uint8_t ucchl 通道号
 * 返回值：   int 格式化之后的字串长度
 * ***************************************************************/
static int format(char * buffer, const mac_link_info_t * info,uint8_t ucchl)
                //    const mac80211_element_t * ssid)
{
    char tmp[64];
    char str[512];
    memset(str,0,512);
    //printf("ssid len %d dev sn %d \n",info->ssid_len,DeviceSN);
    sprintf(buffer, "{\"sn\":%d,", DeviceSN);
    sprintf(tmp, "\"bssid\":\"%02X-%02X-%02X-%02X-%02X-%02X\",", info->bssid[0], info->bssid[1], info->bssid[2], info->bssid[3], info->bssid[4], info->bssid[5]);
    strcat(buffer, tmp);
    sprintf(tmp, "\"src\":\"%02X-%02X-%02X-%02X-%02X-%02X\",", info->src[0], info->src[1], info->src[2], info->src[3], info->src[4], info->src[5]);
    strcat(buffer, tmp);
    if (is_phy_addr_availible(info->dst) == true) {
        sprintf(tmp, "\"dst\":\"%02X-%02X-%02X-%02X-%02X-%02X\",", info->dst[0], info->dst[1], info->dst[2], info->dst[3], info->dst[4], info->dst[5]);
        strcat(buffer, tmp);
    }
    if (info->ssid != NULL) {
    //	printf("ssid %s\n",info->ssid);
        strcat(buffer, "\"ssid\":[");
        //char * str = (char *)malloc(info->ssid_len * 3);
        int i;
#if 0
        for (i=0;i<info->ssid_len;i++) {
        	printf("%#02x,",info->ssid[i]);
        	uint8_t hi,lo;
        	hi = info->ssid[i] >> 4;
        	lo = info->ssid[i] & 0x0F;
            str[i*3] = (hi < 10)? hi + 0x30 : hi + 0x37;
            str[i*3 + 1] = (lo < 10)? lo + 0x30 : lo + 0x37;
            if(i < (info->ssid_len-1))
            {
            	str[i*3 +2] = ',';
            }
        }
        str[i*3] = 0;
        strcat(buffer, str);
        strcat(buffer, "],");
#else
        for (i=0;i<info->ssid_len;i++) {
        	 memset(str,0,info->ssid_len * 3);
        	 if(i < (info->ssid_len-1))
        	 {
        		 sprintf(str,"%d,",info->ssid[i]);
        	 }
        	 else
        	 {
        		 sprintf(str,"%d",info->ssid[i]);
        	 }
        	 strcat(buffer, str);
        }
	    strcat(buffer, "],");
#endif
    }
//    printf("\n");

    sprintf(tmp, "\"fctype\":%d,", info->Type);//modify by lpz 20201211 增加帧类型字段
	strcat(buffer, tmp);
    sprintf(tmp, "\"rssi\":%d,", info->rssi);
    strcat(buffer, tmp);
    sprintf(tmp, "\"freq\":%d,", info->frequency);
    strcat(buffer, tmp);
    sprintf(tmp, "\"channel\":%d,", info->workchl);//信道
    strcat(buffer, tmp);
    sprintf(tmp, "\"angle\":%d,", AntennaAngle);
    strcat(buffer, tmp);

    sprintf(tmp,"\"hwmode\":\"");
	int hwflag=0;
    if(ucchl == 0){
    	if((info->hwmode &IEEE80211B)==IEEE80211B){
    		strcat(tmp,"b");
    		hwflag =1;
    	}
    	if((info->hwmode &IEEE80211G)==IEEE80211G){
    		if(hwflag == 1)
    		{
    			strcat(tmp,"/");
    		}
    		hwflag=1;
    		strcat(tmp,"g");
    	}
    	if((info->hwmode &IEEE80211N)==IEEE80211N){
    		if(hwflag == 1)
			{
				strcat(tmp,"/");
			}
    		strcat(tmp,"n");
    	}
    	if(hwflag == 0){
			strcat(tmp,"unknown");
		}
    }
    else if(ucchl ==1)
    {
    	if((info->hwmode &IEEE80211A)==IEEE80211A){
    		strcat(tmp,"a");
			hwflag =1;
    	}
    	if((info->hwmode &IEEE80211N)==IEEE80211N){
    		if(hwflag == 1)
			{
				strcat(tmp,"/");
			}
			hwflag=1;
			strcat(tmp,"n");
    	}
    	if((info->hwmode &IEEE80211AC)==IEEE80211AC){
    		if(hwflag == 1)
			{
				strcat(tmp,"/");
			}
			strcat(tmp,"ac");
    	}
    	if(hwflag == 0){
    		strcat(tmp,"unknown");
    	}
    }
    else
    {
    	return -1;
    }
    strcat(tmp,"\",");
//    if((info->hwmode &IEEE80211N)==IEEE80211N){
//    	sprintf(tmp, "\"hwmode\":\"11n\",");
//    }
//    else  if((info->hwmode &IEEE80211G)==IEEE80211G){
//    	sprintf(tmp, "\"hwmode\":\"11g\",");
//    }
//    else  if((info->hwmode &IEEE80211B)==IEEE80211B){
//    	sprintf(tmp, "\"hwmode\":\"11b\",");
//    }else{
//    	sprintf(tmp, "\"hwmode\":\"unknown\",");
//    }
    strcat(buffer, tmp);
   // printf("encrypt %#02x\n",info->encrypt);
    if((info->encrypt &(STD_WPA2|STD_WPA)) == (STD_WPA2|STD_WPA)){
    	 sprintf(tmp, "\"encryption\":\"WPA-PSK/WPA2-PSK\"");
    }
    else if((info->encrypt &STD_WPA2) == STD_WPA2){
    	 sprintf(tmp, "\"encryption\":\"WPA2-PSK\"");
    }
    else if((info->encrypt &STD_WPA) == STD_WPA){
    	sprintf(tmp, "\"encryption\":\"WPA-PSK\"");
    }
    else if((info->encrypt &STD_WEP) == STD_WEP){
    	sprintf(tmp, "\"encryption\":\"WEP\"");
    }
    else if((info->encrypt &STD_OPN) == STD_OPN){
    	sprintf(tmp, "\"encryption\":\"No Encryption\"");
    }
    else{
    	sprintf(tmp, "\"encryption\":\"unknown\"");
    }
    strcat(buffer, tmp);
    strcat(buffer, "}");
    printf("ssid buf :%s\n",buffer);
    return strlen(buffer);
}


/*****************************************************************
 * 函数描述：探测信息上传函数，用于将链表格式化后的信息上传到上位机
 * 参数： uint32_t timeout 延时时间
 * 		 uint8_t ucchl 通道
 * 返回值： 无
 * ***************************************************************/
void sniffer_msg_push(uint32_t timeout,uint8_t ucchl)
{
	int len=0;
	 struct wlan_list * node=NULL;
//    if (PcapMsgPushTm[ucchl] > 0) {
//        PcapMsgPushTm[ucchl]--;
//        return;
//    }
	//pthread_mutex_lock(&g_wlanlist_mutex);
    node = wlan_list_read_info(ucchl);
    if (node == NULL){
    //	printf("no node read \n");
    	//pthread_mutex_unlock(&g_wlanlist_mutex);
    	return ;
    }


    len = format(UploadMsgBuf[ucchl], &node->info,ucchl);
  //  pthread_mutex_unlock(&g_wlanlist_mutex);
    //mqtt_publish_msg(MQTT_TOPIC_SCAN, UploadMsgBuf[ucchl]);
  //  pthread_mutex_lock(&g_tmsgsend_mutex);
    if(len >0){
    	mqtt_publish_msg(MQTT_TOPIC_SCAN,(uint8_t *)(UploadMsgBuf[ucchl]),len);
    }
    else
    {
    	ZK_DEV_PRINT("format message error\n");
    }
   // pthread_mutex_unlock(&g_tmsgsend_mutex);
    //PcapMsgPushTm[ucchl] = timeout;
    // destroy_wlan_info(link);
    // printf("%s", UploadMsgBuf);
    // printf("\n");
}
/*****************************************************************
* 函数描述：radiotap 头信息获取函数，用于解析当前radiotap类型
* 参数：	  struct ieee80211_radiotap_iterator *iter radiotap 内键指针
*  		   radiotap_data_t * pradio_data 	radiotap 数据
* 返回值：
****************************************************************/
void radio_message_get(struct ieee80211_radiotap_iterator *iter,radiotap_data_t * pradio_data)
{
	int8_t tmp_signal=0;
	switch (iter->this_arg_index) {
		case IEEE80211_RADIOTAP_TSFT:
			pradio_data->timestamp= le32toh(((uint32_t *)iter->this_arg)[0]);
			pradio_data->timestamp_us= le32toh(((uint32_t *)iter->this_arg)[1]);
			//printf("\tTSFT: %llu %u %u", le64toh(*(unsigned long long *)iter->this_arg),pradio_data->timestamp,pradio_data->timestamp_us);
			break;
		case IEEE80211_RADIOTAP_FLAGS:
			//printf("\tflags: %02x", *iter->this_arg);
			pradio_data->radio_flags=*iter->this_arg;
			break;
		case IEEE80211_RADIOTAP_RATE:
			pradio_data->data_rate=*iter->this_arg;
		//	printf("\trate: %02x\n", *iter->this_arg);
			break;
		case IEEE80211_RADIOTAP_CHANNEL:
			pradio_data->frequency = le16toh(*((uint16_t *)iter->this_arg));
		//	printf("freq: %d", pradio_data->frequency);
			break;
		case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
			tmp_signal=*iter->this_arg;
			if(pradio_data->signal < tmp_signal &&tmp_signal!=0){//modify by lpz 20201129 取最小值
				pradio_data->signal = tmp_signal;
				//printf("use signal %d\n",pradio_data->signal);
			}
			break;
		default:
			break;
	}
}
/*****************************************************************
 * 函数描述：包解析函数，从radiotap头进行包数据解析
 * 参数： uint8_t * arg 通道参数，0-2.4G 1-5.8G
 * 		 const struct pcap_pkthdr * pkthdr pcap文件格式缓存指针
 * 		 const uint8_t * packet 数据包缓存指针
 * 返回值： 无
 * 修改日期：modify by lpz 20200116 修改mac80211_pkt_t结构中timestamp的类型
 * ***************************************************************/
void parse_packet(uint8_t * arg, const struct pcap_pkthdr * pkthdr, const uint8_t * packet)
{
	int res=0,num=0;
	uint8_t ucchl=*((uint8_t *)arg);
	struct ieee80211_radiotap_iterator iter;
	radiotap_data_t t_radio_tata;
#if 0
    const radiotap_t * radiotap = (const radiotap_t *)g_ucmac;
    const mac80211_pkt_t * mac80211 = (const mac80211_pkt_t *)(g_ucmac + sizeof(radiotap_t));
#else
    const radiotap_head_t * radiotap = (const radiotap_head_t *)packet;
    mac80211_pkt_t * mac80211 = ( mac80211_pkt_t *)(packet + radiotap->it_len);
    if(mac80211 == NULL){
    	printf("mac packet error\n");
    	return ;
    }
#endif
    mac80211_element_t * ssid;
    const uint8_t * bssid, * src, * dst;
    mac_link_info_t link_info; 
    memset(&link_info,0,sizeof(link_info));
    memset(&t_radio_tata,0,sizeof(t_radio_tata));
    ssid = NULL;
    bssid = src = dst = NULL;
    res=ieee80211_radiotap_iterator_init(&iter, (struct ieee80211_radiotap_header *)packet, radiotap->it_len, NULL);
    if (res) {
		printf("malformed radiotap header (init returns %d) %d\n", res,packet[0]);
		return ;
	}
    t_radio_tata.signal=-100;
    while (!(res = ieee80211_radiotap_iterator_next(&iter))) {
    	if (iter.is_radiotap_ns){
    		radio_message_get(&iter,&t_radio_tata);
    	}
    }
    PacketCount[ucchl].totalcount++;
    if((t_radio_tata.radio_flags & IEEE80211_RADIOTAP_F_BADFCS) == IEEE80211_RADIOTAP_F_BADFCS){ //帧错误，丢弃
		PacketCount[ucchl].errcount++;
	//	pcap_dump((u_char *)(out_pcap[ucchl]),pkthdr,packet);
		return ;
    }
//    else{
//    	return ;
//    }
    //解析mac帧
    res=mac80211_addr_parse(mac80211, &bssid, &src, &dst, &ssid,&link_info,pkthdr->caplen-radiotap->it_len,ucchl);
    if (is_phy_addr_availible(bssid) == false
    ||  is_phy_addr_availible(src) == false||res == -1)
        return;
    memcpy(link_info.bssid, bssid, 6);//提取bssid ，源mac 和目的mac
    memcpy(link_info.src, src, 6);
    memcpy(link_info.dst, dst, 6);
    if (is_mac80211_element_availible(ssid)) {//判定80211帧有效性
    	if(ssid->len>=SSID_MAXLEN){ //设定SSID 最大长度
    		 link_info.ssid_len= SSID_MAXLEN;
    	}
    	else{
    		 link_info.ssid_len = ssid->len;
    	}
    	if(ssid->len == 0){
    		link_info.ssid = NULL;
    	}
    	else{
    		if(ssid->body[0] == 0){ //检测ssid字段有效性
    			link_info.ssid = NULL;
    		}
    		else{
    			link_info.ssid = ssid->body;
    		}
    	}
    }
    else {
        link_info.ssid=NULL;
    }
    if(mac80211->Type == DataFrame||link_info.workchl == 0){//如果是数据帧或未获取到工作信道，则通过频率至进行计算
       	if(ucchl == IEEE80211_2G4){
       		link_info.workchl=(t_radio_tata.frequency-FREQ2G4_START)/5 +1;
   		}
		else if(ucchl == IEEE80211_5G8){
			num=g_chl5g_num;
			for(int i =0;i<num;i++){
				if(t_radio_tata.frequency == g_charry[i].lfreq){
					link_info.workchl = g_charry[i].channel;
					break;
				}
			}
			if(link_info.workchl == 0){
				link_info.workchl=CHANNEL5G8_START;
			}
		}
    }
    link_info.timestamp = t_radio_tata.timestamp;
    link_info.frequency = t_radio_tata.frequency;
    if(t_radio_tata.signal >0){  //modify by lpz 20201119去掉大于0的信号强度
    	link_info.rssi=-t_radio_tata.signal;
    }
    else{
    	link_info.rssi = t_radio_tata.signal;
    }
    link_info.Type = mac80211->Type;
   //printf("%s %d frq %d  time %d\n",__func__,__LINE__,t_radio_tata.frequency,link_info.timestamp);
   if (DecryptOn == false){ //未开启握手包抓取
	   	  // pthread_mutex_lock(&g_wlanlist_mutex);
    	   wlan_list_add_info(&link_info,ucchl);
    	 //  pthread_mutex_unlock(&g_wlanlist_mutex);
	} else if (DecryptOn == true){ //握手包抓取
		if(WifiDecrypt.encrypt ==STD_WEP){
			do_wifi_wep_decypt(pkthdr,packet,link_info.bssid,link_info.src,link_info.dst);
		}else{
			do_wifi_decypt(pkthdr,packet,link_info.bssid,link_info.src,link_info.dst);
		}
	}
   // pcap_dump((u_char *)(out_pcap[ucchl]),pkthdr,packet);
}
/*****************************************************************
 * 函数描述：循环抓包处理函数
 * 参数： void *arg 抓包通道
 * 返回值： 无
 * ***************************************************************/
void capture_loop(void *arg)
{
    pcap_t * handle; /* Session handle */
    char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
   // struct bpf_program fp; /* The compiled filter */
//    struct pcap_pkthdr header; /* The header that pcap gives us */
//    memset(&header,0,sizeof(struct pcap_pkthdr));
    uint8_t ucchl=*((uint8_t *)arg);
       

    /* Open the session in promiscuous mode */
    handle = pcap_open_live(PcapInterface[ucchl], 1024, 1, 1000, errbuf);//设置抓包接口哦，最大抓包包长，混杂模式，超时时间，和错误信息缓存
    if (handle == NULL) {
    	 printf("%s %d dev:%s chl:%d\n",__func__,__LINE__,PcapInterface[ucchl],ucchl);
        fprintf(stderr, "Couldn't open device %s: %s\n", PcapInterface[ucchl], errbuf);
        return ;
    }
    /* Compile and apply the filter */
   /* if (pcap_compile(handle, &fp, PcapFilter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", PcapFilter, pcap_geterr(handle));
        return -2;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", PcapFilter, pcap_geterr(handle));
        return -3;
    }*/
    /* Grab a packet */
	//pcap_next(handle, &header);

    /* Print its length */

//    char cfile[50];
//    memset(cfile,0,sizeof(cfile));
//    sprintf(cfile,"/mnt/mmc/ssl/tag_%d.pcap",ucchl);
//    out_pcap[ucchl]=pcap_dump_open(handle,cfile);
    printf("Jacked a packet with length of\n");
    while(PcapOn[ucchl] == true)//如果设置了抓包标识，则一直抓包
    {
    	pcap_loop(handle, 100, parse_packet, (u_char *)arg);//设置每抓100个包，产生回调
    	//pcap_dump_flush(out_pcap[ucchl]);
    	//printf("caputer loop  %d %d \n",PcapOn[ucchl],ucchl);
    }
//    pcap_close(handle);
//    pcap_dump_close(out_pcap[ucchl]);
	printf("%s exit\n",__func__);
    pthread_exit(0);
    return ;
}
