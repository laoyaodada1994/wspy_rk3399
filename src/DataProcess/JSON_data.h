
#include<CommHeader.h>


struct scan_options {
    uint8_t angle_start;
    uint8_t angle_end;
    uint8_t angle_step;
    uint8_t channel_cnt;
    uint8_t channel_table[36];
    uint8_t cycle_period;
    bool repeat;
    bool enable;
};

struct scan_cfg {
    struct scan_options band_2_4g;
    struct scan_options band_5_8g;
};
/*******************8
 *
 * ss
 *
 */
typedef struct search_pass_rcv_send {
	int id;
	char sn[32];
	char sid[32];
    //版本
	struct var_pass {
		int id;
	    char var[32];
	} var_passn;
	//IP
    struct ip_pass {
		int     id;
	    char    ip[32];
	} ip_passn;
	//NET
	struct net_net {
	    int   id;
	    char   net[32];
	} net_netn;
	//模式
	struct gm24_58_pass {
		int 	id;
	    char 	gm24[32];
		char 	gm58[32];
	} gm24_58_passn;

	//工作状态
	struct gs24_58_pass {
		int		id;
	    char	gs24[32];
		char	gs58[32];
	} gs24_58_passn;
	//信道
	struct gc24_58_pass {
		int 	id;
		char	gc24[32];
		char	gc58[32];
	} gc24_58_passn;
	//协议
	struct	gp24_58_pass {
		int		id;
		char	gp24[32];
		char	gp58[32];
	} gp24_58_passn;
	//带宽
	struct	gb24_58_pass {
		int id;
		char gb24[32];
		char gb58[32];
	} gb24_58_passn;

	//cpu使用率
	struct cpu_pass {
	    int		id;
	    char	cpu[32];
	} cpu_passn;

	//内存使用率
	struct mem_pass {
	    int	id;
	    char	mem[32];
	} mem_passn;
	//硬盘使用率
	struct	disk_pass {
		int		id;
	    char	disk[32];
	} disk_passn;

	struct	update {
		int		id;
	 	char	update[32];
	} updaten;

	char  		error[32];

}serach_pass_send;




//热点据诶够
typedef struct Apinfo_s
{
    int		  id;
	char	mac[32];
	char	ssid[32];
	char	brand[32];
	char	ch[32];
	char 	ang[32];
	char	pro[32];
	char	pwd[32];

}Apinfo_def;

//mac
typedef struct staInfo_s{
			int    id;
	 		char	mac[32];
	}Stainfon_def;

	//带宽诉据
typedef struct brand_s{
	    	   int		id;
	    	   char		brand[32];
	}Brand_def;

/****
 *
 */
//热点数据结构
typedef struct
{



     int		id;
	 char		type[32];
     char		sn[32];
	 char		sid[128];


//   破密apinfo
	 Apinfo_def decryptn;

// 终端输入apinfo
	 Apinfo_def apAcessn;
    //断开apinfo
	 Brand_def apStopAccessn;

}ctrl_ap_rcv;


//sta客户端数据结构
typedef struct{
		int		id;
		char		type[32];
		char		sn[32];
		char		sid[32];
	struct staInter{
		int 		id;
		Apinfo_def	apInfon;
		Stainfon_def staInfon;

		}staIntern;
	Brand_def           staStopInter;

	struct staTrojan{
		int 		id;
		Apinfo_def	apInfon;
		Stainfon_def staInfon;

	    struct params
	    {
	    int		  id;
		char	interval[32];
		char	times[32];
		char	vulInterval[32];
		char	vulTimes[32];
		char 	anPage[32];
		char	anVul[32];
 	    char	winPage[32];
 	    char	winVul[32];

	    }paramsn;

	  }staTrojann;


	struct staAttach{
		int 		id;
		Apinfo_def	apInfon;
		Stainfon_def staInfon;

		}staAttachn;
	Brand_def           staStopAttach;
	struct staCapture{
		int 		id;
		Apinfo_def	apInfon;
		Stainfon_def staInfon;

		}staCapturen;
	Brand_def           staStopCapture;

}ctrl_sta_rcv;



//下位机客户端数据结构
typedef struct{
	     int		id;
	     char		type[32];
	     char		sn[32];

	     char		sid[32];
	     struct wifiScan{
	    	          int		id;

	    	 	 	 struct g24{
	    	        	    int		id;
	    	    		 	int	channel[12];
	    	    		 	int	cycle;
	    		 			int	repeat;
	    		 			struct g24_angle{

	    		 				 			int	start;
	    		 				 			int	end;
	    		 				 			int	step;
	    		 				 		}anglen;


	    		 				}g24n;
	    		 struct g58{
	    		 	   int		id;
	    		 		int	channel[12];
	    		 		int	cycle;
	    		 		int	repeat;
	    		 	   struct g58_angle{

	    		 				  int	start;
	    		 				  int	end;
	    		 				  int	step;
	    		 				  }anglen;


	    		 			}g58n;

	    		}wifiScann;

	     struct wifiStopScan{
		    	   int		id;
		    	   char		brand[32];
			}wifiStopScann;

		 struct wifimmfiles{
	    	   int		id;
		 		char	file1_url[3][32];
		}wifimmfilesn;

		 struct wifiupdate{
			    	    int		id;
				 		char	file1_url[3][32];
				}wifiupdaten;

}ctrl_machine_rcv;








///控制通道哦啊

typedef struct
{
	int		    id;
	char		sn[32];
	char		sid[32];
	char		error[32];
}ctrl_rcv_send;







/***********************************************************
 * update
*****/
//状态模式结构体
typedef struct
{
    int id;
    char  		sn[32];
 //   版本

	//2.4g
	 struct  g24_update
	{
		int id;
	    char mode[32];
	    char state[32];

	}g24;
   //2.4g
	 struct  g58_update
	{
		int id;
	    char state[32];

	}g58;

}send_status_up;



//心跳包结构
typedef struct
{
    int id;
    char  		sn[32];

}send_heart_up;


//MAC结构体
typedef struct
{
    int id;
    char 	    Time[128];
    char   		SN[32];
    unsigned int Angle;
	unsigned int RSSI;
	unsigned int Range;
	unsigned int Channel;
	char Hwmode[32];
	char Encryption[32];
	char SSID[32];
	char AP[32];
	char STA[32];
	unsigned int Frome_DS;
	unsigned int To_DS;
	char Htmode[32];

}send_mac_up;


//应用帧结构
//待定
typedef struct
{
    int id;
    char  		sn[32];

}send_APPF_up;

//揭秘帧结构
//待定
typedef struct
{
    int id;
    char   sn[32];

}send_decrypt_up;

//应用帧结构
typedef struct
{
    int id;
    char  		sn[32];
    struct  open
   	{
   		int id;
   	 char  		open1[3][32];

   	}openn;
    struct  close
   	{
   		int id;
   		char  		close1[3][32];
   	}closen;


}send_false_up;

//解密
typedef struct
{
    int id;
   	char  		decrypt_cap[1024];
}send_decrypt_Up;



/*************************************************************************
			*函数描述：mqtt客户端连接函数，用于消息发布
			*参数：	 char *json_string 	接收的json数据
					 char *json_string_send  发送的json数据
				
			
			
			
			*返回值： int
			*			 MQTTCLIENT_SUCCESS 0
			*			 MQTTCLIENT_FAILURE -1
*************************************************************************************************/
int Json_send_Pub_Tr(char *json_string ,char *json_string_send);




/*************************************************************************
		*函数描述：mqtt客户端连接函数，用于消息发布
		*参数：	 send_status_up send_status  状态模式发送
				 char *json_string_send  发送的json数据
		*返回值： int
		*			 MQTTCLIENT_SUCCESS 0
		*			 MQTTCLIENT_FAILURE -1
*************************************************************************************************/
int Json_send_Pub_Up(send_status_up send_status,char *json_string_send);
	/*************************************************************************
			*函数描述：mqtt客户端连接函数，用于消息发布
			*参数：	 send_mac_up send_status  状态模式发送
					 char *json_string_send  发送的json数据
			*返回值： int
			*			 MQTTCLIENT_SUCCESS 0
			*			 MQTTCLIENT_FAILURE -1
	*************************************************************************************************/
int Json_Mac_Pub_Up(send_mac_up send_status,char *json_string_send);
		/*************************************************************************
						*函数描述：mqtt客户端连接函数，用于消息发布
						*参数：	 send_false_up send_status  故障模式发送
								 char *json_string_send  发送的json数据
						*返回值： int
						*			 MQTTCLIENT_SUCCESS 0
						*			 MQTTCLIENT_FAILURE -1
		*************************************************************************************************/
int Json_False_Pub_Up(send_false_up send_status,char *json_string_send);




int Mqtt_Send_Pub_Update(void);


/*************************************************************************
		*函数描述：mqtt客户端连接函数，用于消息发布
		*参数：	 send_mac_up send_status  状态模式发送
				 char *json_string_send  发送的json数据
		*返回值： int
		*			 MQTTCLIENT_SUCCESS 0
		*			 MQTTCLIENT_FAILURE -1
*************************************************************************************************/
int Json_ctrl_Pub_Up(ctrl_rcv_send send_status,char *json_string_send);


void Json_ctrl_send_data(char *json_string);


/*************************************************************************
*函数描述：Json_ctrl_commnd根据上位机执行命令
*参数：	 char *json_string


*返回值： int
*			 MQTTCLIENT_SUCCESS 0
*			 MQTTCLIENT_FAILURE -1
*************************************************************************/
void Cmd_Operate(void);

int ctrl_pcap(void);

//传输通道
extern serach_pass_send json_send;
//控制通道
extern ctrl_ap_rcv  ctrl_ap_rcv_int;
extern ctrl_sta_rcv  ctrl_sta_rcv_int;
extern ctrl_machine_rcv ctrl_machine_rcv_int;
//返回信息
extern ctrl_rcv_send ctrl_rcv_send_int;



//信号量
extern sem_t sem;
