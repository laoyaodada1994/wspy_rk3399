/*
 * MqttProcess.h
 *
 *  Created on: Jan 2, 2019
 *      Author: lpz
 */
#include "MQTTAsync.h"
#define myprintf(format,...)  printf("FILE: "__FILE__", LINE: %d:"format"\n", __LINE__, ##__VA_ARGS__)

#define QOS								   1
//MQTT topic
#define MQTT_TOPIC_QUERYDOWN               "queryDown"
#define MQTT_TOPIC_QUERYUP                 "queryUp"
#define STATUS_REPORT_TOPIC                "status"
#define MQTT_TOPIC_CONTROLDOWN             "controlDown"
#define MQTT_TOPIC_CONTROLUP               "controlUp"
#define MQTT_TOPIC_SCAN               	   "scan"
#define MQTT_TOPIC_JH               	   "jh"
#define MQTT_TOPIC_FAIL					   "fail"
#define MQTT_TOPIC_SHELL				   "shell"


#define controlDown 	"controlDown"
#define controlDown_id 	"controlDown_id"
#define controlUp		"controlUp"
#define controlUp_id	"controlUp_id"
#define	heartbeat_id			"heartbeat_id"
#define  mode_topic	       "status"
#define  mode_id	          "status_id"
#define	 scan                 "scan"
#define	 scan_id              "scan_id"
#define	 decrypt              "decrypt"
#define	 decrypt_id           "decrypt_id"
#define	 failure              "fail"
#define	 failure_id           "fail_id"

//#ifndef SRC_MQTT_MQTTPROCESS_H_
#define SRC_MQTT_MQTTPROCESS_H_


enum mqtt_status {
	MqttLost=0,
	MqttConnected,
	MqttDisconnected,
};
extern volatile enum mqtt_status MQTT_Connc_On;
extern MQTTAsync Client;
struct SslInfo
{
	char client_key_file[100];
	char client_key_pass[100];
	char server_key_file[100];
	//char* client_private_key_file;
};
#define USER_MQTT_PORT 1883 //mqtt端口
#define USER_MQTT_SSL_PORT	8883 //mqtt+ssl 端口
/*************************************************************************
*函数描述：mqtt客户端连接函数，用于消息发布
*参数：	 MQTTClient client  mqtt发布句柄
		 char *TOPIC        发布主题
		 MQTTClient_message *pubmsg   发布消息



*返回值： int
*			 MQTTCLIENT_SUCCESS 0
*			 MQTTCLIENT_FAILURE -1
*************************************************************************/
int mqtt_connect_to_server(char * serverip, uint16_t port,const char * client_id,struct SslInfo *psslinfo);

/*************************************************************************
*函数描述：mqtt客户端连接函数，用于消息sub
*参数：	 char *cServerip	mqtt服务器IP
		 uint16_t usPort	mqtt服务器端口
		 void *PUBCLIENTID   mqtt调用参数
		 char *client_TOPPIC      发布主题
          char     client_qos
*返回值： int
*			 MQTTCLIENT_SUCCESS 0
*			 MQTTCLIENT_FAILURE -1
*************************************************************************/



int * MqttClientSub(char *cServerip, uint16_t usPort,char *PUBCLIENTID);

/*************************************************************************
*函数描述：mqtt客户端连接函数，用于消息发布
*参数：	 char *cServerip	mqtt服务器IP
		 uint16_t usPort	mqtt服务器端口
		 void *client_pub   mqtt调用参数
		 char *CLIENTID      发布主题

*返回值： int
*			 MQTTCLIENT_SUCCESS 0
*			 MQTTCLIENT_FAILURE -1
*************************************************************************/


//void * MqttPubConnet(char *cServerip ,uint16_t usPort,char *PUBCLIENTID);
void * MqttPubConnet(char *cServerip, uint16_t usPort,char *PUBCLIENTID,int *flag);



/*****
 *
				*函数描述：mqtt客户端连接函数，用于消息发布
				*参数：	 char *json_string_send 故障模式发送
						 char *PUBCLIENTID 发送的json数据
						 char*PUBTOPIC
				*返回值： int
				*			 MQTTCLIENT_SUCCESS 0
				*			 MQTTCLIENT_FAILURE -1
 ************************************************************/

void Mqtt_Com_Pub_Up(void* client_pub,char *json_string_send, const char*PUBTOPIC);
/*************************************************************************
*函数描述：mqtt消息发布函数，用于想服务器发送mqtt数据
*参数：	const char * topic 发布消息的主题
		const uint8_t * message 消息指针
		int len	消息长度
*返回值： 无
*************************************************************************/
void mqtt_publish_msg(const char * topic, const uint8_t * message,int len);
void destroy_mqtt_client(void);
