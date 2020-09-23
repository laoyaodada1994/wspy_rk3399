/*
 * MqttProcess.c
 *
 *  Created on: Jan 2, 2019
 *      Author: lpz
 */
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "common.h"
#include "MQTTAsync.h"
#include "MQTTClient.h"
#include "MqttProcess.h"
#include "status.h"
#include "script.h"
char default_gw_ip[32];
//MqttSub        waibudingyi
//#define ADDRESS     "tcp://localhost:1883"

//#define PAYLOAD     "Hello World!"
/***********************************************************************************
 *                                  Declare
 ***********************************************************************************/
extern int rxmsg_json_parse(const char * topic, const char * json_string);
extern uint32_t PcapMsgPushTm;

/***********************************************************************************
 *                                  Variable
 ***********************************************************************************/
//#pragma pack(1)
volatile MQTTAsync_token deliveredtoken_tr;
//#pragma pack()
int disc_finished = 0;
int subscribed = 0;
// int finished = 0;
volatile enum mqtt_status MQTT_Connc_On=MqttDisconnected;
MQTTAsync Client=NULL;
/***********************************************************************************
 *                                  Function
 ***********************************************************************************/
void on_mqtt_connlost(void *context, char * cause)
{
    MQTT_Connc_On = MqttLost;

	perror("MQTT connection lost\n");
}

int on_mqtt_received(void * context, char * topic, int topicLen, MQTTAsync_message * message)
{
    if (message->payloadlen == 0) {
        fprintf(stderr, "received null message from topic: %s\n", topic);
        return -1;
    }

    myprintf("received topic %s, msgid:%d pay len %d \n", topic, message->msgid,message->payloadlen);
    
    rxmsg_json_parse(topic, message->payload);
    // memset(message->payload, 0, 10);
    printf("message->payloadlen=%d\n",message->payloadlen);
    message->payloadlen = 0;
    MQTTAsync_freeMessage(&message);
    MQTTAsync_free(topic);
    return 1;
}

void on_mqtt_published(void * context, MQTTClient_deliveryToken dt)
{
     printf("Message with token value %d delivery confirmed\n", dt);
    // deliveredtoken_up = dt;
}

void on_mqtt_disconnect(void* context, MQTTAsync_successData* response)
{
	myprintf("Successful disconnection\n");
	disc_finished = 1;
}

void on_mqtt_subscribe(void * context, MQTTAsync_successData * response)
{
	printf("subscribe topic \"%s\" succeeded\n", (char *)context);

}

void on_mqtt_subscribe_failed(void* context, MQTTAsync_failureData* response)
{
	myprintf("Subscribe failed, rc %d\n", response ? response->code : 0);
	// finished = 1;
}

void onConnect(void * context, MQTTAsync_successData* response)
{
	MQTTAsync client = (MQTTAsync)context;
	MQTTAsync_responseOptions opts = MQTTAsync_responseOptions_initializer;

	printf("MQTT connected\n");
	opts.onSuccess = on_mqtt_subscribe;
	opts.onFailure = on_mqtt_subscribe_failed;
	opts.context = MQTT_TOPIC_QUERYDOWN;
	if (MQTTAsync_subscribe(client, MQTT_TOPIC_QUERYDOWN, QOS, &opts) != MQTTASYNC_SUCCESS) {
		printf("Subscribe topic %s failed\n", MQTT_TOPIC_QUERYDOWN);
	}
	opts.context = MQTT_TOPIC_CONTROLDOWN;
	if (MQTTAsync_subscribe(client, MQTT_TOPIC_CONTROLDOWN, QOS, &opts) != MQTTASYNC_SUCCESS) {
		printf("Subscribe topic %s failed\n", MQTT_TOPIC_CONTROLDOWN);
	}
	printf("get gw\n");
	get_default_gw(default_gw_ip,sizeof(default_gw_ip));
	printf("gw is %s\n",default_gw_ip);
	MQTT_Connc_On = MqttConnected;
}
/*************************************************************************
*函数描述：mqtt连接失败函数，用于处理mqtti无法连接服务器结果
*参数：	void* context 设置的回调参数
		MQTTAsync_failureData* response 应答缓存指针
*返回值： 无
*************************************************************************/
void onConnectFailure(void* context, MQTTAsync_failureData* response)
{
//	int res =0;
//	MQTTAsync client = (MQTTAsync)context;
	myprintf("Connect failed, rc %d\n", response ? response->code : 0);
	MQTT_Connc_On = MqttDisconnected;
	//red_led_on();
	//green_led_off();
//	MQTTAsync_connectOptions conn_opts = MQTTAsync_connectOptions_initializer;
//	conn_opts.keepAliveInterval = 20;
//	conn_opts.cleansession = 1;
//	conn_opts.onSuccess = onConnect;
//	conn_opts.onFailure = onConnectFailure;
//	conn_opts.context = client;
//	if ((res=MQTTAsync_connect(client, &conn_opts)) != MQTTASYNC_SUCCESS) {
//		fprintf(stderr, "Failed to start connect, return code %d\n",res);
//        MQTT_Connc_On = MqttLost;
//		green_led_off();
//		// finished = 1;
//	}
}

void on_mqtt_async_publish_success(void * context, MQTTAsync_successData * response)
{
    MQTTAsync_message * p = &response->alt.pub.message;
    p->payloadlen = 0;
    //MQTTAsync_freeMessage(&p);

//	if (!strcmp((const char *)context, "scan"))
//		PcapMsgPushTm = 0;
}

void on_mqtt_async_publish_failed(void* context, MQTTAsync_failureData* response)
{
    printf("send failed %s\n",response->message);
}
/*************************************************************************
*函数描述：mqtt消息发布函数，用于想服务器发送mqtt数据
*参数：	const char * topic 发布消息的主题
		const uint8_t * message 消息指针
		int len	消息长度
*返回值： 无
*************************************************************************/
void mqtt_publish_msg(const char * topic, const uint8_t * message,int len)
{
	int rc = 0;
	MQTTAsync_responseOptions resp = MQTTAsync_responseOptions_initializer;
	resp.onSuccess = NULL;
	resp.onFailure = on_mqtt_async_publish_failed;
	resp.context = (void *)topic;
#if 0
    MQTTAsync_send(Client,
                   topic, 
                   strlen(message), 
                   message, 
                   2, //QoS = 2
		           0, //retained = 0
                   &resp);
#else
    MQTTAsync_message mqtt_msg = MQTTAsync_message_initializer;
    mqtt_msg.payloadlen = len;
    mqtt_msg.payload = (void *)message;
    mqtt_msg.retained = 0;
    mqtt_msg.qos = 1;
    if(Client == NULL || MQTT_Connc_On !=MqttConnected){
    	if(Client == NULL){
    		ZK_DEV_PRINT("connect status 1 %d\n",MQTT_Connc_On);
    		MQTTAsync_destroy(&Client);
    		sleep(1);
    	    MQTT_Connc_On = MqttDisconnected;
    	}
    	else
    		ZK_DEV_PRINT("connect status 2 %d\n",MQTT_Connc_On);
    	return;
    }
    if ((rc=MQTTAsync_sendMessage(Client, topic, &mqtt_msg, &resp))!=MQTTASYNC_SUCCESS){
    	printf("%s %d error:%d\n",__func__,__LINE__,rc);
    	MQTTAsync_destroy(&Client);
    	sleep(1);
    	MQTT_Connc_On = MqttDisconnected;
    }
//    MQTTAsync_message * p = &mqtt_msg;
//    MQTTAsync_freeMessage(&p);
#endif
}


/*************************************************************************
*函数描述：mqtt客户端连接函数，用于消息发布
*参数：	 MQTTClient client  mqtt发布句柄
		 char *TOPIC        发布主题
		 MQTTClient_message *pubmsg   发布消息



*返回值： int
*			 MQTTCLIENT_SUCCESS 0
*			 MQTTCLIENT_FAILURE -1
*************************************************************************/
int mqtt_connect_to_server(char * cServerip, uint16_t usPort, const char * client_id,struct SslInfo *psslinfo)
{
	MQTTAsync_connectOptions conn_opts = MQTTAsync_connectOptions_initializer;
//	MQTTAsync_disconnectOptions disc_opts = MQTTAsync_disconnectOptions_initializer;
    char cAddress[50];
    MQTTAsync_SSLOptions sslopts =MQTTAsync_SSLOptions_initializer;
	//INFOLOG(splogfile,"连接Mqtt服务器 IP:%s,端口:%d",cServerip,usPort);
	memset(cAddress, 0, sizeof(cAddress));
    if(usPort == USER_MQTT_PORT)
    {
    	sprintf(cAddress,"tcp://%s:%d", cServerip, usPort);
    }
    else if(usPort==USER_MQTT_SSL_PORT)
    {
    	sprintf(cAddress,"ssl://%s:%d", cServerip, usPort);
    }
	MQTTAsync_create(&Client, cAddress, client_id, MQTTCLIENT_PERSISTENCE_NONE, NULL);
	MQTTAsync_setCallbacks(Client, NULL, on_mqtt_connlost, on_mqtt_received, NULL);

	conn_opts.keepAliveInterval = 60;
	conn_opts.cleansession      = 1;
	conn_opts.onSuccess         = onConnect;
	conn_opts.onFailure         = onConnectFailure;
	conn_opts.context           = Client;
	if(usPort == USER_MQTT_SSL_PORT)
	{
		conn_opts.ssl = &sslopts;
//		conn_opts.ssl->trustStore = psslinfo->server_key_file; /*file of certificates trusted by client*/
//		conn_opts.ssl->keyStore = psslinfo->client_key_file; /*file of certificate for client to present to server*/
//		conn_opts.ssl->privateKey = psslinfo->client_key_pass;
//		printf("ca:%s client crt:%s cleint_Key%s\n",conn_opts.ssl->trustStore,conn_opts.ssl->keyStore,conn_opts.ssl->privateKey);
//		conn_opts.ssl->privateKeyPassword="123456";
		conn_opts.ssl->enableServerCertAuth = 0;//
		//conn_opts.ssl->verify = 1;
//		conn_opts.ssl->enabledCipherSuites="aNULL";
//		conn_opts.ssl->enableServerCertAuth = 0;
//		conn_opts.ssl->ssl_error_cb=mqttsslerror;
//
//		conn_opts.ssl->ssl_error_context=Client;
		conn_opts.ssl->struct_version = 1;
		conn_opts.ssl->sslVersion=MQTT_SSL_VERSION_TLS_1_2;
	}
	if (MQTTAsync_connect(Client, &conn_opts) == MQTTASYNC_SUCCESS) {
		sleep(1);
		return 0;
	}
	else {
        perror("Connect to MQTT seriver failed\n");
        MQTTAsync_destroy(&Client);
		return -1;
	}

    return -2;
}

void destroy_mqtt_client(void)
{
     MQTTAsync_destroy(&Client);
}





///////////////////////////////////////////////////////
///crtl



volatile MQTTAsync_token deliveredtokenct;
int disc_finishedct = 0;
int subscribedct = 0;
int finishedct = 0;

void connlostct(void *context, char *cause)
{
	MQTTAsync client = (MQTTAsync)context;
	MQTTAsync_connectOptions conn_opts = MQTTAsync_connectOptions_initializer;
	int rc;

	printf("\n tr——Connection lost\n");
	if (cause)
		myprintf("     cause: %s\n", cause);

	myprintf("Reconnecting\n");
	conn_opts.keepAliveInterval = 20;
	conn_opts.cleansession = 1;
	if ((rc = MQTTAsync_connect(client, &conn_opts)) != MQTTASYNC_SUCCESS)
	{
		myprintf("Failed to start connect, return code %d\n", rc);
		finishedct = 1;
	}
}

void onDisconnectct(void* context, MQTTAsync_successData* response)
{
	myprintf("Successful disconnection\n");
	disc_finishedct = 1;
}


void onSubscribect(void* context, MQTTAsync_successData * response)
{
	printf("Subscribe succeeded\n");
	subscribedct = 1;
}

void onSubscribeFailurect(void* context, MQTTAsync_failureData* response)
{
	myprintf("Subscribe failed, rc %d\n", response ? response->code : 0);
	finishedct = 1;
}


void onConnectct(void* context, MQTTAsync_successData* response)
{
	MQTTAsync client = (MQTTAsync)context;
	MQTTAsync_responseOptions opts = MQTTAsync_responseOptions_initializer;
	int rc;

	myprintf("Successful connection\n");

	myprintf("Subscribing to topic %s\nfor client %s using QoS%d\n\n"
           "Press Q<Enter> to quit\n\n", controlDown, controlDown_id, QOS);
	opts.onSuccess = onSubscribect;
	opts.onFailure = onSubscribeFailurect;
	opts.context = client;

	deliveredtokenct = 0;

	if ((rc = MQTTAsync_subscribe(client, controlDown, QOS, &opts)) != MQTTASYNC_SUCCESS)
	{
		myprintf("Failed to start subscribe, return code %d\n", rc);
		exit(EXIT_FAILURE);
	}
}
void onConnectFailurect(void* context, MQTTAsync_failureData* response)
{
	MQTTAsync client = (MQTTAsync)context;
	int rc;
	myprintf("Connect failed, rc %d\n", response ? response->code : 0);
	MQTTAsync_connectOptions conn_opts = MQTTAsync_connectOptions_initializer;
	conn_opts.keepAliveInterval = 20;
	conn_opts.cleansession = 1;
	conn_opts.onSuccess = onConnectct;
	conn_opts.onFailure = onConnectFailurect;
	conn_opts.context = client;
	if ((rc = MQTTAsync_connect(client, &conn_opts)) != MQTTASYNC_SUCCESS)
	{
		myprintf("Failed to start connect, return code %d\n", rc);
		finishedct = 1;
		exit(EXIT_FAILURE);
		finishedct = 1;
	}
}









/*************************************************************************
*函数描述：mqtt客户端连接函数，用于消息发布
*参数：	 char *cServerip	mqtt服务器IP
		 uint16_t usPort	mqtt服务器端口
		 void *client_pub   mqtt调用参数
		 char *CLIENTID      发布主题JUS

*返回值： int
*			 MQTTCLIENT_SUCCESS 0
*			 MQTTCLIENT_FAILURE -1
*************************************************************************/
volatile MQTTClient_deliveryToken deliveredtoken_up = 0;
int finishedup=0;



void delivered_pub(void *context, MQTTClient_deliveryToken dt)
{
    printf("Message with token value %d delivery confirmed\n", dt);
    deliveredtoken_up = dt;
}

int msgarrvd_pub(void *context, char *topicName, int topicLen, MQTTClient_message *message)
{
    //MQTTClient_freeMessage(&message);
    //MQTTClient_free(topicName);
    return 1;
}

void connlost_pub(void *context, char *cause)
{
    myprintf("\nConnection lost\n");
    myprintf("     cause: %s\n", cause);
}


