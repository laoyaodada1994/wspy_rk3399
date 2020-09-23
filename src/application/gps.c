/***************************************************************************************
 *  File:    neo_m8n.c
 *
 *  Author:  Andy.Zhang
 *
 *  Data:    2015-7-28
 *
 *  Version: v1.0
 *
 *  Describe: Driver file forublox neo-m8n gps module
 *
 * ************************************************************************************
 *   All rights reserved by the author.
 **************************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include "gps.h"
#include "serialport.h"


/*------------------------------Global--------------------------------------*/
struct gps_data_t GPS_Data;

/**************************************************************************************
 *   					Function
 **************************************************************************************/

void hex8_to_ascll(unsigned char hex, char *str)
{
    unsigned char bit4;

    bit4 = hex>>4;
    str[0] = (bit4>9)? (bit4+0x37):(bit4+0x30);

    bit4 = hex&0x0f;
    str[1] = (bit4>9)? (bit4+0x37):(bit4+0x30);

    //str[2] = '\0';
}

bool xdigit_to_uchar(char xdigit[2], uint8_t * uchar)
{
    uint8_t ret=0;

    if( isxdigit(xdigit[0]) && isxdigit(xdigit[1])){
        ret = (xdigit[0]>'9')? (xdigit[0]-0x37):(xdigit[0]-0x30);

        ret <<=  4;

        ret |= (xdigit[1]>'9')? (xdigit[1]-0x37):(xdigit[1]-0x30);

        *uchar = ret;

        return true;
    }

    return false;
}


uint8_t NEMA_CheckSum(char * str)
{
    char * p;
    uint8_t register sum=0;

    p = strchr(str, '$');

    if( p == NULL )
        return 0;

    while( *++p != '*' ){
        sum ^= *p;
    }

    return sum;
}

/**
 * Check if a received packet is correct
 * @param  str [the received packet string]
 * @return     [true:packet is correct; false: packet is bad]
 */
bool NEMA_CheckPacket(char * str)
{
    uint8_t sum,chk;
    char *p;

    if( str[0] != '$' )
        return false;

    p = strchr(str, '*');

    if( p == NULL)
        return false;

    sum = 0;

    while( *++str != '*' ){
        sum ^= *str;
    }

    xdigit_to_uchar(&p[1],&chk);

    if( chk == sum )
        return true;

    return false;
}


char * NEMA_CheckPacket_Ex(char * restrict str)
{
    uint8_t sum,chk;
    char *p;

    if( str[0] != '$' )
        return false;

    p = strchr(str, '*');

    if( p == NULL)
        return NULL;

    sum = 0;

    while( *++str != '*' ){
        sum ^= *str;
    }


    xdigit_to_uchar(&p[1],&chk);

    if( chk == sum ){
        return (p+6);
    }

    return NULL;
}
/**
 * Set module protocols and baudrate
 * @param  msgId       [description]
 * @param  portId      [description]
 * @param  inProto     [description]
 * @param  outProto    [description]
 * @param  baudrate    [description]
 * @param  autobauding [description]
 * @return             [description]
 */
void m8n_setProtocols_and_Baudrate(int msgId,
                                   int portId,
                                   int inProto,
                                   int outProto,
                                   unsigned int baudrate,
                                   int autobauding)
{
    char str[64];
    uint8_t chk;

    sprintf(str,"$PUBX,%d,%d,%04d,%04d,%d,%d*00\r\n",
            msgId,
            portId,
            inProto,
            outProto,
            baudrate,
            autobauding);

    chk = NEMA_CheckSum(str);

    hex8_to_ascll( chk, &str[strlen(str)-4]);

    NEO_UART_WRITE_STRING(str);
}




/*
static void read_gga(char * str)
{
	char *p, temp[2];

	p = strtok( str, ',');

	if( strcmp(p, "$GPGGA") )
		return;

	p = strtok( NULL, ',');

	sscanf("%2d%2d%2d.%3d", &UTC_Time.hour,&UTC_Time.minutes,&UTC_Time.seconds,&UTC_Time.milliseconds);
}
*/



static void parse_gga(char * restrict str)
{
	int chk;
    /*char * end;

     if checksum is bad 
    if( NULL == ( end = NEMA_CheckPacket_Ex( str )) )
        return NULL;
*/
    if( strstr(str, "$GNGGA") == NULL )
        return;

    GPS_Data.UTC_Time.hour          = 0;
    GPS_Data.UTC_Time.minute        = 0;
    GPS_Data.UTC_Time.seconds       = 0;
    GPS_Data.UTC_Time.milliseconds  = 0;
    GPS_Data.latitude               = 0;
    GPS_Data.NS                     = 0;
    GPS_Data.longitude              = 0;
    GPS_Data.EW                     = 0;
    GPS_Data.quality                = 0;
    GPS_Data.numSV                  = 0;
    GPS_Data.HDOP                   = 0;
    GPS_Data.alt                    = 0;
    GPS_Data.uAlt                   = 0;
    GPS_Data.sep                    = 0;
    GPS_Data.uSep                   = 0;
    GPS_Data.diffAge                = 0;
    GPS_Data.diffStation            = 0;


	sscanf( str,"$GNGGA,%2d%2d%2d.%2d,%f,%c,%f,%c,%d,%d,%f,%f,%c,%f,%c,%d,%d,*%x\r\n",
                        &GPS_Data.UTC_Time.hour,
                        &GPS_Data.UTC_Time.minute,
                        &GPS_Data.UTC_Time.seconds,
                        &GPS_Data.UTC_Time.milliseconds,
                        &GPS_Data.latitude,
                        &GPS_Data.NS,
                        &GPS_Data.longitude,
                        &GPS_Data.EW,
                        &GPS_Data.quality,
                        &GPS_Data.numSV,
                        &GPS_Data.HDOP,
                        &GPS_Data.alt,
                        &GPS_Data.uAlt,
                        &GPS_Data.sep,
                        &GPS_Data.uSep,
                        &GPS_Data.diffAge,
			            &GPS_Data.diffStation,
                        &chk);
    //return end;
}

static void parse_gll(char * restrict str)
{
    int cs;
    /* char * end;

    if checksum is bad 
    if( NULL == ( end = NEMA_CheckPacket_Ex( str ) ) )
        return NULL;
*/
    if( strstr(str, "$GNGLL") == NULL )
        return ;

    GPS_Data.latitude               = 0;
    GPS_Data.NS                     = 0;
    GPS_Data.longitude              = 0;
    GPS_Data.EW                     = 0;
    GPS_Data.UTC_Time.hour          = 0;
    GPS_Data.UTC_Time.minute        = 0;
    GPS_Data.UTC_Time.seconds       = 0;
    GPS_Data.UTC_Time.milliseconds  = 0;
    GPS_Data.status                 = 0;
    GPS_Data.posMode                = 0;

    sscanf( str,"$GNGLL,%f,%c,%f,%c,%2d%2d%2d.%2d,%c,%c,*%x\r\n",
                        &GPS_Data.latitude,
                        &GPS_Data.NS,
                        &GPS_Data.longitude,
                        &GPS_Data.EW,
                        &GPS_Data.UTC_Time.hour,
                        &GPS_Data.UTC_Time.minute,
                        &GPS_Data.UTC_Time.seconds,
                        &GPS_Data.UTC_Time.milliseconds,
                        &GPS_Data.status,
                        &GPS_Data.posMode,
                        &cs);
    //return end;
}

#if 0
/**
 * GNSS Satellites in View
 * @param str [received string form the min module]
 */
static void parse_gsv(char * restrict str)
{
    int cs;
    char numMsg,msgNum;

    sscanf( str,"GSV,%c,%c,",
                        &numMsg,
                        &msgNum);
}
#endif

/**
 * Recommended Minimum data
 * @param str [description]
 */
static void parse_rmc( char * restrict str)
{
    int cs;
/*    char * end;

     if checksum is bad 
    if( NULL == ( end = NEMA_CheckPacket_Ex( str ) ) )
        return NULL;
*/
    if( strstr(str, "$GNRMC") == NULL )
        return ;

    GPS_Data.UTC_Time.hour          = 0;
    GPS_Data.UTC_Time.minute        = 0;
    GPS_Data.UTC_Time.seconds       = 0;
    GPS_Data.UTC_Time.milliseconds  = 0;
    GPS_Data.status                 = 0;
    GPS_Data.latitude               = 0;
    GPS_Data.NS                     = 0;
    GPS_Data.longitude              = 0;
    GPS_Data.EW                     = 0;
    GPS_Data.spd                    = 0;
    GPS_Data.cog                    = 0;
    GPS_Data.UTC_Time.date          = 0;
    GPS_Data.UTC_Time.month         = 0;
    GPS_Data.UTC_Time.year          = 0;
    GPS_Data.mv                     = 0;
    GPS_Data.mvEW                   = 0;
    GPS_Data.posMode                = 0;
    GPS_Data.navStatus              = 0;

    sscanf( str,"$GNRMC,%2d%2d%2d.%2d,%c,%f,%c,%f,%c,%f,%f,%2d%2d%2d,%c,%c,%c,%c,*%x\r\n",
                        &GPS_Data.UTC_Time.hour,
                        &GPS_Data.UTC_Time.minute,
                        &GPS_Data.UTC_Time.seconds,
                        &GPS_Data.UTC_Time.milliseconds,
                        &GPS_Data.status,
                        &GPS_Data.latitude,
                        &GPS_Data.NS,
                        &GPS_Data.longitude,
                        &GPS_Data.EW,
                        &GPS_Data.spd,
                        &GPS_Data.cog,
                        &GPS_Data.UTC_Time.date,
                        &GPS_Data.UTC_Time.month,
                        &GPS_Data.UTC_Time.year,
                        &GPS_Data.mv,
                        &GPS_Data.mvEW,
                        &GPS_Data.posMode,
                        &GPS_Data.navStatus,
                        &cs);

    //return end;
}


/**
 * GNSS DOP and Active Satellites
 * @param str [received string]
 */
static void parse_gsa(char * restrict str)
{/*
    char * end;

     if checksum is bad 
    if( NULL == ( end = NEMA_CheckPacket_Ex( str ) ) )
        return NULL;
*/
    if( strstr(str, "$GNGSA") == NULL )
        return ;

    sscanf( str,"$GNGSA,%c,%c,",
                        &GPS_Data.opMode,
                        &GPS_Data.navMode
                       );

    //return end;
}


char * gps_process_data(char * buf)
{
	char * restrict p = buf;

    /* otherwise, what sort of message is it */

    if( NULL == (p = strstr(buf, "$G")) ){
        return p;
    }
    /* if checksum is bad
    if( NEMA_CheckPacket(buf) == false )
        return p;*/

    /* 1. Global positioning system fix data*/
    if( NULL != (p = strstr(buf, "$GNGGA")) ){
        parse_gga(p);
        return p;
    }
    /* 2. Latitude and longitude, with time of position fix and status */
    else if( NULL != (p = strstr(buf, "$GNGLL")) ){
        parse_gll(p);

        return p;
    }
    /* 3. Recommended Minimum data */
    else if( NULL != (p = strstr(buf, "$GNRMC")) ){
        parse_rmc( p );

        return p;
    }
    /* 4. GNSS DOP and Active Satellites */
    else if( NULL != (p = strstr(buf, "$GNGSA")) ){
        parse_gsa( p );

        return p;
    }

    return p;
}

/**
 * Clear all the GPS data
 */
void Clear_GPS_Data(void)
{
    memset(&GPS_Data, 0, sizeof(struct gps_data_t));
}

//void gps_parser(void)
//{
//    int * port;
//    size_t rxlen;
//    char rxbuffer[1024];
//
//    port = serial_open("/dev/ttyUSB0", 19200, 8, 1, 'N');
//    if (port == NULL) {
//        perror("can not open the port\n");
//        return;
//    }
//
//    for (;;) {
//        rxlen = serial_readline(*port, rxbuffer, sizeof(rxbuffer), 1000);
//        if (rxlen > 0) {
//            gps_process_data(rxbuffer);
//            printf("%.*s", rxlen, rxbuffer);
//            printf("latitude:%f, longitude:%f\n", GPS_Data.latitude, GPS_Data.longitude);
//        }
//    }
//}
