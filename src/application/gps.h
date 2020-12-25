/************************************************************************
 * @file: gps.h
 */
#ifndef __GPS_H
#define __GPS_H
#include "serialport.h"

/************************************************************************
 *  Macro
 */
#define NEO_UART_WRITE_STRING(_str_)            //hal_usart1_write((unsigned char *)(_str_),strlen(_str_), 0)

//Operation mode
#define OP_MODE_MANUALLY						'M'
#define OP_MODE_AUTOMATICALLY					'A'
//Navigation mode
#define NAV_MODE_FIX_NOT_AVALIABLE				'1'
#define NAV_MODE_2D_FIX							'2'
#define NAV_MODE_3D_FIX							'3'
/************************************************************************
 *  Type
 */
typedef struct _NMEA_protocol_t{
	uint8_t head;
	uint8_t address[2];
	uint8_t data[];

}NMEA_protocol_t;


typedef struct _time_t{
	int milliseconds;
	int seconds;
	int minute;
	int hour;
	int date;
	int month;
	int year;
	int wday;	
}utc_time_t;


struct gps_data_t{
    utc_time_t UTC_Time;
    float   latitude;	//Latitude (degrees & minutes)
    float   longitude;	//Longitude (degrees & minutes)
    float   HDOP;		//Horizontal Dilution of Precision
    float   alt;		//Altitude above mean sea level
    float   sep;		//Geoid separation: difference between ellipsoid and mean sea level
    float	spd;		//
    float	cog;
    int     quality;
    int     numSV;		//Number of satellites used (range: 0 - 12)
    int     diffAge;	//Age of differential corrections(blank when DGPS is not used)
    int     diffStation;//ID of station providing differential corrections (blank when DGPS is not used)
    char    NS;			//North/South indicator
    char    EW;			//East/West indicator
    char    uAlt;		//Altitude above mean sea level
    char    uSep;		//Separation units: meters (fixed filed)
    char    status;		//V = Data invalid or receiver warning,A = Data valid.
    char    posMode;	//Positioning mode 
    char 	mv;
    char	mvEW;
    char 	navStatus;
    char 	opMode;		//Operation mode,M = Manually set to operate in 2D or 3D mode;A = Automatically switching between 2D or 3D mode
    char 	navMode;	//1:fixnot avaliable; 2:2D fix; 3:3D fix;
};


/************************************************************************
 *  Declare
 */
//Variables
extern struct gps_data_t GPS_Data;
char * gps_process_data(char * buf);
char * nema_process_data(char * buf);
void Clear_GPS_Data(void);
void gps_parser(void);
#endif //__NEO_M8N_H
