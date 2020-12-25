/******************************************************************************
 *  @file: mac80211_fmt.h
 */
#ifndef __MAC80211_FMT_H
#define __MAC80211_FMT_H

/******************************************************************************
 *  Macro
 */
#define SNIFF_PKT_HEAD          (0x58484B5A) //"ZKHX"
#define SNIFF_PKT_TAIL          (0xED)
#define SNIFF_PKT_MIN_SIZE      (23)
#define IEEE80211_TYPE_a        ('a')   //802.11 a
#define IEEE80211_TYPE_b        ('b')   //802.11 b
#define IEEE80211_TYPE_g        ('g')   //802.11 g
#define IEEE80211_TYPE_n        ('n')   //802.11 n
#define IEEE80211_TYPE_ac       ('c')   //802.11 ac


#define MAC80211_ACK             0xD4
#define MAC80211_CTS             0xC4
#define MAC80211_RTS             0xB4
#define MAC80211_BEACON          0x80
#define MAC80211_PROBE_RESP      0x50
#define MAC80211_AUTH            0xB0
#define MAC80211_DATA		     0x08


#define BAD_FCS	0x40
/******************************************************************************
 *  Type
 */
#define WDEVNAME_LEN	10	//设备名称长度，最多10字节
#define IEEE80211BANDS	2 //通道数量2,2.4和5.8
enum ieee80211_bands{
	IEEE80211_2G4 =0,
	IEEE80211_5G8
};

enum mac80211_type_t {
    ManagementFrame = 0x00,
    ControlFrame    = 0x01,
    DataFrame       = 0x02,
    Reserved        = 0x03,
};

enum mac80211_subtype_t {
    /*part1 managment type */
    AssociationRequest      = 0x0,
    AssociationReponse      = 0x1,
    ReassociationRequest    = 0x2,
    ReassociationResponse   = 0x3,
    ProbeRequest            = 0x4,
    ProbeResponse           = 0x5,
    TimingAdvertisement     = 0x06,

    //Reserved
    Beacon                  = 0x8,
    ATIM                    = 0x9, //Announcement traffic indication massage
    Disassocation           = 0x0A,
    Authentication          = 0x0B,
    Deathentication         = 0x0C,
    Action                  = 0x0D,
    ActionNoAck             = 0x0E,
    //Reserved

    /*part2 control type */
    BeamformingReportPoll   = 0x04,
    VHT_NDP_Announcement    = 0x05,
    ControlFrameExtension   = 0x06,
    ControlWrapper          = 0x07,
    BlockAckReq             = 0x08, //Block Ack Request
    BlockAck                = 0x09, //Block Ack
    PowerSavePoll           = 0x0A,
    RTS                     = 0x0B, //Request to Send
    CTS                     = 0x0C, //Clear to send
    ACK                     = 0x0D, //Acknowledgment
    CF_End                  = 0x0E, //Contention-Free End
    CFEnd_CFAck             = 0x0F,

    /*part3 data type */
    Data                    = 0x00,
    Data_CFAck              = 0x01,
    Data_CFPoll             = 0x02,
    Data_CFAck_CFPoll       = 0x03,
    Null                    = 0x04,
    CFAck                   = 0x05,
    CFPoll                  = 0x06,
    CFAck_CFPoll            = 0x07,
};

enum pkt_direct_t {
     STA_to_STA      = 0x00, //To DS:0, From DS:0
     STA_to_AP       = 0x01, //To DS:1, From DS:0
     AP_to_STA       = 0x02, //To DS:0, From DS:1
     AP_to_AP        = 0x03, //To DS:1, From DS:1
 };

typedef struct {
    union {
        uint16_t FrameControl;
        struct {
            uint16_t ProtocolVersion:2;
            uint16_t Type:2;
            uint16_t Subtype:4;
            uint16_t ToDS:1;
            uint16_t FromDS:1;
            uint16_t MoreFlag:1;
            uint16_t Retry:1;
            uint16_t PwrMgt:1;
            uint16_t MoreData:1;
            uint16_t WEP:1;
            uint16_t Order:1;
        };
        struct {
            uint8_t FrameType;
            uint8_t DS:2;
        };
    };
    uint16_t Duration;
    uint8_t  Address1[6];
    uint8_t  Address2[6];
    uint8_t  Address3[6];
    uint16_t  Sequence;
    // uint8_t  Address4[6];
    uint8_t  FrameBody[2312 + 4];
} __attribute__((packed)) mac80211_pkt_t; //

struct mac80211_info_t {
    int rssi;
    int encryption;
    uint8_t ap[6];
    uint8_t sta[6];
    bool ToDS;
    bool FromDS;
    int htmode;
    char ssid[32];
};
#define SSID_MAXLEN 64//ssid 最大长度
typedef struct {
    uint8_t id;
    uint8_t len;
    char body[SSID_MAXLEN]; //ssid 最大长度
} mac80211_element_t;

struct ma80211_beacon {
    uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t capability;
    uint8_t element[1];
};
/*
{
  "Time": 1555495208000,
  "SN": "AF0001",
  "Angle": 59,
  "RSSI": -70,
  "Channel": 165,
  "Hwmode": "11ac",
  "encryption": "WPA2-PSK",
  "SSID": "Sinux-Guest",
  "AP": "F8:C3:9E:1A:2B:3C",
  "STA": "F0:18:98:41:42:43",
  "Frome DS":true,
  "To DS":false,
  "Htmode": "HT20",
  "range": 1000,
}
 */
#endif //__MAC80211_FORMAT_H
