/*=========================================================
*   File name   ：  structdef.h
*   Authored by ：  
*   Date        ：  2005-3-4 15:00:47
*   Description ：  
*
*   Modify by   ：
*       Date            :       2008-4-2 16:35
*=========================================================*/
#ifndef _NPR_DECODEDEF_H__
#define _NPR_DECODEDEF_H__

#include <stdlib.h>

#ifdef DEBUG
    #define TRACE printf
#else
    #define TRACE(...)
#endif

#ifdef DEBUG_MAX
    #define TRACE_MAX printf
#else
    #define TRACE_MAX(...)
#endif




typedef unsigned char   uint8_t;
typedef unsigned char       UCHAR;
typedef short   int         INT16;
typedef unsigned short      UINT16; 
typedef int                 INT32;
typedef unsigned int        UINT32;
typedef long long           INT64;
typedef unsigned long long  UINT64;

enum IP_PAYLOAD
{
    TCP_PROTO=0,
    UDP_PROTO,
    NULL_PROTO
};

//#pragma pack(push) //保存对齐状态
//#pragma pack(1)    //设定紧凑模式
struct IP4Addr 
{
    unsigned int        nIP;
    unsigned short      nPort;
    
    IP4Addr()
    {
        nIP=0;
        nPort=0;
    }
};

class IP4ConnectAddr
{
public:
    IP4Addr Come;
    IP4Addr Conver;
    IP_PAYLOAD nProtocol;
    //ip的层级，最外层从0开始计数
    //区分多层ip头的情况
    unsigned short nLevel;
    IP4ConnectAddr()
    {
        nProtocol=NULL_PROTO;
        nLevel=0;
    }
    bool isSameStream(const IP4ConnectAddr & newOne )
    {
        if(Come.nIP == newOne.Come.nIP 
            && Come.nPort == newOne.Come.nPort
            && Conver.nIP == newOne.Conver.nIP 
            && Conver.nPort == newOne.Conver.nPort
            && nProtocol == newOne.nProtocol  
            &&  nLevel ==  newOne.nLevel)
        {
            return true;
        }
        else 
        {
            return false;
        }
    }  
    bool isConverStream(const IP4ConnectAddr & newOne )
    {
        if(Come.nIP == newOne.Conver.nIP 
            && Come.nPort == newOne.Conver.nPort
            && Conver.nIP == newOne.Come.nIP 
            && Conver.nPort == newOne.Come.nPort
            && nProtocol == newOne.nProtocol  
            &&  nLevel ==  newOne.nLevel)
        {
            return true;
        }
        else 
        {
            return false;
        }
    }
    IP4ConnectAddr & operator =(const IP4ConnectAddr & newOne)
    {        
        Come.nIP = newOne.Come.nIP;
        Come.nPort = newOne.Come.nPort;
        Conver.nIP = newOne.Conver.nIP ;
        Conver.nPort = newOne.Conver.nPort;
        nProtocol  =  newOne.nProtocol;  
        nLevel =  newOne.nLevel;
        return *this;
    }
};
//#pragma pack(pop)  //恢复对齐状态



//--- xiaodong - add sctp decode end---

#endif // _NPR_DECODEDEF_H__
