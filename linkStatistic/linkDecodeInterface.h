///////////////////////////////////////////////////////////
//  linkDecodeInterface.h
//  Implementation of the Class httpAppManager
//  Created on:      19-四月-2016 16:13:52
//  Original author: Administrator
///////////////////////////////////////////////////////////

#if !defined(EA_AAE17FF3_32CE_4457_8EA7_637204D342D9_httpAppInterface_INCLUDED_)
#define EA_AAE17FF3_32CE_4457_8EA7_637204D342D9_httpAppInterface_INCLUDED_


#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string>
#include <vector>
#include <iostream>

#include <algorithm>

#include <string>

#include <dlfcn.h>

#include <iomanip>

#include <sstream>

#include "nprdef.h"


extern unsigned int nCurTime;

#ifdef __cplusplus
extern "C" {
#endif

class ipPkt;

const short int PORPERTY_STREAM_MAX_ELEMENT=10;
const short int PORPERTY_MAXLEN=64;
const int MAX_HEADPKT_INFO=10;

//const short int PORPERTY_STREAM_MAX_ELEMENT=10;
//const short int PORPERTY_MAXLEN=64;



class  out2protobuf
{
public:
    //链接编号，必为偶数
    int m_linkId;
    //是否中间输出结果
    bool m_tmepOutput;
    //线路号
    std::string m_lineNumber;
    //nTime and shake of link
    //标识当前连接第一个数据包到达的时间戳
    struct timeval m_firstTb;
    //标识当前连接最后一个数据包到达的时间戳
    struct timeval m_lastTb;        
    //开始握手包数量
    int m_nHandshake;
    //
    int m_direction;
    //断开握手包数量
    int m_nByeHandshake;
    
    //Basic info of link:
    unsigned int m_cmIp;
    unsigned int m_cvIp;
    unsigned int m_cmPort;
    unsigned int m_cvPort;
    //tcp , udp 类型
    int m_ipPayloadType;
    //流单双向类型
    int m_duplexType;
    //应用协议类型
    int m_appType;
    
    //Basic statistic info of come's stream 
    //come 端
    //发送报数，发送报字节数
    int m_cmPkts;
    int m_cmBytes;
    //有负载的
    int m_cmLoadPkts;
    int m_cmLoadMaclen;
    //发送中的重传包，发送中的重字节
    int m_cmRsPkts;
    int m_cmRsBytes;
    
    //发送中的未知包，发送中的未知字节
    int m_cmUnPkts;
    int m_cmUnBytes;
    //发送中跳跃丢失字节
    int m_cmJumpLostBys;
    
    //发送中的去重后的应用包数，
    int m_cmAppPkts;
    //发送中的去重后的应用包长平方和，
    int m_cmAppLenSq;
    //发送中的去重后的应用字节数
    int m_cmAppBys;
    //mss 允许的最大分片
    int m_cmSegmentMax;
    //握手的窗口大小
    int m_cmWindowSize;
    //握手窗口倍数
    int m_cmWindowScale;
    //sack
    int m_cmSackPermitted;
    //窗口0统计
    int m_cmWinZeroSize;

    //conver 端
    int m_cvPkts;
    int m_cvBytes;
    //有负载的
    int m_cvLoadPkts;
    int m_cvLoadMaclen;
    //发送中的重传包，发送中的重字节
    int m_cvRsPkts;
    int m_cvRsBytes;

    
    //发送中的未知包，发送中的未知字节
    int m_cvUnPkts;
    int m_cvUnBytes;
    //发送中跳跃丢失字节
    int m_cvJumpLostBys;

    
    //发送中的去重后的应用包数，
    int m_cvAppPkts;
    //发送中的去重后的应用包长平方和，
    int m_cvAppLenSq;
    //发送中的去重后的应用字节数
    int m_cvAppBys;
    //mss 允许的最大分片
    int m_cvSegmentMax;
    //握手的窗口大小
    int m_cvWindowSize;
    //握手窗口倍数
    int m_cvWindowScale;
    //sack
    int m_cvSackPermitted;
    //窗口0统计
    int m_cvWinZeroSize;

    //以下都是双向流设计的
    //[0] :come [1] :conver

    
    //Property string statistic of stream(come and conver)        
    //特征串已完成数量，最大为 PORPERTY_STREAM_MAX_ELEMENT
    short int m_porpertyDone[2];
    //每个特征串的包序号
    //short int m_porpertyPktNum[2][PORPERTY_STREAM_MAX_ELEMENT];
    std::vector<short int> m_porpertyPktNum[2];
    //每个特征串长度
    //short int m_porpertyLen[2][PORPERTY_STREAM_MAX_ELEMENT];
    std::vector<short int> m_porpertyLen[2];
    //每个特征串的偏移值，大于0从头开始，小于0从尾部开始
    //short int m_porpertyOffsize[2][PORPERTY_STREAM_MAX_ELEMENT];
    std::vector<short int> m_porpertyOffsize[2];
    //每个特征串
    //char *m_porperty[2][PORPERTY_STREAM_MAX_ELEMENT];
    std::vector<char *> m_porperty[2];

    //零字节负载长度的包统计信息
    //提取完成，可输出的数量
    int m_headZeroLenPktDone[2];
     //提取完成，可输出流内序号
    //int m_zeroLenPktStreamId[2][PORPERTY_STREAM_MAX_ELEMENT];
    std::vector<int> m_zeroLenPktStreamId[2];
     //提取完成，可输出链接内序号
    //int m_zeroLenPktLinkId[2][PORPERTY_STREAM_MAX_ELEMENT];
    std::vector<int> m_zeroLenPktLinkId[2];
      
    //负载长度大于零的包统计信息
    //提取完成，可输出的数量
    int m_payLoadPktDone[2];
    //记录包信息:包长度/
    //unsigned short  m_payLoadPktLen[2][MAX_HEADPKT_INFO];
    std::vector<unsigned short> m_payLoadPktLen[2];
    //记录包信息:包的链接内序号id/
    //unsigned int  m_payLoadPktLinkId[2][MAX_HEADPKT_INFO];
    std::vector<unsigned int> m_payLoadPktLinkId[2];
    //记录包信息:包的流内序号id/
    //unsigned int  m_payLoadPktStreamId[2][MAX_HEADPKT_INFO];
    std::vector<unsigned int> m_payLoadPktStreamId[2];

    out2protobuf()
    {
        m_tmepOutput=false;
        m_linkId =0;
        m_appType=0;
        m_nHandshake=0;
        m_nByeHandshake=0;
        m_ipPayloadType=0;
        m_duplexType=0;
        m_cmAppBys=0;
        m_cmAppLenSq=0;
        m_cmAppPkts=0;
        m_cmBytes=0;
        m_cmIp=0;
        m_cmJumpLostBys=0;
        m_cmLoadMaclen=0;
        m_cmLoadPkts=0;
        m_cmPkts=0;
        m_cmPort=0;
        m_cmRsBytes=0;
        m_cmRsPkts=0;
        m_cmSackPermitted=0;
        m_cmSegmentMax=0;
        m_cmUnBytes=0;
        m_cmUnPkts=0;
        m_cmWindowScale=0;
        m_cmWindowSize=0;
        m_cmWinZeroSize=0;
        m_cvAppBys=0;
        m_cvAppLenSq=0;
        m_cvAppPkts=0;
        m_cvBytes=0;
        m_cvIp=0;        
        m_cvJumpLostBys=0;
        m_cvLoadMaclen=0;
        m_cvLoadPkts=0;
        m_cvPkts=0;
        m_cvPort=0;
        m_cvRsBytes=0;
        m_cvRsPkts=0;
        m_cvSackPermitted=0;
        m_cvSegmentMax=0;
        m_cvUnBytes=0;
        m_cvUnPkts=0;
        m_cvWindowScale=0;
        m_cvWindowSize=0;
        m_cvWinZeroSize=0;
        for(int w =0;w < 2; w ++)
        {
            m_headZeroLenPktDone[w]=0;
            m_payLoadPktDone[w]=0;       
            m_porpertyDone[w]=0;
        }
    }
    ~out2protobuf()
    {
        for(int i =0 ;i<2;i++)
        {
            for(int w=0;w< m_porpertyDone[i];w++)
            {
                if(NULL!=m_porperty[i][w])
                {
                    TRACE_MAX("~out2protobuf free %p\r\n",m_porperty[i][w]);
                    free(m_porperty[i][w]);
                    m_porperty[i][w] =NULL;
                }
            }
            m_payLoadPktLen[i].clear();
            m_payLoadPktLinkId[i].clear();
            m_payLoadPktStreamId[i].clear();
            m_porperty[i].clear();
            m_porpertyLen[i].clear();
            m_porpertyOffsize[i].clear();
            m_porpertyPktNum[i].clear();
            m_zeroLenPktLinkId[i].clear();
            m_zeroLenPktStreamId[i].clear();
        }
    }        
};

typedef int  (*pOutFun) (void * , out2protobuf *  );


class linkPptInit
{     
public:    
    //tcp乱序重传等缓冲队列包数最大设定值
    unsigned int cacheSumMaxSetting;    
    //tcp乱序最大容错的 seq间隔
    unsigned int seqJumpMaxSetting;     
    //tcp乱序最大容错间隔次数
    unsigned int seqJumpSumMax; 
    //链接超时最大时间
    unsigned int RstFinTimeout;
    //UDP链接超时最大时间  
    unsigned int UdpTimeout;
    //通用链接无挥手超时最大时间
    unsigned int nNoByeDefaultTimeout; 
    //TCP通用链接seq多次重复cache超时 
    unsigned int nCacheTimeout;   
    unsigned int nOutputMaxTime;
    //解码配置文档
    //std::string decodeFileName;
    //seq相同的不同包缓冲
    bool bTcpSeqSameCache;
    linkPptInit()
    { 
        cacheSumMaxSetting=100;  
        seqJumpMaxSetting =65536;
        seqJumpSumMax=1000;
        RstFinTimeout =35;
        nNoByeDefaultTimeout=305;
        nCacheTimeout =1;
        //decodeFileName="";
        bTcpSeqSameCache=false;
        nOutputMaxTime=1800;
    };
};

//初始化
//return >0:全部成功初始化并且有效
//return <0:初始化失败或初始化无效
//retrun 0:仅仅时全流量分析工作
int nprInitLinkDecode( linkPptInit * pInit,pOutFun pFun, void * pOutObj );
int nprDecodeLink(ipPkt * pkt);
void nprLinkPoolClose();
void nprCheckTimeout();

#ifdef __cplusplus
}
#endif

#endif
