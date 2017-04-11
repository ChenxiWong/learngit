
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>
#include <sstream>
#include <netinet/ether.h>

#include "appLinkInterface.h"
#include "linkstream.h"
#include "tcpReassembly.h"


//__thread void * pOutObj =NULL;
//__thread pOutFun pFun=NULL;

#define min(a,b) ((a)<(b)?(a):(b))


UINT32 linkStream::m_linkStepId=0;
UINT32 linkStream::UdpTimeout = 30;
UINT32 linkStream::RstFinTimeout =30;
UINT32 linkStream::nNoByeDefaultTimeout=30;
UINT32 linkStream::nCacheTimeout=1;
UINT32 linkStream::nOutputMaxTime = 3600;


linkStream::linkStream()
{
    m_nLinkPktError=LINK_NORMAL;
    m_lastCome=0;
    m_lastConver=0;
    m_linkId = m_linkStepId;
    m_linkStepId+=2;
    m_statusCome=FLOW_NULL; 
    m_statusConv=FLOW_NULL;     
    m_direction=DIRECT_NULL;  
    memset(m_synFlagStatistic,0,sizeof(UINT32)*256);
    //memset(m_ComeOrConver,0,sizeof(STREAM)*FLOW_SUM);
    //memset(m_synComeFlagsQueuen,0,sizeof(UINT16)*FLOW_SUM);
    //memset(m_synConverFlagsQueuen,0,sizeof(UINT16)*FLOW_SUM);
    m_flagsSum =0 ;
    m_converFlagsSum =0;
    m_comeFlagsSum =0;
    m_bAckAck =false;
    m_ackAckSum=0;
    m_duplex =DUPLEX_NULL;
    m_isClose = OTHER_NULL;
    m_pPreTimeout = NULL;
    m_pNextTimeout=NULL;
    //m_nNoByeTimeout =nNoByeDefaultTimeout; 
    m_pkt[0] = NULL;
    m_pkt[1] = NULL;
    /*
    m_pkt[0].m_nFlowType = 0;
    m_pkt[1].m_nFlowType = 1;
    m_pkt[0].m_nStreamId = m_linkId;
    m_pkt[1].m_nStreamId = (m_linkId+1);
    */
    m_streamPktResend[0]=0;
    m_streamPktResend[1]=0;
    m_streamPktSum[0]=0;
    m_streamPktSum[1]=0;
    m_streamLoadPktSum[0]=0;
    m_streamLoadPktSum[1]=0;
    m_streamTotalMacLen[0]=0;
    m_streamTotalMacLen[1]=0;
    m_streamTotalPayloadMacLen[0]=0;
    m_streamTotalPayloadMacLen[1]=0;
    m_streamResendMacLen[0]=0;
    m_streamResendMacLen[1]=0;
    m_firstTb.tv_sec=0;
    m_firstTb.tv_usec=0;
    m_tb.tv_sec=0;
    m_tb.tv_usec=0;
    m_lastOutputTb.tv_sec=0;
    m_lastOutputTb.tv_usec=0;
    m_timeoutTb.tv_sec=0;
    m_timeoutTb.tv_usec=0;
    m_nHandshake =0; 
    m_nByeHandshake =0;
    m_seqStatus =SEQ_ERR;
    m_seqTryStatus = SEQ_ERR;
    
    m_lastLen[0]=9999;
    m_lastLen[1]=9999;
    m_lastFlow[0]=FLOW_NULL;
    m_lastFlow[1]=FLOW_NULL;    
    m_lastTcpFlag[0] = 0;
    m_lastTcpFlag[1] = 0;
    m_nlastSeqNum[0] = 0;
    m_nlastSeqNum[1] = 0;
    m_lineNumber="";
    //m_decode=NULL;

}


linkStream::linkStream(const IP4ConnectAddr & linkAdd)
{   
    m_nLinkPktError=LINK_NORMAL;
    m_linkAdd = linkAdd;    
    m_lastCome=0;
    m_lastConver=0;
    m_linkId = m_linkStepId;
    m_linkStepId+=2;
    m_pkt[0] = NULL;
    m_pkt[1] = NULL;
    /*
    m_pkt[0].m_nFlowType = 0;
    m_pkt[1].m_nFlowType = 1;
    m_pkt[0].m_nStreamId = m_linkId;
    m_pkt[1].m_nStreamId = (m_linkId+1);
    */
    m_statusCome=FLOW_NULL; 
    m_statusConv=FLOW_NULL;     
    m_direction=DIRECT_NULL;      
    memset(m_synFlagStatistic,0,sizeof(UINT32)*256);
    //memset(m_ComeOrConver,0,sizeof(STREAM)*FLOW_SUM);
    //memset(m_synComeFlagsQueuen,0,sizeof(UINT16)*FLOW_SUM);
    //memset(m_synConverFlagsQueuen,0,sizeof(UINT16)*FLOW_SUM);
    m_flagsSum =0 ;
    m_converFlagsSum =0;
    m_comeFlagsSum =0;
    m_bAckAck =false;
    m_ackAckSum=0;
    m_duplex =DUPLEX_NULL;
    m_isClose = OTHER_NULL;
    m_pPreTimeout = NULL;
    m_pNextTimeout=NULL;
    //m_nNoByeTimeout =nNoByeDefaultTimeout;
    m_streamPktSum[0]=0;
    m_streamPktSum[1]=0;
    m_streamLoadPktSum[0]=0;
    m_streamLoadPktSum[1]=0;
    m_streamTotalMacLen[0]=0;
    m_streamTotalMacLen[1]=0;
    m_streamTotalPayloadMacLen[0]=0;
    m_streamTotalPayloadMacLen[1]=0;
    
    m_streamPktResend[0]=0;
    m_streamPktResend[1]=0;
    m_streamResendMacLen[0]=0;
    m_streamResendMacLen[1]=0;
    
    m_streamPktUnknow[0]=0;
    m_streamPktUnknow[1]=0;
    m_streamUnknowMacLen[0]=0;
    m_streamUnknowMacLen[1]=0;
        
    m_firstTb.tv_sec=0;
    m_firstTb.tv_usec=0;
    m_tb.tv_sec=0;
    m_tb.tv_usec=0;
    m_timeoutTb.tv_sec=0;
    m_timeoutTb.tv_usec=0;
    m_lastOutputTb.tv_sec=0;
    m_lastOutputTb.tv_usec=0;
    m_nHandshake =0;
    m_nByeHandshake =0;
    m_bAppLinkOpen =0;
    m_seqStatus =SEQ_ERR;
    m_seqTryStatus=SEQ_ERR;
    m_lastLen[0]=9999;
    m_lastLen[1]=9999;
    m_lastFlow[0]=FLOW_NULL;
    m_lastFlow[1]=FLOW_NULL;    
    m_lastTcpFlag[0] = 0;
    m_lastTcpFlag[1] = 0;
    m_nlastSeqNum[0] = 0;
    m_nlastSeqNum[1] = 0;
    m_lineNumber="";
    //m_decode=NULL;
    
};
    
    
linkStream::~linkStream()
{    

    flushCache();

    flushDecode();
    //然后统计输出
    statisticOut(false);

/*
    if(m_bDecodeOpen != 0 && m_decode !=NULL )
    {
        nprRelease(m_decode);
        m_decode =NULL;
    }
*/    

    if(m_bAppLinkOpen != 0 && m_appLink.pObj!=NULL )
    {
        nprAppLinkRelease(m_appLink.pObj);
        m_appLink.pObj =NULL;
    }
    for(int w =0; w < 2 ;w++)
    {

        if(NULL!= m_pkt[w])
        {
           delete m_pkt[w];
           m_pkt[w] =NULL;
        } 
    }
    m_ComeOrConver.clear();
    m_synComeFlagsQueuen.clear();
    m_synConverFlagsQueuen.clear();
    
}   
void linkStream::basicOut()
{
    //链接id
    //TRACE("LinkId %d \r\n",m_linkId);     
    
    //ip和port
    char sz_ip[48];
    memset(sz_ip,0x0,48);
    UINT32 cip=htonl(m_linkAdd.Come.nIP); 
    inet_ntop(AF_INET, (void *)&cip, sz_ip, 16); 
    //TRACE("comeIpPort   %15s : %6u\r\n",sz_ip,m_linkAdd.Client.nPort);

    
    char sz_ip2[48];
    memset(sz_ip2,0x0,48);
    UINT32 sip=htonl(m_linkAdd.Conver.nIP);   
    inet_ntop(AF_INET, (void *)&sip, sz_ip2, 16); 
    //TRACE("converIpPort %15s : %6u\r\n",sz_ip2,m_linkAdd.Server.nPort);

    printf("linkId %d   %15s : %6u ==> %15s : %6u\r\n",
        m_linkId,sz_ip,m_linkAdd.Come.nPort,sz_ip2,m_linkAdd.Conver.nPort);   

}

void linkStream::statisticOut(bool tmepOutput)
{           

    //TRACE("test return .... LinkId %d \r\n",m_linkId);
    //return;
    
    out2protobuf * out  = new out2protobuf;
    int minValue=0;
    //链接id
    TRACE("\r\nLinkId %d  m_lineNumber=%s\r\n",m_linkId,m_lineNumber.c_str());

    out->m_lineNumber= m_lineNumber;
    
    TRACE("tmpOut %d\r\n",tmepOutput);
    out->m_tmepOutput = tmepOutput;
    
    TRACE("Time and shake:\r\n");  
    
    //链接开始时间
    TRACE("firsttime %u:%u\r\n",(unsigned int)m_firstTb.tv_sec,(unsigned int)m_firstTb.tv_usec);  
    out->m_firstTb = m_firstTb;
    
    //链接开始握手情
    if(m_nHandshake)
    {
        TRACE("handshake %u\r\n",m_nHandshake);
    }
    out->m_nHandshake = m_nHandshake;

    out->m_direction=-1;
    if(m_linkAdd.nProtocol == TCP_PROTO )
    {
        if(m_direction == FLOW_COME_CLIENT)
        {
            TRACE("direction COME_CLIENT\r\n");
        }
        else if(m_direction == FLOW_COME_SERVER)
        {
            TRACE("direction COME_SERVER\r\n");
        } 
        else if(m_direction == DIRECT_NULL)
        {
            TRACE("direction NULL\r\n");
        }
        else
        {
            TRACE("direction unknown\r\n");
        }
        out->m_direction = m_direction;
    }
    
    //链接结束时间
    TRACE("last-time %u:%u\r\n",(unsigned int)m_tb.tv_sec,(unsigned int)m_tb.tv_usec);
    
    TRACE("out  time %llu\r\n",(unsigned long long)(m_timeoutTb.tv_sec-m_tb.tv_sec));      
    out->m_lastTb = m_tb; 
    
    //链接结束握手情况
    if(m_nByeHandshake)
    {
        TRACE("bye-shake %u\r\n",m_nByeHandshake);
    }
    out->m_nByeHandshake = m_nByeHandshake;
    
    TRACE("Basic of link:\r\n");  
    
    //ip和port
    char sz_ip[48];
    memset(sz_ip,0x0,48);
    UINT32 cip=htonl(m_linkAdd.Come.nIP); 
    inet_ntop(AF_INET, (void *)&cip, sz_ip, 16); 
    TRACE("cmIpPort  %15s:%6u\r\n",sz_ip,m_linkAdd.Come.nPort);
    out->m_cmIp = m_linkAdd.Come.nIP;
    out->m_cmPort = m_linkAdd.Come.nPort;

    
    memset(sz_ip,0x0,48);
    UINT32 sip=htonl(m_linkAdd.Conver.nIP);   
    inet_ntop(AF_INET, (void *)&sip, sz_ip, 16); 
    TRACE("cvIpPort  %15s:%6u\r\n",sz_ip,m_linkAdd.Conver.nPort);
    out->m_cvIp = m_linkAdd.Conver.nIP;
    out->m_cvPort = m_linkAdd.Conver.nPort;

    //tcp/udp协议类别
    out->m_ipPayloadType = -1;
    if(m_linkAdd.nProtocol == TCP_PROTO)
    {
        TRACE("tcp/udp   TCP\r\n");
        out->m_ipPayloadType = 0;
    }
    else if(m_linkAdd.nProtocol == UDP_PROTO)
    {
        TRACE("tcp/udp   UDP\r\n");
        out->m_ipPayloadType = 1;
    }  
    else
    {
        TRACE("tcp/udp   unknown\r\n");
        out->m_ipPayloadType = -1;        
    }
    //单双向
    string duplex ="";
    switch(m_duplex)
    {
        case DUPLEX_ALL:
            {
                duplex= "DUPLEX_ALL";break;
            }
        case CLIENT_ONLY:       
            {
                duplex= "CLIENT_ONLY" ;break;
            }
        case SERVER_ONLY:       
            {
                duplex= "SERVER_ONLY" ;break;
            }
        case DUPLEX_NOSHAKE:    
            {
                duplex= "DUPLEX_NOSHAKE" ;break;
            }
        case NOSHAKE:           
            {
                duplex= "NOSHAKE" ;break;
            }
        //case DUPLEX_ALLCLOSE:   
        //    {
        //        duplex= "DUPLEX_ALLCLOSE" ;break;
        //    }
        case UDP_SINGAL:       
            {
                duplex= "UDP_SINGAL" ;break;
            }
        case DUPLEX_UDP:       
            {
                duplex= "DUPLEX_UDP" ;break;
            }
        case DUPLEX_NULL:       
            {
                duplex= "DUPLEX_NULL" ;break;
            }
        default:                
            {
                duplex= "UNKNOWN";break;
            }    
    }
    TRACE("duplex    %s / %d\r\n",duplex.c_str(),m_duplex);
    out->m_duplexType = m_duplex;
    
    //应用协议类别
    TRACE("appType   %u/%u\r\n",m_appLink.PID,m_appLink.TID);
    out->m_appType = m_appLink.PID;

    int flowtype=0;

    TRACE("Basic of come:\r\n");      
    //come端 :0
    flowtype=0;
    if(m_pkt[flowtype]!=NULL)
    {
        //握手的窗口大小
        if(m_pkt[flowtype]->m_windowSize)
        {
        TRACE("cmWinsize %12d\r\n",m_pkt[flowtype]->m_windowSize);
        }
        
        //窗口的scale
        if(m_pkt[flowtype]->m_windowScale)
        {
        TRACE("cmW-Scale %12d\r\n",m_pkt[flowtype]->m_windowScale);
        }
        //0窗口的次数
        if(m_pkt[flowtype]->m_winZeroSize)
        {
        TRACE("cmZeroWin %12d\r\n",m_pkt[flowtype]->m_winZeroSize);
        }
        //窗口的scale
        if(m_pkt[flowtype]->m_sackPermitted)
        {
        TRACE("cmIsSack  %12d\r\n",m_pkt[flowtype]->m_sackPermitted);
        }
        //握手的最大包分片
        if(m_pkt[flowtype]->m_segmentMax)
        {
        TRACE("cmMaxTcp  %12d\r\n",m_pkt[flowtype]->m_segmentMax);
        }
        out->m_cmWindowSize= m_pkt[flowtype]->m_windowSize;
        out->m_cmWindowScale= m_pkt[flowtype]->m_windowScale;
        out->m_cmWinZeroSize= m_pkt[flowtype]->m_winZeroSize;
        out->m_cmSackPermitted= m_pkt[flowtype]->m_sackPermitted;
        out->m_cmSegmentMax= m_pkt[flowtype]->m_segmentMax;
    }
    
    //发送报数，发送报字节数
    if(m_streamPktSum[flowtype])
    {
    TRACE("comePkts  %12d\r\n",m_streamPktSum[flowtype]);   
    }
    if(m_streamTotalMacLen[flowtype])
    {
    TRACE("comeBytes %12d\r\n",m_streamTotalMacLen[flowtype]);
    }
    if(m_streamLoadPktSum[flowtype])
    {
    TRACE("cmLoadPkt %12d\r\n",m_streamLoadPktSum[flowtype]); 
    }
    if(m_streamTotalPayloadMacLen[flowtype])
    {
    TRACE("cmLoadLen %12d\r\n",m_streamTotalPayloadMacLen[flowtype]); 
    }
    out->m_cmPkts = m_streamPktSum[flowtype];
    out->m_cmBytes = m_streamTotalMacLen[flowtype];
    out->m_cmLoadPkts = m_streamLoadPktSum[flowtype];
    out->m_cmLoadMaclen= m_streamTotalPayloadMacLen[flowtype];

    
    //发送中的重传包，发送中的重字节
    if(m_streamPktResend[flowtype])
    {
    TRACE("cmRsPkts  %12d\r\n",m_streamPktResend[flowtype]);
    }
    if(m_streamResendMacLen[flowtype])
    {
    TRACE("cmRsBytes %12d\r\n",m_streamResendMacLen[flowtype]);
    }
    out->m_cmRsPkts= m_streamPktResend[flowtype];
    out->m_cmRsBytes= m_streamResendMacLen[flowtype];


    //发送中的未知包，发送中的未知字节
    if(m_streamPktUnknow[flowtype])
    {
    TRACE("cmUnknPkt %12d\r\n",m_streamPktUnknow[flowtype]);
    }
    if(m_streamUnknowMacLen[flowtype])
    {
    TRACE("cmUnknBys %12d\r\n",m_streamUnknowMacLen[flowtype]);
    }
    out->m_cmUnPkts= m_streamPktUnknow[flowtype];
    out->m_cmUnBytes= m_streamUnknowMacLen[flowtype];

    
    if(m_pkt[flowtype]!=NULL && m_pkt[flowtype]->m_seqLostBytes)
    {
        TRACE("cmJumpBys %12d\r\n",m_pkt[flowtype]->m_seqLostBytes);
        out->m_cmJumpLostBys= m_pkt[flowtype]->m_seqLostBytes;
    }


    
    //发送中的去重后的应用包数，发送中的去重后的应用包长平方和，发送中的去重后的应用字节数
    if(m_pkt[flowtype]!=NULL)
    {
        if(m_pkt[flowtype]->m_payLoadPktSum)
        {
        TRACE("cmAppPkts %12d\r\n",m_pkt[flowtype]->m_payLoadPktSum);
        }
        if(m_pkt[flowtype]->m_payLoadSumSquares)
        {
        TRACE("cmLoadSqr %12d\r\n",m_pkt[flowtype]->m_payLoadSumSquares);
        }
        if(m_pkt[flowtype]->m_payLoadLen)
        {
        TRACE("cmAppByte %12d\r\n",m_pkt[flowtype]->m_payLoadLen);
        }
        out->m_cmAppPkts= m_pkt[flowtype]->m_payLoadPktSum;
        out->m_cmAppLenSq= m_pkt[flowtype]->m_payLoadSumSquares;
        out->m_cmAppBys= m_pkt[flowtype]->m_payLoadLen;
    }
    //conver端 :1   
    TRACE("Basic of conver:\r\n"); 
    flowtype=1;
    if(m_pkt[flowtype]!=NULL)
    {
        //握手的窗口大小
        if(m_pkt[flowtype]->m_windowSize)
        {
        TRACE("cvWinsize %12d\r\n",m_pkt[flowtype]->m_windowSize);
        }
        //窗口的scale
        if(m_pkt[flowtype]->m_windowScale)
        {
        TRACE("cvW-Scale %12d\r\n",m_pkt[flowtype]->m_windowScale);
        }
        //0窗口的次数
        if(m_pkt[flowtype]->m_winZeroSize)
        {
        TRACE("cvZeroWin %12d\r\n",m_pkt[flowtype]->m_winZeroSize);
        }
        //窗口的scale
        if(m_pkt[flowtype]->m_sackPermitted)
        {
        TRACE("cvIsSack  %12d\r\n",m_pkt[flowtype]->m_sackPermitted);
        }
        //握手的最大包分片
        if(m_pkt[flowtype]->m_segmentMax)
        {
        TRACE("cvMaxTcp  %12d\r\n",m_pkt[flowtype]->m_segmentMax); 
        }
        out->m_cvWindowSize= m_pkt[flowtype]->m_windowSize;
        out->m_cvWindowScale= m_pkt[flowtype]->m_windowScale;
        out->m_cvWinZeroSize= m_pkt[flowtype]->m_winZeroSize;
        out->m_cvSackPermitted= m_pkt[flowtype]->m_sackPermitted;
        out->m_cvSegmentMax= m_pkt[flowtype]->m_segmentMax;

    }
    
    //发送报数，发送报字节数
    if(m_streamPktSum[flowtype])
    {
    TRACE("covsPkts  %12d\r\n",m_streamPktSum[flowtype]); 
    }  
    if(m_streamTotalMacLen[flowtype])
    {
    TRACE("covsBytes %12d\r\n",m_streamTotalMacLen[flowtype]);
    }
    if(m_streamLoadPktSum[flowtype])
    {
    TRACE("cvLoadPkt %12d\r\n",m_streamLoadPktSum[flowtype]); 
    }
    if(m_streamTotalPayloadMacLen[flowtype])
    {
    TRACE("cvLoadLen %12d\r\n",m_streamTotalPayloadMacLen[flowtype]); 
    }
    out->m_cvPkts = m_streamPktSum[flowtype];
    out->m_cvBytes = m_streamTotalMacLen[flowtype];
    out->m_cvLoadPkts = m_streamLoadPktSum[flowtype];
    out->m_cvLoadMaclen= m_streamTotalPayloadMacLen[flowtype];
    
    //发送中的重传包，发送中的重字节
    if(m_streamPktResend[flowtype])
    {
    TRACE("cvRsPkts  %12d\r\n",m_streamPktResend[flowtype]);
    }
    if(m_streamResendMacLen[flowtype])
    {
    TRACE("cvRsBytes %12d\r\n",m_streamResendMacLen[flowtype]);
    }
    out->m_cvRsPkts= m_streamPktResend[flowtype];
    out->m_cvRsBytes= m_streamResendMacLen[flowtype];
    
    //发送中的未知包，发送中的未知字节
    if(m_streamPktUnknow[flowtype])
    {
    TRACE("cvUnknPkt %12d\r\n",m_streamPktUnknow[flowtype]);
    }
    if(m_streamUnknowMacLen[flowtype])
    {
    TRACE("cvUnknBys %12d\r\n",m_streamUnknowMacLen[flowtype]);
    }
    out->m_cvUnPkts= m_streamPktUnknow[flowtype];
    out->m_cvUnBytes= m_streamUnknowMacLen[flowtype];
    
    if(m_pkt[flowtype]!=NULL && m_pkt[flowtype]->m_seqLostBytes)
    {
        TRACE("cvJumpBys %12d\r\n",m_pkt[flowtype]->m_seqLostBytes);
        out->m_cvJumpLostBys= m_pkt[flowtype]->m_seqLostBytes;
    }
    
    //发送中的去重后的应用包数，发送中的去重后的应用包长平方和，发送中的去重后的应用字节数
    if(m_pkt[flowtype]!=NULL)
    {
        if(m_pkt[flowtype]->m_payLoadPktSum)
        {
        TRACE("cvAppPkts %12d\r\n",m_pkt[flowtype]->m_payLoadPktSum);
        }
        if(m_pkt[flowtype]->m_payLoadSumSquares)
        {
        TRACE("cvLoadSqr %12d\r\n",m_pkt[flowtype]->m_payLoadSumSquares);
        }
        if(m_pkt[flowtype]->m_payLoadLen)
        {
        TRACE("cvAppByte %12d\r\n",m_pkt[flowtype]->m_payLoadLen);
        }
        out->m_cvAppPkts= m_pkt[flowtype]->m_payLoadPktSum;
        out->m_cvAppLenSq= m_pkt[flowtype]->m_payLoadSumSquares;
        out->m_cvAppBys= m_pkt[flowtype]->m_payLoadLen;
    }
        
    //come端 :0
    flowtype=0;
    if(m_pkt[flowtype]!=NULL)
    {    
        if(m_pkt[flowtype]->m_porpertyDone)
        {
        TRACE("Property of come:\r\n"); 
        } 
        
        //包特征偏移，特征长度、特征串
        for(int w =0;w <m_pkt[flowtype]->m_porpertyDone  ;w++)
        {                       
            //包特征偏移，特征长度、特征串      
            TRACE("cm[%1d]Ppt Off %4d Len %3d Str ",
                m_pkt[flowtype]->m_porpertyPktNum[w],
                m_pkt[flowtype]->m_porpertyOffsize[w],
                m_pkt[flowtype]->m_porpertyLen[w]);
            for(int z=0;z< m_pkt[flowtype]->m_porpertyLen[w] ; z++)
            {
                unsigned char prt = (unsigned char)m_pkt[flowtype]->m_porperty[w][z];
                TRACE_MAX("%02x ",prt);(void)prt;
            }
            TRACE("\r\n");
            
            out->m_porpertyPktNum[flowtype].push_back(m_pkt[flowtype]->m_porpertyPktNum[w]);
            short int poffsize = m_pkt[flowtype]->m_porpertyOffsize[w];
            out->m_porpertyOffsize[flowtype].push_back(poffsize);
            short int porlen = m_pkt[flowtype]->m_porpertyLen[w];
            out->m_porpertyLen[flowtype].push_back(porlen);
            
            if(tmepOutput)
            {
                char * tmp  = (char *)malloc( m_pkt[flowtype]->m_porpertyLen[w] +1);
                memcpy(tmp,m_pkt[flowtype]->m_porperty[w], m_pkt[flowtype]->m_porpertyLen[w]);     
                tmp[ m_pkt[flowtype]->m_porpertyLen[w]]='\0';
                out->m_porperty[flowtype].push_back(tmp);
            }
            else
            {
                out->m_porperty[flowtype].push_back(m_pkt[flowtype]->m_porperty[w]);
                m_pkt[flowtype]->m_porperty[w]=NULL;
            }
        }
        out->m_porpertyDone[flowtype]= m_pkt[flowtype]->m_porpertyDone;
        

        minValue = min(m_pkt[flowtype]->m_zeroLenPktSum,m_pkt[flowtype]->m_headZeroLenInfoMax);
        
        if(minValue)
        {
            TRACE("Come[%d pkts][%d/%d]:\r\n",
            minValue,m_pkt[flowtype]->m_zeroLenPktSum,m_pkt[flowtype]->m_headZeroLenInfoMax);  
        }
        for(int w =0;w < minValue ;w++)
        {               
            //包无负载,流序号，链接序号            
            int tmp = m_pkt[flowtype]->m_zeroLenPktStreamId[w];
            out->m_zeroLenPktStreamId[flowtype].push_back(tmp);
            tmp = m_pkt[flowtype]->m_zeroLenPktLinkId[w];
            out->m_zeroLenPktLinkId[flowtype].push_back(tmp);
            TRACE("cm[%1d]SrmId   %6d      ",w,m_pkt[flowtype]->m_zeroLenPktStreamId[w]);
            TRACE("cm[%1d]LinkId  %6d\r\n",w,m_pkt[flowtype]->m_zeroLenPktLinkId[w]);
        }
        out->m_headZeroLenPktDone[flowtype]=minValue;

        minValue = min(m_pkt[flowtype]->m_payLoadPktSum,m_pkt[flowtype]->m_headPayLoadInfoMax);
        if(minValue)
        {
        TRACE("Come[%d pkts][%d/%d] payload:\r\n",
            minValue,m_pkt[flowtype]->m_payLoadPktSum,m_pkt[flowtype]->m_headPayLoadInfoMax);  
        //TRACE("\r\nStreamId and linkId of come's stream,for exmaple %d ( ptks of payload):\r\n",minValue);
        }
        for(int w =0;w <minValue ;w++)
        {               
            //包负载长度,流序号，链接序号
            TRACE("cm[%1d]SrmId  %6d ",w,m_pkt[flowtype]->m_payLoadPktStreamId[w ]);
            TRACE("cm[%1d]LinkId %6d ",w,m_pkt[flowtype]->m_payLoadPktLinkId[w ]);
            TRACE("cm[%1d]AppLen %6d\r\n",w,m_pkt[flowtype]->m_payLoadPktLen[w ]);
            out->m_payLoadPktStreamId[flowtype].push_back(m_pkt[flowtype]->m_payLoadPktStreamId[w]);
            out->m_payLoadPktLinkId[flowtype].push_back(m_pkt[flowtype]->m_payLoadPktLinkId[w]);
            out->m_payLoadPktLen[flowtype].push_back(m_pkt[flowtype]->m_payLoadPktLen[w]);
        }
        out->m_payLoadPktDone[flowtype]=minValue;

    }
    //conver端 :1
    flowtype=1;        
    if(m_pkt[flowtype]!=NULL)
    {    
        if(m_pkt[flowtype]->m_porpertyDone)
        {
        TRACE("Property of conver:\r\n");  
        }  

        for(int w =0;w <m_pkt[flowtype]->m_porpertyDone  ;w++)
        {                       
            //包特征偏移，特征长度、特征串
            TRACE("cv[%1d]Ppt Off %4d Len %3d Str ",
                m_pkt[flowtype]->m_porpertyPktNum[w],
                m_pkt[flowtype]->m_porpertyOffsize[w],
                m_pkt[flowtype]->m_porpertyLen[w]);
            for(int z=0;z< m_pkt[flowtype]->m_porpertyLen[w] ; z++)
            {           
                unsigned char prt = (unsigned char)m_pkt[flowtype]->m_porperty[w][z];
                TRACE_MAX("%02x ",prt);(void)prt;
            }
            TRACE("\r\n");        
            out->m_porpertyPktNum[flowtype].push_back(m_pkt[flowtype]->m_porpertyPktNum[w]);
            out->m_porpertyOffsize[flowtype].push_back(m_pkt[flowtype]->m_porpertyOffsize[w]);
            out->m_porpertyLen[flowtype].push_back(m_pkt[flowtype]->m_porpertyLen[w]);
            //memcpy(out->m_porperty[flowtype][w],m_pkt[flowtype]->m_porperty[w],out->m_porpertyLen[flowtype][w]);             
            if(tmepOutput)
            {
                char * tmp  = (char *)malloc( m_pkt[flowtype]->m_porpertyLen[w]+1);
                memcpy(tmp,m_pkt[flowtype]->m_porperty[w], m_pkt[flowtype]->m_porpertyLen[w]); 
                tmp[ m_pkt[flowtype]->m_porpertyLen[w]]='\0';
                out->m_porperty[flowtype].push_back(tmp);
            }
            else
            {
                out->m_porperty[flowtype].push_back(m_pkt[flowtype]->m_porperty[w]);
                m_pkt[flowtype]->m_porperty[w]=NULL;
            }       
        }
        out->m_porpertyDone[flowtype]= m_pkt[flowtype]->m_porpertyDone;
        
            
        minValue = min(m_pkt[flowtype]->m_zeroLenPktSum,m_pkt[flowtype]->m_headZeroLenInfoMax);    
        if(minValue)
        {
        TRACE("Conver[%d pkts][%d/%d]:\r\n",
            minValue,m_pkt[flowtype]->m_zeroLenPktSum,m_pkt[flowtype]->m_headZeroLenInfoMax);  
        //TRACE("\r\nStreamId and linkId of conver's stream,for exmaple %d ( ptks of no payload):\r\n",minValue); 
        }  
        for(int w =0;w <minValue;w++)
        {               
            //包无负载,流序号，链接序号
            TRACE("cv[%1d]SrmId  %6d ",w,m_pkt[flowtype]->m_zeroLenPktStreamId[w]);
            TRACE("cv[%1d]LinkId %6d\r\n",w,m_pkt[flowtype]->m_zeroLenPktLinkId[w]);
            out->m_zeroLenPktStreamId[flowtype].push_back(m_pkt[flowtype]->m_zeroLenPktStreamId[w]);
            out->m_zeroLenPktLinkId[flowtype].push_back(m_pkt[flowtype]->m_zeroLenPktLinkId[w]);
        }
        out->m_headZeroLenPktDone[flowtype]=minValue;

        minValue = min(m_pkt[flowtype]->m_payLoadPktSum,m_pkt[flowtype]->m_headPayLoadInfoMax);  
        if(minValue)
        {
        TRACE("Conver[%d pkts][%d/%d] payload:\r\n",
            minValue,m_pkt[flowtype]->m_payLoadPktSum,m_pkt[flowtype]->m_headPayLoadInfoMax);  
        //TRACE("\r\nStreamId and linkId of conver's stream,for exmaple %d ( ptks of payload):\r\n",minValue);
        }  
        for(int w =0;w <minValue;w++)
        {               
            //包负载长度,流序号，链接序号
            TRACE("cv[%1d]SrmId  %6d ",w,m_pkt[flowtype]->m_payLoadPktStreamId[w ]);
            TRACE("cv[%1d]LinkId %6d ",w,m_pkt[flowtype]->m_payLoadPktLinkId[w ]);
            TRACE("cv[%1d]AppLen %6d\r\n",w,m_pkt[flowtype]->m_payLoadPktLen[w ]);
            out->m_payLoadPktStreamId[flowtype].push_back(m_pkt[flowtype]->m_payLoadPktStreamId[w]);
            out->m_payLoadPktLinkId[flowtype].push_back(m_pkt[flowtype]->m_payLoadPktLinkId[w]);
            out->m_payLoadPktLen[flowtype].push_back(m_pkt[flowtype]->m_payLoadPktLen[w]);
        }
        out->m_payLoadPktDone[flowtype]=minValue;
    }
    TRACE("\r\n");

    if(NULL!= pFun)
    {
        pFun(pOutObj,out);
    }
    else
    {
        delete out;
    }
}


void linkStream::flushDecode()
{
    for(int w =0; w < 2 ;w++)
    {
        if(NULL!= m_pkt[w ])
        {
            m_pkt[w ]->addCachePkt();
            decodeCall(w ,false);    
            m_pkt[w ]->flushDecode(); 
        }
    }
}
void linkStream::flushCache()
{
    for(int w =0; w < 2 ;w++)
    {
        if(NULL!= m_pkt[w ])
        {
            UINT32 last=0; 
            do
            {
                last = m_pkt[w ]->cacheSum ;
                m_pkt[w ]->cacheCheck(0,0);
                TRACE("info,cacheCheck w=%d cacheSum=%d.\r\n",w,last);
            }
            while( last != m_pkt[w ]->cacheSum );
            //彻底清除
            m_pkt[w ]->flushCache();
        }
    }
}
bool linkStream::cacheTimeout(UINT32 nCur,UINT32 nTimeOut)
{
    if( nTimeOut && (nCur - m_tb.tv_sec) >= nTimeOut )   
    {
        flushDecode();
        TRACE("info,cacheTimeout() .flush ID[%u]/%d.\r\n",m_linkId,nTimeOut);
        return true;
    }
    if( (nCur - m_tb.tv_sec) >= nCacheTimeout )
    {
        TRACE("info,cacheTimeout() .flush ID[%u]/%d.\r\n",m_linkId,nCacheTimeout);
        flushDecode();
        return true;
    }
    return false;
}

bool linkStream::checkTimeout(UINT32 nCur,UINT32 nTimeOut)
{
    if( nTimeOut && (nCur - m_tb.tv_sec) >= nTimeOut )   
    {
        m_timeoutTb.tv_sec=nCur;
        return true;
    }
    if( (nCur - m_tb.tv_sec) >= nNoByeDefaultTimeout )
    {
        m_timeoutTb.tv_sec=nCur;
        return true;
    }
    return false;
}


bool linkStream::checkTimeout(struct timeval & nCur,UINT32 nTimeOut)
{
    if( nTimeOut && (nCur.tv_sec - m_tb.tv_sec) >= nTimeOut )    
    {
        m_timeoutTb.tv_sec=nCur.tv_sec;
        return true;
    }
    if( (nCur.tv_sec - m_tb.tv_sec) >= nNoByeDefaultTimeout )
    {
        m_timeoutTb.tv_sec=nCur.tv_sec;
        return true;
    }
    return false;
}

uint8_t linkStream::isSameLink(const IP4ConnectAddr & linkAdd)
{
    if(m_linkAdd.isSameStream(linkAdd))
    {
        return FLOW_COME;
    }
    else if(m_linkAdd.isConverStream(linkAdd))
    {
        return FLOW_CONVER;
    }
    else
    {
        return FLOW_NULL;
    }
}   

bool linkStream::isClose( UINT32 nCur)
{
    bool ret=false;  
    if(OTHER_NULL != m_isClose  )
    {
        if( (nCur -m_tb.tv_sec) >= RstFinTimeout)  
        {
            ret= true;
        }
    }
    else if(OTHER_NULL == m_isClose)
    {    
        //默认的需要自然超时，非结束超时
        if((nCur - m_tb.tv_sec) >= nNoByeDefaultTimeout)  
        {
            ret= true;
        }
    }
    
    if(ret)
    {        
        m_timeoutTb.tv_sec=nCur;
    }
    return ret;
}



bool linkStream::willClose()
{
    if( m_duplex == CLIENT_ONLY||
            m_duplex == SERVER_ONLY || 
            m_duplex == NOSHAKE )
    {   
        if(m_isClose == COME_CLOSING ) 
        {
            return true;
        }   
        else if(m_isClose == COME_CLOSED  ) 
        {
            return true;
        }
    }
    
    
    if( m_duplex == DUPLEX_ALL  || m_duplex == DUPLEX_NOSHAKE )
    {       
        if(m_isClose == DUPLEX_CLOSING_CLOSING  )
        {
            return true;
        }
        else if(m_isClose == DUPLEX_CLOSING_CLOSED   )
        {
            return true;
        }   
        else if(m_isClose == DUPLEX_CLOSED_CLOSING  )
        {
            return true;
        }
        else if(m_isClose == DUPLEX_CLOSED )
        {
            return true;
        }
    }
    if(OTHER_CLOSE == m_isClose   )
    {
        return true;
    }
    
    return false;
}


int linkStream::setRst( uint8_t flow)
{
    (void)flow;
    m_isClose = OTHER_CLOSE;
    return 0;

}


int linkStream::setClosed( uint8_t flow)
{
    if(flow == FLOW_COME)
    {   
        //come端发回ack回应cover的fin关闭包
        //设置conver的 colse...
        if(m_duplex == DUPLEX_ALL ||m_duplex == DUPLEX_NOSHAKE) 
        {
            if(m_isClose == CONVER_CLOSING)
            {
                m_isClose = CONVER_CLOSED;
            }       
            else if( m_isClose == DUPLEX_CLOSING_CLOSING)
            {
                m_isClose = DUPLEX_CLOSING_CLOSED;
            }
            else if( m_isClose == DUPLEX_CLOSED_CLOSING)
            {
                m_isClose = DUPLEX_CLOSED;
            }
            else if( m_isClose == OTHER_CLOSE || m_isClose == CONVER_CLOSED )
            {
                //超时和seq进一步判断
                printf("error-or-info,re-setClosed flow_come DUPLEX_ALL m_isClose=%d m_nSeqNum=%u .\r\n",m_isClose,m_nSeqNum);
            }
            else
            {
                printf("error,setClosed flow_come DUPLEX_ALL m_isClose=%d m_nSeqNum=%u .\r\n",m_isClose,m_nSeqNum);
                m_isClose = OTHER_CLOSE;
                return -1;
            }            
        }
        else if( m_duplex == CLIENT_ONLY|| m_duplex == SERVER_ONLY ||m_duplex == NOSHAKE)
        {
            if( m_isClose == COME_CLOSING)
            {
                m_isClose = COME_CLOSED;
            }       
            else 
            {
                printf("error,setClosed flow_come CLIENT_ONLY/SERVER_ONLY m_isClose=%d id[%d] m_streamPktSum[%d]=%d  m_nSeqNum=%u .\r\n",
                m_isClose,m_linkId,m_flowDir,m_streamPktSum[m_flowDir],m_nSeqNum);
                m_isClose = OTHER_CLOSE;
                return -1;
            }
        }
        /*
        else if(m_duplex == NOSHAKE ||m_duplex == DUPLEX_NOSHAKE ) 
        {            
            //无握手包的状态
            TRACE("info,setClosed flow_come m_duplex=%d m_isClose=%d  id[%d] m_streamPktSum[%d]=%d m_nSeqNum=%u .\r\n",
                m_duplex,m_isClose,m_linkId,m_flowDir,m_streamPktSum[m_flowDir],m_nSeqNum);
            m_isClose = OTHER_CLOSE;
        }
        */
        else
        {
            //握手未识别 m_duplex=DUPLEX_NULL
            printf("error,setClosed flow_come m_duplex=%d m_isClose=%d  id[%d] m_streamPktSum[%d]=%d m_nSeqNum=%u .\r\n",
                m_duplex,m_isClose,m_linkId,m_flowDir,m_streamPktSum[m_flowDir],m_nSeqNum);
            m_isClose = OTHER_CLOSE;
            return -1;
        }
    }
    else if(flow == FLOW_CONVER)
    {   
        //cover端发回ack回应come的fin关闭包
        //设置come的 colse...
        if(m_duplex == DUPLEX_ALL ||m_duplex == DUPLEX_NOSHAKE ) 
        {
            if( m_isClose == COME_CLOSING)
            {
                m_isClose = COME_CLOSED;
            }       
            else if(m_isClose == DUPLEX_CLOSING_CLOSING)
            {
                m_isClose = DUPLEX_CLOSED_CLOSING;
            }
            else if(m_isClose == DUPLEX_CLOSING_CLOSED)
            {
                m_isClose = DUPLEX_CLOSED;
            }
            else if( m_isClose == OTHER_CLOSE)
            {
                printf("info,setClosed flow_conver DUPLEX_ALL m_isClose=%d m_nSeqNum=%u .\r\n",m_isClose,m_nSeqNum);
            }
            else
            {
                printf("error,setClosed flow_conver m_isClose=%d  id[%d] m_streamPktSum[%d]=%d m_nSeqNum=%u .\r\n",
                m_isClose,m_linkId,m_flowDir,m_streamPktSum[m_flowDir],m_nSeqNum);
                m_isClose = OTHER_CLOSE;
                return -1;
            }
        }
        else if( m_duplex == CLIENT_ONLY|| m_duplex == SERVER_ONLY ||m_duplex == NOSHAKE)
        {
            if(m_isClose == CONVER_CLOSING)
            {
                m_isClose = CONVER_CLOSED;
            }       
            else 
            {
                printf("error,setClosed flow_conver CLIENT_ONLY/SERVER_ONLY m_isClose=%d  id[%d] m_streamPktSum[%d]=%d m_nSeqNum=%u .\r\n",
                m_isClose,m_linkId,m_flowDir,m_streamPktSum[m_flowDir],m_nSeqNum );
                m_isClose = OTHER_CLOSE;
                return -1;
            }
        }
        /*
        else if(m_duplex == NOSHAKE ||m_duplex == DUPLEX_NOSHAKE ) 
        {            
            //无握手包的状态
            TRACE("info,setClosed flow_conver m_duplex=%d m_isClose=%d  id[%d] m_streamPktSum[%d]=%d m_nSeqNum=%u .\r\n",
                m_duplex,m_isClose,m_linkId,m_flowDir,m_streamPktSum[m_flowDir],m_nSeqNum);
            m_isClose = OTHER_CLOSE;
        }
        */
        else
        {
            printf("error,setClosed flow_conver m_duplex=%d m_isClose=%d  id[%d] m_streamPktSum[%d]=%d m_nSeqNum=%u .\r\n",
                m_duplex,m_isClose,m_linkId,m_flowDir,m_streamPktSum[m_flowDir],m_nSeqNum);
            m_isClose = OTHER_CLOSE;
            return -1;
        }
    }
    else
    {
        printf("error,setClosed id[%d] m_streamPktSum[%d]=%d m_nSeqNum=%u .\r\n",
                m_linkId,m_flowDir,m_streamPktSum[m_flowDir],m_nSeqNum);
        m_isClose = OTHER_CLOSE;
        return -1;
    }
    return 0;

}


int linkStream::setClosing( uint8_t flow)
{
    if(flow == FLOW_COME)
    {
        //FLOW_COME端fin关闭包
        if( m_isClose == OTHER_NULL)
        {
            m_isClose = COME_CLOSING;
        }
        else if( m_isClose == OTHER_CLOSE)
        {
            m_isClose = COME_CLOSING;
        }
        else if( m_isClose == CONVER_CLOSING)
        {
            m_isClose = DUPLEX_CLOSING_CLOSING;
        }
        else if( m_isClose == CONVER_CLOSED)
        {
            m_isClose = DUPLEX_CLOSING_CLOSED;
        }
        else if( m_isClose == DUPLEX_CLOSING_CLOSED || 
            m_isClose == DUPLEX_CLOSING_CLOSING  ||
            m_isClose == COME_CLOSED||//fin已经被回应
            m_isClose == COME_CLOSING ||
            m_isClose == DUPLEX_CLOSED ||
            m_isClose == DUPLEX_CLOSED_CLOSING)
        {
            //判断时间和seq error or info
            //fin-fin 可能间隔长达10多秒
            //fin 多次发送,
            if(m_seqTryStatus != SEQ_SUCCESS && m_seqTryStatus !=SEQ_RESEND )
            {
                TRACE("error,linkStream::setClosing() finfin id[%d] m_isClose=%d id[%d] m_streamPktSum[%d]=%d m_nSeqNum=%u  flow_come.\r\n",
                    m_linkId,m_isClose ,m_linkId,m_flowDir,m_streamPktSum[m_flowDir],m_nSeqNum);
            }
            else
            {
                TRACE("infor,linkStream::setClosing() finfin id[%d] m_isClose=%d id[%d] m_streamPktSum[%d]=%d m_nSeqNum=%u  flow_come.\r\n",
                    m_linkId,m_isClose ,m_linkId,m_flowDir,m_streamPktSum[m_flowDir],m_nSeqNum);
            }
        }
        else
        {
            printf("error,linkStream::setClosing() id[%d] m_isClose=%d id[%d] m_streamPktSum[%d]=%d m_nSeqNum=%u  flow_come.\r\n",
                m_linkId,m_isClose ,m_linkId,m_flowDir,m_streamPktSum[m_flowDir],m_nSeqNum);
            m_isClose = OTHER_CLOSE;
            return -1;
        }
    }
    else if(flow == FLOW_CONVER)
    {
        //FLOW_CONVER端fin关闭包
        if( m_isClose == OTHER_NULL)
        {
            m_isClose = CONVER_CLOSING;
        }
        else if(m_isClose == OTHER_CLOSE)
        {
            m_isClose = CONVER_CLOSING;
        }
        else if(m_isClose == COME_CLOSING)
        {
            m_isClose = DUPLEX_CLOSING_CLOSING;
        }
        else if(m_isClose == COME_CLOSED)
        {
            m_isClose = DUPLEX_CLOSED_CLOSING;
        }
        else if( m_isClose == DUPLEX_CLOSED_CLOSING || 
            m_isClose == DUPLEX_CLOSING_CLOSING  ||
            m_isClose == CONVER_CLOSED||//fin已经被回应
            m_isClose == CONVER_CLOSING ||
            m_isClose == DUPLEX_CLOSED ||
            m_isClose ==DUPLEX_CLOSING_CLOSED)
        {
            //判断时间和seq error or info
            //fin-fin 间隔长达10多秒
            //fin 多次发送,        
            if(m_seqTryStatus != SEQ_SUCCESS && m_seqTryStatus !=SEQ_RESEND )
            {
                printf("error,linkStream::setClosing() finfin id[%d] m_isClose=%d id[%d] m_streamPktSum[%d]=%d m_nSeqNum=%u  flow_conver.\r\n",
                    m_linkId,m_isClose,m_linkId,m_flowDir,m_streamPktSum[m_flowDir],m_nSeqNum);
            }
            else
            {
                printf("info,linkStream::setClosing() finfin id[%d] m_isClose=%d id[%d] m_streamPktSum[%d]=%d m_nSeqNum=%u  flow_conver.\r\n",
                    m_linkId,m_isClose,m_linkId,m_flowDir,m_streamPktSum[m_flowDir],m_nSeqNum);                
            }           
        }
        else
        {
            printf("error,linkStream::setClosing()  id[%d] m_isClose=%d id[%d] m_streamPktSum[%d]=%d m_nSeqNum=%u flow_conver.\r\n",
                m_linkId,m_isClose,m_linkId,m_flowDir,m_streamPktSum[m_flowDir],m_nSeqNum);
            m_isClose = OTHER_CLOSE;
            return -1;
        }
    }
    else
    {
        printf("error,setClosing.\r\n");
        m_isClose = OTHER_CLOSE;
        return -1;
    }
    return 0;
}

int linkStream::tcpFin()
{
    return tcpFinAck();
}
int linkStream::tcpSyn()
{
    return -1;
}
int linkStream::tcpRst()
{
    m_nByeHandshake++;
    int ret =0;
    if(m_duplex == CLIENT_ONLY )
    {//fin fllow ack    
        TRACE("tcpRst  CLIENT_ONLY.\r\n");
        ret = setRst(FLOW_COME);        
    }
    else if(m_duplex == SERVER_ONLY )
    {
        TRACE("tcpRst  SERVER_ONLY.\r\n");
        ret = setRst(FLOW_COME);
    }
    else if(m_duplex == DUPLEX_ALL ||m_duplex == NOSHAKE ||m_duplex == DUPLEX_NOSHAKE)
    {
        if(m_ComeOrConver[m_flagsSum-1] == FLOW_COME)
        {           
            ret =setRst(FLOW_COME);
            TRACE("info,tcpRst DUPLEX_ALL %s rst.\r\n", "COME" );
        }
        else if(m_ComeOrConver[m_flagsSum-1] == FLOW_CONVER)
        {       
            ret =setRst(FLOW_CONVER);
            TRACE("info,tcpRst DUPLEX_ALL %s rst.\r\n","CONVER");
        }
    }
    else if(m_duplex == DUPLEX_NULL )
    {
        ////2016/9/19,第一个包为rst
        if(m_flagsSum ==1)
        {
            if( m_ComeOrConver[0] == FLOW_COME )
            {
                m_duplex = NOSHAKE; 
                ret =setRst(FLOW_COME);
            }
        }////2016/9/19
        else
        {
            printf("error,tcpRst  DUPLEX_NULL.\r\n");
            ret =  -1;
        }
    }
    //else if(m_duplex == DUPLEX_ALLCLOSE )
    //{
    //    TRACE("info,tcpRst  DUPLEX_CLOSE.\r\n");
    //}
    else 
    {
        printf("error,tcpRst  m_nSeqNum=%u .\r\n" ,m_nSeqNum );
        ret =  -1;
    }

    return ret;
}
int linkStream::tcpPsh()
{
    return -1;
}
int linkStream::tcpAckClear(uint8_t flow)
{
    if( flow == FLOW_COME )
    {
        if(m_flagsSum > 4)
        {
            m_flagsSum--;
            m_ComeOrConver.pop_back();
            m_synComeFlagsQueuen.pop_back();
            m_comeFlagsSum --;
            m_ackAckSum --;
            //TRACE("infor,back tcpAckClear FLOW_COME m_flagsSum = %d.\r\n",m_flagsSum);
        }
    }
    if( flow == FLOW_CONVER)
    {
        if(m_flagsSum > 4)
        {
            m_flagsSum--;
            m_ComeOrConver.pop_back();
            m_synConverFlagsQueuen.pop_back();
            m_converFlagsSum --;
            m_ackAckSum --;
            //TRACE("infor,back tcpAckClear FLOW_CONVER m_flagsSum = %d.\r\n",m_flagsSum);
        }
    }
    return 0;
}

    
int linkStream::tcpFinAck()
{
    m_nByeHandshake++;
    int ret =0;
    if(m_duplex == CLIENT_ONLY )
    {//fin fllow ack    
        TRACE("tcpFinAck   C(only).\r\n");
        ret = setClosing(FLOW_COME);        
    }
    else if(m_duplex == SERVER_ONLY )
    {
        TRACE("tcpFinAck   S(only).\r\n");
        ret = setClosing(FLOW_COME);
    }
    else if(m_duplex == DUPLEX_ALL )
    {
        if(m_ComeOrConver[m_flagsSum-1] == FLOW_COME)
        {           
            ret =setClosing(FLOW_COME);
            TRACE("tcpFinAck DUPLEX_ALL %s fin.\r\n", "COME" );
        }
        else if(m_ComeOrConver[m_flagsSum-1] == FLOW_CONVER)
        {       
            ret =setClosing(FLOW_CONVER);
            TRACE("tcpFinAck DUPLEX_ALL %s fin.\r\n","CONVER");
        }
    }
    else if(m_duplex == NOSHAKE || m_duplex == DUPLEX_NOSHAKE)
    {
        TRACE_MAX("tcpFinAck  X_NOSHAKE id[%d] m_streamPktSum[%d]=%d m_nSeqNum=%u .\r\n",
                m_linkId,m_flowDir,m_streamPktSum[m_flowDir],m_nSeqNum);
        if(m_ComeOrConver[m_flagsSum-1] == FLOW_COME)
        {           
            ret =setClosing(FLOW_COME);
            TRACE("tcpFinAck X_NOSHAKE %s fin.\r\n", "COME" );
        }
        else if(m_ComeOrConver[m_flagsSum-1] == FLOW_CONVER)
        {       
            ret =setClosing(FLOW_CONVER);
            TRACE("tcpFinAck X_NOSHAKE %s fin.\r\n","CONVER");
        } 
    }
    else if(m_duplex == DUPLEX_NULL )
    {
        ////2016/9/19,第一个包为fin
        if(m_flagsSum ==1)
        {
            if( m_ComeOrConver[0] == FLOW_COME )
            {
                m_duplex = NOSHAKE; 
                ret =setClosing(FLOW_COME);
            }
        }////2016/9/19
        else
        {
            //握手未识别错误
            printf("error,tcpFinAck  DUPLEX_NULL id[%d] m_streamPktSum[%d]=%d m_nSeqNum=%u .\r\n",
                    m_linkId,m_flowDir,m_streamPktSum[m_flowDir],m_nSeqNum);   
            return -1;      
        }
    }
    //else if(m_duplex == DUPLEX_ALLCLOSE )
    //{
    //    printf("error,tcpFinAck  DUPLEX_CLOSE.id[%d] m_streamPktSum[%d]=%d m_nSeqNum=%u .\r\n",
    //            m_linkId,m_flowDir,m_streamPktSum[m_flowDir],m_nSeqNum);
    //    return -1;
    //}
    else 
    {
        printf("error,tcpFinAck.id[%d] m_streamPktSum[%d]=%d m_nSeqNum=%u .\r\n",
                m_linkId,m_flowDir,m_streamPktSum[m_flowDir],m_nSeqNum);
        return -1;
    }
    return ret ;
}

int linkStream::tcpPshAck()
{
    if( m_ComeOrConver[m_flagsSum-1] == FLOW_COME )
    {
        m_synComeFlagsQueuen[m_comeFlagsSum-1]=TCP_ACK;
        //TRACE("infor,tcpPshAck FLOW_COME turn to TCP_ACK.\r\n");
    }
    else
    {
        m_synConverFlagsQueuen[m_converFlagsSum-1]=TCP_ACK;
        //TRACE("infor,tcpPshAck FLOW_CONVER turn to TCP_ACK.\r\n");
    }
    return tcpAck();    
}

int linkStream::tcpAck()
{
    int ret=0;
    if( m_bLastAckAck )
    {
        m_bAckAck = true;
        m_ackAckSum ++;
    }
    else
    {
        m_bAckAck = true;
        m_ackAckSum =1;
    }

    if(m_flagsSum == 2)
    {
        if( m_ComeOrConver[0] == FLOW_COME &&
            m_ComeOrConver[1] == FLOW_COME &&
            m_synComeFlagsQueuen[0] == TCP_SYN 
        )
        {
            TRACE("C only.\r\n");
        } 
        else  if( m_ComeOrConver[0] == FLOW_COME &&
                  m_ComeOrConver[1] == FLOW_COME &&
                  m_synComeFlagsQueuen[0] == (TCP_SYN | TCP_ACK)
        )
        {       
            TRACE("S only.\r\n");
        }
        else if(0==m_nHandshake && m_duplex== DUPLEX_NULL )
        {
            m_duplex = NOSHAKE;
            TRACE("info,tcpAck  NOSHAKE  m_flagsSum = 2, m_duplex= %d, m_nHandshake= %d m_nSeqNum=%u .\r\n",m_duplex,m_nHandshake,m_nSeqNum);
        }
        else if(0==m_nHandshake && m_duplex== NOSHAKE && m_ComeOrConver[0]!= m_ComeOrConver[1] )
        {
            m_duplex = DUPLEX_NOSHAKE;
            TRACE("info,tcpAck  DUPLEX_NOSHAKE  m_flagsSum = 2, m_duplex= %d, m_nHandshake= %d m_nSeqNum=%u .\r\n",m_duplex,m_nHandshake,m_nSeqNum);
        } 
        else if(0==m_nHandshake && (m_duplex== NOSHAKE || m_duplex== DUPLEX_NOSHAKE) )
        {
            //nothing
        }
        else
        {
            printf("error,tcpAck    m_flagsSum = 2, m_duplex= %d, m_nHandshake= %d m_nSeqNum=%u .\r\n",m_duplex,m_nHandshake,m_nSeqNum);
            return -1;
        }
    }
    else if(m_flagsSum == 3)
    {
        if( m_ComeOrConver[0] == FLOW_COME &&
            m_ComeOrConver[1] == FLOW_CONVER &&
            m_ComeOrConver[2] == FLOW_COME &&
            m_synConverFlagsQueuen[0] == (TCP_SYN|TCP_ACK) )
        {
            TRACE("C2S created.\r\n");          
            m_duplex = DUPLEX_ALL;
            m_direction = FLOW_COME_CLIENT;     
            
        } 
        else if( m_ComeOrConver[0] == FLOW_COME &&
                 m_ComeOrConver[1] == FLOW_COME &&
                 m_ComeOrConver[2] == FLOW_COME &&
                 m_synComeFlagsQueuen[0] == (TCP_SYN|TCP_ACK) )
        {
            TRACE("S(only) created.\r\n"); 
            m_duplex = SERVER_ONLY; 
            m_direction = FLOW_COME_SERVER;
        } 
        else if( m_ComeOrConver[0] == FLOW_COME &&
                 m_ComeOrConver[1] == FLOW_COME &&
                 m_ComeOrConver[2] == FLOW_COME &&
                 m_synComeFlagsQueuen[0] == TCP_SYN )
        {
            TRACE("C(only) created.\r\n"); 
            m_duplex = CLIENT_ONLY; 
            m_direction = FLOW_COME_CLIENT;
        }
        else if(0==m_nHandshake && m_duplex== DUPLEX_NULL )
        {
            m_duplex = NOSHAKE;
            TRACE("info,tcpAck NOSHAKE   m_flagsSum = 3, m_duplex= %d, m_nHandshake= %d  m_nSeqNum=%u .\r\n",m_duplex,m_nHandshake, m_nSeqNum);
        } 
        else if(0==m_nHandshake && m_duplex== NOSHAKE && m_ComeOrConver[0]!= m_ComeOrConver[1] )
        {
            m_duplex = DUPLEX_NOSHAKE;
            TRACE("info,tcpAck DUPLEX_NOSHAKE   m_flagsSum = 3, m_duplex= %d, m_nHandshake= %d  m_nSeqNum=%u .\r\n",m_duplex,m_nHandshake, m_nSeqNum);
        }
        else if(0==m_nHandshake && m_duplex== NOSHAKE && m_ComeOrConver[2]!= m_ComeOrConver[1] )
        {
            m_duplex = DUPLEX_NOSHAKE;
            TRACE("info,tcpAck DUPLEX_NOSHAKE   m_flagsSum = 3, m_duplex= %d, m_nHandshake= %d  m_nSeqNum=%u .\r\n",m_duplex,m_nHandshake, m_nSeqNum);
        }
        else if(0==m_nHandshake && (m_duplex== NOSHAKE || m_duplex== DUPLEX_NOSHAKE) )
        {
            //nothing
        }  
        else 
        {
            printf("error,tcpAck    m_flagsSum = 3, m_duplex= %d, m_nHandshake= %d  m_nSeqNum=%u .\r\n",m_duplex,m_nHandshake, m_nSeqNum);
            return -1;
        }   
    }
    
    else if(m_flagsSum > 3)
    {
        INT16 f_1 = m_flagsSum-1;
        INT16 f_2 = m_flagsSum-2;
        //ack fllow ack
        if( m_bAckAck && m_ackAckSum > 2 )
        {           
            if( m_ComeOrConver[f_1] == FLOW_COME)
            {               
                ret=tcpAckClear(FLOW_COME);
            }
            else if ( m_ComeOrConver[f_1] == FLOW_CONVER )
            {               
                ret=tcpAckClear(FLOW_CONVER);
            }
        }
        else if(m_bAckAck && m_ackAckSum > 1 )
        {
            if(m_seqTryStatus == SEQ_SUCCESS || m_seqTryStatus == SEQ_RESEND )
            {       
                //seq正常不算错误
                TRACE("info,tcpAck m_ackAckSum=[%d] >1  m_seqTryStatus=SEQ_SUCCESS/SEQ_RESEND id[%d] m_streamPktSum[%d]=%d m_nSeqNum=%u.\r\n",
                    m_ackAckSum,m_linkId,m_flowDir,m_streamPktSum[m_flowDir],m_nSeqNum);                    
            }
            else if(willClose())
            {
                //seq 差距大，并且间隔超时才error。
                //fin，rst后，可能还要许多数据在传送
                printf("error-or-info,tcpAck  willClose() m_isClose=%d, fin-ack-ack-ack ,m_seqTryStatus=%d m_ackAckSum=[%d] >1  id[%d] m_streamPktSum[%d]=%d m_nSeqNum=%u.\r\n",
                       m_isClose,m_seqTryStatus,m_ackAckSum,m_linkId,m_flowDir,m_streamPktSum[m_flowDir],m_nSeqNum);
                return -1;                
            }
            else
            {
                 printf("error,tcpAck m_isClose=%d, m_seqTryStatus=%d m_ackAckSum[%d] >1  id[%d] m_streamPktSum[%d]=%d m_nSeqNum=%u.\r\n",
                        m_isClose,m_seqTryStatus,m_ackAckSum,m_linkId,m_flowDir,m_streamPktSum[m_flowDir],m_nSeqNum);
                 return -1;
            }
        }
        else  if(m_bAckAck && m_ackAckSum > 0)
        {   
            if( m_ComeOrConver[m_flagsSum-2] != m_ComeOrConver[m_flagsSum-1] )
            {//DUPLEX_ALl           
                if (  (TCP_FIN & m_synConverFlagsQueuen[m_converFlagsSum-1])  ||    (TCP_FIN & m_synComeFlagsQueuen[m_comeFlagsSum-1]) )
                {
                    setClosed( m_ComeOrConver[m_flagsSum-1]);
                }
                else if (  (TCP_RST & m_synConverFlagsQueuen[m_converFlagsSum-1])  ||   (TCP_RST & m_synComeFlagsQueuen[m_comeFlagsSum-1]) )
                {
                    //ack fllow rst.
                }
                else
                {
                    printf("error, flow=%s tcpAck    m_ackAckSum[%d] m_nSeqNum=%u.\r\n", m_ComeOrConver[f_2]== FLOW_CONVER ?"CONVER":"COME" ,m_ackAckSum,m_nSeqNum);
                    return -1;
                }
            }
            else if( m_ComeOrConver[m_flagsSum-2] == m_ComeOrConver[m_flagsSum-1])
            {
                if(m_duplex == DUPLEX_ALL  || m_duplex == DUPLEX_NOSHAKE)
                {                    
                    //something ...
                    if(m_seqTryStatus == SEQ_SUCCESS || m_seqTryStatus == SEQ_RESEND )
                    {       
                        //seq正常不算错误
                        TRACE("tcpAck m_ackAckSum=[%d] >0  m_seqTryStatus=SEQ_SUCCESS/SEQ_RESEND id[%d] m_streamPktSum[%d]=%d m_nSeqNum=%u.\r\n",
                            m_ackAckSum,m_linkId,m_flowDir,m_streamPktSum[m_flowDir],m_nSeqNum);                    
                    }
                    else if(willClose())
                    {
                        //http-seq-1.pcap fin阶段出错
                        printf("DUPLEX_ALL/NOSHAKE/DUPLEX_NOSHAKE m_duplex=%d m_direction = %s  m_nSeqNum=%u.\r\n", 
                        m_duplex,
                        m_direction == FLOW_COME_CLIENT  ?"COME_CLIENT":"COME_SERVER",
                        m_nSeqNum  ); 
                    }
                    else
                    {                      
                        printf("error,DUPLEX_ALL id[%d] m_direction = %s  m_nSeqNum=%u.\r\n",
                            m_linkId,m_direction == FLOW_COME_CLIENT  ?"COME_CLIENT":"COME_SERVER",m_nSeqNum); 
                    
                    }
                    return -1;
                }
                else if(m_duplex == CLIENT_ONLY || m_duplex == SERVER_ONLY || m_duplex == NOSHAKE)
                {
                    bool bComeFin = (m_comeFlagsSum > 1 && m_synComeFlagsQueuen[m_comeFlagsSum-2] & TCP_FIN);
                    if(bComeFin)
                    {
                        setClosed(FLOW_COME);
                    }
                    else
                    {
                        printf("error,CLIENT_ONLY/SERVER_ONLY  m_direction = %s.\r\n", m_direction == FLOW_COME_CLIENT  ?"COME_CLIENT":"COME_SERVER" ); 
                        return -1;                  
                    }
                }
                else
                {
                    printf("error,other m_direction = %s.\r\n", m_direction == FLOW_COME_CLIENT  ?"COME_CLIENT":"COME_SERVER" ); 
                    return -1; 
                }
            }
            else
            {
                printf("error,tcpAck    can not reach 1.\r\n");
                return -1;
            }   
        }
        else
        {
            printf("error,tcpAck    can not reach 2.\r\n");
            return -1;
        }       
    }
    else if( 0==m_nHandshake )
    {
        //m_flagsSum=1,
        //第一个数据包不是握手包
        if(m_duplex == DUPLEX_NULL)
        {
            m_duplex = NOSHAKE;
        }
        else 
        {            
            printf("error,tcpAck m_flagsSum < 2, m_duplex= %d, m_nHandshake= %d  m_nSeqNum=%u .\r\n",m_duplex,m_nHandshake, m_nSeqNum);
        }
    }
    else
    {
        printf("error,tcpAck final-else  m_flagsSum < 2, m_duplex= %d, m_nHandshake= %d  m_nSeqNum=%u .\r\n",m_duplex,m_nHandshake, m_nSeqNum);
        return -1;
    }
    return ret;
}
int linkStream::tcpUrg()
{
    return -1;
}
int linkStream::tcpUrgAck()
{
    return tcpPshAck();
}
int linkStream::tcpSyn_ack0(ipPkt * pkt)
{

    ////2016/9/19,最早识别
    if(m_flagsSum ==1)
    {
        if( m_ComeOrConver[0] == FLOW_COME &&
                 m_synComeFlagsQueuen[0] == TCP_SYN )
        {
            m_duplex = CLIENT_ONLY; 
        }
    }////2016/9/19
    
    m_nHandshake ++;
    if(m_direction == DIRECT_NULL )
    {
        m_direction = FLOW_COME_CLIENT;
        if(FLOW_COME == m_statusCome)
        {
            m_pkt[0]->decodeSynAck0(pkt);
            TRACE("C link...\r\n");
        }
        else
        {
            printf("error,tcpSyn_ack0   FLOW_COME != m_statusCome  m_nSeqNum=%u.\r\n",m_nSeqNum);
            return -1;
        }
    }
    else 
    {
        if(0)
        {
            //client-syn 多次发起，seq一致
            //去重可解决
            printf("info,re-tcpSyn_ack0   m_direction != FLOW_NULL, m_nSeqNum=%u.\r\n",m_nSeqNum);
        }
        else
        {
            printf("error-to-info,re-tcpSyn_ack0   m_direction != FLOW_NULL, m_nSeqNum=%u.\r\n",m_nSeqNum);
        }
        return -1;
    }

    return 0;
}
int linkStream::tcpSynAck(ipPkt * pkt)
{
    ////2016/9/19,最早识别
    if(CLIENT_ONLY == m_duplex &&  FLOW_CONVER ==  m_ComeOrConver[m_flagsSum -1 ]  )
    {
        m_duplex = DUPLEX_ALL;
    }
    else  if(m_flagsSum ==1)
    {
        if( DUPLEX_NULL == m_duplex &&  FLOW_COME ==  m_ComeOrConver[m_flagsSum -1 ] )
        {
            m_duplex = SERVER_ONLY;
        }
    }////2016/9/19


    m_nHandshake++;
    if(m_direction == DIRECT_NULL)
    {
        m_direction = FLOW_COME_SERVER;
        if(FLOW_COME != m_statusCome)
        {
            printf("error,tcpSynAck m_direction=DIRECT_NULL, FLOW_COME != m_statusFlow m_nSeqNum=%u.\r\n",m_nSeqNum);
            return -1;
        }
        if(m_flagsSum == 1)
        {
            if( m_ComeOrConver[0] == FLOW_COME)
            {
                m_pkt[0]->decodeSynAck(pkt);
                TRACE("S link...\r\n");
            }
            else
            {
                printf("error,tcpSynAck m_direction=DIRECT_NULL,m_flagsSum=[1] m_nSeqNum=%u.\r\n",m_nSeqNum);
                return -1;
            }
        }
        else
        {           
            printf("error,tcpSynAck m_direction=DIRECT_NULL,m_flagsSum=%d  [TCP_SYN & TCP_ACK]   m_nSeqNum=%u.\r\n",m_flagsSum,m_nSeqNum);
            return -1;
        }
    }
    else
    {
        //方向已经存在
        if(m_flagsSum == 2)
        {
            if( m_ComeOrConver[0] == FLOW_COME && m_ComeOrConver[1] == FLOW_CONVER)
            {
                m_pkt[1]->decodeSynAck(pkt);
                TRACE("infor,server port link...\r\n");
            }
            else
            {
                printf("error,tcpSynAck else m_flagsSum = 2 m_nSeqNum=%u.\r\n",m_nSeqNum);
                return -1;
            }
        }
        else if(m_flagsSum == 1)
        {
            printf("error,tcpSynAck else m_flagsSum=[1]   [TCP_SYN & TCP_ACK]   m_nSeqNum=%u.\r\n",m_nSeqNum);
            return -1;
        }
        else
        {      
            //多个client-re-syn,导致m_flagsSum>3;
            //去重,序号判断
            if(0)
            {
                //client-syn 多次发起，seq一致
                //去重可解决
                printf("info, re-syn,tcpSynAck else m_flagsSum=%d  [TCP_SYN & TCP_ACK]   m_nSeqNum=%u.\r\n",m_flagsSum,m_nSeqNum);
            }
            else
            {
                printf("error-or-info, re-syn,tcpSynAck else m_flagsSum=%d  [TCP_SYN & TCP_ACK]   m_nSeqNum=%u.\r\n",m_flagsSum,m_nSeqNum);
            }
            return -1;
        }
    }
    return 0;
}
int linkStream::tcpRstAck()
{
    return tcpRst();
}
int linkStream::tcpFinPshAck()
{
    return tcpFin();
}

int linkStream::firstPacket(uint8_t flow,ipPkt * pkt)
{
    if(FLOW_NULL == m_statusCome)
    {   
        if(FLOW_COME  == flow) 
        {
            stringstream ss;
            ss << setfill('0')<< setw(3)<< (uint32_t) pkt->src_num1 << setw(3) << (uint32_t)pkt->src_num2 << setw(3) <<(uint32_t) pkt->dst_num;
            m_lineNumber= ss.str();            
            
            m_statusCome = flow;
            if(0==m_firstTb.tv_sec)
            {           
                m_firstTb.tv_sec = m_tb.tv_sec; 
                m_firstTb.tv_usec = m_tb.tv_usec; 
            }   
            if(NULL!= m_pkt[0])
            {
                printf("error,m_pkt[0] is not NULL.\r\n");
            }
            else
            {
                m_pkt[0] = new tcpReassembly;
                m_pkt[0]->m_nFlowType = 0;
                m_pkt[0]->m_nStreamId = m_linkId;
                m_pkt[0]->m_pLink =this;
            }
        }
    }
    if(FLOW_NULL == m_statusConv)
    {
        if(FLOW_CONVER == flow)
        {
            m_statusConv = flow;
            if(0==m_firstTb.tv_sec)
            {
                m_firstTb.tv_sec = m_tb.tv_sec; 
                m_firstTb.tv_usec = m_tb.tv_usec; 
            }
            if(NULL!= m_pkt[1])
            {
                printf("error,m_pkt[1] is not NULL.\r\n");
            }
            else
            {   
                m_pkt[1] = new tcpReassembly;
                m_pkt[1]->m_nFlowType = 1;
                m_pkt[1]->m_nStreamId = (m_linkId+1);
                m_pkt[1]->m_pLink =this;
            }
        }   
    }


    return 0;
}
int linkStream::flagsEnqueuen(uint8_t flow,uint8_t TcpFlag)
{       
    //m_ComeOrConver[m_flagsSum]= flow;
    m_ComeOrConver.push_back(flow);
    m_flagsSum ++;
    if(flow == FLOW_COME)
    {       
        //m_synComeFlagsQueuen[m_comeFlagsSum]=TcpFlag;
        m_synComeFlagsQueuen.push_back(TcpFlag);
        m_comeFlagsSum ++;
    }
    else if(flow == FLOW_CONVER)
    {       
        //m_synConverFlagsQueuen[m_converFlagsSum]=TcpFlag;
        m_synConverFlagsQueuen.push_back(TcpFlag);
        m_converFlagsSum++;
    }
    m_bLastAckAck = m_bAckAck;
    m_bAckAck =false;
    return 0;
}


int linkStream::decodeCall(int id,bool bAcknowledgmentSeq)
{

    UINT32 ackSeq=0;

    if(bAcknowledgmentSeq && m_linkAdd.nProtocol==TCP_PROTO)
    {   
        //单向包取最大值
        if(id ==0 )
        {
            if(NULL== m_pkt[1])
            {
                ackSeq= -1;
            }
            else
            {
                ackSeq = m_pkt[1]->m_nAckSeq;
            }
        }
        else if(id ==1)
        {
            if(NULL== m_pkt[0])
            {
                ackSeq= -1;
            }
            else
            {
                ackSeq = m_pkt[0]->m_nAckSeq;
            }
        }
    }  

    

    while(m_pkt[id]->m_pktDecoded < m_pkt[id]->m_pktSumForDecode)
    {  

        ipPkt * cur= m_pkt[id]->headDecode;
        assert(cur);        

        if(bAcknowledgmentSeq && ackSeq < cur->reqSeq)
        {
            TRACE("info,decodeCall() acknowledgmentSeq not received.\r\n");
            break ;
        }
        
        if(cur ==m_pkt[id]->tailDecode)
        {
            if(m_pkt[id]->tailDecode->next ==NULL)
            {
                m_pkt[id]->tailDecode =NULL;
            }
            else
            {
                printf("error,linkStream::decodeCall() m_pkt[id].tailDecode->next is not NULL.\r\n");
            }
        }
        //不在统计全部毛流量，改为统计有效的毛流量
        m_pkt[id]->m_macLen +=cur->macLen;
        m_pkt[id]->m_pktDecoded++;
        m_pkt[id]->headDecode = cur->next;
        if(m_bAppLinkOpen != 0 )
        {
            int nError=m_nLinkPktError;
            if(m_nLinkPktError > 0)
            {
                TRACE("info,decodeCall() m_nLinkPktError =%d.\r\n",m_nLinkPktError);
            }
            //m_decode = nprDecodeApp(cur,m_decode,id,nError);
            nError = nprAppLink(cur,id,nError,m_appLink);
        }
        else
        {
            delete cur;
        }
    }   
    return 0;
}

int linkStream::decodeTcpStream(int id, ipPkt * pkt)
{
    int ret =0;
    //统计毛流量
    m_streamTotalMacLen[id] +=pkt->macLen ;
    m_streamPktSum[id]++;  
    if(pkt->len >0)
    {
        m_streamLoadPktSum[id]++;
        m_streamTotalPayloadMacLen[id] +=pkt->macLen;
    }
    pkt->streamPktSerialId = m_streamPktSum[id];
    pkt->linkPktSerialId = m_streamPktSum[0]+m_streamPktSum[1];

    m_pkt[id]->winZeroSize(pkt);

    m_seqTryStatus = m_pkt[id]->upSeqOnly(pkt,0);
    m_seqStatus = m_pkt[id]->upSeqData(pkt,1,0);
    if(m_pkt[id]->m_resendLenStatus > 0 && m_seqStatus == SEQ_ERR )
    {
        m_seqStatus = m_pkt[id]->upSeqData(pkt,1,1);
    }

    
    if(m_seqStatus == SEQ_SUCCESS)
    {
        ret = m_pkt[id]->addTcpPkt( pkt);
        m_pkt[id]->cacheTryAdd();    
        decodeCall(id,true);
    }
    else if(m_seqStatus == SEQ_ERR)
    {
        ret = m_pkt[id]->cachePkt( pkt);
    }
    else if(m_seqStatus == SEQ_RESEND)
    {
        m_streamPktResend[id]++;
        m_streamResendMacLen[id]+=pkt->macLen;  
        delete pkt;
        TRACE_MAX(" linkStream::dealTcpStream()  SEQ_RESEND other.\r\n"); 
    }
    else if(m_seqStatus == SEQ_ERR_DEL)
    {
        m_streamPktUnknow[id]++;
        m_streamUnknowMacLen[id]+=pkt->macLen;  
        delete pkt;
        TRACE(" dealTcpStream SEQ_ERR_DEL.\r\n"); 
    }
    else
    {
        delete pkt;
        printf(" error,linkStream::dealTcpStream()  SEQ_XXXXX other.\r\n");
        return -1; 
    }
    
    
    //test online
    TRACE_MAX(" ===>dealTcpStream  m_pkt[%s] macLen[%d]  payLoadLen[%d] m_pktDecoded[%d] m_pktSumForDecode[%d].\r\n",
        id == 0 ? "COME":"CONVER",
        m_pkt[id]->m_macLen,
        m_pkt[id]->m_payLoadLen,
        m_pkt[id]->m_pktDecoded,
        m_pkt[id]->m_pktSumForDecode);

    TRACE_MAX("====>dealTcpStream  m_pkt[%s] PktSum[%u] TotalMacLen[%u] TotalPayloadMacLen[%u] PktResend[%u] ResendMacLen[%u].\r\n",
        id == 0 ? "COME":"CONVER",
        m_streamPktSum[id],
        m_streamTotalMacLen[id],
        m_streamTotalPayloadMacLen[id],
        m_streamPktResend[id],
        m_streamResendMacLen[id]);  
     
    return ret;

}


int linkStream::decodeUdpStream(int id, ipPkt * pkt)
{
    int ret =0;
    
    //统计毛流量
    m_streamTotalMacLen[id] +=pkt->macLen ;
    m_streamPktSum[id]++;  
    if(pkt->len >0)
    {
        m_streamLoadPktSum[id]++;
        m_streamTotalPayloadMacLen[id] +=pkt->macLen;
    }
    pkt->streamPktSerialId = m_streamPktSum[id];
    pkt->linkPktSerialId = m_streamPktSum[0]+m_streamPktSum[1];


    ret = m_pkt[id]->addUdpPkt( pkt);
    decodeCall(id,false);     

    //test online
    TRACE_MAX(" ===>dealTcpStream  m_pkt[%s] macLen[%d]  payLoadLen[%d] m_pktDecoded[%d] m_pktSumForDecode[%d].\r\n",
        id == 0 ? "COME":"CONVER",
        m_pkt[id]->m_macLen,
        m_pkt[id]->m_payLoadLen,
        m_pkt[id]->m_pktDecoded,
        m_pkt[id]->m_pktSumForDecode);

    TRACE_MAX("====>dealTcpStream  m_pkt[%s] PktSum[%u] TotalMacLen[%u] TotalPayloadMacLen[%u] PktResend[%u] ResendMacLen[%u].\r\n",
        id == 0 ? "COME":"CONVER",
        m_streamPktSum[id],
        m_streamTotalMacLen[id],
        m_streamTotalPayloadMacLen[id],
        m_streamPktResend[id],
        m_streamResendMacLen[id]);  
     
    return ret;

}

bool linkStream::findResendPkt()
{
    
    if( m_tcpFlag ==  m_lastTcpFlag[m_flowDir] &&
        m_len ==  m_lastLen[m_flowDir] &&
        m_flow ==  m_lastFlow[m_flowDir] &&
        m_nSeqNum ==  m_nlastSeqNum[m_flowDir] )
    {
        return true; 
    }
    else
    {
        m_lastTcpFlag[m_flowDir] = m_tcpFlag;
        m_lastLen[m_flowDir] = m_len;
        m_lastFlow[m_flowDir] = m_flow;
        m_nlastSeqNum[m_flowDir] = m_nSeqNum;
        return false;
    }
}


int linkStream::dealStream(ipPkt * pkt, struct timeval & nCur, uint8_t flow)
{
    if(0 !=m_firstTb.tv_sec)
    { 
        if(0 != m_lastOutputTb.tv_sec)
        {
            if( (nCur.tv_sec - m_lastOutputTb.tv_sec) > nOutputMaxTime)
            {
                statisticOut(true);
                m_lastOutputTb.tv_sec = nCur.tv_sec;
            }
        }
        else if( (nCur.tv_sec - m_firstTb.tv_sec) > nOutputMaxTime)
        {
            statisticOut(true);
            m_lastOutputTb.tv_sec = nCur.tv_sec;
        }
    }
    
    if(m_linkAdd.nProtocol==TCP_PROTO)
    {
        return dealTcpStream( pkt,   nCur, flow);
    }
    if(m_linkAdd.nProtocol==UDP_PROTO)
    {
        return dealUdpStream( pkt,   nCur, flow);
    }
    delete pkt;
    return -1;

}

int linkStream::dealTcpStream(ipPkt * pkt, struct timeval & nCur, uint8_t flow)
{    
    //TRACE_MAX("\r\n");
    m_tb.tv_sec = nCur.tv_sec; 
    m_tb.tv_usec = nCur.tv_usec; 
  
    m_tcpFlag = pkt->byTcpFlag;
    m_len =pkt->len;
    m_flow =flow;
    m_nSeqNum = pkt->reqSeq;
    m_nAckSeq = pkt->ackSeq;
    
    firstPacket(flow,pkt);
    
    int ret =0;
    int id =0;
    bool findresend=true;
    if(m_flow == FLOW_COME)
    {   
        m_flowDir =0;
        id =0;
        findresend=findResendPkt( );
        //decodeTcpStream(m_flowDir,pkt);
    }
    else  if(m_flow == FLOW_CONVER)
    {     
        m_flowDir =1;
        id =1;
        findresend=findResendPkt( );
        //decodeTcpStream(m_flowDir,pkt);     
    }
    
    m_synFlagStatistic[pkt->byTcpFlag]++;

    //重复包不处理
    if(true == findresend)
    {
        //更新为成功处理
        m_seqTryStatus = SEQ_SUCCESS;
        m_seqStatus = SEQ_SUCCESS;
        //处理重复的数据包，并删除
        decodeTcpStream(m_flowDir,pkt);
        return ret;
    }
    
    flagsEnqueuen(flow,pkt->byTcpFlag);

    if(m_nAckSeq ==0 && m_tcpFlag == TCP_SYN)
    {
        m_tcpFlag =  TCP_SYN_ACK0;
    }

    switch(m_tcpFlag)
    {
    case TCP_FIN:
    {   
        if( tcpFin())
        {
            printf("tcpflags  %5d  [TCP_FIN]   id[%d] m_streamPktSum[%d]=%d.\r\n",m_synFlagStatistic[m_tcpFlag],
                m_linkId,id,m_streamPktSum[id]);     
        }
        break;
    }
    case TCP_SYN:
    {           
        if( tcpSyn())
        {
            printf("tcpflags  %5d  [TCP_SYN]   id[%d] m_streamPktSum[%d]=%d.\r\n",m_synFlagStatistic[m_tcpFlag],
                m_linkId,id,m_streamPktSum[id]);      
        }
        break;
    }
    
    case TCP_RST:
    {           
        if( tcpRst()) 
        {
            printf("tcpflags  %5d  [TCP_RST]   id[%d] m_streamPktSum[%d]=%d.\r\n",m_synFlagStatistic[m_tcpFlag],
                m_linkId,id,m_streamPktSum[id]);     
        }
        break;
    }
    case TCP_PSH:
    {           
        if( tcpPsh()) 
        {
            printf("tcpflags  %5d  [TCP_PSH]   id[%d] m_streamPktSum[%d]=%d.\r\n",m_synFlagStatistic[m_tcpFlag],
                m_linkId,id,m_streamPktSum[id]);     
        }
        break;
    }   
    case TCP_ACK:
    {           
        if( tcpAck()) 
        {
            printf("tcpflags  %5d  [TCP_ACK]   id[%d] m_streamPktSum[%d]=%d.\r\n",m_synFlagStatistic[m_tcpFlag],
                m_linkId,id,m_streamPktSum[id]);        
        }
        break;
    }   
    case TCP_URG:
    {           
        if( tcpUrg()) 
        {
            printf("tcpflags  %5d  [TCP_URG]   id[%d] m_streamPktSum[%d]=%d.\r\n",m_synFlagStatistic[m_tcpFlag],
                m_linkId,id,m_streamPktSum[id]);     
        }
        tcpUrg();
        break;
    }
    case TCP_FIN|TCP_ACK:
    {           
        if( tcpFinAck()) 
        {
            printf("tcpflags  %5d  [TCP_FIN|TCP_ACK]   id[%d] m_streamPktSum[%d]=%d.\r\n",m_synFlagStatistic[m_tcpFlag],
                m_linkId,id,m_streamPktSum[id]);       
        }
        break;
    }
    case TCP_PSH|TCP_ACK:
    {           
        if( tcpPshAck()) 
        {
            printf("tcpflags  %5d  [TCP_PSH|TCP_ACK]   id[%d] m_streamPktSum[%d]=%d.\r\n",m_synFlagStatistic[m_tcpFlag],
                m_linkId,id,m_streamPktSum[id]);     
        }
        break;
    }
    case TCP_SYN_ACK0:
    {
        if( tcpSyn_ack0( pkt)) 
        {
            printf("tcpflags  %5d  [TCP_SYN_ACK0]   id[%d] m_streamPktSum[%d]=%d.\r\n",m_synFlagStatistic[m_tcpFlag],
                m_linkId,id,m_streamPktSum[id]);      
        }
        break;
    }
    case TCP_SYN|TCP_ACK:
    {
        if( tcpSynAck( pkt)) 
        {
            printf("tcpflags  %5d  [TCP_SYN|TCP_ACK]   id[%d] m_streamPktSum[%d]=%d.\r\n",m_synFlagStatistic[m_tcpFlag],
                m_linkId,id,m_streamPktSum[id]);       
        }
        break;
    }
    case TCP_RST|TCP_ACK:
    {
        if( tcpRstAck()) 
        {
            printf("tcpflags  %5d  [TCP_RST|TCP_ACK]   id[%d] m_streamPktSum[%d]=%d.\r\n",m_synFlagStatistic[m_tcpFlag],
                m_linkId,id,m_streamPktSum[id]);        
        }
        break;
    }
    case TCP_PSH|TCP_ACK|TCP_FIN:
    {
        if( tcpFinPshAck()) 
        {
            printf("tcpflags  %5d  [TCP_PSH|TCP_ACK|TCP_FIN]   id[%d] m_streamPktSum[%d]=%d.\r\n",m_synFlagStatistic[m_tcpFlag],
                m_linkId,id,m_streamPktSum[id]);     
        }
        break;
    }
    default:
    {
        printf("tcpflags [0x%x]   id[%d] m_streamPktSum[%d]=%d.\r\n",m_tcpFlag,
                m_linkId,id,m_streamPktSum[id]);     
        break;
    }
    }
    //最后处理数据包，不用保留的将删除
    decodeTcpStream(m_flowDir,pkt);
    return ret;

}

int linkStream::dealUdpStream(ipPkt * pkt, struct timeval & nCur, uint8_t flow)
{    
    TRACE_MAX("\r\n");
    m_tb.tv_sec = nCur.tv_sec; 
    m_tb.tv_usec = nCur.tv_usec; 
    
    m_len =pkt->len;
    m_flow =flow;
    
    firstPacket(flow,pkt);    
    
    int ret =0;
    if(m_flow == FLOW_COME)
    {   
        m_flowDir =0;
        decodeUdpStream(m_flowDir,pkt);
    }
    else  if(m_flow == FLOW_CONVER)
    {     
        m_flowDir =1;
        decodeUdpStream(m_flowDir,pkt);     
    }
    
 
    return ret;

}

int linkStream::dumpSyn()
{
    TRACE("syn stack m_linkId[%d].\r\n",m_linkId);
    for(int i=0;i<m_flagsSum;i++)
    {
        TRACE("syn stack [0x%x].\r\n",m_ComeOrConver[i]);
    }
    return 0;
}
