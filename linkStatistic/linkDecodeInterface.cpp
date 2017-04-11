///////////////////////////////////////////////////////////
//  linkDecodeInterface.cpp
//  Implementation of the Class httpAppManager
//  Created on:      19-四月-2016 16:13:52
//  Original author: Administrator
///////////////////////////////////////////////////////////

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include "linkDecodeInterface.h"

#include "nprlinkpool.h"

#include "ipPkt.h"

#include "linkstream.h"

#include "ip_fragment.h"

#include "appLinkInterface.h"

const short int PORPERTY_MAX_ELEMENT=10;

__thread void * pOutObj=NULL;

__thread pOutFun pFun=NULL;


//四元组管理器,第一个元素管理TCP连接，第二个元素管理UDP 
__thread nprLinkPool * g_nprLinkPool=NULL;;

//解析总开关
__thread bool bOpen=false;

__thread CIP_Fragment * g_ip_Fragment=NULL;

//#define POOL_TIMEOUT 60

unsigned int nCurTime=0;



int nprInitLinkDecode(linkPptInit * pInit,pOutFun pFunction, void * pObj )
{
    int ret =0;

    if(pOutObj ==NULL)
    {
        pOutObj = pObj ;
    }
    else
    {        
        //失败或无效的初始化
        ret =-1;
        return ret;
    }
    
    if(pFun ==NULL)
    {
        pFun = pFunction ;
    }
    else
    {        
        //失败或无效的初始化
        ret =-1;
        return ret;
    }

    tcpReassembly::cacheSumMaxSetting = pInit->cacheSumMaxSetting;
    tcpReassembly::seqJumpMaxSetting = pInit->seqJumpMaxSetting;
    tcpReassembly::seqJumpSumMax = pInit->seqJumpSumMax;
    tcpReassembly::bTcpSeqSameCache = pInit->bTcpSeqSameCache;
    linkStream::RstFinTimeout = pInit->RstFinTimeout;
    linkStream::UdpTimeout=pInit->UdpTimeout;
    linkStream::nNoByeDefaultTimeout = pInit->nNoByeDefaultTimeout;
    linkStream::nCacheTimeout =pInit->nCacheTimeout;
    linkStream::nOutputMaxTime =pInit->nOutputMaxTime;
    
    printf("init, linkppt RstFinTimeout=%d\r\n",pInit->RstFinTimeout);
    printf("init, linkppt nNoByeDefaultTimeout=%d\r\n",pInit->nNoByeDefaultTimeout);    
    printf("init, linkppt cacheSumMaxSetting=%d\r\n",pInit->cacheSumMaxSetting);
    printf("init, linkppt seqJumpMaxSetting=%d\r\n",pInit->seqJumpMaxSetting);
    printf("init, linkppt seqJumpSumMax=%d\r\n",pInit->seqJumpSumMax);
    printf("init, linkppt UdpTimeout=%d\r\n",pInit->UdpTimeout);
    printf("init, linkppt bTcpSeqSameCache=%d\r\n",pInit->bTcpSeqSameCache);
    printf("init, linkppt nCacheTimeout=%d\r\n",pInit->nCacheTimeout);
    printf("init, linkppt nOutputMaxTime=%d\r\n",pInit->nOutputMaxTime);

    if(NULL ==  g_nprLinkPool)
    {
        g_nprLinkPool = new nprLinkPool;
        printf("info, pthread_self=%lu g_nprLinkPool=%p\r\n",pthread_self(),g_nprLinkPool);
    }
    else
    {
        printf("error,pthread_self=%lu g_nprLinkPool is not NULL.\r\n",pthread_self());
    }

    if(NULL == g_ip_Fragment)
    {
        g_ip_Fragment = new CIP_Fragment;
        printf("info, pthread_self=%lu g_ip_Fragment=%p.\r\n",pthread_self(),g_ip_Fragment);
    }
    else
    {
        printf("error,pthread_self=%lu g_ip_Fragment is not NULL.\r\n",pthread_self());
    }
    bOpen = true;
    g_nprLinkPool->m_bDecodeOpen = bOpen;
    
    //string strFile = "/conf/extract-npr.xml";
    //ret = nprInitAppDecode(strFile);
    
    string rootPath =  string(getenv("NPR_ROOT"));
    ret = nprInitAppLink(rootPath);
    return 0;
}



int nprDecodeLink(ipPkt * newOne)
{  
    static unsigned long long int sum=0;
    static unsigned long long int sumIpFragment=0;
    static unsigned long long int sumNoIpFragment=1;
    static unsigned long long int sumPrintf=0;
       
    struct timeval tv;
    struct timezone tz;     
    gettimeofday(&tv,&tz);
    
    
    int ret =0;   
    
    //if (tv.tv_sec >= (int)nCurTime ) 
    {
        nCurTime = tv.tv_sec;
    }

    int ipret = g_ip_Fragment->ProcessIP(newOne); 

    if(ipret ==NEED_FRAGMENT)
    {
        sumIpFragment++ ; 
        if (newOne->nError )
        {
            delete newOne;
            return -1;
        }
    }
    else if(ipret ==DO_NOT_NEED_FRAGMENT)
    {
        sumNoIpFragment ++ ;
    }
    
    if(newOne->ipPayProto == 0x6)
    {        
        //linkTcpProperty(newOne);
        newOne->initTcp();
    }
    else if(newOne->ipPayProto == 0x11)
    {        
        //linkUdpProperty(newOne);
        newOne->initUdp();
    }
    else
    {
        delete newOne;
        return -1;
    }
    linkStream * pStreamLink=NULL;
    //首先对于TCP连接在四元组连接池中进行查找   
    //STREAM flow =FLOW_NULL;
    uint8_t flow =FLOW_NULL;
    pStreamLink = g_nprLinkPool->sFindConnect(newOne->m_connectAddress,flow);  
    if(pStreamLink ==NULL)
    {   
        if(pStreamLink ==NULL)
        {
            pStreamLink = g_nprLinkPool->sNewConnect( newOne->m_connectAddress);
            flow =FLOW_COME;
        }
    }
    else
    {
        if (pStreamLink->isClose(nCurTime))
        {
            TRACE("m_linkId[%u] find link isClose=true close g_nprLinkPool=%p.\r\n",pStreamLink->m_linkId,g_nprLinkPool);
            g_nprLinkPool->sCloseConnect(pStreamLink);
            pStreamLink = g_nprLinkPool->sNewConnect( newOne->m_connectAddress);
            flow =FLOW_COME;
        }       
    }
    if(pStreamLink !=NULL)
    {            
        pStreamLink->dealStream( newOne,tv,flow);
        //pStreamLink->dealTcpStream( newOne,tv,flow);
        if (pStreamLink->isClose(nCurTime))
        {
            TRACE("m_linkId[%6u] isClose=true g_nprLinkPool[TCP_POOL]=%p\r\n",pStreamLink->m_linkId,g_nprLinkPool);
            g_nprLinkPool->sCloseConnect(pStreamLink);
        }
        else
        {
            g_nprLinkPool->moveTimeoutTail(pStreamLink);
        }
        g_nprLinkPool->sCheckTimeout(nCurTime);
        
    }

    
    sumPrintf++;
    sum++;
    TRACE("S=%llu\r\n",sum);
    if(sumPrintf == 5000)
    {
        printf("ID[%u]",pStreamLink->m_linkId);
        printf(" S=%llu\r\n",sum);
        sumPrintf=0;
    }
    else
    {
        //uint32_t percent =(uint32_t)( ((double)sumIpFragment)/(sumNoIpFragment+sumIpFragment)*1000000);
        //printf("ID[%u] F=%u/%llu\r\n",pStreamLink->m_linkId,percent,sumIpFragment);
    }

    return ret;
}

void nprCheckTimeout()
{
    g_nprLinkPool->sCheckTimeout( nCurTime);
}
void nprLinkPoolClose()
{ 
    g_nprLinkPool->Close();  
}

