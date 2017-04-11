///////////////////////////////////////////////////////////
//  tcpReassemblycpp
//  Implementation of the Class tcpReassembly
//  Created on:      15-十月-2015 14:08:38
//  Original author: huiliang
///////////////////////////////////////////////////////////


#include <string.h>
#include <arpa/inet.h>
#include <assert.h>

#include "tcpReassembly.h"
#include "linkstream.h"

//const short int PORPERTY_STREAM_MAX_ELEMENT=10;
//const short int PORPERTY_MAXLEN=64;


static PropertyParm pktHeadProperty(-1,0,32);
static PropertyParm pktTailProperty(-1,-32,32);


UINT32 tcpReassembly::cacheSumMax=0;
UINT32 tcpReassembly::cacheSumMaxSetting=100;  
UINT32 tcpReassembly::seqJumpMaxSetting =65536;
UINT32 tcpReassembly::seqJumpSumMax=1000;

UINT32 SEGMENT_TCP = 5000;

bool tcpReassembly::bTcpSeqSameCache=false;

tcpReassembly::tcpReassembly()
{
    /*
    m_payLoadLen=0;
    m_macLen=0;
    m_pMacBuf = NULL;
    head = NULL;    
    tail = NULL;    
    headDecode = NULL;  
    tailDecode = NULL;  
    m_pktSumForDecode=0;    
    m_pktDecoded=0;
    m_nSeqNum=0;
    m_nAckSeq=0;
    m_nLastLen=-1;
    extractDone=EXTRACT_DONE;
    m_nId=0;
    cacheSum=0;
    notCacheLenZero=0;
    m_nFirstAckSeq=0;
    m_payLoadSumSquares=0;
    m_payLoadPktSum=0;
    m_zeroLenPktSum=0;
    m_headPayLoadInfoMax=0;
    m_headZeroLenInfoMax=0;
    m_porpertyDone=0;
    */
    init(10,10);
}


tcpReassembly::~tcpReassembly()
{
    flushCache();   
    flushDecode();   

    for(int w =0;w < m_porpertyDone  ;w++)
    {
        if(NULL!=m_porperty[w])
        {
            free(m_porperty[w]);
            TRACE_MAX("~tcpReassembly free %p\r\n",m_porperty[w]);
            m_porperty[w]=NULL;
        }
    }
    m_porpertyDone=0;
    
    m_payLoadPktLen.clear(); 
    m_payLoadPktLinkId.clear(); 
    m_payLoadPktStreamId.clear(); 
    m_zeroLenPktLinkId.clear(); 
    m_zeroLenPktStreamId.clear();     
    m_porpertyPktNum.clear(); 
    m_porpertyLen.clear(); 
    m_porpertyOffsize.clear(); 
    m_porperty.clear(); 
}
void tcpReassembly::init(int headPaLoadMax=0,int headZeroLenMax=0)
{
    m_payLoadLen=0;
    m_macLen=0;
    m_pMacBuf = NULL;
    head = NULL;    
    tail = NULL;    
    headDecode = NULL;  
    tailDecode = NULL;  
    m_pktSumForDecode=0;    
    m_pktDecoded=0;
    m_nSeqNum[0]=0;
    m_nSeqNum[1]=0;
    m_nAckSeq=0;
    m_nLastLen[0]=-1;
    m_nLastLen[1]=-1;
    m_nLastSeq[0]=0;
    m_nLastSeq[1]=0;
    extractDone=EXTRACT_DONE;
    m_nStreamId=0;
    cacheSum=0;
    notCacheLenZero=0;
    m_nFirstAckSeq=0;
    m_payLoadSumSquares=0;
    m_payLoadPktSum=0;
    m_zeroLenPktSum=0;
    m_porpertyDone=0;
    m_headPayLoadInfoMax=headPaLoadMax;
    m_headZeroLenInfoMax=headZeroLenMax;
    m_segmentMax = 0;
    m_windowSize=0;
    m_windowScale=0;
    m_sackPermitted=0;
    m_winZeroSize=0;  
    m_seqJumpSum=0;            
    m_seqLostBytes=0;    
    m_streamSeqStatus=0;
    m_addCache[0]=NULL;
    m_addCache[1]=NULL;
    m_resendLenStatus =0;
    
    if(m_headZeroLenInfoMax > MAX_HEADPKT_INFO || m_headPayLoadInfoMax > MAX_HEADPKT_INFO)
    {
        printf("error,tcpReassembly::init() by [m_headZeroLenInfoMax[%d] > %d || m_headPayLoadInfoMax[%d] > %d]\r\n",
            m_headZeroLenInfoMax,
            m_headPayLoadInfoMax,
            MAX_HEADPKT_INFO,MAX_HEADPKT_INFO);
        exit(0);
    }
}   
    
void tcpReassembly::flushCache()
{   
#ifdef EXTRACT_DEBUG        
    if(extractDone == REASSEMBLY_DATA)
    {
        printf("error,tcpReassembly::clear()  extractDone!!\r\n");
    }
#endif

    ipPkt * cur=NULL;
    if(this->head != NULL)
    {
        while(this->head->next!=NULL)
        {       
            cur=this->head;                     
            this->head=this->head->next;
            if(cur!=NULL)
            {           
                m_pLink->m_streamUnknowMacLen[m_nFlowType] += cur->macLen;
                m_pLink->m_streamPktUnknow[m_nFlowType] ++;
                delete cur;
            }
        }
        m_pLink->m_streamUnknowMacLen[m_nFlowType] += head->macLen;
        m_pLink->m_streamPktUnknow[m_nFlowType] ++;
        delete this->head;
    }
    this->head =NULL;
    this->tail =NULL;
}

    
void tcpReassembly::flushDecode()
{   
#ifdef EXTRACT_DEBUG        
    if(extractDone == REASSEMBLY_DATA)
    {
        printf("error,tcpReassembly::clear()  extractDone!!\r\n");
    }
#endif
    ipPkt * cur=NULL;

    if(this->headDecode != NULL)
    {
        printf(" error,tcpReassembly::clear() id[%6u] headDecode is not NULL.\r\n",m_nStreamId);
        while(this->headDecode->next!=NULL)
        {       
            cur=this->headDecode;                       
            this->headDecode=this->headDecode->next;
            if(cur!=NULL)
            {           
                delete cur;
            }
        }
        delete this->headDecode;
    }
    this->headDecode =NULL;
    this->tailDecode =NULL;

}

void tcpReassembly::winZeroSize( ipPkt *pkt)
{
    if(0 == ntohs(*( (uint16_t *) (pkt->pTcpUdp +14) )) )
    {
        m_winZeroSize++;
    }
}

void tcpReassembly::decodeSynAck( ipPkt *pkt)
{
    decodeSynAck0( pkt);
}

void tcpReassembly::decodeSynAck0( ipPkt * pkt)
{
    //窗口
    m_windowSize =  ntohs( *((uint16_t *) ( pkt->pTcpUdp+14)) );
    
    //tcp head option 
    if(pkt->tcpudpHeadLen > 20)
    {
        int pos =20; 
        unsigned char type =0;
        unsigned char len=0;
        for(;pos < pkt->tcpudpHeadLen;)
        {
            type =pkt->pTcpUdp[pos];
            if(type == 0x0)
            {          
                //end option
                break;              
            }
            else if(type == 0x01)
            {          
                //no operation
                pos ++;                
            }
            else if(type == 0x02)
            {          
                //mss
                len =( unsigned char) pkt->pTcpUdp[pos+1];
                m_segmentMax =   ntohs( *((uint16_t *) (pkt->pTcpUdp +pos+2)));
                pos =pos + len ;   
            }
            else if(type == 0x03)
            {          
                //mss
                len =( unsigned char) pkt->pTcpUdp[pos+1];
                m_windowScale =  ( unsigned char) ( pkt->pTcpUdp[pos+2] );
                pos =pos + len ;   
            }
            else if(type == 0x04)
            {          
                //mss
                len =( unsigned char) pkt->pTcpUdp[pos+1];
                m_sackPermitted = 1;
                pos =pos + len ;   
            }
            else
            {
                len =( unsigned char) pkt->pTcpUdp[pos+1];
                pos =pos + len ;   
            }
            //死循环防护
            if(len ==0)
            {
                break;                
            }
        }
    }
}

STATUS_SEQ tcpReassembly::upSeq( ipPkt *pkt,int nLenErrIndex)
{
    //记录末2包的长度
    UINT32 nLastSeqTmp=   m_nSeqNum[nLenErrIndex];
    unsigned int nSeqNum = pkt->reqSeq;
    unsigned int nAckSeqNum =pkt->ackSeq;
    /*
    if(nAckSeqNum < m_nAckSeq)
    {
        TRACE(" tcpReassembly::upSeqData() id[%6u] seq[%11u/%11u] ack[%11u/%11u] len[%5u/%5u] m_nAckSeq[%5u/%5u].\r\n",
            m_nStreamId,m_nSeqNum[nLenErrIndex],nSeqNum,m_nAckSeq , nAckSeqNum,m_nLastLen[nLenErrIndex] ,  pkt->len,nAckSeqNum,m_nAckSeq);   
        return SEQ_ERR;
    }
    */
    if(m_nSeqNum[nLenErrIndex] ==0)
    {
        TRACE_MAX(" tcpReassembly::upSeq() id[%6u] seq[%11u/%11u] ack[%11u/%11u].\r\n",
            m_nStreamId,m_nSeqNum[nLenErrIndex],nSeqNum,m_nAckSeq , nAckSeqNum);
        m_nSeqNum[nLenErrIndex] = nSeqNum;
        m_nLastLen[nLenErrIndex] =0;
    }
    else if(m_nSeqNum[nLenErrIndex] + 1 == nSeqNum)
    {
        TRACE_MAX(" tcpReassembly::upSeq() id[%6u] seq[%11u/%11u] ack[%11u/%11u].\r\n",
            m_nStreamId,m_nSeqNum[nLenErrIndex],nSeqNum,m_nAckSeq , nAckSeqNum);
        m_nSeqNum[nLenErrIndex] = nSeqNum;
        m_nLastLen[nLenErrIndex] =0;
    }
    else if( (m_nSeqNum[nLenErrIndex] -1) == nSeqNum)
    {
        // fin的回应包，提前普通ack到达，导致乱序不能识别        
        TRACE(" info,upSeq() id[%6u] seq[%11u/%11u] ack[%11u/%11u] len[%5u/%5u] RESEND(1 1).\r\n",
        m_nStreamId,m_nSeqNum[nLenErrIndex],nSeqNum,m_nAckSeq , nAckSeqNum,m_nLastLen[nLenErrIndex] , 0);
        return SEQ_RESEND;
    }
    else if( m_nSeqNum[nLenErrIndex] + m_nLastLen[nLenErrIndex] == nSeqNum )
    {
        TRACE_MAX(" tcpReassembly::upSeq() id[%6u] seq[%11u/%11u] ack[%11u/%11u] len[%5u/%5u].\r\n",
            m_nStreamId,m_nSeqNum[nLenErrIndex],nSeqNum,m_nAckSeq , nAckSeqNum,m_nLastLen[nLenErrIndex] , 0);
        m_nSeqNum[nLenErrIndex] = nSeqNum;
        m_nLastLen[nLenErrIndex] =0;
    }
    else if( (m_nSeqNum[nLenErrIndex] + m_nLastLen[nLenErrIndex] + 1 ) == nSeqNum)
    {
        // fin的回应包
        TRACE_MAX(" tcpReassembly::upSeq() id[%6u] seq[%11u/%11u] ack[%11u/%11u] len[%5u/%5u].\r\n",
        m_nStreamId,m_nSeqNum[nLenErrIndex],nSeqNum,m_nAckSeq , nAckSeqNum,m_nLastLen[nLenErrIndex] , 0);
        m_nSeqNum[nLenErrIndex] = nSeqNum;
        m_nLastLen[nLenErrIndex] =0;
    } 

    ///////////////////////////////////////////////////////
    //len==0 识别为确认
    else if( (nSeqNum ==  m_nLastSeq[0])  &&  (m_nLastLen[0] == 0))
    {
        //确认包
        TRACE_MAX(" info,upSeq() id[%6u] seq[%11u/%11u] ack[%11u/%11u] len[%5u/%5u] (1).\r\n",
        m_nStreamId,m_nSeqNum[nLenErrIndex],nSeqNum,m_nAckSeq , nAckSeqNum,m_nLastLen[nLenErrIndex] , 0);
    }
    else if( (nSeqNum ==  m_nLastSeq[1])  &&  (m_nLastLen[1] == 0))
    {
        //确认包
        TRACE_MAX(" info,upSeq() id[%6u] seq[%11u/%11u] ack[%11u/%11u] len[%5u/%5u] (2).\r\n",
        m_nStreamId,m_nSeqNum[nLenErrIndex],nSeqNum,m_nAckSeq , nAckSeqNum,m_nLastLen[nLenErrIndex] , 0);
    } 
    //len==0 识别为确认
    ///////////////////////////////////////////////////////
    
    //避免识别为重传导致序号对应失败
    else if( (nSeqNum ==  m_nLastSeq[0])   ||  (m_nLastSeq[1] == nSeqNum) )
    {
        //乱序的确认包
        TRACE(" info,upSeq() id[%6u] seq[%11u/%11u] ack[%11u/%11u] len[%5u/%5u] RESEND(1 2).\r\n",
        m_nStreamId,m_nSeqNum[nLenErrIndex],nSeqNum,m_nAckSeq , nAckSeqNum,m_nLastLen[nLenErrIndex] , 0);
        return SEQ_RESEND;
    } 
    else if(m_seqJumpSum > 0 && nSeqNum < m_nSeqNum[nLenErrIndex] && nSeqNum > ( m_nSeqNum[nLenErrIndex] - seqJumpMaxSetting*3 ) )
    {
        //跳跃状态已经出现
        TRACE(" info,upSeq() id[%6u] seq[%11u/%11u] ack[%11u/%11u] len[%5u/%5u] RESEND(1 j).\r\n",m_nStreamId,m_nSeqNum[nLenErrIndex],nSeqNum,m_nAckSeq , nAckSeqNum,m_nLastLen[nLenErrIndex] , 0);
        return SEQ_RESEND;
    }
    else
    {
        //简单的长度为0错误包
        TRACE_MAX(" info,upSeq() id[%6u] seq[%11u/%11u] ack[%11u/%11u] lastLen[%5u] ERR.\r\n",
            m_nStreamId,
            m_nSeqNum[nLenErrIndex],
            nSeqNum,
            m_nAckSeq ,
            nAckSeqNum,
            m_nLastLen[nLenErrIndex]
            );
        return SEQ_ERR;
    }   
    
    m_nAckSeq = nAckSeqNum;
    if(m_nFirstAckSeq ==0)
    {
        m_nFirstAckSeq=m_nAckSeq;
    }
    
    if(m_nSeqNum[nLenErrIndex] != nLastSeqTmp)
    {
        m_nLastSeq[1] = m_nLastSeq[0];
        m_nLastSeq[0] = nLastSeqTmp; 
    }

    return SEQ_SUCCESS;
}

STATUS_SEQ tcpReassembly::statusUpSeqData( ipPkt * pkt)
{
    (void)pkt;
    if(m_streamSeqStatus == 1)
    {        
        return SEQ_ERR_DEL;
    }
    return SEQ_ERR_DEL;
}

STATUS_SEQ tcpReassembly::upSeqOnly( ipPkt * pkt,int nLenErrIndex)
{
    unsigned int nSeqNum = pkt->reqSeq;
    unsigned int nAckSeqNum =pkt->ackSeq;
    (void)nAckSeqNum;
    int nLen =  pkt->len;   
    
    if( (m_nSeqNum[nLenErrIndex] + m_nLastLen[nLenErrIndex]) == nSeqNum)
    {
        return SEQ_SUCCESS;
    }
    else if( m_nSeqNum[nLenErrIndex] == nSeqNum  && m_nLastLen[nLenErrIndex] == nLen)
    {
        TRACE_MAX(" upSeqOnly id[%6u] seq[%11u/%11u] ack[%11u/%11u] len[%5u/%5u] RESEND(2 0).\r\n",
            m_nStreamId,m_nSeqNum[nLenErrIndex],nSeqNum,m_nAckSeq , nAckSeqNum,m_nLastLen[nLenErrIndex] , nLen);
        return SEQ_RESEND;
    }
    else if( m_nSeqNum[nLenErrIndex] == nSeqNum + nLen && nLen )
    {
        TRACE_MAX(" ,upSeqOnly id[%6u] seq[%11u/%11u] ack[%11u/%11u] len[%5u/%5u] RESEND(2 1).\r\n",
            m_nStreamId,m_nSeqNum[nLenErrIndex],nSeqNum,m_nAckSeq , nAckSeqNum,m_nLastLen[nLenErrIndex] , nLen);
        return SEQ_RESEND;
    }
    else if( (nSeqNum ==  m_nLastSeq[0]) || m_nLastSeq[1] == nSeqNum)
    {
        TRACE_MAX(" upSeqOnly id[%6u] seq[%11u/%11u] ack[%11u/%11u] len[%5u/%5u] RESEND(2 2).\r\n",
            m_nStreamId,m_nSeqNum[nLenErrIndex],nSeqNum,m_nAckSeq , nAckSeqNum,m_nLastLen[nLenErrIndex] , nLen);
        return SEQ_RESEND;
    }     
    else if( (m_nSeqNum[nLenErrIndex] + m_nLastLen[nLenErrIndex] + 1 ) == nSeqNum)
    {
        //承载数据且fin的回应包
        return SEQ_SUCCESS;
    }
    else if( (m_nSeqNum[nLenErrIndex] -1) == nSeqNum)
    {
        // fin的回应包提前普通ack到达，导致乱序不能识别
        return SEQ_SUCCESS;
    }
    else if(m_nLastLen[nLenErrIndex] ==-1)
    {
        return SEQ_SUCCESS;        
    }   
    else if(m_nSeqNum[nLenErrIndex] + 1 == nSeqNum )
    {
        return SEQ_SUCCESS;
    }
    else if(m_seqJumpSum > 0 && nSeqNum < m_nSeqNum[nLenErrIndex] && nSeqNum > ( m_nSeqNum[nLenErrIndex] - seqJumpMaxSetting*3 ) )
    {
        //跳跃状态已经出现
        TRACE( " info,upSeqOnly id[%6u] seq[%11u/%11u] ack[%11u/%11u] len[%5u/%5u] RESEND(2 j).\r\n",
        m_nStreamId,m_nSeqNum[nLenErrIndex],nSeqNum,m_nAckSeq , nAckSeqNum,m_nLastLen[nLenErrIndex] , nLen);
        return SEQ_RESEND;
    }
    //小概率情况
    else if( m_nSeqNum[nLenErrIndex] == nSeqNum && m_nLastLen[nLenErrIndex] != nLen && nLen > 0 && m_nLastLen[nLenErrIndex] > 0 )
    {
        //异常情况，开始的seq相同，但长度不同，需要对端的确认(ack)来辅助分析，暂不处理
        TRACE(" warning,upSeqOnly() id[%6u] seq[%11u/%11u] ack[%11u/%11u] len[%5u/%5u] RESEND(2 3).\r\n",
            m_nStreamId,m_nSeqNum[nLenErrIndex],nSeqNum,m_nAckSeq , nAckSeqNum,m_nLastLen[nLenErrIndex],nLen);
        //return SEQ_ERR;
        //预判按照预判重传分析，并不实际处理数据
        return SEQ_RESEND;
    }
    else 
    {
        TRACE_MAX( " info,upSeqOnly id[%6u] seq[%11u/%11u] ack[%11u/%11u] len[%5u/%5u] ERR 2.\r\n",
            m_nStreamId,m_nSeqNum[nLenErrIndex],nSeqNum,m_nAckSeq , nAckSeqNum,m_nLastLen[nLenErrIndex] ,nLen );   
        TRACE_MAX( " info,upSeqOnly id[%6u]  m_nLastSeq[0](%u) m_nLastSeq[1](%u) ERR 2.\r\n",
            m_nStreamId,m_nLastSeq[0],m_nLastSeq[1] );     
        return SEQ_ERR;
    }
}

STATUS_SEQ tcpReassembly::upSeqData( ipPkt * pkt,bool firstTryUp,int nLenErrIndex)
{
    //记录末2包的长度
    UINT32 nLastSeqTmp=   m_nSeqNum[nLenErrIndex];

    unsigned int nSeqNum = pkt->reqSeq;
    unsigned int nAckSeqNum = pkt->ackSeq;
    int nLen =  pkt->len;   
    
    if(nAckSeqNum < m_nAckSeq)
    {
        TRACE_MAX(" tcpReassembly::upSeqData(%d) id[%6u] seq[%11u/%11u] ack[%11u/%11u] ERR.\r\n",
            firstTryUp,m_nStreamId,m_nSeqNum[nLenErrIndex],nSeqNum,m_nAckSeq , nAckSeqNum);   
        TRACE_MAX(" tcpReassembly::upSeqData(%d) id[%6u] len[%5u/%5u] m_nAckSeq[%5u/%5u] ERR.\r\n",
            firstTryUp,m_nStreamId,m_nLastLen[nLenErrIndex] , nLen,nAckSeqNum,m_nAckSeq);   
        return SEQ_ERR;
    }    

    if(nLen ==0)
    {
        return upSeq(  pkt ,nLenErrIndex);
    } 
    
    if(m_streamSeqStatus !=0 )
    {
        return statusUpSeqData(pkt);
    }

    //len > 0 
    if(m_nLastLen[nLenErrIndex] ==-1)
    {
        TRACE_MAX(" tcpReassembly::upSeqData(%d) id[%6u] seq[%11u/%11u] ack[%11u/%11u] len[%5u/%5u].\r\n",
            firstTryUp,m_nStreamId,m_nSeqNum[nLenErrIndex],nSeqNum,m_nAckSeq , nAckSeqNum,m_nLastLen[nLenErrIndex] , nLen);
        m_nSeqNum[nLenErrIndex] = nSeqNum;
        m_nLastLen[nLenErrIndex] = nLen;
    }   
    else if( (m_nSeqNum[nLenErrIndex] + m_nLastLen[nLenErrIndex] + 1 ) == nSeqNum)
    {
        // fin的回应包
        //握手会议包
        TRACE_MAX(" tcpReassembly::upSeqData(%d) id[%6u] seq[%11u/%11u] ack[%11u/%11u] len[%5u/%5u].\r\n",
        firstTryUp,m_nStreamId,m_nSeqNum[nLenErrIndex],nSeqNum,m_nAckSeq , nAckSeqNum,m_nLastLen[nLenErrIndex] , nLen);
        m_nSeqNum[nLenErrIndex] = nSeqNum;
        m_nLastLen[nLenErrIndex] =nLen;
    }
    else if( (m_nSeqNum[nLenErrIndex] -1) == nSeqNum)
    {
        // fin的回应包，提前普通ack到达，导致乱序不能识别         
        if( m_nAckSeq < nAckSeqNum)
        {
            m_nAckSeq = nAckSeqNum;
        }
        TRACE_MAX(" info,upSeqData(%d) id[%6u] seq[%11u/%11u] ack[%11u/%11u] len[%5u/%5u] RESEND(3 1).\r\n",
            firstTryUp,m_nStreamId,m_nSeqNum[nLenErrIndex],nSeqNum,m_nAckSeq , nAckSeqNum,m_nLastLen[nLenErrIndex] , nLen);              
        return SEQ_RESEND;
    }
    else if( (m_nSeqNum[nLenErrIndex] + m_nLastLen[nLenErrIndex]) == nSeqNum)
    {
        TRACE_MAX(" tcpReassembly::upSeqData(%d) id[%6u] seq[%11u/%11u] ack[%11u/%11u] len[%5u/%5u].\r\n",
            firstTryUp,m_nStreamId,m_nSeqNum[nLenErrIndex],nSeqNum,m_nAckSeq , nAckSeqNum,m_nLastLen[nLenErrIndex] , nLen);
        m_nSeqNum[nLenErrIndex] = nSeqNum;
        m_nLastLen[nLenErrIndex] = nLen;
    }
    else if( m_nSeqNum[nLenErrIndex] == nSeqNum && m_nLastLen[nLenErrIndex] ==0)
    {
        TRACE_MAX(" info,upSeqData(%d) id[%6u] seq[%11u/%11u] ack[%11u/%11u] len[%5u/%5u] RESEND(3 2).\r\n",
            firstTryUp,m_nStreamId,m_nSeqNum[nLenErrIndex],nSeqNum,m_nAckSeq , nAckSeqNum,m_nLastLen[nLenErrIndex],nLen);
        m_nSeqNum[nLenErrIndex] = nSeqNum;
        m_nLastLen[nLenErrIndex] = nLen;          
        if( m_nAckSeq < nAckSeqNum)
        {
            m_nAckSeq = nAckSeqNum;
        }
        return SEQ_RESEND;
    }    
    else if( m_nSeqNum[nLenErrIndex] == nSeqNum  && m_nLastLen[nLenErrIndex] == nLen)
    {
        TRACE_MAX(" info,upSeqData id[%6u] seq[%11u/%11u] ack[%11u/%11u] len[%5u/%5u] RESEND(3 5).\r\n",
            m_nStreamId,m_nSeqNum[nLenErrIndex],nSeqNum,m_nAckSeq , nAckSeqNum,m_nLastLen[nLenErrIndex] , nLen);
        return SEQ_RESEND;
    }
    else if( m_nSeqNum[nLenErrIndex] == nSeqNum && m_nLastLen[nLenErrIndex] != nLen && m_nLastLen[nLenErrIndex] >0 && nLen >0 )
    {
        //异常情况，开始的seq相同，但长度不同，需要对端的确认(ack)来辅助分析，暂不处理
        if( m_resendLenStatus ==0)
        {        
            if( m_nAckSeq >= nAckSeqNum)
            {
                //回退为较小的值，防止出错
                m_nAckSeq = nAckSeqNum;
            }        
            //暂时存储出错的数据
            //0第一个包，1第二个包
            if(0== m_nSeqNum[1] && -1==m_nLastLen[1])
            {                
                m_nSeqNum[1] = nSeqNum;
                m_nLastLen[1] = nLen; 
                m_resendLenStatus =1;
                TRACE_MAX(" info,upSeqData(%d) id[%6u] seq[%11u/%11u] ack[%11u/%11u] len[%5u/%5u] SUCCESS.\r\n",
                    firstTryUp,m_nStreamId,m_nSeqNum[nLenErrIndex],nSeqNum,m_nAckSeq , nAckSeqNum,m_nLastLen[nLenErrIndex],nLen);
                return SEQ_SUCCESS; 
            }
            else
            {
                printf(" error,upSeqData(%d) id[%6u] seq[%11u/%11u] ack[%11u/%11u] len[%5u/%5u] ERR(1).\r\n",
                    firstTryUp,m_nStreamId,m_nSeqNum[nLenErrIndex],nSeqNum,m_nAckSeq , nAckSeqNum,m_nLastLen[nLenErrIndex],nLen); 
            }
        }
        else
        {
            TRACE(" warning,upSeqData(%d) id[%6u] seq-0[%11u/%11u] ack[%11u/%11u] len[%5u/%5u] m_resendLenStatus=%d ERR(2).\r\n",
                firstTryUp,m_nStreamId,m_nSeqNum[0],nSeqNum,m_nAckSeq , nAckSeqNum,m_nLastLen[0],nLen,m_resendLenStatus);
            TRACE(" warning,upSeqData(%d) id[%6u] seq-1[%11u/%11u] ack[%11u/%11u] len[%5u/%5u] m_resendLenStatus=%d ERR(3).\r\n",
                firstTryUp,m_nStreamId,m_nSeqNum[1],nSeqNum,m_nAckSeq , nAckSeqNum,m_nLastLen[1],nLen,m_resendLenStatus);
        }
        return SEQ_ERR;
    }
    else if( (nSeqNum ==  m_nLastSeq[0]) || m_nLastSeq[1] == nSeqNum)
    {
        //已经达到，又收到重传包
        TRACE_MAX(" info,upSeqData(%d) id[%6u] seq[%11u/%11u] ack[%11u/%11u] len[%5u/%5u] RESEND(3 3).\r\n",
        firstTryUp,m_nStreamId,m_nSeqNum[nLenErrIndex],nSeqNum,m_nAckSeq , nAckSeqNum,m_nLastLen[nLenErrIndex] , nLen);
        if( m_nAckSeq < nAckSeqNum)
        {
            m_nAckSeq = nAckSeqNum;
        }
        return SEQ_RESEND;
    }
    else if(m_seqJumpSum > 0 && nSeqNum < m_nSeqNum[nLenErrIndex] && nSeqNum > ( m_nSeqNum[nLenErrIndex] - seqJumpMaxSetting*3 ) )
    {
        //跳跃状态已经出现
        TRACE(" info,upSeqData(%d) id[%6u] seq[%11u/%11u] ack[%11u/%11u] len[%5u/%5u] RESEND(3 j).\r\n",
        firstTryUp,m_nStreamId,m_nSeqNum[nLenErrIndex],nSeqNum,m_nAckSeq , nAckSeqNum,m_nLastLen[nLenErrIndex] , nLen);
        return SEQ_RESEND;
    }
    else 
    {
        //一般应该是后续的包提前到达的情况
        //不在输出bug信息,避免乱序时日志过多
        //TRACE(" tcpReassembly::upSeqData() id[%6u] seq[%11u/%11u] ack[%11u/%11u] len[%5u/%5u].\r\n",m_nStreamId,m_nSeqNum[nLenErrIndex],nSeqNum,m_nAckSeq , nAckSeqNum,m_nLastLen[nLenErrIndex] , nLen);
        return SEQ_ERR;
    }
    
    if(nAckSeqNum < m_nAckSeq)
    {
        TRACE_MAX(" warning,tcpReassembly::upSeqData(%d) id[%6u] seq[%11u/%11u] ack[%11u/%11u] len[%5u/%5u] m_nAckSeq[%5u/%5u].\r\n",
            firstTryUp,m_nStreamId,m_nSeqNum[nLenErrIndex],nSeqNum,m_nAckSeq , nAckSeqNum,m_nLastLen[nLenErrIndex] , nLen,nAckSeqNum,m_nAckSeq);       
    }    
    
    m_nAckSeq = nAckSeqNum;
    if(m_nFirstAckSeq ==0)
    {
        //记录最早的确认号，以便于处理无握手包、单向流等特殊情况。
        m_nFirstAckSeq=m_nAckSeq;
    } 

    if(m_nSeqNum[nLenErrIndex] != nLastSeqTmp)
    {
        m_nLastSeq[1] = m_nLastSeq[0];
        m_nLastSeq[0] = nLastSeqTmp; 
    }
    return SEQ_SUCCESS;
}

int tcpReassembly::cachePkt(ipPkt * newOne)
{
    int nLenErrIndex =0;
    if(newOne->len > 0 && newOne->reqSeq >= m_nSeqNum[nLenErrIndex] )
    {
        if( newOne->freeType != MALLOC_FREE )
        {
            //没有复制过的原始dpdk包
            newOne->copyFromDpdkBuf();
        }
        //此处部使用newOne->reqSeq > m_nSeqNum[nLenErrIndex]
        //处理多次不同长度的重传包
        int pos=cacheSum;
        if(this->head ==NULL )
        {   
            this->head=newOne;
            this->tail=newOne;
            newOne->pre = NULL;
            newOne->next = NULL;    
            cacheSum++;
            pos++;
            TRACE("  cache-head,Id[%d] cacheSum[%u] pos=%d.\r\n",
                newOne->linkPktSerialId,cacheSum,pos);
        }
        else if(this->head !=NULL && this->tail !=NULL )
        {   
            newOne->pre =NULL;
            newOne->next =NULL;
            //安装reqSeq排序，小序号在链表头
            if(newOne->reqSeq >=  tail->reqSeq )
            {
                //加到队尾部
                newOne->pre = this->tail ;
                this->tail->next = newOne;
                newOne->next = NULL;    
                this->tail =newOne;
                pos++;
                TRACE_MAX("add to tail pos.\r\n");
            }
            else
            {   
                //查找合适位置，加到队前部
                ipPkt *cur =this->tail->pre;
                for(; cur !=NULL;cur = cur->pre )
                {
                    TRACE_MAX("newOne->reqSeq=%u cur->reqSeq=%u cur->linkPktSerialId=%u.\r\n",
                        newOne->reqSeq, cur->reqSeq,cur->linkPktSerialId);
                    //向前查找合适的插入点，加到队列中
                    if(newOne->reqSeq >=  cur->reqSeq )
                    {
                        newOne->pre = cur ;
                        newOne->next = cur->next;  
                        cur->next->pre = newOne;
                        cur->next = newOne;    
                        TRACE_MAX("find pos.\r\n");
                        break;
                    }
                    pos --;
                }
                if(cur ==NULL)
                {   
                    //直接加入到队列头部
                    newOne->next= this->head;
                    newOne->pre=NULL;
                    this->head->pre = newOne;
                    this->head = newOne;      
                    TRACE_MAX("add to head pos.\r\n");
                }
            }
            cacheSum++;
            TRACE("  cache-middle,Id[%d] cacheSum[%u] pos=%d [%d/%d].\r\n",
                newOne->linkPktSerialId,cacheSum,pos,head->linkPktSerialId,tail->linkPktSerialId);
        }
        else
        {       
            printf("  error,tcpReassembly::cachePkt() head or tail is NULL,cacheSum[%u].\r\n",cacheSum);
        }
    }
    else
    {
        if( newOne->reqSeq <= m_nSeqNum[nLenErrIndex]  && newOne->len > 0 )
        {   
            //SEQ_ERR 的包,有负载
            //此处按照重传处理
            m_pLink->m_streamPktResend[m_nFlowType]++;
            m_pLink->m_streamResendMacLen[m_nFlowType]+=newOne->macLen;  
            TRACE("  warn,cachePkt() a resend pkt(payload).\r\n" );            
        }
        else if (newOne->reqSeq <= m_nSeqNum[nLenErrIndex]  &&  newOne->len <= 0 )
        {   
            //SEQ_ERR、无负载包,重传无法判断。。。暂时看不到意义
            //按照非重传处理
            //TRACE("  warn,tcpReassembly::cachePkt() there is a resend pkt(no-payload) ...... \r\n" );  
            //不在统计全部毛流量，改为统计有效的毛流量
            m_macLen +=newOne->macLen;
            notCacheLenZero++;    
            //视为已经被解析解码
            m_pktSumForDecode++;    
            m_pktDecoded++;   
            TRACE_MAX("  cachePkt() newOne->len <= 0,len[%d],cacheSum[%u] (no-payload 1).\r\n",
                newOne->len,cacheSum);                   
        }
        else if( newOne->reqSeq > m_nSeqNum[nLenErrIndex] &&  newOne->len <= 0 )
        {
            //SEQ_ERR、无负载包,重传无法判断。。。暂时看不到意义
            //按照非重传处理
            //TRACE("  warn,tcpReassembly::cachePkt() there is a resend pkt(no-payload) ...... \r\n" ); 
            //不在统计全部毛流量，改为统计有效的毛流量
            m_macLen +=newOne->macLen;
            notCacheLenZero++;  
            //视为已经被解析解码
            m_pktSumForDecode++;    
            m_pktDecoded++;
            TRACE_MAX("  cachePkt() newOne->len <= 0,len[%d],cacheSum[%u] (no-payload 2).\r\n",newOne->len,cacheSum);
        }
        delete newOne;
    }
    if(cacheSum > cacheSumMax)
    {
        cacheSumMax = cacheSum;           
        syslog(LOG_ERR,"tcpReassembly::cachePkt()  cacheSumMax = %d !\n",cacheSumMax);
    }
    

    /*
    if(cacheSum > cacheSumMaxSetting)
    {
        //cacheSumMaxSetting = cacheSumMaxSetting * 1.5; 
        if(seqJumpMaxSetting >  head->reqSeq - m_nSeqNum[nLenErrIndex]  && seqJumpSumMax > m_seqJumpSum)
        {
            m_seqJumpSum ++;
            m_seqLostBytes =m_seqLostBytes + ( head->reqSeq - m_nSeqNum[nLenErrIndex]);
            printf("cachePkt(%d) Sum=%u/%u,Lost=%u,Jump=%u/%u,SeqNum[%d]=%u %u.\r\n",
                head->linkPktSerialId,
                cacheSum,
                cacheSumMaxSetting,
                m_seqLostBytes,
                m_seqJumpSum,
                seqJumpSumMax,
                nLenErrIndex,
                m_nSeqNum[nLenErrIndex],
                head->reqSeq);  
            //跳过中断的部分包，
            //如果中断的包最终到了，会按照重传识别和处理
            m_nSeqNum[nLenErrIndex] = head->reqSeq ;
            m_nLastLen[nLenErrIndex] =0;
            
            //尝试序号重试
            cacheTryAdd();    
            m_pLink->decodeCall(m_nFlowType);            
            
        }
        else
        {
            m_streamSeqStatus=1;
            printf("  warnning,tcpReassembly::cachePkt() this stream will be a error-stream.\r\n");  
        }
    }
    */
    cacheCheck(nLenErrIndex,cacheSumMaxSetting);
    
    return 0;
}

int tcpReassembly::cacheCheck(const int &nLenErrIndex,const UINT32 & cacheSumIn)
{ 
    if(cacheSum > cacheSumIn)
    {
        UINT32 jumpLen=0;
        jumpLen = ( head->reqSeq - m_nSeqNum[nLenErrIndex]);
        if( m_nLastLen[nLenErrIndex] > 0)
        {   
            //最后的数据包不计算在内
            jumpLen =jumpLen -m_nLastLen[nLenErrIndex] ;
        }            
        //if(seqJumpMaxSetting >  head->reqSeq - m_nSeqNum[nLenErrIndex]  && seqJumpSumMax > m_seqJumpSum)
        if(seqJumpMaxSetting > jumpLen  && seqJumpSumMax > m_seqJumpSum)
        {
            m_seqJumpSum ++;
            m_seqLostBytes =m_seqLostBytes + jumpLen;
            //m_seqLostBytes =m_seqLostBytes + ( head->reqSeq - m_nSeqNum[nLenErrIndex]);
            //if( m_nLastLen[nLenErrIndex] > 0)
            //{   
            //    //最后的数据包不计算在内
            //    m_seqLostBytes =m_seqLostBytes -m_nLastLen[nLenErrIndex] ;
            //}
            TRACE("cacheCheck(%d) Sum=%u/%u,Lost=%u,Jump=%u/%u,SeqNum[%d]=%u %u.\r\n",
                head->linkPktSerialId,
                cacheSum,
                cacheSumIn,
                m_seqLostBytes,
                m_seqJumpSum,
                seqJumpSumMax,
                nLenErrIndex,
                m_nSeqNum[nLenErrIndex],
                head->reqSeq);  
            //跳过中断的部分包，
            //如果中断的包最终到了，会按照重传识别和处理
            m_nSeqNum[nLenErrIndex] = head->reqSeq ;
            m_nLastLen[nLenErrIndex] =0;
            m_pLink->m_nLinkPktError = LINK_ERR_JUMP;

            //尝试序号重试
            cacheTryAdd();    
            m_pLink->decodeCall(m_nFlowType,true);     
            
        }
        else
        {
            m_pLink->m_nLinkPktError = LINK_ERR_SUPER_JUMP;
            m_streamSeqStatus=1;
            printf("  warnning,cacheCheck() this stream will be a error-stream.\r\n");  
        }
    }

    return 0;
}


int tcpReassembly::cacheTryAdd()
{
    int nLenErrIndex =0;
    if(this->head !=NULL && this->tail !=NULL )
    {
        TRACE(" cacheTryAdd() sum[%u].\r\n",cacheSum);
        ipPkt * cur;
        ipPkt * tempNext;
        for(cur = head;cur!=NULL;)
        {           
            if(cur->reqSeq > (m_nSeqNum[nLenErrIndex] + SEGMENT_TCP) )
            {   
                //大于最大的分片，不在循环，直接跳出,
                //因为队列安装序号递增的，后续的更不会匹配当前序号
                break;
            }
            
            tempNext= cur->next;
            STATUS_SEQ ret = upSeqData( cur,0,0);   
            if( m_resendLenStatus > 0 && ret == SEQ_ERR )
            {
                ret =upSeqData(cur,0,1);
            }
            if(ret == SEQ_SUCCESS || ret == SEQ_RESEND || ret == SEQ_ERR_DEL)
            {                                
                if(cur == tail)
                {
                    if(tempNext != NULL)
                    {
                        printf("error,tcpReassembly::cacheTryAdd()  id[%6u] tempNext is not NULL.\r\n",
                            m_nStreamId);
                    }
                    tail=NULL;
                }
                head= tempNext;
                if(head !=NULL)
                {
                    head->pre = NULL;
                }
                cur->next=NULL;
                cur->pre=NULL;                
                cacheSum--;
                if(ret == SEQ_SUCCESS )
                {
                    addTcpPkt(cur);
                    TRACE("  cacheTryAdd() move,sum[%u].\r\n",cacheSum);
                }
                else if( ret == SEQ_RESEND )
                { 
                    m_pLink->m_streamPktResend[m_nFlowType]++;
                    m_pLink->m_streamResendMacLen[m_nFlowType]+=cur->macLen;
                    delete cur;  
                    TRACE("  cacheTryAdd() delete-re,sum[%u].\r\n",cacheSum);
                }                
                else if( ret == SEQ_ERR_DEL)
                { 
                    m_pLink->m_streamPktUnknow[m_nFlowType]++;
                    m_pLink->m_streamUnknowMacLen[m_nFlowType]+=cur->macLen;
                    delete cur;  
                    TRACE("  cacheTryAdd() delete-err,sum[%u].\r\n",cacheSum);
                }
                else
                {
                    delete cur;  
                    printf("  error,tcpReassembly::cacheTryAdd().\r\n");
                }
                cur=head;
            }
            else
            {
                if( cur->reqSeq <= m_nSeqNum[nLenErrIndex] )
                {   
                    m_pLink->m_streamPktUnknow[m_nFlowType]++;
                    m_pLink->m_streamUnknowMacLen[m_nFlowType]+=cur->macLen;
                    if(cur->reqSeq  +  cur->len >  m_nSeqNum[nLenErrIndex] )
                    {                        
                        printf("  error,tcpReassembly::cacheTryAdd()  id[%6u] delete-pkt cur->reqSeq[%11u] = m_nSeqNum[nLenErrIndex][%11u] payloadlen=%d.\r\n",
                            m_nStreamId,cur->reqSeq,m_nSeqNum[nLenErrIndex],cur->len); 
                    }
                    else
                    {                        
                        TRACE("  tcpReassembly::cacheTryAdd() something link resend.\r\n");
                    }          
                    head = cur->next; 
                    cacheSum--;
                    assert( cacheSum==0 ? head==NULL :  head!=NULL );
                    assert( cacheSum==0 ? cur==tail  :  cur!=tail );
                    if(head!=NULL)
                    {
                        head->pre =NULL;
                    }
                    else
                    {
                        tail =NULL;
                    }
                    delete cur; 
                    cur =head;   
                }
                else
                {
                    break;
                }
            }
        }
    }
    else
    {
        return -1;
    }
    return 0;
}


int tcpReassembly::getPropertyString(const ipPkt * newOne, const struct PropertyParm & pParm)
{
    if(m_porpertyDone >= PORPERTY_STREAM_MAX_ELEMENT)
    {
        return -1;
    }
    if(pParm.m_packetNum < 0 ||  pParm.m_packetNum == m_payLoadPktSum )
    {
        if(pParm.m_offSize >= 0 )
        {
            //m_porpertyOffsize[m_porpertyDone]= pParm.m_offSize;
            //m_porpertyPktNum[m_porpertyDone]= m_payLoadPktSum;
            int len=0;
            if( pParm.m_offSize + pParm.m_propertyLen < newOne->len )   
            {
                //m_porpertyLen[m_porpertyDone]= pParm.m_propertyLen;
                len = pParm.m_propertyLen;
                m_porpertyLen.push_back(pParm.m_propertyLen);
            }
            else if( pParm.m_offSize >= newOne->len )   
            {
                //m_porpertyLen[m_porpertyDone]= 0;
                len=0;
            }
            else
            {               
                //m_porpertyLen[m_porpertyDone]= newOne->len - pParm.m_offSize;
                len=newOne->len - pParm.m_offSize;
                m_porpertyLen.push_back(len);
            }
            if(len > 0 )
            {
                char * p  =(char *) malloc(m_porpertyLen[m_porpertyDone]+1);
                TRACE_MAX("getPropertyString malloc %p by len=%d\r\n",p,m_porpertyLen[m_porpertyDone]);
                if(p==NULL || len !=m_porpertyLen[m_porpertyDone])
                {
                    return 0;
                }
                memcpy(p, newOne->pPayLoad, m_porpertyLen[m_porpertyDone]);
                p[m_porpertyLen[m_porpertyDone]]='\0';
                
                m_porperty.push_back(p);
                m_porpertyOffsize.push_back(pParm.m_offSize);
                m_porpertyPktNum.push_back(m_payLoadPktSum);
                m_porpertyDone++;
            }
        }
        else if( pParm.m_offSize < 0 &&  pParm.m_propertyLen <= (-pParm.m_offSize)  )  
        {
            //m_porpertyPktNum[m_porpertyDone]= m_payLoadPktSum; 
            int len=0;     
            if( pParm.m_offSize + newOne->len > 0 ) 
            {
                //m_porpertyLen[m_porpertyDone]= pParm.m_propertyLen;
                m_porpertyLen.push_back(pParm.m_propertyLen);
                len=pParm.m_propertyLen;
                //m_porpertyOffsize[m_porpertyDone]= pParm.m_offSize;
                m_porpertyOffsize.push_back(pParm.m_offSize);
            }
            else if(newOne->len <=0 )
            {
                
            }
            else 
            {               
                //m_porpertyLen[m_porpertyDone]=  newOne->len ;
                //m_porpertyOffsize[m_porpertyDone]= - newOne->len ;
                m_porpertyLen.push_back( newOne->len);
                m_porpertyOffsize.push_back( (-newOne->len) );
                len = newOne->len;
            }   
            if(len >0)
            {
                char * p =(char *) malloc(m_porpertyLen[m_porpertyDone]+1);
                TRACE_MAX("getPropertyString malloc %p by len=%d\r\n",p,m_porpertyLen[m_porpertyDone]);
                if(p==NULL || len !=m_porpertyLen[m_porpertyDone])
                {
                    return 0;
                }
                memcpy(p, newOne->pPayLoad + newOne->len + m_porpertyOffsize[m_porpertyDone],
                    m_porpertyLen[m_porpertyDone]);                
                p[m_porpertyLen[m_porpertyDone]]='\0';
                
                m_porpertyPktNum.push_back(m_payLoadPktSum); 
                m_porperty.push_back(p);   
                m_porpertyDone++;
            }
        }
        TRACE_MAX("  tcpReassembly::getPropertyString() m_porpertyDone[%d],m_porpertyPktNum[%d],m_porpertyLen[%d],m_porpertyOffsize[%d].\r\n",
            m_porpertyDone,
            m_porpertyPktNum[m_porpertyDone-1],
            m_porpertyLen[m_porpertyDone-1],
            m_porpertyOffsize[m_porpertyDone-1]);
    }
    return 0;
}

int tcpReassembly::addCachePkt()
{ 
    if(NULL!= m_addCache[0])
    {
        addPktCall( m_addCache[0]);
    }
    if(NULL!= m_addCache[1])
    {
        addPktCall( m_addCache[1]);
    }
    m_addCache[0]=NULL;
    m_addCache[1]=NULL;
    return 0;
}


int tcpReassembly::addTcpPkt(ipPkt * newOneIn)
{   
    if(m_resendLenStatus >=2 )
    {
        m_resendLenStatus=0;
        m_nSeqNum[0] = newOneIn->reqSeq; 
        m_nLastLen[0]= newOneIn->len; 
        if(bTcpSeqSameCache)
        {            
            //或许被'小'超时机制释放了
            if(NULL ==m_addCache[0]|| NULL ==m_addCache[1])
            {
                m_pLink->m_nLinkPktError = LINK_ERR_SIMILAR_PKT;
            }
            if(newOneIn->reqSeq == m_addCache[0]->reqSeq + m_addCache[0]->len)
            {            
                TRACE_MAX(" addTcpPkt()  id[%6u] m_resendLenStatus reqSeq=[%11u]/[%11u] len=[%6d]/[%6d] delete[%d] .\r\n",
                    m_nStreamId,m_addCache[0]->reqSeq,m_nSeqNum[0],m_addCache[0]->len,m_nLastLen[0],m_addCache[1]->len); 
                delete m_addCache[1];
                m_addCache[1]=NULL;          
            } 
            else if(newOneIn->reqSeq == m_addCache[1]->reqSeq + m_addCache[1]->len)
            {
                TRACE_MAX(" addTcpPkt()  id[%6u] m_resendLenStatus reqSeq=[%11u]/[%11u] len=[%6d]/[%6d] delete[%d] .\r\n",
                    m_nStreamId,m_addCache[1]->reqSeq,m_nSeqNum[1],m_addCache[1]->len,m_nLastLen[1],m_addCache[0]->len); 
                delete m_addCache[0];
                m_addCache[0]=NULL;
                //m_nSeqNum[0] =m_nSeqNum[1];
                //m_nLastLen[0]=m_nLastLen[1];  
            }
            else
            {
                printf(" error,addTcpPkt()  id[%6u] m_resendLenStatus not find pkt.\r\n",m_nStreamId);           
            }
        }
        /*
        else
        {            
            m_nSeqNum[0] newOneIn->reqSeq;
            m_nLastLen[0]=newOneIn->len; 
        }
        */
        m_nSeqNum[1] =0;
        m_nLastLen[1]=-1;
    }
    else if( m_resendLenStatus > 0 )
    {
        m_resendLenStatus++;
        TRACE_MAX(" addTcpPkt()  id[%6u] m_resendLenStatus=%d m_nLastLen=[0:%6d]/[1:%6d] reqSeq=[0:%11u]/[1:%11u].\r\n",
            m_nStreamId,m_resendLenStatus,m_nLastLen[0],m_nLastLen[1],m_nSeqNum[0],m_nSeqNum[1] );   
        TRACE_MAX(" addTcpPkt()  id[%6u] m_resendLenStatus=%d len=[%6d] reqSeq=[%11u].\r\n",
            m_nStreamId,m_resendLenStatus,newOneIn->len,newOneIn->reqSeq);   
    }
      
    if( newOneIn->freeType != MALLOC_FREE )
    {
        //没有复制过的原始dpdk包
        newOneIn->copyFromDpdkBuf();
    }
    ipPkt * newOne =NULL;
    if(bTcpSeqSameCache)
    {
        //应对多次重传长度不一致的情况    
        newOne = m_addCache[0];  
        m_addCache[0]=m_addCache[1];
        m_addCache[1]=newOneIn;
        if(newOne == NULL)
        {   
            return 0;
        }
    }
    else
    {
        //无缓冲机制
        if( m_resendLenStatus >0 )
        {
            m_pLink->m_nLinkPktError = LINK_ERR_SIMILAR_PKT;
        }
        newOne = newOneIn;
    }
    return addPktCall( newOne);
}

int tcpReassembly::addUdpPkt(ipPkt * newOne)
{
    m_pktSumForDecode++;
    if(newOne->len > 0)
    {
        if(m_payLoadPktSum < m_headPayLoadInfoMax)
        {
            //m_payLoadPktLen[m_payLoadPktSum] =newOne->len;
            //m_payLoadPktLinkId[m_payLoadPktSum] =newOne->linkPktSerialId;
            //m_payLoadPktStreamId[m_payLoadPktSum] =m_pktSumForDecode;
            m_payLoadPktLen.push_back(newOne->len);            
            m_payLoadPktLinkId.push_back(newOne->linkPktSerialId);
            m_payLoadPktStreamId.push_back(m_pktSumForDecode);

            TRACE_MAX(" tcpReassembly::addPktCall() id[%6u],m_payLoadPktSum[%d]/Max[%d],m_payLoadPktLen[%d],m_payLoadPktLinkId[%d],m_payLoadPktStreamId[%d].\r\n",
            m_nStreamId,
            m_payLoadPktSum+1,
            m_headPayLoadInfoMax,
            m_payLoadPktLen[m_payLoadPktSum],
            m_payLoadPktLinkId[m_payLoadPktSum],
            m_payLoadPktStreamId[m_payLoadPktSum]);
        }
        if(m_payLoadPktSum * 2 < m_headPayLoadInfoMax )
        {
            getPropertyString(newOne,pktHeadProperty);
            getPropertyString(newOne,pktTailProperty);
        }
        m_payLoadPktSum ++;
        this->m_payLoadLen += newOne->len;
        this->m_payLoadSumSquares  += (newOne->len*newOne->len);
        if(this->headDecode ==NULL )
        {   
            this->m_pMacBuf=newOne->pMac;
            this->headDecode=newOne;
            this->tailDecode=newOne;
            newOne->pre = NULL;
            newOne->next = NULL;    
            newOne->streamPktSerialId = m_pktSumForDecode;
            this->extractDone = REASSEMBLY_DATA;            
            TRACE_MAX(" tcpReassembly::addPktCall() headDecode == NULL,streamPktSerialId[%d].\r\n"
                ,newOne->streamPktSerialId);
        }
        else if(this->headDecode !=NULL && this->tailDecode !=NULL )
        {   
            newOne->pre = this->tailDecode ;
            this->tailDecode->next = newOne;
            newOne->next = NULL;        
            newOne->streamPktSerialId = m_pktSumForDecode;                  
            this->tailDecode = newOne;
            TRACE_MAX(" tcpReassembly::addPktCall() headDecode != NULL,streamPktSerialId[%d].\r\n"
                ,newOne->streamPktSerialId);
        }
        else
        {   
            //不在统计全部毛流量，改为统计有效的毛流量
            m_macLen +=newOne->macLen;
            printf(" error,tcpReassembly::addPktCall() head or tail is NULL,streamPktSerialId[%d].\r\n",newOne->streamPktSerialId);
            //视为已经解析
            m_pktDecoded++; 
            delete newOne;  
            return -1;
        }
    }
    else
    {
        if(m_zeroLenPktSum < m_headZeroLenInfoMax)
        {
            //m_zeroLenPktLinkId[m_zeroLenPktSum] =newOne->linkPktSerialId;
            //m_zeroLenPktStreamId[m_zeroLenPktSum] =m_pktSumForDecode;
            m_zeroLenPktLinkId.push_back(newOne->linkPktSerialId);            
            m_zeroLenPktStreamId.push_back(m_pktSumForDecode);            
            TRACE_MAX(" tcpReassembly::addPktCall() id[%6u],m_zeroLenPktSum[%d]/Max[%d],m_zeroLenPktLinkId[%d],m_zeroLenPktStreamId[%d].\r\n",
                m_nStreamId,
                m_zeroLenPktSum+1,
                m_headZeroLenInfoMax,
                m_zeroLenPktLinkId[m_zeroLenPktSum],
                m_zeroLenPktStreamId[m_zeroLenPktSum]);
        }
        m_zeroLenPktSum++;
        //不在统计毛流量，改为统计净流量
        m_macLen +=newOne->macLen;
        //视为已经解析
        m_pktDecoded++; 
        TRACE_MAX(" tcpReassembly::addPktCall() id[%6u],newOne->len <= 0,m_pktSumForDecode[%d] m_pktDecoded[%d].\r\n",
            m_nStreamId,
            m_pktSumForDecode,
            m_pktDecoded);
        
        delete newOne;  
    }
    return 0;
}

int tcpReassembly::addPktCall(ipPkt * newOne)
{
    m_pktSumForDecode++;
    if(newOne->len > 0)
    {
        if(m_payLoadPktSum < m_headPayLoadInfoMax)
        {
            //m_payLoadPktLen[m_payLoadPktSum] =newOne->len;
            //m_payLoadPktLinkId[m_payLoadPktSum] =newOne->linkPktSerialId;
            //m_payLoadPktStreamId[m_payLoadPktSum] =m_pktSumForDecode;
            m_payLoadPktLen.push_back(newOne->len);
            m_payLoadPktLinkId.push_back(newOne->linkPktSerialId);
            m_payLoadPktStreamId.push_back(m_pktSumForDecode);

            TRACE_MAX(" tcpReassembly::addPktCall() id[%6u],m_payLoadPktSum[%d]/Max[%d],m_payLoadPktLen[%d],m_payLoadPktLinkId[%d],m_payLoadPktStreamId[%d].\r\n",
            m_nStreamId,
            m_payLoadPktSum+1,
            m_headPayLoadInfoMax,
            m_payLoadPktLen[m_payLoadPktSum],
            m_payLoadPktLinkId[m_payLoadPktSum],
            m_payLoadPktStreamId[m_payLoadPktSum]);
        }
        if(m_payLoadPktSum * 2 < m_headPayLoadInfoMax )
        {
            getPropertyString(newOne,pktHeadProperty);
            getPropertyString(newOne,pktTailProperty);
        }
        m_payLoadPktSum ++;
        this->m_payLoadLen += newOne->len;
        this->m_payLoadSumSquares  += (newOne->len*newOne->len);
        if(this->headDecode ==NULL )
        {   
            this->m_pMacBuf=newOne->pMac;
            this->headDecode=newOne;
            this->tailDecode=newOne;
            newOne->pre = NULL;
            newOne->next = NULL;    
            newOne->streamPktSerialId = m_pktSumForDecode;
            this->extractDone = REASSEMBLY_DATA;            
            TRACE_MAX(" tcpReassembly::addPktCall() headDecode == NULL,streamPktSerialId[%d].\r\n"
                ,newOne->streamPktSerialId);
        }
        else if(this->headDecode !=NULL && this->tailDecode !=NULL )
        {   
            newOne->pre = this->tailDecode ;
            this->tailDecode->next = newOne;
            newOne->next = NULL;        
            newOne->streamPktSerialId = m_pktSumForDecode;                  
            this->tailDecode = newOne;
            TRACE_MAX(" tcpReassembly::addPktCall() headDecode != NULL,streamPktSerialId[%d].\r\n"
                ,newOne->streamPktSerialId);
        }
        else
        {   
            //不在统计全部毛流量，改为统计有效的毛流量
            m_macLen +=newOne->macLen;
            printf(" error,tcpReassembly::addPktCall() head or tail is NULL,streamPktSerialId[%d].\r\n",newOne->streamPktSerialId);
            //视为已经解析
            m_pktDecoded++; 
            delete newOne;  
            return -1;
        }
    }
    else
    {
        if(m_zeroLenPktSum < m_headZeroLenInfoMax)
        {
            //m_zeroLenPktLinkId[m_zeroLenPktSum] =newOne->linkPktSerialId;
            //m_zeroLenPktStreamId[m_zeroLenPktSum] =m_pktSumForDecode;
            m_zeroLenPktLinkId.push_back(newOne->linkPktSerialId);            
            m_zeroLenPktStreamId.push_back(m_pktSumForDecode);          
            TRACE_MAX(" tcpReassembly::addPktCall() id[%6u],m_zeroLenPktSum[%d]/Max[%d],m_zeroLenPktLinkId[%d],m_zeroLenPktStreamId[%d].\r\n",
                m_nStreamId,
                m_zeroLenPktSum+1,
                m_headZeroLenInfoMax,
                m_zeroLenPktLinkId[m_zeroLenPktSum],
                m_zeroLenPktStreamId[m_zeroLenPktSum]);
        }
        m_zeroLenPktSum++;
        //不在统计毛流量，改为统计净流量
        m_macLen +=newOne->macLen;
        //视为已经解析
        m_pktDecoded++; 
        TRACE_MAX(" tcpReassembly::addPktCall() id[%6u],newOne->len <= 0,m_pktSumForDecode[%d] m_pktDecoded[%d].\r\n",
            m_nStreamId,
            m_pktSumForDecode,
            m_pktDecoded);
        
        delete newOne;  
    }
    return 0;
}

