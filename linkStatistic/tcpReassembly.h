///////////////////////////////////////////////////////////
//  tcpReassembly.h
//  Implementation of the Class tcpReassembly
//  Created on:      15-十月-2015 14:08:37
//  Original author: huiliang
///////////////////////////////////////////////////////////

#if !defined(EA_C7B2E46E_00B4_4e81_B3E2_69F6B65B868B_tcpReassembly_INCLUDED_)
#define EA_C7B2E46E_00B4_4e81_B3E2_69F6B65B868B_tcpReassembly_INCLUDED_

#include <string.h>
#include <pthread.h>  
#include "basicHeadfile.h"
#include "ipPkt.h"
#include "nprdef.h"
#include "linkDecodeInterface.h"

//const short int PORPERTY_STREAM_MAX_ELEMENT;
//const short int PORPERTY_MAXLEN;

class streamDecode;
class linkStream;
class tcpReassemblyLock
{
public:
    //通过构造函数加锁
    tcpReassemblyLock( pthread_mutex_t & mutex): m_mutex(mutex)  
    {
            pthread_mutex_lock(&m_mutex);
    }
    //通过析构函数解锁
    ~tcpReassemblyLock() 
    {
    #ifdef EXTRACT_DEBUG
        //printf("unlock ! [%x]\r\n",&m_mutex);
    #endif
        pthread_mutex_unlock(&m_mutex);
    }
    
private:
    pthread_mutex_t & m_mutex;
};

class PropertyParm
{
public: 
    //要获取特征的包序号，-1为不指定
    int m_packetNum;
    //特征字段的偏移值，>0 从包头开始，<0 从包尾开始
    int m_offSize;
    //特征字段的长度
    int m_propertyLen;
    PropertyParm(int num,int off,int len )
    {
        m_packetNum= num;
        m_offSize= off;
        m_propertyLen =len;
    }
};


enum STATUS_REASSEMBLY
{
    EMPTY=0,
    REASSEMBLY_DATA,
    EXTRACT_DONE        
};

enum STATUS_SEQ
{
    SEQ_ERR=0,
    SEQ_RESEND,
    SEQ_SUCCESS,
    SEQ_ERR_DEL,  
};


/**
 * 输入的http原始数据
 */
class tcpReassembly
{
public: 
    /**
     * 数据有效的载荷，去重后的
     */
    int m_payLoadLen;
    /**
     * 数据有效的载荷长度平方和
     */
    int m_payLoadSumSquares;
    
    /**
     * 数据有载荷，去重后的包数量
     */
    int m_payLoadPktSum;    

    
    //记录最开始的负载包信息的最大值/
    unsigned short  m_headPayLoadInfoMax;
    //记录最开始的包信息:包长度/
    //unsigned short  m_payLoadPktLen[MAX_HEADPKT_INFO];
    vector<unsigned short>  m_payLoadPktLen;    
    //记录最开始的包信息:包的链接id/
    //unsigned int  m_payLoadPktLinkId[MAX_HEADPKT_INFO];
    vector<unsigned int>  m_payLoadPktLinkId;
    //记录最开始的包信息:包的流id/
    //unsigned int  m_payLoadPktStreamId[MAX_HEADPKT_INFO];
    vector<unsigned int>  m_payLoadPktStreamId;

    
    //数据有载荷，去重后的包数量/
    int m_zeroLenPktSum;    
    //记录最开始的非负载包信息的最大值/
    unsigned short  m_headZeroLenInfoMax;
    //记录最开始的包信息:包的链接id/
    //unsigned int  m_zeroLenPktLinkId[MAX_HEADPKT_INFO];
    vector<int>  m_zeroLenPktLinkId;
    //记录最开始的包信息:包的流id/
    //unsigned int  m_zeroLenPktStreamId[MAX_HEADPKT_INFO];
    vector<int>  m_zeroLenPktStreamId;

    
    //特征串已完成数量，最大为 PORPERTY_STREAM_MAX_ELEMENT
    short int m_porpertyDone;
    //每个特征串的包号
    //INT16 m_porpertyPktNum[PORPERTY_STREAM_MAX_ELEMENT];
    vector<short int>  m_porpertyPktNum;
    //每个特征串长度
    //INT16 m_porpertyLen[PORPERTY_STREAM_MAX_ELEMENT];
    vector<short int>  m_porpertyLen;
    //每个特征串的偏移值，大于0从头开始，小于0从尾部开始
    //short int m_porpertyOffsize[PORPERTY_STREAM_MAX_ELEMENT];
    vector<short int>  m_porpertyOffsize;
    //每个特征串
    //char m_porperty[PORPERTY_STREAM_MAX_ELEMENT][PORPERTY_MAXLEN];   
    vector<char *>  m_porperty;
    
    
    //数据包总长度,有效的毛流量
    //重传不在计入
    int m_macLen;

    //链路层数据头指针
    char *m_pMacBuf;
    
    //tcp乱序重传等缓冲队列头指针
    ipPkt * head;
    //tcp乱序重传等缓冲队列尾指针
    ipPkt * tail;
    
    //tcp乱序重传等缓冲队列包数量    
    UINT32 cacheSum;    
    //tcp乱序重传等缓冲队列包数的曾经最大值
    static UINT32 cacheSumMax;    
    //tcp乱序重传等缓冲队列包数最大设定值
    static UINT32 cacheSumMaxSetting;    
    //tcp乱序最大容错的 seq间隔
    static UINT32 seqJumpMaxSetting;     
    //tcp乱序最大容错间隔次数
    static UINT32 seqJumpSumMax;       
    //tcp乱序已经出现的容错间隔次数
    UINT32 m_seqJumpSum;             
    //tcp乱序已经出现的容错间隔次数
    int m_seqLostBytes;    
    
    /**
     * 不需要缓冲解析的0字节包累加数
     */ 
    UINT32 notCacheLenZero;
    /**
     * 流id自增号,需要解析的包数，无论是否有负载
     */ 
    int m_pktSumForDecode;
    //tcp序号重排后的待解析头指针
    ipPkt * headDecode;
    //tcp序号重排后的待解析尾指针
    ipPkt * tailDecode;

    //父指针，链接指针
    linkStream * m_pLink;
    
    /**
     * 已经解析的包数，无论是否有负载
     */ 
    int m_pktDecoded;

    /**
     *全文抽取解码完成状态
     */ 
    int extractDone;

    
    //单向流的当前重排后的seq，严格递增，最后一个包的开始序号
    //数组用来处理异常，通常只使用0
    UINT32 m_nSeqNum[2];
    //单向流数据包seq重排后，最后重排的末包的长度
    //数组用来处理异常，通常只使用0
    int m_nLastLen[2];
    
    //单向流数据包seq重排后
    UINT32 m_nLastSeq[2];
    
    //单向流数据包seq重排后，最后重排的末包的确认seq号
    UINT32 m_nAckSeq;
    //单向流第一个确认seq号
    UINT32 m_nFirstAckSeq;
    //链接id号，双向流的id时相邻的奇数和偶数
    UINT32 m_nStreamId;
    //come or conver, 0 or 1
    int m_nFlowType;

    //mss 允许的最大分片
    int m_segmentMax;
    //握手的窗口大小
    int m_windowSize;
    //握手窗口倍数
    int m_windowScale;
    //sack
    int m_sackPermitted;
    //窗口0统计
    int m_winZeroSize;

    //0,正常，1，error
    //状况太差，无法解析的链接
    int m_streamSeqStatus;

    //解析队列临时缓冲
    //应对重传包场对不一致的情况
    ipPkt * m_addCache[2];
    //不同长度的重传出现
    //0,正常，1，不同长度重传发生
    int m_resendLenStatus;
    //seq相同的不同包缓冲
    static bool bTcpSeqSameCache;
public: 
    tcpReassembly();
    virtual ~tcpReassembly();

    
    /**
     *  初始化
     */ 
    void init(int headPaLoadMax,int headZeroLenMax);


    /**
     *  仅仅处理无负载的包，重排seq，判别seq是否按照学号递增
     *  pkt:tcp包
     *  return: SEQ_ERR 出错，SEQ_RESEND 重传，SEQ_SUCCESS  排序正确
     */ 
    STATUS_SEQ upSeq(  ipPkt *pkt,int nLenErrIndex);
    
    /**
     *  仅仅处理舠eq，判别seq是否按照学号递增
     *  pkt:tcp包
     *  return: SEQ_ERR 出错，SEQ_RESEND 重传，SEQ_SUCCESS  排序正确
     */ 
    STATUS_SEQ upSeqOnly( ipPkt * pkt,int nLenErrIndex);
    
    /**
     *  异常状态处理，包跳跃频繁，包积压严重状态处罚
     *  pkt:tcp包
     *  return: SEQ_ERR 出错，SEQ_RESEND 重传，SEQ_SUCCESS  排序正确 SEQ_ERR_DEL 后续删除
     */ 
    STATUS_SEQ statusUpSeqData( ipPkt * pkt);
    /**
     *  重排seq，判别seq是否按照学号递增，处理全部tcp包
     *  pkt:tcp包
     *  return: SEQ_ERR 出错，SEQ_RESEND 重传，SEQ_SUCCESS  排序正确
     */ 
    STATUS_SEQ upSeqData( ipPkt *pkt,bool firstTryUp,int nLenErrIndex);

    /**
     *  重排seq非严格递增的包，暂时进入缓冲队列
     *  return: 0 完成，其他 出错
     */
    int cachePkt(ipPkt * newOne);  
    /**
     *  重排Tcp的seq递增的包，暂时进入待解析队列
     *  newOne:tcp包
     *  return: 0 完成，其他 出错
     */
    int addTcpPkt(ipPkt * newOne);
     /**
     *  udp的包，暂时进入待解析队列
     *  newOne:tcp包
     *  return: 0 完成，其他 出错
     */
    int addUdpPkt(ipPkt * newOne);
     
    int addPktCall(ipPkt * newOne);
    int addCachePkt();
    /**
     *  从入缓冲队列中，再次判断是否seq递增，并加入待解码队列
     *  return: 0 完成，其他 出错
     */
     
    
    int cacheTryAdd( );
     
    /**
     *  获取特征串
     */
     int getPropertyString(const ipPkt * newOne, const struct PropertyParm & pParm);

    /**
     *  清理缓冲队列和待解析队列
     */
    void flushCache();   
    void flushDecode();

    
    /**
     *  服务器端握手包解析
     */
    void decodeSynAck( ipPkt *pkt);
    
    /**
     *  客户端握手包解析
     */
    void decodeSynAck0( ipPkt *pkt);
    
    /**
     *  zero window size 次数
     */
    void winZeroSize( ipPkt *pkt);

    int cacheCheck(const int &nLenErrIndex,const UINT32 & cacheSum);
private:

    //int addMid(ipPkt *pre,ipPkt *next,ipPkt * newOne);
    

};
#endif // !defined(EA_C7B2E46E_00B4_4e81_B3E2_69F6B65B868B_Reassembly_INCLUDED_)
