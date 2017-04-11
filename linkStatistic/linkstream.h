


#ifndef __LINKSTREAM_H__
#define __LINKSTREAM_H__



#include <sys/time.h>

#include "basicHeadfile.h"
#include "nprlinkpool.h"
#include "tcpReassembly.h"

#include "appLinkInterface.h"

#include "nprdef.h"


extern __thread void * pOutObj;

extern __thread pOutFun pFun;



class httpSessionDecode;

enum LINK_ERR
{
    LINK_NORMAL=0,
    LINK_ERR_JUMP,
    LINK_ERR_SUPER_JUMP,
    LINK_ERR_SIMILAR_PKT,
    LINK_ERR_OTHER
};

enum DUPLEX
{
    DUPLEX_NULL,
    CLIENT_ONLY,
    SERVER_ONLY,
    DUPLEX_ALL,
    NOSHAKE,
    DUPLEX_NOSHAKE,
    UDP_SINGAL,
    DUPLEX_UDP
};

enum CLOSE_STREAM
{
    //come 端发生fin
    COME_CLOSING,
    //conver 端发生fin
    CONVER_CLOSING,
    //COME-sendfin CONVER-sendfin
    DUPLEX_CLOSING_CLOSING,
    //COME CONVER
    DUPLEX_CLOSING_CLOSED,
    DUPLEX_CLOSED_CLOSING,
    COME_CLOSED,
    CONVER_CLOSED,
    DUPLEX_CLOSED,
    OTHER_CLOSE,
    OTHER_NULL
};



class linkStream
{
public:
    //在连接池的超时链表中指向前后节点的指针，用以维护超时链表
    linkStream *m_pPreTimeout,*m_pNextTimeout;
    
    //全部链接的步增(步长为2)编号，保证一个链路一个编号；Come流为单号，conver流为双号
    static UINT32 m_linkStepId;

    //TCP链接超时最大时间
    static UINT32 RstFinTimeout;
    //TCP通用链接无挥手超时最大时间
    static UINT32 nNoByeDefaultTimeout;
    //TCP通用链接seq多次重复cache超时
    static UINT32 nCacheTimeout;
        
    static UINT32 nOutputMaxTime;
    
    //UDP链接超时最大时间
    static UINT32 UdpTimeout;
    
    //链接编号，必为偶数
    UINT32 m_linkId;
    //链接的五元组
    IP4ConnectAddr m_linkAdd;
    
    //come流包自增号
    int m_lastCome;
    //conver流包自增号
    int m_lastConver;

    //开始握手包数量
    int m_nHandshake;
    //断开握手包数量
    int m_nByeHandshake;

    string m_lineNumber;

    //come流的状态(NULL or COME)
    uint8_t m_statusCome;
    //conver流的状态(NULL or CONVER)
    uint8_t m_statusConv;

    //COME map (client or service)
    STREAM m_direction;

    //在哈希表中指向下一个连接对象的指针
    linkStream *m_pNext;

    //当前tcp包的负载长度
    UINT32 m_len;

    //当前tcp包的流类型(COME or CONVER)
    uint8_t m_flow;
    //当前tcp包的tcp-flag
    unsigned m_tcpFlag;
    //当前tcp包的tcp-seq
    UINT32 m_nSeqNum;
    //当前tcp包的tcp-ackseq确认号
    UINT32 m_nAckSeq;

    //当前tcp包的负载长度
    UINT32 m_lastLen[2];
    //当前tcp包的tcp-flag
    uint8_t m_lastFlow[2];
    //当前tcp包的tcp-flag
    unsigned m_lastTcpFlag[2];
    //当前tcp包的tcp-seq
    UINT32 m_nlastSeqNum[2];
    //当前tcp包的tcp-ackseq确认号
    UINT32 m_nlastAckSeq[2];
    //当前包的序号的递增状态处理结果
    STATUS_SEQ m_seqStatus;
    //当前包的序号的递增的测试状态
    STATUS_SEQ m_seqTryStatus;

    //流方向号，0 come ， 1 conver 
    int m_flowDir;

    //统计tcp-flag的出现次数
    //UINT32 m_synFlagStatistic[FLOW_SUM];
    UINT32 m_synFlagStatistic[256];
    //缩减版本的come和conver序列，ack连续时会被压缩
    //STREAM m_ComeOrConver[FLOW_SUM];
    //uint8_t m_ComeOrConver[FLOW_SUM];
    vector<uint8_t> m_ComeOrConver;
    //缩减版本的come和conver序列总数，ack连续时会被压缩，总数会减少
    INT16 m_flagsSum;


    //记载come流的tcp-flag的序列和总次数
    //INT16 m_synComeFlagsQueuen[FLOW_SUM];
    vector<uint8_t> m_synComeFlagsQueuen;
    INT16 m_comeFlagsSum;
    //记载conver流的tcp-flag的序列和总次数
    //INT16 m_synConverFlagsQueuen[FLOW_SUM];
    vector<uint8_t> m_synConverFlagsQueuen;
    INT16 m_converFlagsSum;

    
    //当前被识别为流的双工状态
    DUPLEX m_duplex;

    //当前为流的关闭状态
    CLOSE_STREAM m_isClose;

    //come和conver的与ack正常传送的流交互序列中
    //当前的包是否(代表正常)的ack包(或其他等同ack的非异常的flags包)
    bool m_bAckAck;
    //m_bAckAck 的上一个值
    bool m_bLastAckAck;

    //连续都是m_bAckAck为真的包累加数
    //即视为正常传输的包数(为了压减序列)
    INT16 m_ackAckSum;

    //四元组的hash值
    UINT32  m_nFourHash ;
    
    //标识当前连接最后一个数据包到达的时间戳
    //UINT32 m_nTimeStamp;
    struct timeval m_tb;
    
    //标识当前连接第一个数据包到达的时间戳
    //UINT32 m_nFirstTimeStamp;
    struct timeval m_firstTb;
    //超时发现时间
    struct timeval m_timeoutTb;
    //超长链接定时输出
    struct timeval m_lastOutputTb;

    //链接无挥手自然超时阈值
    //UINT32 m_nNoByeTimeout;

    //delete 
    //int m_questIndex;
    //delete 
    //int m_ackIndex;

    //包重组对象:0 come, 1 conver
    tcpReassembly* m_pkt[2];
    
    //单向流解析对象:0 come, 1 conver
    //httpSessionDecode *m_decode[2];
    //void *m_decode;
    appLink m_appLink;

    
    //各个单向流的自增序号
    int m_streamPktSum[2];
    //各个单向流的自增序号
    int m_streamLoadPktSum[2];
    //各个单向的tcp全部数据包的毛长度
    int m_streamTotalMacLen[2];
    
    //各个单向的tcp重传数据包数
    int m_streamPktResend[2];   
    //各个单向的tcp重传数据包的毛长度
    int m_streamResendMacLen[2];
    
    //各个单向的tcp未知数据包数
    int m_streamPktUnknow[2];   
    //各个单向的tcp未知数据包的毛长度
    int m_streamUnknowMacLen[2];
    
    
    //各个单向的tcp全部数据包的净载荷长度( 未去重 )
    int m_streamTotalPayloadMacLen[2];
    //解码是否开启
    int m_bAppLinkOpen;

    int m_nLinkPktError;
    linkStream();
    ~linkStream();
    //使用四元组初始化
    //stream:五元组对象
    //返回值:无返回值
    linkStream(const IP4ConnectAddr  & stream);
    
    //统计信息输出
    void statisticOut(bool tmepOutput);
    
    void basicOut();
    //判断链接是否超时
    //nCurTime:当前时间
    //nTimeOut:超时阈值
    //返回值:true 超时，false 未超时
    bool checkTimeout(UINT32 nCurTime,UINT32 nTimeOut=0);   
    bool checkTimeout(struct timeval & nCurTime,UINT32 nTimeOut);
    bool cacheTimeout(UINT32 nCurTime,UINT32 nTimeOut=0);    
    void flushDecode();
    void flushCache();
    
    //判断链接是否给定四元组相同
    //stream:五元组对象
    //返回值:FLOW_COME 第一条流,FLOW_CONVER 反向流,FLOW_NULL 未匹配
    uint8_t isSameLink(const IP4ConnectAddr & stream);
    
    //判断链接是否已经关闭
    //nCurTime:当前时间
    //返回值:true 已经关闭，false 未关闭
    bool isClose( UINT32 nCurTime);
    //bool isCloseTcp( UINT32 nCurTime);
    //bool isCloseUdp( UINT32 nCurTime);
    
    //设置一个方向流为正在关闭
    //flow:FLOW_COME 第一条流,FLOW_CONVER 反向流
    //返回值:0 设置完成，<0 设置异常
    int setClosing( uint8_t flow);
    
    //设置一个方向流为关闭状态
    //flow:FLOW_COME 第一条流,FLOW_CONVER 反向流
    //返回值:0 设置完成，<0 设置异常
    int setClosed( uint8_t flow);
    
    //设置一个方向流为重置状态
    //flow:FLOW_COME 第一条流,FLOW_CONVER 反向流
    //返回值:0 设置完成，<0 设置异常
    int setRst( uint8_t flow);
    
    
    //判断链接是关闭或准关闭状态
    //返回值:true 已经关闭或准关闭状态，false 未关闭或准关闭状态
    bool willClose( );
    
    //处理对应的tcpflag
    //返回值:0 设置完成，<0 设置异常
    int tcpFin();
    //处理对应的tcpflag
    //返回值:0 设置完成，<0 设置异常
    int tcpSyn();
    //处理对应的tcpflag
    //返回值:0 设置完成，<0 设置异常
    int tcpRst();
    //处理对应的tcpflag
    //返回值:0 设置完成，<0 设置异常
    int tcpPsh();   
    //压缩ack序列
    //flow:FLOW_COME 第一条流,FLOW_CONVER 反向流
    //返回值:0 设置完成，<0 设置异常
    int tcpAckClear(uint8_t flow);
    //处理对应的tcpflag
    //返回值:0 设置完成，<0 设置异常
    int tcpAck();
    //处理对应的tcpflag
    //返回值:0 设置完成，<0 设置异常
    int tcpFinAck();    
    //处理对应的tcpflag
    //返回值:0 设置完成，<0 设置异常
    int tcpPshAck();
    //处理对应的tcpflag
    //返回值:0 设置完成，<0 设置异常
    int tcpUrg();
    //处理对应的tcpflag
    //返回值:0 设置完成，<0 设置异常
    int tcpSyn_ack0(ipPkt * pkt);
    //处理对应的tcpflag
    //返回值:0 设置完成，<0 设置异常
    int tcpSynAck(ipPkt * pkt);
    //处理对应的tcpflag
    //返回值:0 设置完成，<0 设置异常
    int tcpRstAck();
    //处理对应的tcpflag
    //返回值:0 设置完成，<0 设置异常
    int tcpUrgAck();
    //处理对应的tcpflag
    //返回值:0 设置完成，<0 设置异常
    int tcpFinPshAck();
    
    //解析tcpseq符合规则的数据包队列
    //返回值:0 解析完成，<0 解析异常
    int decodeCall(int id,bool bAcknowledgmentSeq);
    
    //依据sequeuen号来实时解析tcp数据包
    //id:0 FLOW_COME-第一条流,1 FLOW_CONVER-反向流
    //pkt:数据包
    //返回值:0 解析完成
    int decodeTcpStream(int id, ipPkt * pkt);

    //实时解析udp数据包
    //id:0 FLOW_COME-第一条流,1 FLOW_CONVER-反向流
    //pkt:数据包
    //返回值:0 解析完成    
    int decodeUdpStream(int id, ipPkt * pkt);

    //实时解析数据包//id:0 FLOW_COME-第一条流,1 FLOW_CONVER-反向流
    //pkt:数据包
    //nCurTime:当前时间
    //返回值:0 解析完成
    int dealStream(ipPkt *pkt, struct timeval&  nCurTime,uint8_t flow);
    //实时解析tcp数据包，分别处理数据包和flag序列
    //id:0 FLOW_COME-第一条流,1 FLOW_CONVER-反向流
    //pkt:数据包
    //nCurTime:当前时间
    //返回值:0 解析完成
    int dealTcpStream(ipPkt *pkt, struct timeval&  nCurTime,uint8_t flow);
    //实时解析udp数据包
    //id:0 FLOW_COME-第一条流,1 FLOW_CONVER-反向流
    //pkt:数据包
    //nCurTime:当前时间
    //返回值:0 解析完成
    int dealUdpStream(ipPkt *pkt, struct timeval&  nCurTime,uint8_t flow);
    
    //同步序列FLOW_COME-第一条流, FLOW_CONVER-反向流
    //返回值:0 解析完成
    int dumpSyn();
    
    //识别双向流的各第一个数据包，主要是为了tcpflags处理
    //flow:0 FLOW_COME-第一条流,1 FLOW_CONVER-反向流
    //返回值:0 解析完成
    int firstPacket(uint8_t flow,ipPkt * pkt);
    
    //记录和统计双向流的tcpflags
    //flow:0 FLOW_COME-第一条流,1 FLOW_CONVER-反向流
    //TcpFlag:tcpflags
    //返回值:0 解析完成
    int flagsEnqueuen(uint8_t flow,uint8_t TcpFlag);    
    //发现重复包
    //return true - false;
    bool findResendPkt();
};

#endif

