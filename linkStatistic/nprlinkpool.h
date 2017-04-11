/*=========================================================
*   File name   ：  linkpool.h
*   Authored by ：  daihw
*   Date        ：  2005-3-4 9:52:30
*   Description ：  
*
*   Modify      ：  zjk
*   Modify  :     2006-05-25 15:00:00
*=========================================================*/
#ifndef __NPR_LINKPOOL_H__
#define __NPR_LINKPOOL_H__

#include "nprdef.h"

#define  MAX_LINKHASH_SIZE (1024*1024)
#define  LINKHASH (MAX_LINKHASH_SIZE-1)


class linkStream;


#define FLOW_NULL (0xff)
#define FLOW_COME (0x1)
#define FLOW_CONVER (0x2)


enum STREAM
{
    TCP_URG = 0x20,
    TCP_ACK = 0x10,
    TCP_PSH =0x08,
    TCP_RST =0x04,
    TCP_SYN =0x02,
    TCP_FIN =0x01,
    TCP_SYN_ACK0 =0x100,
    //FLOW_COME=0x200,
    //FLOW_CONVER=0x400,
    FLOW_COME_CLIENT=0x800,
    FLOW_COME_SERVER=0x1000,
    //FLOW_NULL=0x2000,
    DIRECT_NULL =0x2000,
    FLOW_SUM =4096
};



class nprLinkPool  
{
public: 

    
    //查找四元组连接对象
    linkStream* sFindConnect(const IP4ConnectAddr& ConnectAddr,uint8_t & flow);
    linkStream * sNewConnect( const IP4ConnectAddr& ConnectAddr);
    //添加四元组连接对象到连接管理器中
    linkStream* sAddConnect(linkStream *pLink, const IP4ConnectAddr& ConnectAddr);
    void sCheckTimeout(UINT32 nCurTime );
    linkStream* moveTimeoutTail(linkStream * pLink);    
    void sCloseConnect(linkStream *pLink);

    //设置CLink对象的超时时间
    //void SetTimeout(UINT32 nTime) { m_nTimeout = nTime; }

    //获取最大连接数
    UINT64 GetMaxLink();  
    //获取当前连接数
    UINT64 GetCurLink();  
    //删除所有的四元组连接对象，释放资源
    void    Close();



public:
    nprLinkPool () ;
    virtual ~nprLinkPool ();
    void SetLinkPoolType(int iTcpOrUdp); //added by gchen@1010-04-22
    
private:
    UINT32  Hash(const IP4ConnectAddr& ConnectAddr);
    UINT32  Hash(const IP4Addr& clientAddr, const IP4Addr& serverAddr);
    
    
private:  
    
    linkStream* m_streamTable[MAX_LINKHASH_SIZE];
    //超时时间，以秒为单位
    //UINT32 m_nTimeout;
    //在超时链表中使用的前、后向指针
    linkStream*m_pStreamHead, *m_pStreamTail;
    linkStream*m_pStreamCacheClearHead;


private:
    //统计使用
    UINT64 m_nMaxLink;      //最大连接数
    UINT64 m_nCurLink;      //当前连接数
    INT32  m_nTcpOrUdp; 
public : 

    //解码是否打开
    int m_bDecodeOpen;

};


/*==========================================================
* Function      : nprLinkPool::Hash
* Description   : 根据四元组地址进行HASH
* Return        : INT32 HASH值
* Parament      : const IP4ConnectAddr& ConnectAddr 四元组
* Comments      : 
*=========================================================*/
inline UINT32   nprLinkPool::Hash(const IP4ConnectAddr& ConnectAddr)
{
    return ( ConnectAddr.Conver.nPort^ConnectAddr.Come.nPort)^((ConnectAddr.Conver.nIP^ConnectAddr.Come.nIP)&(LINKHASH));
}

/*==========================================================
* Function      : nprLinkPool::Hash
* Description   : 根据四元组地址进行HASH
* Return        : UINT32 HASH值
* Parament      : const IPv4TransportAddr& clientAddr 客户端地址
* Parament      : const IPv4TransportAddr& serverAddr 服务器地址
* Comments      : 
*=========================================================*/
inline UINT32   nprLinkPool::Hash(const IP4Addr& clientAddr, const IP4Addr& serverAddr)
{
    return (clientAddr.nPort^serverAddr.nPort)^((serverAddr.nIP^clientAddr.nIP)&0x000FFFFF);
}

#endif // __NPR_LINKPOOL_H__

