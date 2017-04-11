/*=========================================================
*   File name   ��  linkpool.h
*   Authored by ��  daihw
*   Date        ��  2005-3-4 9:52:30
*   Description ��  
*
*   Modify      ��  zjk
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

    
    //������Ԫ�����Ӷ���
    linkStream* sFindConnect(const IP4ConnectAddr& ConnectAddr,uint8_t & flow);
    linkStream * sNewConnect( const IP4ConnectAddr& ConnectAddr);
    //�����Ԫ�����Ӷ������ӹ�������
    linkStream* sAddConnect(linkStream *pLink, const IP4ConnectAddr& ConnectAddr);
    void sCheckTimeout(UINT32 nCurTime );
    linkStream* moveTimeoutTail(linkStream * pLink);    
    void sCloseConnect(linkStream *pLink);

    //����CLink����ĳ�ʱʱ��
    //void SetTimeout(UINT32 nTime) { m_nTimeout = nTime; }

    //��ȡ���������
    UINT64 GetMaxLink();  
    //��ȡ��ǰ������
    UINT64 GetCurLink();  
    //ɾ�����е���Ԫ�����Ӷ����ͷ���Դ
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
    //��ʱʱ�䣬����Ϊ��λ
    //UINT32 m_nTimeout;
    //�ڳ�ʱ������ʹ�õ�ǰ������ָ��
    linkStream*m_pStreamHead, *m_pStreamTail;
    linkStream*m_pStreamCacheClearHead;


private:
    //ͳ��ʹ��
    UINT64 m_nMaxLink;      //���������
    UINT64 m_nCurLink;      //��ǰ������
    INT32  m_nTcpOrUdp; 
public : 

    //�����Ƿ��
    int m_bDecodeOpen;

};


/*==========================================================
* Function      : nprLinkPool::Hash
* Description   : ������Ԫ���ַ����HASH
* Return        : INT32 HASHֵ
* Parament      : const IP4ConnectAddr& ConnectAddr ��Ԫ��
* Comments      : 
*=========================================================*/
inline UINT32   nprLinkPool::Hash(const IP4ConnectAddr& ConnectAddr)
{
    return ( ConnectAddr.Conver.nPort^ConnectAddr.Come.nPort)^((ConnectAddr.Conver.nIP^ConnectAddr.Come.nIP)&(LINKHASH));
}

/*==========================================================
* Function      : nprLinkPool::Hash
* Description   : ������Ԫ���ַ����HASH
* Return        : UINT32 HASHֵ
* Parament      : const IPv4TransportAddr& clientAddr �ͻ��˵�ַ
* Parament      : const IPv4TransportAddr& serverAddr ��������ַ
* Comments      : 
*=========================================================*/
inline UINT32   nprLinkPool::Hash(const IP4Addr& clientAddr, const IP4Addr& serverAddr)
{
    return (clientAddr.nPort^serverAddr.nPort)^((serverAddr.nIP^clientAddr.nIP)&0x000FFFFF);
}

#endif // __NPR_LINKPOOL_H__

