#ifndef IP_FRAGMENT_H
#define IP_FRAGMENT_H

#include <netinet/ip.h>
#include "ipfragmentcommon.h"
#include "ipPkt.h"
#include <assert.h>

typedef void * (*MEMALLOC)(uint32_t nSize, uint32_t nID);
typedef void (*MEMFREE)(void* addr);


class CIP_Fragment
{
public:
    CIP_Fragment();
    ~CIP_Fragment();
    
    int ProcessIP(ipPkt *tcpipFilterContext);
    void CheckIPTimeout();
    
    //void DelLongNode();
    
private:
    ipPkt *DefragIP(ipPkt *tcpipFilterContext);
    IPNode *FindIPNode(ipPkt *tcpipFilterContext);
    void QueueIPFrag(IPNode *qp, IPPacket *skb);
    ipPkt *ReasmIPFrag(IPNode *qp, ipPkt *skb);
    

    inline IPNode* CreateIPNode(UINT16 hash, ipPkt *tcpipFilterContext);
    inline void DestroyIPNode(IPNode* pNode);
    inline IPPacket* CreateIPPacket(ipPkt *tcpipFilterContext);
    inline void DestroyIPPacket(IPPacket* ipPacketHead);
    void FreeNodefromTable(IPNode *pNode);
    inline void RmTimeoutNode(IPNode *pNode);
    void AddTimeoutNode(IPNode *pNode);
#ifdef IPFRAG_DEBUG
    void CheckTimeoutList();
    void CheckHashTable();
#endif
    IPNode *m_hashIPTable[IPQ_HASHSZ];
    //IPNode *m_qsortArray[USER_NUM];
    IPNode *m_nodeTimeHead, *m_nodeTimeTail;

#ifdef IPFRAG_DEBUG
    UINT32 m_ipCount;
#endif
};

#endif//IP_FRAGMENT_H
