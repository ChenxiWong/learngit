/*=============================================================================
*   File name   ：  ip_fragment.cpp
*   Authored by ：  lzr
*   Date        ：  2009-7-22
*   Description ：  
*   Modify      ：  
*=============================================================================*/

#include "ip_fragment.h"
#include <stdlib.h>
#include <stdio.h>

#ifdef IPFRAG_DEBUG
    UINT64 ipfragToIPCount = 0;
#endif


static inline unsigned char * pskb_pull(IPPacket *skb, unsigned int len)
{
    if (len > skb->len)
        return NULL;
    skb->len -= len;
    return  skb->ipPacket += len;
}


#ifdef IPFRAG_DEBUG
inline void CIP_Fragment::CheckTimeoutList()
{
    IPNode *pNode = m_nodeTimeHead;
    if(NULL == pNode)
        return;
    int i = 0;
    for(; pNode != NULL; i++, pNode = pNode->nextTimeout);
    assert( i == m_ipCount);
}
#endif


#ifdef IPFRAG_DEBUG
inline void CIP_Fragment::CheckHashTable()
{
/*  for(int i=0; i< IPQ_HASHSZ; i++)
    {
        for(int j = i+1; j < IPQ_HASHSZ; j++)
        {
            if(m_hashIPTable[i] && m_hashIPTable[j])
            {
                if(m_hashIPTable[i] == m_hashIPTable[j])
                {
                    printf("m_hashIPTable[%d] = %p,m_hashIPTable[%d] = %p\n", i, m_hashIPTable[i], j, m_hashIPTable[j]);
                }
                
                assert(m_hashIPTable[i] != m_hashIPTable[j]);
            }
        }
    }
*/
}
#endif


CIP_Fragment::CIP_Fragment()
{
    memset(&m_hashIPTable, 0, sizeof(m_hashIPTable));
    //memset(&m_qsortArray, 0, sizeof(m_qsortArray));
    m_nodeTimeHead = m_nodeTimeTail = NULL;
    
#ifdef IPFRAG_DEBUG
    m_ipCount = 0;
#endif
}


CIP_Fragment::~CIP_Fragment()
{
    //A10DBG("Before ~CIP_Fragment: m_ipCount = %d\n",m_ipCount);
    IPNode *ipNode = NULL, *tempIP = NULL;  
 
    for (int j=0; j<IPQ_HASHSZ; j++)
    {
        ipNode = m_hashIPTable[j];
        
        while(ipNode)
        {
            tempIP = ipNode->next;
            DestroyIPNode(ipNode);
            ipNode = tempIP;
            
#ifdef IPFRAG_DEBUG
            m_ipCount--;
#endif
        }
        m_hashIPTable[j] = 0;
    }
    //A10DBG("After ~CIP_Fragment: m_ipCount = %d\n",m_ipCount);
}


/*==============================================================================
* Function      :   CIP_Fragment::ProcessIP
* Description       :   ip defrag处理过程，CIP_Fragment类对外接口
* Return        :   error number 
* Parament      :   
* Comments      :  
*=============================================================================*/

#define IPV4_HDR_MF_SHIFT   13
#define IPV4_HDR_MF_FLAG    (1 << IPV4_HDR_MF_SHIFT)
#define IPV4_HDR_OFFSET_MASK    ((1 << IPV4_HDR_MF_SHIFT) - 1)

int CIP_Fragment::ProcessIP(ipPkt* tcpipFilterContext)
{
#ifdef IPFRAG_DEBUG
    CheckTimeoutList();
#endif
    if(NULL == tcpipFilterContext->pIp || tcpipFilterContext->ipHeadLen < 20 || tcpipFilterContext->macLen > 65535)
    {
        tcpipFilterContext->nError = ERROR_IP;
        return DO_NOT_NEED_FRAGMENT;
    }

    struct iphdr *iph = (struct iphdr *)(tcpipFilterContext->pIp);

    bool isNeedDefrag = false;

    uint16_t flag_offset = ntohs(iph->frag_off);

    uint16_t ip_ofs = (uint16_t)(flag_offset & IPV4_HDR_OFFSET_MASK);
    uint16_t ip_flag = (uint16_t)(flag_offset & IPV4_HDR_MF_FLAG);

    if( ip_flag != 0 || ip_ofs  != 0)
    {        
        isNeedDefrag = true;
    }

    if (iph->frag_off & htons(IP_MF|IP_OFFSET))
    {
        isNeedDefrag = true;
        tcpipFilterContext = DefragIP(tcpipFilterContext);
    }

#ifdef IPFRAG_DEBUG
    CheckTimeoutList();
#endif
    if (isNeedDefrag)
    {
        return NEED_FRAGMENT;
    }
    else
    {
        return DO_NOT_NEED_FRAGMENT;
    }
}


/*==============================================================================
* Function      :   CIP_Fragment::DecompIP
* Description       :   IP解压缩
* Return        :   IP内包含的上层协议类型
* Parament      :   
* Comments      :  
*=============================================================================*/
ipPkt *CIP_Fragment::DefragIP(ipPkt *tcpipFilterContext)
{
    ipPkt *ret = NULL;
    IPNode *pNode = NULL;

    pNode = FindIPNode(tcpipFilterContext);
    if(NULL == pNode)
    {
        tcpipFilterContext->nError = ERROR_IP;
        return tcpipFilterContext;
    }
    
    IPPacket *ipPacket = NULL;
    ipPacket = CreateIPPacket(tcpipFilterContext);
    if(ipPacket == NULL)
    {
        FreeNodefromTable(pNode);
        tcpipFilterContext->nError = ERROR_IP;
        return tcpipFilterContext;
    }
    
    QueueIPFrag(pNode, ipPacket);

    /*
    //2016-8-25 phl 
    if(tcpipFilterContext->bReleaseiph)//说明已经在别的层重组过ip碎片了
    {
            tcpipFilterContext->bReleaseiph = false;
    }
    */
    
    if (pNode->last_in == (FIRST_IN|LAST_IN) && pNode->meat == pNode->len)
    {
        ret = ReasmIPFrag(pNode, tcpipFilterContext);
        FreeNodefromTable(pNode);
        return ret;
    }

    /*
#ifdef A10_SHOW_PACKET
    IPPacket* packet = ipListHead;
    while(packet != NULL)
    {
        printf("IP: packet->seqNum = %d, packet->len = %d\n",packet->seqNum, packet->len);
        printf("IP: packet->payload:\n");
        for(int i=0;i<packet->len;i++)
        {
            printf("%x ",packet->ipPacket[i]);
        }
        printf("\n");
        packet = packet->next;
    }
#endif  
    */
    tcpipFilterContext->nError = ERROR_IP;
    return tcpipFilterContext;
}


/*==============================================================================
* Function      :   CIP_Fragment::QueueIPFrag
* Description       :   在hash链表中查找IPNode
* Return        :   IPNode* 
* Parament      :   
* Comments      :  
*=============================================================================*/
void CIP_Fragment::QueueIPFrag(IPNode *qp, IPPacket *skb)
{
    struct IPPacket *prev, *next;
    int flags, offset;
    int ihl, end, tmplen;
    struct iphdr *iph = (struct iphdr *)(skb->ipPacket);
    UCHAR *tmppkt = skb->ipPacket;

    //if (qp->last_in & COMPLETE)
    //  goto err;

    offset = ntohs(iph->frag_off);
    flags = offset & ~IP_OFFSET;
    offset &= IP_OFFSET;
    offset <<= 3;       /* offset is in 8-byte chunks */
    ihl = iph->ihl << 2;
    
    if(ihl > MAX_IPHEADER_LEN)
    {
        goto err;
    }

    /* Determine the position of this fragment. */
    end = offset + skb->len - ihl;

    /* Is this the final fragment? */
    if ((flags & IP_MF) == 0) {
        /* If we already have some bits beyond end
         * or have different end, the segment is corrrupted.
         */
        if (end < qp->len ||
            ((qp->last_in & LAST_IN) && end != qp->len))
            goto err;
        qp->last_in |= LAST_IN;
        qp->len = end;
    } else {
        if (end&7) {
            end &= ~7;
        }
        if (end > qp->len) {
            /* Some bits beyond end -> corruption. */
            if (qp->last_in & LAST_IN)
                goto err;
            qp->len = end;
        }
    }
    if (end == offset)
        goto err;

    //if (pskb_pull(skb, ihl) == NULL)
    //  goto err;
    //if (pskb_trim(skb, end-offset))
    //  goto err;

    /*
     * Drop off the filled data in the packet tail 
     */
    tmplen = end - offset;
    if(tmplen >= (int)(skb->len))
        goto err;
    skb->len = tmplen;
    skb->ipPacket += ihl;

    /* Find out which fragments are in front and at the back of us
     * in the chain of fragments so far.  We must know where to put
     * this fragment, right?
     */
    prev = NULL;
    for(next = qp->fragments; next != NULL; next = next->next) {
        if (next->offset >= offset)
            break;  /* bingo! */
        prev = next;
    }

    /* We found where to put this one.  Check for overlap with
     * preceding fragment, and, if needed, align things so that
     * any overlaps are eliminated.
     */
    if (prev) {
        int i = (prev->offset + prev->len) - offset;

        if (i > 0) {
            offset += i;
            if (end <= offset)
                goto err;
            if (!pskb_pull(skb, i))
                goto err;
        }
    }

    while (next && next->offset < end) {
        int i = end - next->offset; /* overlap is 'i' bytes */

        if (i < (int)(next->len)) {
            /* Eat head of the next overlapped fragment
             * and leave the loop. The next ones cannot overlap.
             */
            if (!pskb_pull(next, i))
                goto err;
            next->offset += i;
            qp->meat -= i;
            break;
        } else {
            struct IPPacket *free_it = next;

            /* Old fragmnet is completely overridden with
             * new one drop it.
             */
            next = next->next;

            if (prev)
                prev->next = next;
            else
                qp->fragments = next;

            qp->meat -= free_it->len;
            DestroyIPPacket(free_it);
        }
    }

    skb->offset = offset;

    /* Insert this fragment in the chain of fragments. */
    skb->next = next;
    if (prev)
        prev->next = skb;
    else
        qp->fragments = skb;

    qp->timeStamp = skb->timeStamp;
    AddTimeoutNode(qp);
    
    qp->meat += skb->len;
    //atomic_add(skb->truesize, &ip_frag_mem);
    if (offset == 0) {
        qp->last_in |= FIRST_IN;
        memcpy(qp->ipHeader, tmppkt, ihl);
        qp->ipHeaderLen = ihl;
    }

    return;

err:
    //kfree_skb(skb);
    DestroyIPPacket(skb);
}


/*==============================================================================
* Function      :   CIP_Fragment::QueueIPFrag
* Description   :  
* Return        :  
* Parament      :   
* Comments      :  
*=============================================================================*/
ipPkt *CIP_Fragment::ReasmIPFrag(IPNode *qp, ipPkt *skb)
{
    struct iphdr *iph;
    struct IPPacket *fp, *head = qp->fragments;
    int len;
    int ihlen = 0 ;
    int offset;
    UCHAR *packet = NULL;
    int memLen = 0 ;

    assert(head != NULL);
    assert(head->offset == 0);

    /* Allocate a new buffer for the datagram. */
    ihlen = qp->ipHeaderLen;
    if(ihlen > MAX_IPHEADER_LEN)
    {
        goto out_oversize;
    }
    len = ihlen + qp->len;

    if(len > 65535)
        goto out_oversize;

    /* Head of list must not be cloned. */
//  packet = CreateBuff();
    memLen = ihlen ;
    for (fp=head; fp; fp = fp->next) { 
        memLen += fp->len;
    } 
    //packet = (UCHAR*)MMalloc(MID_CIP_FRAGMENT_REASMIPFRAG , memLen);
    packet = (UCHAR*)malloc( memLen);

    if (!packet)
        goto out_nomem;
    
    /* Copy the original IP headers into the new buffer. */ 
    memcpy(packet, &(qp->ipHeader), ihlen); 
    offset = ihlen;
    
    /* Copy the data portions of all fragments into the new buffer. */ 
    for (fp=head; fp; fp = fp->next) { 
        memcpy(packet+offset, fp->ipPacket, fp->len); 
        offset += fp->len;
    } 
    
    /* Done with all fragments. Fixup the new IP header. */ 
    iph = (struct iphdr *)packet; 
    iph->frag_off = 0; 
    iph->tot_len = htons(len); 

    skb->ipFragment(qp->len,(char*) packet);

#ifdef IPFRAG_DEBUG
    ipfragToIPCount++;
#endif
    
    return skb; 

out_nomem: 
    goto out_fail; 
out_oversize: 
out_fail: 
    if(packet)
    {
        //MFree(packet);
        free(packet);
    }
    skb->nError = ERROR_IP;
    return skb; 
}


IPNode *CIP_Fragment::FindIPNode(ipPkt *tcpipFilterContext)
{
    struct iphdr *iph = (struct iphdr *)const_cast<char *>(tcpipFilterContext->pIp);
    UINT16 id = iph->id;
    UINT32 saddr = iph->saddr;
    UINT32 daddr = iph->daddr;
    UCHAR  protocol = iph->protocol;
    UINT16 hash = ipqhashfn(id, saddr, daddr, protocol);
    IPNode *pNode = NULL;

    for(pNode = m_hashIPTable[hash]; pNode; pNode = pNode->next)
    {
        if(pNode->id == id      &&
           pNode->saddr == saddr    &&
           pNode->daddr == daddr    &&
           pNode->protocol == protocol)
        {
            return pNode;
        }
    }
    
    pNode = CreateIPNode(hash, tcpipFilterContext);
    if(pNode == NULL)
    {
        return NULL;
    }

    pNode->timeStamp=nCurTime;
    AddTimeoutNode(pNode);

#ifdef IPFRAG_DEBUG
        CheckHashTable();
#endif

    return pNode;
}


inline IPNode* CIP_Fragment::CreateIPNode(UINT16 hash, ipPkt *tcpipFilterContext)
{
    //IPNode* pNode = (IPNode* )MMalloc(MID_CIP_FRAGMENT_CREATEIPNODE , sizeof(IPNode));
    IPNode* pNode = (IPNode* )malloc(sizeof(IPNode));
        if (NULL == pNode)
        {
                return NULL;
        }
        memset(pNode , 0 , sizeof(IPNode));
    
#ifdef IPFRAG_DEBUG
        m_ipCount++;
#endif

    struct iphdr *iph = (struct iphdr *)const_cast<char *>(tcpipFilterContext->pIp);
    pNode->id = iph->id;
    pNode->saddr = iph->saddr;
    pNode->daddr = iph->daddr;
    pNode->protocol = iph->protocol;

    //将节点加到哈希链表头
        pNode->next = m_hashIPTable[hash];
        m_hashIPTable[hash] = pNode;

#ifdef IPFRAG_DEBUG
        CheckHashTable();
#endif

        return pNode;
}


inline void CIP_Fragment::DestroyIPNode(IPNode* pNode)
{
    IPPacket *tmpPacket = NULL;
    while(pNode->fragments != NULL)
    {
        tmpPacket = pNode->fragments;
        pNode->fragments = pNode->fragments->next;
        DestroyIPPacket(tmpPacket);
    }
    pNode->fragments = NULL;
    //MFree(pNode);
    free(pNode);
}


inline IPPacket* CIP_Fragment::CreateIPPacket(ipPkt *tcpipFilterContext)
{
    //新建packet节点
    //IPPacket *ipPacket = (IPPacket *)MMalloc(MID_CIP_FRAGMENT_CREATEIPPACKET , sizeof(IPPacket));
    IPPacket *ipPacket = (IPPacket *)malloc(sizeof(IPPacket));
    
    if(NULL == ipPacket)
    {
        return NULL;
    }
    memset(ipPacket, 0, sizeof(IPPacket));
    
    ipPacket->len = ntohs(((struct iphdr *)const_cast<char *>(tcpipFilterContext->pIp))->tot_len);
    if(0 == ipPacket->len || ipPacket->len > 65535 || ipPacket->len > (UINT32)( tcpipFilterContext->macLen) )
    {
        //MFree(ipPacket);
        free(ipPacket);
        return NULL;
    }
    
    //ipPacket->data = (UCHAR *)MMalloc(MID_CIP_FRAGMENT_CREATEIPPACKET , ipPacket->len);
    ipPacket->data = (UCHAR *)malloc( ipPacket->len);
    if(NULL == ipPacket->data)
    {
        //MFree(ipPacket);
        free(ipPacket);
        return NULL;
    }
    ipPacket->ipPacket = ipPacket->data;
    memcpy(ipPacket->ipPacket, tcpipFilterContext->pIp, ipPacket->len);
    ipPacket->timeStamp = nCurTime;
    
    return ipPacket;
}


inline void CIP_Fragment::DestroyIPPacket(IPPacket* ipPacket)
{
    if(ipPacket)
    {
        if(ipPacket->data)
        {
            //MFree(ipPacket->data);
            free(ipPacket->data);
            ipPacket->data = NULL;
        }
        //MFree(ipPacket);
        free(ipPacket);
    }
}


void CIP_Fragment::CheckIPTimeout()
{
#ifdef IPFRAG_DEBUG
        CheckHashTable();
        CheckTimeoutList();
#endif
    
    IPNode *pNode = m_nodeTimeHead;
    IPNode *tmpNode = NULL;
    
    //从超时链表头开始检查超时
    while(pNode != NULL)
    {
        if(pNode->CheckTimeout())
        {
            tmpNode = pNode;
            pNode = pNode->nextTimeout;
            FreeNodefromTable(tmpNode);
        }
        else
        {
            return;
        }
    }
    
#ifdef IPFRAG_DEBUG
        CheckHashTable();
        CheckTimeoutList();
#endif
    
}


void CIP_Fragment::FreeNodefromTable(IPNode *pNode)
{
#ifdef IPFRAG_DEBUG
    CheckHashTable();
    CheckTimeoutList();
#endif


    if ( pNode == NULL )
    {
        printf("error,FreeNodefromTable pNode is NULL.\r\n");
        return;
    }

    //计算当前节点对应的哈希值
    UINT16 nHash = ipqhashfn(pNode->id, pNode->saddr, pNode->daddr, pNode->protocol);
    IPNode *pPre = NULL;
    IPNode *pNext = m_hashIPTable[nHash];

    if ( pNext == NULL )
    {
        printf("error,FreeNodefromTable pNext is NULL - first get.\r\n");
        return;
    }

    //从哈希链表中取出传入节点
    if (pNext == pNode)
    {
        m_hashIPTable[nHash] = pNext->next;
    }
    else
    {
        while(pNext != pNode)
        {
            pPre = pNext;
            pNext = pNext->next;

            // by rongjie
            if ( pNext == NULL )
            {
                printf("error,FreeNodefromTable pNext is NULL - second use.\r\n");
                //DUMPERRLOG("warn", 0, "a10decode", "CA10Decode", "FreeNodefromTable", "pNext is NULL - second use");
                return;
            }
        }
        pPre->next= pNext->next;
    }

#ifdef IPFRAG_DEBUG
        //当前连接数减一
        m_ipCount--;
#endif
    
    //从当前超时链表中取出节点
    RmTimeoutNode(pNode);

    DestroyIPNode(pNode);

#ifdef IPFRAG_DEBUG
    CheckHashTable();
    CheckTimeoutList();
#endif

}


/*==============================================================================
* Function      :   CIP_Fragment::RmTimeoutNode
* Description       :   将节点IPNode的超时链表中删除
* Return        :   void 
* Parament      :   
* Comments      :  
*=============================================================================*/
inline void CIP_Fragment::RmTimeoutNode(IPNode *pNode)
{
    assert(pNode);

    if((pNode->preTimeout == NULL && pNode->nextTimeout == NULL && pNode != m_nodeTimeHead))
    {
        return;
    }

    //从当前超时链表中取出节点
    if(pNode == m_nodeTimeTail)
    {
        m_nodeTimeTail = pNode->preTimeout;
        if(m_nodeTimeTail)
            m_nodeTimeTail->nextTimeout = NULL;
        else
            m_nodeTimeHead =  NULL;
    }
    else if(pNode == m_nodeTimeHead)
    {
        m_nodeTimeHead = pNode->nextTimeout;
        m_nodeTimeHead->preTimeout = NULL;
    }
    else
    {
        pNode->preTimeout->nextTimeout = pNode->nextTimeout;
        pNode->nextTimeout->preTimeout = pNode->preTimeout;
    }

    pNode->preTimeout = pNode->nextTimeout = NULL;

}


/*==============================================================================
* Function      :   CIP_Fragment::AddTimeoutNode
* Description       :   将节点添加到IPNode的超时链表
* Return        :   void 
* Parament      :   
* Comments      :  
*=============================================================================*/
void CIP_Fragment::AddTimeoutNode(IPNode *pNode)
{
    assert(pNode);
    
    //如果该节点已在原超时链表中
    RmTimeoutNode(pNode);

    //将节点加到超时链表尾
    if(m_nodeTimeHead != NULL)
    {
        m_nodeTimeTail->nextTimeout = pNode;
        pNode->nextTimeout = NULL;
        pNode->preTimeout = m_nodeTimeTail;
        m_nodeTimeTail = pNode;
    }
    else
    {
        m_nodeTimeHead = m_nodeTimeTail = pNode;
        pNode->preTimeout = pNode->nextTimeout = NULL;
    }

#ifdef IPFRAG_DEBUG
    CheckTimeoutList();
#endif
#ifdef IPFRAG_DEBUG
    CheckHashTable();
#endif

}

#if 0
static int Compar(const void* a, const void* b)
{
    IPNode* aa = (IPNode*)a;
    IPNode* bb = (IPNode*)b;

    if(aa->seqNum > bb->seqNum) return 1;
    if(aa->seqNum == bb->seqNum) return 0;
    if(aa->seqNum < bb->seqNum) return -1;
}


void CIP_Fragment::DelLongNode()
{
    IPNode *node = NULL, *temp = NULL;
    int i=0, j=0;
    memset(&m_qsortArray, 0, USER_NUM*sizeof(IPNode *));
    
    for (i=0; i<IPQ_HASHSZ; i++)
    {
        node = (IPNode*)m_hashIPTable[i];

        while(node)
        {
            temp = node->next;
            m_qsortArray[j] = node;
            if(j < USER_NUM-1)
            {
                j++;
            }
            else
            {
                break;
            }
            node = temp;
        }
    }
    
    qsort(m_qsortArray, USER_NUM, sizeof(IPNode *), Compar);

    for(i=USER_NUM-1; i>0; i--)
    {
        FreeNodefromTable(m_qsortArray[i], true);
        
        bool lowerFlag = (float)(g_pA10MemManager->GetAllocedMemSize()) / (g_nA10MemSize*1000000) >= MEM_LOWER_LIMIT;
        if(!lowerFlag)
        {
            break;
        }
    }
    
}
#endif



