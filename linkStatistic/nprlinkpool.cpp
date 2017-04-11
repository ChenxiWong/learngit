/*=========================================================
*   File name   ：  linkpool.cpp
*   Authored by ：  daihw,wanyl
*   Date        ：  2005-3-24 20:38:45
*   Description ：  
*
*   Modify      ：  
*=========================================================*/


#include "nprlinkpool.h"
#include "linkstream.h"


nprLinkPool::nprLinkPool()
{   
    memset(m_streamTable, 0, sizeof(m_streamTable));
    //m_nTimeout = 60;    
    m_nMaxLink = 0;     //最大连接数
    m_nCurLink = 0;     //当前连接数

    m_pStreamHead =NULL;
    m_pStreamTail =NULL;
    m_pStreamCacheClearHead=NULL;

    m_nTcpOrUdp = 0xffffffff;
    m_bDecodeOpen=0;
}

//added by gchen@1010-04-22 for ip rules stat
void nprLinkPool::SetLinkPoolType(int iTcpOrUdp)
{
    m_nTcpOrUdp = iTcpOrUdp;
}


nprLinkPool::~nprLinkPool()
{
    //
    //do something;
}






linkStream* nprLinkPool::moveTimeoutTail(linkStream * pLink)
{
    //如果找到节点加当前链接到超时链表尾
    if(pLink)
    {
        if(pLink == m_pStreamTail)
        {
            return pLink; 
        }
        
        if(pLink == m_pStreamCacheClearHead)
        {
            //清理缓冲链表头更新
            m_pStreamCacheClearHead = pLink->m_pNextTimeout;
        }
        if(pLink == m_pStreamHead)
        {
            m_pStreamHead = pLink->m_pNextTimeout;
            m_pStreamHead->m_pPreTimeout = NULL;
        }
        else
        {
            pLink->m_pPreTimeout->m_pNextTimeout = pLink->m_pNextTimeout;
            pLink->m_pNextTimeout->m_pPreTimeout = pLink->m_pPreTimeout;
        }
        m_pStreamTail->m_pNextTimeout = pLink;
        pLink->m_pNextTimeout = NULL;
        pLink->m_pPreTimeout = m_pStreamTail;
        m_pStreamTail = pLink;
        return pLink;   
    }
    return NULL;
}


linkStream* nprLinkPool::sFindConnect(const IP4ConnectAddr& ConnectAddr,uint8_t & flow)
{
    linkStream *pLink =NULL;
    //计算哈希值
    UINT32 nHash = Hash(ConnectAddr);
    //查找相应的哈希链表
    for(pLink = m_streamTable[nHash]; pLink!=NULL; pLink = pLink->m_pNext)
    {       
        //比较连接的四元组于CLink中的四元组，四元组相等则找到四元组中对应的节点
        flow =  pLink->isSameLink( ConnectAddr);
        if(FLOW_NULL !=flow)
        {
            break;
        }       
    }
    
   return pLink;    
}


linkStream *     nprLinkPool::sNewConnect( const IP4ConnectAddr& ConnectAddr)
{
    linkStream *pLink = new linkStream(ConnectAddr);  
    pLink->m_bAppLinkOpen = m_bDecodeOpen;


    //记录连接数，当前
    m_nCurLink++;
    //记录最大连接数
    if (m_nCurLink  > m_nMaxLink) 
    {
        m_nMaxLink = m_nCurLink;
    }
    
    //根据连接的四元计算哈希值
    UINT32  nHash = Hash(ConnectAddr);
    //将新申请的节点添加到链表头
    pLink->m_pNext = m_streamTable[nHash];
    m_streamTable[nHash] = pLink;
    
    //加当前链接到超时链表尾
    if(m_pStreamHead != NULL)
    {
        m_pStreamTail->m_pNextTimeout = pLink;
        pLink->m_pNextTimeout = NULL;
        pLink->m_pPreTimeout = m_pStreamTail;
        m_pStreamTail = pLink;        
    }
    else
    {
        m_pStreamHead =  pLink;
        m_pStreamTail = pLink;     
        //清理缓冲链表头
        m_pStreamCacheClearHead = pLink;
    }    
    pLink->m_nFourHash = nHash;
    TRACE_MAX("info,sNewConnect pthread_self=%lu m_linkId[%d] m_nCurLink=%llu.\r\n",
        pthread_self(),pLink->m_linkId,m_nCurLink);
    pLink->basicOut();
    //返回节点指针
    return pLink;

}



void nprLinkPool::sCloseConnect(linkStream *pLink)
{
    
    if ( pLink == NULL )
    {
        printf("error,nprLinkPool::sCloseConnect,pLink is NULL.\r\n");
        return;
    }


    //当前连接数减一
    //if(m_nCurLink > 0)
    m_nCurLink--;
    
    linkStream *pPre;
    linkStream *pNext = m_streamTable[pLink->m_nFourHash];

    // by rongjie
    if ( pNext == NULL )
    {
        printf("error,nprLinkPool::sCloseConnect,pNext is NULL - first get.\r\n");
        return;
    }

    //从哈希链表中取出传入节点
    if (pNext == pLink)
    {
        m_streamTable[pLink->m_nFourHash] = pNext->m_pNext;
    }
    else
    {
        while(pNext != pLink)
        {
            pPre = pNext;
            pNext = pNext->m_pNext;

            // by rongjie
            if ( pNext == NULL )
            {
                printf("error,nprLinkPool::sCloseConnect,pNext is NULL - second use.\r\n");
                return;
            }
        }
        pPre->m_pNext = pNext->m_pNext;
    }
    
        
    if(pLink == m_pStreamCacheClearHead)
    {
        //清理缓冲链表头更新
        m_pStreamCacheClearHead = pLink->m_pNextTimeout;
    }
        
    //从当前超时链表中取出节点
    if(pLink == m_pStreamTail)
    {
        m_pStreamTail = pLink->m_pPreTimeout;
        if(m_pStreamTail)
            m_pStreamTail->m_pNextTimeout = NULL;
        else
            m_pStreamHead =  NULL;
    }
    
    else if(pLink == m_pStreamHead)
    {
        m_pStreamHead = pLink->m_pNextTimeout;
        m_pStreamHead->m_pPreTimeout = NULL;
    }
    else
    {
        pLink->m_pPreTimeout->m_pNextTimeout = pLink->m_pNextTimeout;
        pLink->m_pNextTimeout->m_pPreTimeout = pLink->m_pPreTimeout;
    }
    TRACE("info,sCloseConnect m_linkId[%4d] m_nCurLink=%llu .\r\n"
        ,pLink->m_linkId,m_nCurLink);
    //删除节点
    delete pLink;

}


void nprLinkPool::sCheckTimeout( UINT32 nCur )
{
    //遍历超时链表，删除超时节点
    linkStream*pLink = m_pStreamHead;
    linkStream *pTemp;  

    int timeoutlink=0;

    while(pLink)
    { 
        pTemp = pLink->m_pNextTimeout;
        if (  pLink->checkTimeout(nCur) )
        {        
            if(m_pStreamCacheClearHead == pLink)
            {
                //清理缓冲链表头更新
                m_pStreamCacheClearHead = pTemp;
            }
            sCloseConnect(pLink);
            m_pStreamHead = pTemp;
            m_pStreamHead->m_pPreTimeout = NULL;
            if(pLink == m_pStreamTail)
            {
                 m_pStreamTail =NULL;
            }
            //超时处理限定3个，
            //避免耗时
            //导致接入数据包拥塞
            timeoutlink++;
            if(timeoutlink > 2)
            {
                break;
            }
        }
        else
        {
            break;
        }
        pLink = pTemp;
    }


    if(tcpReassembly::bTcpSeqSameCache)
    {    //清理缓,从冲链表头开始
        if(NULL ==m_pStreamCacheClearHead )
        {
            m_pStreamCacheClearHead= m_pStreamHead;
            printf("error,sCheckTimeout m_pStreamCacheClearHead is NULL.\r\n");
        }
        pLink = m_pStreamCacheClearHead;
        //timeoutlink 继续累加;
        while(pLink)
        { 
            pTemp = pLink->m_pNextTimeout;
            if (  pLink->cacheTimeout(nCur) )
            {                    
                pLink = pTemp;
                timeoutlink++;
                if(timeoutlink > 5)
                {
                    break;
                }
            }
            else
            {
                break;
            } 
        }
    }
}


linkStream * nprLinkPool::sAddConnect(linkStream *pLink, const IP4ConnectAddr& ConnectAddr)
{

    UINT32 nHash = Hash(ConnectAddr);
    //将节点加到哈希链表头
    pLink->m_pNext = m_streamTable[nHash];
    m_streamTable[nHash] = pLink;

    return pLink;
}





/*==========================================================
* Function      : CLinkPool::Close
* Description   : 
* Return        : void
* Parament      : 
* Comments      : 删除所有的四元组连接对象，释放资源
*=========================================================*/
void    nprLinkPool::Close()
{
    linkStream *pTemp1,*pTemp2;
    //遍历所有哈希链表，删除所有的节点
    for(int i= 0; i<MAX_LINKHASH_SIZE; i++)
    {
        pTemp1 = m_streamTable[i];
        while(pTemp1)
        {   
            //删除链表上的节点          
            pTemp2 = pTemp1;
            pTemp1 = pTemp1->m_pNext;
            //modified by lzr for rpc 
            sCloseConnect(pTemp2);
            //delete pTemp2;
        }
        //清空哈希数组头
        m_streamTable[i] = NULL;
    }

    //超时指针附空
    m_pStreamTail = m_pStreamHead = NULL;

}




/*==========================================================
* Function      : nprLinkPool::GetMaxLink
* Description   : 
* Return        : void
* Parament      : 
* Comments      :返回最大连接数
*=========================================================*/
UINT64 nprLinkPool::GetMaxLink()
{
    return  m_nMaxLink; 
}

/*==========================================================
* Function      : nprLinkPool::GetMaxLink
* Description   : 
* Return        : void
* Parament      : 
* Comments      :返回当前连接数
*=========================================================*/
UINT64 nprLinkPool::GetCurLink()
{
    return  m_nCurLink; 
}




