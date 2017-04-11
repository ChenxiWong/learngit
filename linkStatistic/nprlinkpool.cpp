/*=========================================================
*   File name   ��  linkpool.cpp
*   Authored by ��  daihw,wanyl
*   Date        ��  2005-3-24 20:38:45
*   Description ��  
*
*   Modify      ��  
*=========================================================*/


#include "nprlinkpool.h"
#include "linkstream.h"


nprLinkPool::nprLinkPool()
{   
    memset(m_streamTable, 0, sizeof(m_streamTable));
    //m_nTimeout = 60;    
    m_nMaxLink = 0;     //���������
    m_nCurLink = 0;     //��ǰ������

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
    //����ҵ��ڵ�ӵ�ǰ���ӵ���ʱ����β
    if(pLink)
    {
        if(pLink == m_pStreamTail)
        {
            return pLink; 
        }
        
        if(pLink == m_pStreamCacheClearHead)
        {
            //����������ͷ����
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
    //�����ϣֵ
    UINT32 nHash = Hash(ConnectAddr);
    //������Ӧ�Ĺ�ϣ����
    for(pLink = m_streamTable[nHash]; pLink!=NULL; pLink = pLink->m_pNext)
    {       
        //�Ƚ����ӵ���Ԫ����CLink�е���Ԫ�飬��Ԫ��������ҵ���Ԫ���ж�Ӧ�Ľڵ�
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


    //��¼����������ǰ
    m_nCurLink++;
    //��¼���������
    if (m_nCurLink  > m_nMaxLink) 
    {
        m_nMaxLink = m_nCurLink;
    }
    
    //�������ӵ���Ԫ�����ϣֵ
    UINT32  nHash = Hash(ConnectAddr);
    //��������Ľڵ���ӵ�����ͷ
    pLink->m_pNext = m_streamTable[nHash];
    m_streamTable[nHash] = pLink;
    
    //�ӵ�ǰ���ӵ���ʱ����β
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
        //����������ͷ
        m_pStreamCacheClearHead = pLink;
    }    
    pLink->m_nFourHash = nHash;
    TRACE_MAX("info,sNewConnect pthread_self=%lu m_linkId[%d] m_nCurLink=%llu.\r\n",
        pthread_self(),pLink->m_linkId,m_nCurLink);
    pLink->basicOut();
    //���ؽڵ�ָ��
    return pLink;

}



void nprLinkPool::sCloseConnect(linkStream *pLink)
{
    
    if ( pLink == NULL )
    {
        printf("error,nprLinkPool::sCloseConnect,pLink is NULL.\r\n");
        return;
    }


    //��ǰ��������һ
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

    //�ӹ�ϣ������ȡ������ڵ�
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
        //����������ͷ����
        m_pStreamCacheClearHead = pLink->m_pNextTimeout;
    }
        
    //�ӵ�ǰ��ʱ������ȡ���ڵ�
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
    //ɾ���ڵ�
    delete pLink;

}


void nprLinkPool::sCheckTimeout( UINT32 nCur )
{
    //������ʱ����ɾ����ʱ�ڵ�
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
                //����������ͷ����
                m_pStreamCacheClearHead = pTemp;
            }
            sCloseConnect(pLink);
            m_pStreamHead = pTemp;
            m_pStreamHead->m_pPreTimeout = NULL;
            if(pLink == m_pStreamTail)
            {
                 m_pStreamTail =NULL;
            }
            //��ʱ�����޶�3����
            //�����ʱ
            //���½������ݰ�ӵ��
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
    {    //����,�ӳ�����ͷ��ʼ
        if(NULL ==m_pStreamCacheClearHead )
        {
            m_pStreamCacheClearHead= m_pStreamHead;
            printf("error,sCheckTimeout m_pStreamCacheClearHead is NULL.\r\n");
        }
        pLink = m_pStreamCacheClearHead;
        //timeoutlink �����ۼ�;
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
    //���ڵ�ӵ���ϣ����ͷ
    pLink->m_pNext = m_streamTable[nHash];
    m_streamTable[nHash] = pLink;

    return pLink;
}





/*==========================================================
* Function      : CLinkPool::Close
* Description   : 
* Return        : void
* Parament      : 
* Comments      : ɾ�����е���Ԫ�����Ӷ����ͷ���Դ
*=========================================================*/
void    nprLinkPool::Close()
{
    linkStream *pTemp1,*pTemp2;
    //�������й�ϣ����ɾ�����еĽڵ�
    for(int i= 0; i<MAX_LINKHASH_SIZE; i++)
    {
        pTemp1 = m_streamTable[i];
        while(pTemp1)
        {   
            //ɾ�������ϵĽڵ�          
            pTemp2 = pTemp1;
            pTemp1 = pTemp1->m_pNext;
            //modified by lzr for rpc 
            sCloseConnect(pTemp2);
            //delete pTemp2;
        }
        //��չ�ϣ����ͷ
        m_streamTable[i] = NULL;
    }

    //��ʱָ�븽��
    m_pStreamTail = m_pStreamHead = NULL;

}




/*==========================================================
* Function      : nprLinkPool::GetMaxLink
* Description   : 
* Return        : void
* Parament      : 
* Comments      :�������������
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
* Comments      :���ص�ǰ������
*=========================================================*/
UINT64 nprLinkPool::GetCurLink()
{
    return  m_nCurLink; 
}




