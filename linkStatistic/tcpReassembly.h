///////////////////////////////////////////////////////////
//  tcpReassembly.h
//  Implementation of the Class tcpReassembly
//  Created on:      15-ʮ��-2015 14:08:37
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
    //ͨ�����캯������
    tcpReassemblyLock( pthread_mutex_t & mutex): m_mutex(mutex)  
    {
            pthread_mutex_lock(&m_mutex);
    }
    //ͨ��������������
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
    //Ҫ��ȡ�����İ���ţ�-1Ϊ��ָ��
    int m_packetNum;
    //�����ֶε�ƫ��ֵ��>0 �Ӱ�ͷ��ʼ��<0 �Ӱ�β��ʼ
    int m_offSize;
    //�����ֶεĳ���
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
 * �����httpԭʼ����
 */
class tcpReassembly
{
public: 
    /**
     * ������Ч���غɣ�ȥ�غ��
     */
    int m_payLoadLen;
    /**
     * ������Ч���غɳ���ƽ����
     */
    int m_payLoadSumSquares;
    
    /**
     * �������غɣ�ȥ�غ�İ�����
     */
    int m_payLoadPktSum;    

    
    //��¼�ʼ�ĸ��ذ���Ϣ�����ֵ/
    unsigned short  m_headPayLoadInfoMax;
    //��¼�ʼ�İ���Ϣ:������/
    //unsigned short  m_payLoadPktLen[MAX_HEADPKT_INFO];
    vector<unsigned short>  m_payLoadPktLen;    
    //��¼�ʼ�İ���Ϣ:��������id/
    //unsigned int  m_payLoadPktLinkId[MAX_HEADPKT_INFO];
    vector<unsigned int>  m_payLoadPktLinkId;
    //��¼�ʼ�İ���Ϣ:������id/
    //unsigned int  m_payLoadPktStreamId[MAX_HEADPKT_INFO];
    vector<unsigned int>  m_payLoadPktStreamId;

    
    //�������غɣ�ȥ�غ�İ�����/
    int m_zeroLenPktSum;    
    //��¼�ʼ�ķǸ��ذ���Ϣ�����ֵ/
    unsigned short  m_headZeroLenInfoMax;
    //��¼�ʼ�İ���Ϣ:��������id/
    //unsigned int  m_zeroLenPktLinkId[MAX_HEADPKT_INFO];
    vector<int>  m_zeroLenPktLinkId;
    //��¼�ʼ�İ���Ϣ:������id/
    //unsigned int  m_zeroLenPktStreamId[MAX_HEADPKT_INFO];
    vector<int>  m_zeroLenPktStreamId;

    
    //��������������������Ϊ PORPERTY_STREAM_MAX_ELEMENT
    short int m_porpertyDone;
    //ÿ���������İ���
    //INT16 m_porpertyPktNum[PORPERTY_STREAM_MAX_ELEMENT];
    vector<short int>  m_porpertyPktNum;
    //ÿ������������
    //INT16 m_porpertyLen[PORPERTY_STREAM_MAX_ELEMENT];
    vector<short int>  m_porpertyLen;
    //ÿ����������ƫ��ֵ������0��ͷ��ʼ��С��0��β����ʼ
    //short int m_porpertyOffsize[PORPERTY_STREAM_MAX_ELEMENT];
    vector<short int>  m_porpertyOffsize;
    //ÿ��������
    //char m_porperty[PORPERTY_STREAM_MAX_ELEMENT][PORPERTY_MAXLEN];   
    vector<char *>  m_porperty;
    
    
    //���ݰ��ܳ���,��Ч��ë����
    //�ش����ڼ���
    int m_macLen;

    //��·������ͷָ��
    char *m_pMacBuf;
    
    //tcp�����ش��Ȼ������ͷָ��
    ipPkt * head;
    //tcp�����ش��Ȼ������βָ��
    ipPkt * tail;
    
    //tcp�����ش��Ȼ�����а�����    
    UINT32 cacheSum;    
    //tcp�����ش��Ȼ�����а������������ֵ
    static UINT32 cacheSumMax;    
    //tcp�����ش��Ȼ�����а�������趨ֵ
    static UINT32 cacheSumMaxSetting;    
    //tcp��������ݴ�� seq���
    static UINT32 seqJumpMaxSetting;     
    //tcp��������ݴ�������
    static UINT32 seqJumpSumMax;       
    //tcp�����Ѿ����ֵ��ݴ�������
    UINT32 m_seqJumpSum;             
    //tcp�����Ѿ����ֵ��ݴ�������
    int m_seqLostBytes;    
    
    /**
     * ����Ҫ���������0�ֽڰ��ۼ���
     */ 
    UINT32 notCacheLenZero;
    /**
     * ��id������,��Ҫ�����İ����������Ƿ��и���
     */ 
    int m_pktSumForDecode;
    //tcp������ź�Ĵ�����ͷָ��
    ipPkt * headDecode;
    //tcp������ź�Ĵ�����βָ��
    ipPkt * tailDecode;

    //��ָ�룬����ָ��
    linkStream * m_pLink;
    
    /**
     * �Ѿ������İ����������Ƿ��и���
     */ 
    int m_pktDecoded;

    /**
     *ȫ�ĳ�ȡ�������״̬
     */ 
    int extractDone;

    
    //�������ĵ�ǰ���ź��seq���ϸ���������һ�����Ŀ�ʼ���
    //�������������쳣��ͨ��ֻʹ��0
    UINT32 m_nSeqNum[2];
    //���������ݰ�seq���ź�������ŵ�ĩ���ĳ���
    //�������������쳣��ͨ��ֻʹ��0
    int m_nLastLen[2];
    
    //���������ݰ�seq���ź�
    UINT32 m_nLastSeq[2];
    
    //���������ݰ�seq���ź�������ŵ�ĩ����ȷ��seq��
    UINT32 m_nAckSeq;
    //��������һ��ȷ��seq��
    UINT32 m_nFirstAckSeq;
    //����id�ţ�˫������idʱ���ڵ�������ż��
    UINT32 m_nStreamId;
    //come or conver, 0 or 1
    int m_nFlowType;

    //mss ���������Ƭ
    int m_segmentMax;
    //���ֵĴ��ڴ�С
    int m_windowSize;
    //���ִ��ڱ���
    int m_windowScale;
    //sack
    int m_sackPermitted;
    //����0ͳ��
    int m_winZeroSize;

    //0,������1��error
    //״��̫��޷�����������
    int m_streamSeqStatus;

    //����������ʱ����
    //Ӧ���ش������Բ�һ�µ����
    ipPkt * m_addCache[2];
    //��ͬ���ȵ��ش�����
    //0,������1����ͬ�����ش�����
    int m_resendLenStatus;
    //seq��ͬ�Ĳ�ͬ������
    static bool bTcpSeqSameCache;
public: 
    tcpReassembly();
    virtual ~tcpReassembly();

    
    /**
     *  ��ʼ��
     */ 
    void init(int headPaLoadMax,int headZeroLenMax);


    /**
     *  ���������޸��صİ�������seq���б�seq�Ƿ���ѧ�ŵ���
     *  pkt:tcp��
     *  return: SEQ_ERR ����SEQ_RESEND �ش���SEQ_SUCCESS  ������ȷ
     */ 
    STATUS_SEQ upSeq(  ipPkt *pkt,int nLenErrIndex);
    
    /**
     *  ���������seq���б�seq�Ƿ���ѧ�ŵ���
     *  pkt:tcp��
     *  return: SEQ_ERR ����SEQ_RESEND �ش���SEQ_SUCCESS  ������ȷ
     */ 
    STATUS_SEQ upSeqOnly( ipPkt * pkt,int nLenErrIndex);
    
    /**
     *  �쳣״̬��������ԾƵ��������ѹ����״̬����
     *  pkt:tcp��
     *  return: SEQ_ERR ����SEQ_RESEND �ش���SEQ_SUCCESS  ������ȷ SEQ_ERR_DEL ����ɾ��
     */ 
    STATUS_SEQ statusUpSeqData( ipPkt * pkt);
    /**
     *  ����seq���б�seq�Ƿ���ѧ�ŵ���������ȫ��tcp��
     *  pkt:tcp��
     *  return: SEQ_ERR ����SEQ_RESEND �ش���SEQ_SUCCESS  ������ȷ
     */ 
    STATUS_SEQ upSeqData( ipPkt *pkt,bool firstTryUp,int nLenErrIndex);

    /**
     *  ����seq���ϸ�����İ�����ʱ���뻺�����
     *  return: 0 ��ɣ����� ����
     */
    int cachePkt(ipPkt * newOne);  
    /**
     *  ����Tcp��seq�����İ�����ʱ�������������
     *  newOne:tcp��
     *  return: 0 ��ɣ����� ����
     */
    int addTcpPkt(ipPkt * newOne);
     /**
     *  udp�İ�����ʱ�������������
     *  newOne:tcp��
     *  return: 0 ��ɣ����� ����
     */
    int addUdpPkt(ipPkt * newOne);
     
    int addPktCall(ipPkt * newOne);
    int addCachePkt();
    /**
     *  ���뻺������У��ٴ��ж��Ƿ�seq��������������������
     *  return: 0 ��ɣ����� ����
     */
     
    
    int cacheTryAdd( );
     
    /**
     *  ��ȡ������
     */
     int getPropertyString(const ipPkt * newOne, const struct PropertyParm & pParm);

    /**
     *  ��������кʹ���������
     */
    void flushCache();   
    void flushDecode();

    
    /**
     *  �����������ְ�����
     */
    void decodeSynAck( ipPkt *pkt);
    
    /**
     *  �ͻ������ְ�����
     */
    void decodeSynAck0( ipPkt *pkt);
    
    /**
     *  zero window size ����
     */
    void winZeroSize( ipPkt *pkt);

    int cacheCheck(const int &nLenErrIndex,const UINT32 & cacheSum);
private:

    //int addMid(ipPkt *pre,ipPkt *next,ipPkt * newOne);
    

};
#endif // !defined(EA_C7B2E46E_00B4_4e81_B3E2_69F6B65B868B_Reassembly_INCLUDED_)
