///////////////////////////////////////////////////////////
//  ipPkt.h
//  Implementation of the Class ipPkt
//  Created on:      15-ʮ��-2015 14:08:37
//  Original author: huiliang
///////////////////////////////////////////////////////////

#if !defined(EA_C7B2E46E_00B4_4e81_B3E2_69F6B65B868B_tcpPkt_INCLUDED_)
#define EA_C7B2E46E_00B4_4e81_B3E2_69F6B65B868B_tcpPkt_INCLUDED_


#include "nprdef.h"
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <string.h>
#include <stdio.h>

#define ERROR_MAC                   1
#define ERROR_IP                    2
#define ERROR_TCP                   3
#define ERROR_UDP                   4
#define ERROR_ICMP                  5

enum FREE_TYPE
{
    MALLOC_FREE,
    DPDK_FREE,
    NO_FREE
};

class ipPkt
{
public:
    IP4ConnectAddr m_connectAddress;

    //��·��
    uint8_t src_num1 ;
    uint8_t src_num2 ;
    uint8_t dst_num ;

    

    //��·������ͷָ��
    char * pMac;
    //total len
    int macLen;

    
    //ipͷָ��
    char * pIp;
    //ip len
    uint8_t ipPayProto;
    int ipPayLoadLen;
    //ipͷ����
    unsigned char ipHeadLen;
    
    //ip ���鷵��״̬
    unsigned char   nError;
    //�Ƿ�������ipheader
    bool bReassembIphead; 

    
    //tcpͷָ��/udpͷָ��
    char * pTcpUdp;
    //tcp��ͷ�ĳ���
    int tcpudpHeadLen;
    unsigned int reqSeq;
    unsigned int ackSeq;
    unsigned char byTcpFlag;
    
    
    //tcp/udp�غ�����ͷָ��
    char * pPayLoad;
    //tcp/udp�����صĳ���
    int len;
    
    ipPkt * next;
    ipPkt * pre;

    //��Ҫ�ͷŵ��ڴ��ַ
    void * pFree;
    //�ͷ�����
    FREE_TYPE freeType;
    //DPDK�ͷź���
    void (*pFunDpdkfree )(void*);
    
    //��Ҫ��������İ����
    //���ӵİ�������
    int linkPktSerialId;
    //���İ�������
    int streamPktSerialId;
    /*
    ipPkt()
    {
        pMac=NULL;
        ipPayLoadLen =0;
        pIp=NULL;
        ipPayLoadLen=0;
        ipPayLoadLen=0;
        ipHeadLen=0;
        nError=0;
        bReassembIphead=false;
        pTcpUdp=NULL;
        tcpudpHeadLen=0;
        reqSeq=0;
        ackSeq=0;
        byTcpFlag=0;
        pPayLoad=NULL;
        len=0;
        next=0;
        pre=NULL;
        pFree=NULL;
        freeType=NO_FREE;
        pFunDpdkfree=NULL;
        linkPktSerialId=0;
        streamPktSerialId=0;
    }
    */
    ~ipPkt()
    {
        bufFree();
    }   

    void ipFragment(int ipPayLoadLenNew,char* ipPacket)
    {      

        bufFree();
        macLen =macLen- ipPayLoadLen + ipPayLoadLenNew ;
        ipPayLoadLen= ipPayLoadLenNew;
        bReassembIphead = true; 
        pIp =ipPacket;
        
        pFree =pIp;            
        freeType=MALLOC_FREE;
        pMac=NULL;
    }
    void initIp( char* buff,struct iphdr * p_iphdr,int buff_len)
    {         
        pMac =buff;   
        if(NULL!=pMac)
        {
            src_num1 = ((struct ethhdr *)pMac)->h_source[4];
            src_num2 = ((struct ethhdr *)pMac)->h_source[5];
            src_num1 += 1;
            src_num2 += 1;
            dst_num = ((struct ethhdr *)pMac)->h_dest [3];
        } 
        pIp = (char *)p_iphdr;   
        ipPayProto = p_iphdr->protocol;
        freeType = NO_FREE;    
        
        ipHeadLen=p_iphdr->ihl << 2;
        macLen = buff_len;
        
        m_connectAddress.Come.nIP=  ntohl(p_iphdr->saddr) ;
        m_connectAddress.Conver.nIP= ntohl(p_iphdr->daddr);
    }  
    void initUdp( )
    { 
        struct udphdr *p_udphdr = (struct udphdr *) ( pIp + ipHeadLen);
        pTcpUdp = (char*)(p_udphdr);
        tcpudpHeadLen =sizeof(struct udphdr);
        pPayLoad = pTcpUdp + tcpudpHeadLen;    
        len = ntohs(p_udphdr->len)  - tcpudpHeadLen ;
          
        m_connectAddress.Come.nPort= ntohs( p_udphdr->source );
        m_connectAddress.Conver.nPort=  ntohs(p_udphdr->dest );
        m_connectAddress.nProtocol= UDP_PROTO;
    }
    
    void initTcp( )
    { 
        uint16_t ipTotlen = ntohs(((struct iphdr*) pIp)->tot_len);
        pTcpUdp =  ( pIp + ipHeadLen);    
        tcpudpHeadLen =((struct tcphdr *)pTcpUdp)->doff * 4;
        
        UINT32*  pSeq=(UINT32*)(pTcpUdp+8);
        ackSeq = ntohl(*pSeq);
        pSeq=(UINT32*)(pTcpUdp+4);
        reqSeq = ntohl(*pSeq); 

        pPayLoad =pTcpUdp + tcpudpHeadLen ;
        len = ipTotlen - ipHeadLen -  tcpudpHeadLen;
        byTcpFlag =(unsigned char)(pTcpUdp[13]);
        
        m_connectAddress.Come.nPort= ntohs( ((struct tcphdr *)pTcpUdp )->source );
        m_connectAddress.Conver.nPort=  ntohs(((struct tcphdr *)pTcpUdp)->dest );
        m_connectAddress.nProtocol= TCP_PROTO;
    
    }
    void bufFree()
    {
        if(NULL!= pFree)
        {
            if(freeType == MALLOC_FREE)
            {
                free(pFree);
                pFree = NULL;
                freeType= NO_FREE;                
            }
            else if(freeType == DPDK_FREE)
            {
                pFunDpdkfree(pFree);
                pFree = NULL;
                freeType= NO_FREE; 
            }
            else
            {
                printf("error,bufFree is not unknown[%d].\r\n",freeType);            
            }
        }
        else if(freeType != NO_FREE)
        {
            printf("error,bufFree is not NO_FREE.\r\n");            
        }
    }


    void copyFromDpdkBuf()
    {        
        //25\����    & 0xff 
        if(freeType == MALLOC_FREE)
        {
            return;
        }
        pFree = malloc( 1 + (macLen | 0xff) );
        freeType = MALLOC_FREE;    
        memcpy(pFree,pMac,macLen ); 
        pIp =((char*) pFree)+(pIp - pMac); 
        pMac =(char*) pFree;
        
        if(ipPayProto == 0x6)
        {        
            reInitTcp();
        }
        else if(ipPayProto == 0x11)
        {        
            reInitUdp();
        }
    }
    void init()
    {
        src_num1=0;
        src_num2=0;
        dst_num=0;
        pMac =NULL;
        pPayLoad =NULL;
        pIp=NULL;
        pTcpUdp=NULL;
        ipPayLoadLen =0;
        reqSeq=0;
        ackSeq=0;
        byTcpFlag=0;
        len=0;
        //addSerial=0;
        linkPktSerialId=0;
        streamPktSerialId=0;
        tcpudpHeadLen=0;
        next=NULL;
        pre=NULL;
        pFree=NULL;
        nError=0;
        ipHeadLen=0;
        bReassembIphead=false; 
        freeType=NO_FREE;
        pFunDpdkfree=NULL;
    }       

    //pIpָ����ڲ�仯ʱ���øú���
    void reInitTcp()
    {      
        pTcpUdp = (char*)(pIp + ipHeadLen);
        pPayLoad = pTcpUdp + tcpudpHeadLen;        
    }  
    void reInitUdp()
    {      
        pTcpUdp = (char*)(pIp + + ipHeadLen);
        //sizeof(struct udphdr)=8
        pPayLoad = pTcpUdp + 8 ;      
    }
};

#endif 
