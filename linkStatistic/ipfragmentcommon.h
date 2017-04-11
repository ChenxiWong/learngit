

#include <string.h>


#ifndef IPFRAGMENTCOMMEN_H
#define IPFRAGMENTCOMMEN_H

#define EXPIRES 2

/* IP flags. */
#define IP_CE       0x8000      /* Flag: "Congestion"       */
#define IP_DF       0x4000      /* Flag: "Don't Fragment"   */
#define IP_MF       0x2000      /* Flag: "More Fragments"   */
#define IP_OFFSET   0x1FFF      /* "Fragment Offset" part   */

#define MAX_IPHEADER_LEN 40

//ip���麯���ķ���ֵ����ʾ�����ip����������Ƭ������Ҫ����
#define DO_NOT_NEED_FRAGMENT 1

#define NEED_FRAGMENT 2




typedef unsigned char       UCHAR;
typedef short   int         INT16;
typedef unsigned short      UINT16; 
typedef int                 INT32;
typedef unsigned int        UINT32;
typedef long long           INT64;
typedef unsigned long long  UINT64;

extern UINT32 nCurTime;

#define IPQ_HASHSZ  0x10000

/*
 * Was: ((((id) >> 1) ^ (saddr) ^ (daddr) ^ (prot)) & (IPQ_HASHSZ - 1))
 *
 * I see, I see evil hand of bigendian mafia. On Intel all the packets hit
 * one hash bucket with this hash function. 8)
 */
static inline UINT16 ipqhashfn(UINT16 id, UINT32 saddr, UINT32 daddr, UCHAR prot)
{
    unsigned int h = saddr ^ daddr;

    h ^= (h>>16)^id;
    h ^= (h>>8)^prot;
    return h & (IPQ_HASHSZ - 1);
}


struct IPPacket                 // ������������İ��ṹ����
{
    UCHAR *ipPacket;            // ������
    UCHAR *data;
    UINT32 len;             // ���������
    int offset;             // ��ǰ��Ƭ����offset
    IPPacket *next;             // ��һ���ڵ��ָ��
    UINT32 timeStamp;

    IPPacket()
    {
        memset(this, 0x0, sizeof(IPPacket));
    }
};


struct IPNode
{
    UINT32  saddr;
    UINT32  daddr;
    UINT16  id;
    UCHAR   protocol;
    UCHAR   last_in;
#define COMPLETE    4
#define FIRST_IN    2
#define LAST_IN     1
    int len;        /* total length of original datagram    */
    int meat;
    
    UINT32 timeStamp;               //timeout 
    IPNode *next;
    IPPacket *fragments;                //��Ƭ��
    UCHAR ipHeader[MAX_IPHEADER_LEN];
    UINT16 ipHeaderLen;
    IPNode *preTimeout, *nextTimeout;       //��ʱ����ǰ����ָ��
    //UINT32 packetCount;               //��ǰ����������

    IPNode()
    {
        memset(this, 0x0, sizeof(IPNode));
    }
    
    bool CheckTimeout()
    {
            return  nCurTime - timeStamp >= EXPIRES;
    }
};


#endif //IPFRAGMENTCOMMEN_H
