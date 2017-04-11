///////////////////////////////////////////////////////////
//  appLinkInterface.h
//  Created on:      19-����-2016 16:13:52
//  Original author: Administrator
///////////////////////////////////////////////////////////

#if !defined(EA_AAE17FF3_32CE_4457_8EA7_637204D342D9_applicationInterface_INCLUDED_)
#define EA_AAE17FF3_32CE_4457_8EA7_637204D342D9_applicationInterface_INCLUDED_


#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string>
#include <vector>
#include <iostream>
#include <algorithm>
#include <string>
#include <dlfcn.h>
#include <iomanip>
#include <sstream>

#include "nprdef.h"
#include "basicHeadfile.h"


#ifdef __cplusplus
extern "C" {
#endif

class ipPkt;

#define STRING(x) #x


class appLink
{
public:
    //Э��ID
    UINT32  PID;
    //��������ʶ������ 0 ��ʾ�˿�ʶ�� 1��ʾ������ʶ��
    UINT32 TID;
    void * pObj;
    appLink()
    {
        PID =0;
        TID =0;
        pObj=NULL;
    }
};


//��ʼ��
//return >0:ȫ���ɹ���ʼ��������Ч
//return <0:��ʼ��ʧ�ܻ��ʼ����Ч
//retrun 0:����ʱȫ������������
int nprInitAppLink(std::string rootPath);
int nprAppLink(ipPkt * newOne,int isConver,int & nError, appLink &nAppLink);
void nprAppLinkRelease(void*);

        
#ifdef __cplusplus
}
#endif

#endif
