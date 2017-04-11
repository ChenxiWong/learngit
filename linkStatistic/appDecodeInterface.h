///////////////////////////////////////////////////////////
//  appDecodeInterface.h
//  Implementation of the Class httpAppManager
//  Created on:      19-四月-2016 16:13:52
//  Original author: Administrator
///////////////////////////////////////////////////////////

#if !defined(EA_AAE17FF3_32CE_4457_8EA7_637204D342D9_appDecodeInterface_INCLUDED_)
#define EA_AAE17FF3_32CE_4457_8EA7_637204D342D9_appDecodeInterface_INCLUDED_


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


extern unsigned int nCurTime;

#ifdef __cplusplus
extern "C" {
#endif

class ipPkt;

#define STRING(x) #x

//初始化
//return >0:全部成功初始化并且有效
//return <0:初始化失败或初始化无效
//retrun 0:仅仅时全流量分析工作
int nprInitAppDecode(std::string decodeFileName);
void *  nprDecodeApp(ipPkt * pkt,void * appObj,int comeOrconfer,int & nError);
void nprRelease(void*);

MASK_LEN_TYPE  initAppErr(char*);
MASK_LEN_TYPE  initAppProtoStatus(char*);
MASK_LEN_TYPE  initAppValuekey(char*);



#define INIT_ERR(err) \
    do{                                   \
        err=-1;                           \
        char e_data[256];                 \
        sprintf(e_data,"%s",STRING(err)); \
        MASK_LEN_TYPE ret= initAppErr(e_data);    \
        err =ret;                                   \
        TRACE("%s init.\n",STRING(err) );\
    }while(0);

#define INIT_PROTOSTATUS(protoStatus)      \
    do{                                         \
        protoStatus=-1;                           \
        char e_data[256];                           \
        sprintf(e_data,"%s",STRING(protoStatus));   \
        MASK_LEN_TYPE ret= initAppProtoStatus(e_data);   \
        protoStatus= ret;                               \
        TRACE("%s init.\n",STRING(protoStatus) );\
    }while(0);

#define INIT_VALUEKEY(err) \
        do{                                   \
            err=-1;                           \
            char e_data[256];                 \
            sprintf(e_data,"%s",STRING(err)); \
            MASK_LEN_TYPE ret= initAppValuekey(e_data);    \
            err =ret;                                   \
            TRACE("%s init.\n",STRING(err) );\
        }while(0);

    
        
#ifdef __cplusplus
}
#endif

#endif
