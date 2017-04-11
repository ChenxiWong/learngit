///////////////////////////////////////////////////////////
//  appLinkInterface.h
//  Created on:      19-四月-2016 16:13:52
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
    //协议ID
    UINT32  PID;
    //用于区分识别类型 0 表示端口识别， 1表示特征码识别。
    UINT32 TID;
    void * pObj;
    appLink()
    {
        PID =0;
        TID =0;
        pObj=NULL;
    }
};


//初始化
//return >0:全部成功初始化并且有效
//return <0:初始化失败或初始化无效
//retrun 0:仅仅时全流量分析工作
int nprInitAppLink(std::string rootPath);
int nprAppLink(ipPkt * newOne,int isConver,int & nError, appLink &nAppLink);
void nprAppLinkRelease(void*);

        
#ifdef __cplusplus
}
#endif

#endif
