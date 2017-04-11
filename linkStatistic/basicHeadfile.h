

#if !defined(BASICHEADFILE_INCLUDED_)
#define BASICHEADFILE_INCLUDED_

#ifndef NPR_DEBUG
//#define NPR_DEBUG 
#endif

#define NPR_FACTORY

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

typedef  unsigned int MASK_LEN_TYPE;
const int  MASK_LEN=(sizeof(MASK_LEN_TYPE)*8);

using namespace std;

#endif
