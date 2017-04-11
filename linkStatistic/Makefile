#=============================================================================
# Makefile for transformer 
# Author      :	Tongkedong <tongkd@126.com>
# Date        :	2008-01-20
# Copyright   : Copyright(c) 2007 - 2010 Run Technology, Inc. All rights reserved.
# Description :	build capture module
#=============================================================================
SO_NAME = liblink.so
SRCS = $(shell ls *.cpp)
OBJS = $(SRCS:.cpp=.o)
CC      = g++
CFLAGS = -fPIC -W -Wall -Wchar-subscripts -Wcomment -Wformat  \
   -Wmissing-braces -Wparentheses -Wswitch -Wunused -Wunused-parameter \
   -Wfloat-equal -Wshadow -Wcast-align -Wsign-compare \
   -Wpointer-arith -Woverloaded-virtual  -Wno-deprecated -minline-all-stringops
LDFLAGS = -L/usr/local/lib -lxerces-c -L./ -lapplink
INCLUDES=  -I . 
ifeq ($(INSTALL_DIR),)
INSTALL_DIR=../debug/
endif

ifeq ($(ACTION),release)
CFLAGS += -O2 -fno-strict-aliasing -Wuninitialized  -DSET_SCHED 
else
CFLAGS += -g -O0 -Wunreachable-code -DSET_SCHED 
#-DNPR_DEBUG  -DDEBUG 
#-DDEBUG_MAX 
endif

EXTCFLAGS += -shared



.PHONY: all
all: $(SO_NAME)
	@echo make sofile $(SO_NAME) finished.

$(SO_NAME):$(OBJS)
	@echo Build $(SO_NAME)
	$(CC) $(INCLUDES) $(CFLAGS) $(EXTCFLAGS) $(LDFLAGS) -o $@ $^

-include .depend
%.o: %.cpp
	$(CC) $(INCLUDES) $(CFLAGS) $(LDFLAGS) -c -o $@ $<
	#@cp -af $@ $(INSTALL_DIR)

.PHONY: depend
depend:
	$(CC) $(INCLUDES) -E -MM *.cpp > .depend

.PHONY: install
install:
	#cp -af $(OBJS) $(INSTALL_DIR)

.PHONY: clean 
clean:
	rm -rf *.o *core

.PHONY: distclean 
distclean:
	rm -rf *.o *core .depend
