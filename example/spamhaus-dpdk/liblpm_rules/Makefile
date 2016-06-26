#   BSD LICENSE
#
#   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions
#   are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#     * Neither the name of Intel Corporation nor the names of its
#       contributors may be used to endorse or promote products derived
#       from this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overriden by command line or environment
#RTE_SDK = /home/vagrant/ddos/dpdk
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

#CONFIG_RTE_BUILD_SHARED_LIB=y
# binary name
#LIB = libhelloworld.so
SHARED = liblpm_rules.so

# all source are stored in SRCS-y
SRCS-y := lpm_rules.c

RTE_BUILD_SHARED_LIB=y
#CFLAGS += -fPIC
LDLIBS += -lrte_eal -lrte_lpm
CFLAGS += -O3
#CFLAGS += $(WERROR_FLAGS) -L/home/developer/dpdk/x86_64-native-linuxapp-gcc/lib/
CFLAGS += -L/home/developer/dpdk/x86_64-native-linuxapp-gcc/lib/
#CFLAGS += -L/home/vagrant/ddos/dpdk/x86_64-native-linuxapp-gcc/lib
EXTRA_CFLAGS += -g -O0
#CFLAGS += $(WERROR_FLAGS) -L$(LDLIBS)

#include $(RTE_SDK)/mk/rte.extlib.mk
include $(RTE_SDK)/mk/rte.extshared.mk
