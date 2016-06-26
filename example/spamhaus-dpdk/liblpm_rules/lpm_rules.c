/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>

#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_cycles.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>

#include "lpm_rules.h"

static struct rte_lpm *ipv4_l3fwd_lpm_lookup_struct[NB_SOCKETS];

int lpm_table_init(int socketid) {
	char s[64];
	struct rte_lpm_config config_ipv4;

	/* create the LPM table */
	config_ipv4.max_rules = IPV4_L3FWD_LPM_MAX_RULES;
	config_ipv4.number_tbl8s = IPV4_L3FWD_LPM_NUMBER_TBL8S;
	config_ipv4.flags = 0;
	snprintf(s, sizeof(s), "IPV4_L3FWD_LPM_%d", socketid);
	ipv4_l3fwd_lpm_lookup_struct[socketid] =
			rte_lpm_create(s, socketid, &config_ipv4);

	if (ipv4_l3fwd_lpm_lookup_struct[socketid] == NULL)
		rte_exit(EXIT_FAILURE,
			"Unable to create the l3fwd LPM table on socket %d\n",
			socketid);

	return 1;
}

int lpm_entry_add(unsigned int ip, int depth, int next_hop, int socketid) {
	int ret = -1;
	/* populate the LPM table */
	ret = rte_lpm_add(ipv4_l3fwd_lpm_lookup_struct[socketid],
			ip,
			depth,
			next_hop);

	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Unable to add entry to the l3fwd LPM table on socket %d\n", socketid);
	}

	printf("LPM: Adding route 0x%08x / %d (%d)\n",
			(unsigned)ip,
			depth,
			next_hop);
	return 1;
}

int lpm_entry_lookup(unsigned int ip, int socketid) {
	int ret = -1;
	uint32_t next_hop;

	return (uint8_t) ((rte_lpm_lookup(ipv4_l3fwd_lpm_lookup_struct[socketid],
		ip,
		&next_hop) == 0) ? next_hop : 255);
}

int get_lcore() {
	return rte_lcore_id();
}

int lpm_get_dst_port(struct rte_mbuf *m, int socketid) {
    struct ether_hdr *eth_hdr;
    struct ipv4_hdr *ipv4_hdr;

    eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);

    if (RTE_ETH_IS_IPV4_HDR(m->packet_type)) {
        /* Handle IPv4 headers.*/
        ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *,
                sizeof(struct ether_hdr));
	
        return lpm_entry_lookup(rte_be_to_cpu_32(((struct ipv4_hdr *)ipv4_hdr)->dst_addr), socketid);
    }

    return -1;
}
