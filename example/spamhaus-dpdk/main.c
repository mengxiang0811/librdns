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
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/queue.h>

#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ip.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include "rdns.h"
#include "rdns_curve.h"
#include "rdns_ev.h"

//#define DEBUG
#define SIMMOD

#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32


#define IP_VERSION 0x40                                                         
#define IP_HDRLEN  0x05 /* default IP header length == five 32-bits words. */   
#define IP_DEFTTL  64   /* from RFC 1340. */                                    
#define IP_VHL_DEF (IP_VERSION | IP_HDRLEN)                                     
#define IP_DN_FRAGMENT_FLAG 0x0040

static const struct rte_eth_conf port_conf_default = {
	.rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN, },
};

static unsigned nb_ports;
struct rte_mempool *mbuf_pool;

/* the Lua interpreter */
lua_State* L;

#define NUM_TESTS	2
#define RDNS_SERV	"8.8.8.8"
#define RDNS_PORT	53
static char buff[NUM_TESTS + 1][128];
static int tot_tests = NUM_TESTS;
static int remain_tests = 0;

static void
rdns_regress_callback (struct rdns_reply *reply, void *arg)
{
	struct rdns_reply_entry *entry;
	char out[INET6_ADDRSTRLEN + 1];
	const struct rdns_request_name *name;

	printf("In the callback function with lcore = %u\n", rte_lcore_id());

	if (reply->code == RDNS_RC_NOERROR) {
		entry = reply->entries;
		while (entry != NULL) {
			if (entry->type == RDNS_REQUEST_A) {
				inet_ntop (AF_INET, &entry->content.a.addr, out, sizeof (out));
				printf ("%s has A record %s\n", (char *)arg, out);
			}
			else if (entry->type == RDNS_REQUEST_AAAA) {
				inet_ntop (AF_INET6, &entry->content.aaa.addr, out, sizeof (out));
				printf ("%s has AAAA record %s\n", (char *)arg, out);
			}
			else if (entry->type == RDNS_REQUEST_SOA) {
				printf ("%s has SOA record %s %s %u %d %d %d\n",
						(char *)arg,
						entry->content.soa.mname,
						entry->content.soa.admin,
						entry->content.soa.serial,
						entry->content.soa.refresh,
						entry->content.soa.retry,
						entry->content.soa.expire);
			}
			else if (entry->type == RDNS_REQUEST_TLSA) {
				char *hex, *p;
				unsigned i;

				hex = malloc (entry->content.tlsa.datalen * 2 + 1);
				p = hex;

				for (i = 0; i < entry->content.tlsa.datalen; i ++) {
					sprintf (p, "%02x",  entry->content.tlsa.data[i]);
					p += 2;
				}

				printf ("%s has TLSA record (%d %d %d) %s\n",
						(char *)arg,
						(int)entry->content.tlsa.usage,
						(int)entry->content.tlsa.selector,
						(int)entry->content.tlsa.match_type,
						hex);

				free (hex);
			}
			entry = entry->next;
		}
	}
	else {
		name = rdns_request_get_name (reply->request, NULL);
		printf ("Cannot resolve %s record for %s: %s\n",
				rdns_strtype (name->type),
				(char *)arg,
				rdns_strerror (reply->code));
	}

    printf("remain_tests = %d; tot_tests = %d\n", remain_tests, tot_tests);
	if (--remain_tests == 0 && tot_tests == 0) {
		printf ("End of test cycle\n");
		rdns_resolver_release (reply->resolver);
	}
}

    static void
rdns_test_a (struct rdns_resolver *resolver)
{
#if 1
    char *addr = "2.0.0.127.zen.spamhaus.org";
    rdns_make_request_full (resolver, rdns_regress_callback, addr, 1.0, 2, 1, addr, RDNS_REQUEST_A);
    remain_tests++;

    while (tot_tests > 0) {
        memset(buff[NUM_TESTS - tot_tests], 0, sizeof(buff[NUM_TESTS - tot_tests]));

        printf("Please input the IP address to lookup the zen.spamhaus.org block lists!\n");
        scanf("%s", buff[NUM_TESTS - tot_tests]);
        strcat(buff[NUM_TESTS - tot_tests], ".zen.spamhaus.org");

        printf("The lookup is %s\n", buff[NUM_TESTS - tot_tests]);

        rdns_make_request_full (resolver, rdns_regress_callback, buff[NUM_TESTS - tot_tests], 1.0, 2, 1, buff[NUM_TESTS - tot_tests], RDNS_REQUEST_A);
        remain_tests ++;

        tot_tests--;
    }

    printf("tot_tests = %d\n", tot_tests);
#endif
}
/* simulation test */

static struct ipv4_hdr ip_hdr_template[1];
static struct ether_hdr l2_hdr_template[1];

	void
init_hdr_templates(void)
{
	memset(ip_hdr_template, 0, sizeof(ip_hdr_template));
	memset(l2_hdr_template, 0, sizeof(l2_hdr_template));

	ip_hdr_template[0].version_ihl = IP_VHL_DEF;
	ip_hdr_template[0].type_of_service = (2 << 2); // default DSCP 2 
	ip_hdr_template[0].total_length = 0; 
	ip_hdr_template[0].packet_id = 0;
	ip_hdr_template[0].fragment_offset = IP_DN_FRAGMENT_FLAG;
	ip_hdr_template[0].time_to_live = IP_DEFTTL;
	ip_hdr_template[0].next_proto_id = IPPROTO_IP;
	ip_hdr_template[0].hdr_checksum = 0;
	ip_hdr_template[0].src_addr = rte_cpu_to_be_32(0x00000000);
	ip_hdr_template[0].dst_addr = rte_cpu_to_be_32(0x07010101);

	l2_hdr_template[0].d_addr.addr_bytes[0] = 0x0a;
	l2_hdr_template[0].d_addr.addr_bytes[1] = 0x00;
	l2_hdr_template[0].d_addr.addr_bytes[2] = 0x27;
	l2_hdr_template[0].d_addr.addr_bytes[3] = 0x00;
	l2_hdr_template[0].d_addr.addr_bytes[4] = 0x00;
	l2_hdr_template[0].d_addr.addr_bytes[5] = 0x01;

	l2_hdr_template[0].s_addr.addr_bytes[0] = 0x08;
	l2_hdr_template[0].s_addr.addr_bytes[1] = 0x00;
	l2_hdr_template[0].s_addr.addr_bytes[2] = 0x27;
	l2_hdr_template[0].s_addr.addr_bytes[3] = 0x7d;
	l2_hdr_template[0].s_addr.addr_bytes[4] = 0xc7;
	l2_hdr_template[0].s_addr.addr_bytes[5] = 0x68;

	l2_hdr_template[0].ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

	return;
}

/*
 * Initialises a given port using global settings and with the rx buffers
 * coming from the mbuf_pool passed as parameter
 */
	static inline int
port_init(uint8_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	int retval;
	uint16_t q;

	if (port >= rte_eth_dev_count())
		return -1;

	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL);
		if (retval < 0)
			return retval;
	}

	retval  = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	struct ether_addr addr;

	rte_eth_macaddr_get(port, &addr);
	printf("Port %u MAC: %02"PRIx8" %02"PRIx8" %02"PRIx8
			" %02"PRIx8" %02"PRIx8" %02"PRIx8"\n",
			(unsigned)port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	rte_eth_promiscuous_enable(port);

	return 0;
}

	static int
lpm_main_loop(__attribute__((unused)) void *arg)
{
	struct rdns_resolver *resolver_ev;
	struct ev_loop *eloop;

	eloop = ev_default_loop (0);
	resolver_ev = rdns_resolver_new ();
	rdns_bind_libev (resolver_ev, eloop);

	rdns_resolver_add_server (resolver_ev, RDNS_SERV, RDNS_PORT, 0, 8);

	rdns_resolver_init (resolver_ev);

	rdns_test_a (resolver_ev);
	ev_loop (eloop, 0);

	printf("All rdns requests are finished!!!\n");

	return;

	lua_State *tl = lua_newthread(L);

#ifndef SIMMOD
	uint8_t port;

	for (port = 0; port < nb_ports; port++)
		if (rte_eth_dev_socket_id(port) > 0 &&
				rte_eth_dev_socket_id(port) !=
				(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

	printf("\nCore %u forwarding packets with LPM. [Ctrl+C to quit]\n",
			rte_lcore_id());

	for (;;) {
		for (port = 0; port < nb_ports; port++) {
			struct rte_mbuf *bufs[BURST_SIZE];
			const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
					bufs, BURST_SIZE);
			uint16_t buf;

			if (unlikely(nb_rx == 0))
				continue;

			for (buf = 0; buf < nb_rx; buf++) {
				printf("*******************Recieve PKT*******************\n");
				struct rte_mbuf *mbuf = bufs[buf];
				unsigned int len = rte_pktmbuf_data_len(mbuf);
				rte_pktmbuf_dump(stdout, mbuf, len);

				printf("***************PKT LOOKUP**************\n");
				lua_checkstack(tl, 20);

				/* push functions and arguments */
				lua_getglobal(tl, "llpm_get_dst_port"); /* function to be called */
				lua_pushlightuserdata(tl, mbuf);   /* push 1st argument */
				//lua_pushinteger(tl, 0);   /* push 2nd argument */

				if (lua_pcall(tl, 1, 1, 0) != 0)
					error(tl, "error running function `llpm_get_dst_port': %s", lua_tostring(tl, -1));

				/* retrieve result */
				int nexthop = 0;
				nexthop = lua_tointeger(tl, -1);
				lua_pop(tl, 1);  /* pop returned value */

				printf("\t\t\t#######The next hop is %d\n", nexthop);

				/*release the packet*/
				rte_pktmbuf_free(mbuf);
			}
		}
	}
#else
	int loop = 10;

	while (loop-- > 0) {
		struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
#ifdef DEBUG
		printf("*******************Construct PKT*******************\n");
#endif
		mbuf->packet_type |= RTE_PTYPE_L3_IPV4;
		struct ether_hdr *pneth = (struct ether_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
		//struct ether_hdr *pneth = rte_pktmbuf_mtod(&mbuf, struct ether_hdr *);
		struct ipv4_hdr *ip = (struct ipv4_hdr *) &pneth[1];

		pneth = rte_memcpy(pneth, &l2_hdr_template[0],
				sizeof(struct ether_hdr));

		ip = rte_memcpy(ip, &ip_hdr_template[0],
				sizeof(struct ipv4_hdr));

		unsigned int new_ip_addr = 0;

		new_ip_addr += loop * (1 << 24) + (1 << 16) + (1 << 8) + loop;

		ip->dst_addr = rte_cpu_to_be_32(new_ip_addr);

#ifdef DEBUG
		unsigned int len = rte_pktmbuf_data_len(mbuf);
		rte_pktmbuf_dump(stdout, mbuf, len);

		printf("***************PKT LOOKUP**************\n");
#endif
		lua_checkstack(tl, 20);

		/* push functions and arguments */
		lua_getglobal(tl, "llpm_get_dst_port"); /* function to be called */
		lua_pushlightuserdata(tl, (void *)mbuf);   /* push 1st argument */
		//lua_pushinteger(tl, 0);   /* push 2nd argument */

		if (lua_pcall(tl, 1, 1, 0) != 0)
			error(tl, "error running function `llpm_get_dst_port': %s", lua_tostring(tl, -1));

		/* retrieve result */
		int nexthop = 0;
		nexthop = lua_tointeger(tl, -1);
		lua_pop(tl, 1);  /* pop returned value */

		printf("LCORE %d#######The next hop is %d for %d.1.1.%d\n", rte_lcore_id(), nexthop, loop, loop);

		rte_pktmbuf_free(mbuf);

		sleep(rand()%10);
	}

#endif
	return 0;
}

	int
main(int argc, char **argv)
{
	int ret;
	unsigned lcore_id;
	int i = 0;

	uint8_t portid;

	init_hdr_templates();
	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("Cannot init EAL\n");
#ifndef SIMMOD
	argc -= ret;
	argv += ret;

	nb_ports = rte_eth_dev_count();
	printf("There are %d ports!\n", nb_ports);
	if (nb_ports < 2 || (nb_ports & 1))
		rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
			NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0,
			RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* initialize all ports */
	for (portid = 0; portid < nb_ports; portid++)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8"\n",
					portid);

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too much enabled lcores - "
				"App uses only 1 lcore\n");
#else
	srand(time(NULL));
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
			NUM_MBUFS * 2, MBUF_CACHE_SIZE, 0,
			RTE_MBUF_DEFAULT_BUF_SIZE, 0);
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

#endif
	/* initialize Lua */
	L = luaL_newstate();
	//lua_open();

	/* load Lua base libraries */
	luaL_openlibs(L);

#if 1
	/* load the script */
	luaL_loadfile(L, "./lpm.lua");
	//luaL_loadfile(L, "./test.lua");
	if (lua_pcall(L, 0, 0, 0) != 0)
		error(L, "error running function `lpm.lua': %s", lua_tostring(L, -1));

	printf("After load the lua file!!!\n");
	/* setup the LPM table */
	lua_getglobal(L, "llpm_setup");
	//lua_getglobal(L, "test");
	if (lua_pcall(L, 0, 0, 0) != 0)
		error(L, "error running function `llpm_setup': %s", lua_tostring(L, -1));
#endif

#if 0
	/* call lpm_main_loop() on every slave lcore */
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		rte_eal_remote_launch(lpm_main_loop, NULL, lcore_id);
	}
#endif

	/* call it on master lcore too */
	lpm_main_loop(NULL);

	rte_eal_mp_wait_lcore();

	printf("All tasks are finished!\n");

	lua_close(L);

	printf("Close the Lua State: L!\n");

	return 0;
}
