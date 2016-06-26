#ifndef LPM_RULES_H
#define LPM_RULES_H

#include <rte_mbuf.h>

#define NB_SOCKETS	1
#define IPV4_L3FWD_LPM_MAX_RULES         1024
#define IPV4_L3FWD_LPM_NUMBER_TBL8S (1 << 8)

int lpm_table_init(int socket_id);
int lpm_entry_add(unsigned int ip, int depth, int next_hop, int socketid);
int lpm_entry_lookup(unsigned int ip, int socketid);
int lpm_get_dst_port(struct rte_mbuf *m, int socketid);
int get_lcore();
#endif
