#include <stdlib.h>
#include <stdio.h>
#include "rdns.h"
#include "rdns_curve.h"
#include "rdns_ev.h"

#define NUM_TESTS   2
static char buff[NUM_TESTS + 1][128];
static int tot_tests = NUM_TESTS;
static int remain_tests = 0;

static void
rdns_regress_callback (struct rdns_reply *reply, void *arg)
{
	struct rdns_reply_entry *entry;
	char out[INET6_ADDRSTRLEN + 1];
	const struct rdns_request_name *name;

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

    int
main(int argc, char **argv)
{
    struct rdns_resolver *resolver_ev;
    struct ev_loop *loop;

    loop = ev_default_loop (0);
    resolver_ev = rdns_resolver_new ();
    rdns_bind_libev (resolver_ev, loop);

    rdns_resolver_add_server (resolver_ev, argv[1], strtoul (argv[2], NULL, 10), 0, 8);

    rdns_resolver_init (resolver_ev);

    rdns_test_a (resolver_ev);
    ev_loop (loop, 0);

    return 0;
}
