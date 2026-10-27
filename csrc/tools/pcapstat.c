/* nx-pcapstat: print capture counters as key=value lines (C-only path). */
#include "nexus_pkt.h"

#include <inttypes.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s FILE.pcap\n", argv[0]);
        return 2;
    }
    nx_pcap_stats s;
    int rc = nx_pcap_parse_file(argv[1], &s, NULL);
    if (rc != NX_OK && s.packets == 0) {
        fprintf(stderr, "nx-pcapstat: %s: %s\n", argv[1], nx_strerror(rc));
        return 1;
    }
#define P(f) printf(#f "=%" PRIu64 "\n", (uint64_t)s.f)
    P(packets); P(bytes_captured); P(bytes_wire); P(vlan_tagged); P(qinq); P(arp);
    P(ipv4); P(ipv6); P(other_l3); P(tcp); P(udp); P(icmp); P(other_l4);
    P(fragments); P(bad_ipv4_csum); P(truncated); P(malformed);
#undef P
    if (rc != NX_OK)
        fprintf(stderr, "nx-pcapstat: warning: %s (counters cover the readable part)\n",
                nx_strerror(rc));
    return rc == NX_OK ? 0 : 1;
}
