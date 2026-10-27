/*
 * nexus_pkt: a small, dependency-free packet and pcap parser.
 *
 * Design goals (data-plane style, not a DPDK replacement):
 *   - zero allocation on the per-packet path (caller owns all memory)
 *   - every header access is bounds-checked against the captured length
 *   - no global state, so the parser is safe to run per-thread / per-core
 *
 * Supported: classic libpcap files (LE/BE, usec/nsec timestamps) with
 * LINKTYPE_ETHERNET; Ethernet II, 802.1Q / 802.1ad (QinQ) tags, ARP,
 * IPv4 (with header checksum verification), IPv6 (fixed header plus
 * hop-by-hop/routing/fragment/destination-options extension headers),
 * TCP, UDP, ICMP and ICMPv6.
 */
#ifndef NEXUS_PKT_H
#define NEXUS_PKT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NX_ABI_VERSION 1
#define NX_MAX_CAPLEN 262144u

/* Return codes. Negative values are errors. */
enum nx_status {
    NX_OK = 0,
    NX_ERR_ARG = -1,         /* NULL pointer or bad argument               */
    NX_ERR_IO = -2,          /* could not open / read the file             */
    NX_ERR_BAD_MAGIC = -3,   /* not a classic pcap file                    */
    NX_ERR_LINKTYPE = -4,    /* link type other than Ethernet              */
    NX_ERR_TRUNCATED = -5,   /* file ends in the middle of a header/record */
    NX_ERR_NOMEM = -6,       /* flow table storage too small               */
    NX_ERR_BAD_RECORD = -7   /* record caplen larger than NX_MAX_CAPLEN    */
};

/* Frame-level decode flags (nx_frame_info.flags). */
#define NX_F_VLAN        0x0001u /* at least one 802.1Q/802.1ad tag          */
#define NX_F_QINQ        0x0002u /* two or more tags                         */
#define NX_F_IPV4        0x0004u
#define NX_F_IPV6        0x0008u
#define NX_F_ARP         0x0010u
#define NX_F_FRAGMENT    0x0020u /* IPv4 MF/offset or IPv6 fragment header   */
#define NX_F_BAD_CSUM    0x0040u /* IPv4 header checksum mismatch            */
#define NX_F_TRUNCATED   0x0080u /* a header was cut off by the capture      */
#define NX_F_MALFORMED   0x0100u /* header fields are internally inconsistent */
#define NX_F_HAS_PORTS   0x0200u /* src_port/dst_port are valid              */

typedef struct nx_frame_info {
    uint32_t flags;
    uint16_t ethertype;     /* innermost ethertype after VLAN tags         */
    uint16_t vlan_outer;    /* VLAN ID of the outer tag (0 if untagged)    */
    uint16_t vlan_inner;    /* VLAN ID of the inner tag (0 if none)        */
    uint8_t  ip_proto;      /* L4 protocol number (IPv4 proto / IPv6 NH)   */
    uint8_t  ip_ttl;        /* IPv4 TTL or IPv6 hop limit                  */
    uint8_t  src_ip[16];    /* IPv4 uses the first 4 bytes                 */
    uint8_t  dst_ip[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t l3_offset;     /* byte offset of the L3 header in the frame   */
    uint16_t l4_offset;     /* byte offset of the L4 header (0 if none)    */
    uint32_t l3_len;        /* length claimed by the L3 header             */
} nx_frame_info;

/* Aggregate counters for a capture. All counters are packet counts unless
 * the name says bytes. */
typedef struct nx_pcap_stats {
    uint64_t packets;
    uint64_t bytes_captured;  /* sum of caplen                       */
    uint64_t bytes_wire;      /* sum of original (wire) length       */
    uint64_t vlan_tagged;
    uint64_t qinq;
    uint64_t arp;
    uint64_t ipv4;
    uint64_t ipv6;
    uint64_t other_l3;
    uint64_t tcp;
    uint64_t udp;
    uint64_t icmp;            /* ICMP and ICMPv6                     */
    uint64_t other_l4;
    uint64_t fragments;
    uint64_t bad_ipv4_csum;
    uint64_t truncated;       /* caplen < wire len or header cut off */
    uint64_t malformed;
    uint32_t min_wire_len;
    uint32_t max_wire_len;
    uint64_t first_ts_ns;     /* timestamps normalised to nanoseconds */
    uint64_t last_ts_ns;
} nx_pcap_stats;

/* A 5-tuple flow (IPv4 or IPv6) with counters. */
typedef struct nx_flow {
    uint8_t  src_ip[16];
    uint8_t  dst_ip[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  ip_proto;
    uint8_t  ip_version;      /* 4 or 6; 0 marks an empty slot        */
    uint16_t _pad;
    uint64_t packets;
    uint64_t bytes;           /* wire bytes                           */
} nx_flow;

/* Fixed-capacity open-addressing flow table. The caller provides the
 * slot storage, so there is no allocation while parsing. Capacity must be
 * a power of two. */
typedef struct nx_flow_table {
    nx_flow *slots;
    uint32_t capacity;
    uint32_t used;
    uint64_t dropped;         /* packets not tracked because the table was full */
} nx_flow_table;

int nx_abi_version(void);
const char *nx_strerror(int status);

/* RFC 1071 Internet checksum over `len` bytes. Returns the folded,
 * complemented 16-bit sum in host order. */
uint16_t nx_inet_checksum(const uint8_t *data, size_t len);

/* Decode one Ethernet frame of `caplen` captured bytes. Always fills
 * `info` (zeroed first). Returns NX_OK, or NX_ERR_ARG on NULL input.
 * Truncation and malformation are reported via info->flags, not errors. */
int nx_parse_frame(const uint8_t *frame, size_t caplen, nx_frame_info *info);

int nx_flow_table_init(nx_flow_table *t, nx_flow *slots, uint32_t capacity);
/* Account one decoded frame; frames without IP are ignored. */
void nx_flow_table_add(nx_flow_table *t, const nx_frame_info *info, uint32_t wire_len);

/* Parse a whole pcap image held in memory. `flows` may be NULL. */
int nx_pcap_parse_buffer(const uint8_t *buf, size_t len, nx_pcap_stats *stats,
                         nx_flow_table *flows);
/* Convenience wrapper that reads `path` in streaming fashion. */
int nx_pcap_parse_file(const char *path, nx_pcap_stats *stats, nx_flow_table *flows);

#ifdef __cplusplus
}
#endif
#endif /* NEXUS_PKT_H */
