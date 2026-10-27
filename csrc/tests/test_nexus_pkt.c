/* Unit tests for nexus_pkt. Plain C, no framework; run under ctest.
 * Build with -DNX_SANITIZE=ON to run the same tests under ASan/UBSan. */
#include "nexus_pkt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_failures;
static int g_checks;

#define CHECK(cond)                                                                    \
    do {                                                                               \
        g_checks++;                                                                    \
        if (!(cond)) {                                                                 \
            g_failures++;                                                              \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond);   \
        }                                                                              \
    } while (0)
#define CHECK_EQ(a, b) CHECK((long long)(a) == (long long)(b))

static size_t put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
    return 2;
}

static void put32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void put32be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/* Ethernet header with up to two VLAN tags. Returns bytes written. */
static size_t eth(uint8_t *p, uint16_t ethertype, int ntags, uint16_t vid0, uint16_t vid1)
{
    size_t o = 0;
    memset(p, 0xAA, 6);
    memset(p + 6, 0xBB, 6);
    o = 12;
    if (ntags >= 1) {
        o += put16(p + o, ntags == 2 ? 0x88A8 : 0x8100);
        o += put16(p + o, vid0);
    }
    if (ntags == 2) {
        o += put16(p + o, 0x8100);
        o += put16(p + o, vid1);
    }
    o += put16(p + o, ethertype);
    return o;
}

static size_t ipv4(uint8_t *p, uint8_t proto, uint16_t payload_len, uint16_t frag)
{
    memset(p, 0, 20);
    p[0] = 0x45;
    put16(p + 2, (uint16_t)(20 + payload_len));
    put16(p + 4, 0x1234);
    put16(p + 6, frag);
    p[8] = 64;
    p[9] = proto;
    p[12] = 10; p[13] = 0; p[14] = 0; p[15] = 1;
    p[16] = 10; p[17] = 0; p[18] = 0; p[19] = 2;
    put16(p + 10, nx_inet_checksum(p, 20));
    return 20;
}

static size_t l4ports(uint8_t *p, uint16_t sp, uint16_t dp, size_t hdrlen)
{
    memset(p, 0, hdrlen);
    put16(p, sp);
    put16(p + 2, dp);
    if (hdrlen == 20)
        p[12] = 0x50; /* TCP data offset 5 */
    return hdrlen;
}

static size_t udp4_frame(uint8_t *f, uint16_t sp, uint16_t dp)
{
    size_t o = eth(f, 0x0800, 0, 0, 0);
    o += ipv4(f + o, 17, 8, 0);
    o += l4ports(f + o, sp, dp, 8);
    return o;
}

static void test_checksum(void)
{
    /* RFC 1071 section 3 example */
    const uint8_t d[] = {0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7};
    CHECK_EQ(nx_inet_checksum(d, sizeof(d)), 0x220d);
    const uint8_t odd[] = {0x01};
    CHECK_EQ(nx_inet_checksum(odd, 1), 0xFEFF);
}

static void test_ipv4_udp(void)
{
    uint8_t f[128];
    size_t n = udp4_frame(f, 5353, 53);
    nx_frame_info fi;
    CHECK_EQ(nx_parse_frame(f, n, &fi), NX_OK);
    CHECK(fi.flags & NX_F_IPV4);
    CHECK(fi.flags & NX_F_HAS_PORTS);
    CHECK(!(fi.flags & (NX_F_BAD_CSUM | NX_F_TRUNCATED | NX_F_MALFORMED | NX_F_VLAN)));
    CHECK_EQ(fi.ip_proto, 17);
    CHECK_EQ(fi.src_port, 5353);
    CHECK_EQ(fi.dst_port, 53);
    CHECK_EQ(fi.src_ip[3], 1);
    CHECK_EQ(fi.dst_ip[3], 2);
    CHECK_EQ(fi.l3_offset, 14);
    CHECK_EQ(fi.l4_offset, 34);
    CHECK_EQ(fi.ip_ttl, 64);

    /* Ethernet padding beyond the IP total length must be ignored */
    memset(f + n, 0, 18);
    CHECK_EQ(nx_parse_frame(f, n + 18, &fi), NX_OK);
    CHECK(!(fi.flags & (NX_F_TRUNCATED | NX_F_MALFORMED)));

    f[14 + 10] ^= 0xFF; /* corrupt the IPv4 checksum */
    nx_parse_frame(f, n, &fi);
    CHECK(fi.flags & NX_F_BAD_CSUM);
}

static void test_vlan_qinq(void)
{
    uint8_t f[128];
    size_t o = eth(f, 0x0800, 1, 0x2000 | 100, 0); /* PCP bits must be masked */
    o += ipv4(f + o, 6, 20, 0);
    o += l4ports(f + o, 40000, 443, 20);
    nx_frame_info fi;
    nx_parse_frame(f, o, &fi);
    CHECK(fi.flags & NX_F_VLAN);
    CHECK(!(fi.flags & NX_F_QINQ));
    CHECK_EQ(fi.vlan_outer, 100);
    CHECK_EQ(fi.dst_port, 443);
    CHECK_EQ(fi.l3_offset, 18);

    o = eth(f, 0x0800, 2, 200, 300);
    o += ipv4(f + o, 17, 8, 0);
    o += l4ports(f + o, 1, 2, 8);
    nx_parse_frame(f, o, &fi);
    CHECK(fi.flags & NX_F_QINQ);
    CHECK_EQ(fi.vlan_outer, 200);
    CHECK_EQ(fi.vlan_inner, 300);
    CHECK_EQ(fi.ethertype, 0x0800);
    CHECK(fi.flags & NX_F_HAS_PORTS);

    /* three stacked tags is more than we accept */
    o = eth(f, 0x8100, 2, 1, 2);
    put16(f + o, 3);
    put16(f + o + 2, 0x0800);
    nx_parse_frame(f, o + 4, &fi);
    CHECK(fi.flags & NX_F_MALFORMED);
}

static void test_ipv4_fragments_and_malformed(void)
{
    uint8_t f[128];
    nx_frame_info fi;
    size_t o = eth(f, 0x0800, 0, 0, 0);
    o += ipv4(f + o, 17, 8, 0x2000); /* MF set, offset 0: first fragment */
    o += l4ports(f + o, 7, 9, 8);
    nx_parse_frame(f, o, &fi);
    CHECK(fi.flags & NX_F_FRAGMENT);
    CHECK(fi.flags & NX_F_HAS_PORTS);

    o = eth(f, 0x0800, 0, 0, 0);
    o += ipv4(f + o, 17, 8, 0x0010); /* offset 16*8: no L4 header */
    o += 8;
    nx_parse_frame(f, o, &fi);
    CHECK(fi.flags & NX_F_FRAGMENT);
    CHECK(!(fi.flags & NX_F_HAS_PORTS));
    CHECK_EQ(fi.l4_offset, 0);

    o = eth(f, 0x0800, 0, 0, 0);
    ipv4(f + o, 17, 8, 0);
    f[o] = 0x44; /* IHL 4 < 5 */
    nx_parse_frame(f, o + 28, &fi);
    CHECK(fi.flags & NX_F_MALFORMED);
    CHECK(!(fi.flags & NX_F_IPV4));

    ipv4(f + o, 17, 8, 0);
    f[o] = 0x65; /* version 6 inside an IPv4 ethertype */
    nx_parse_frame(f, o + 28, &fi);
    CHECK(fi.flags & NX_F_MALFORMED);
}

static size_t ipv6_hdr(uint8_t *p, uint8_t nh, uint16_t payload)
{
    memset(p, 0, 40);
    p[0] = 0x60;
    put16(p + 4, payload);
    p[6] = nh;
    p[7] = 255;
    p[8] = 0x20; p[9] = 0x01; p[10] = 0x0d; p[11] = 0xb8; p[23] = 1;
    p[24] = 0x20; p[25] = 0x01; p[26] = 0x0d; p[27] = 0xb8; p[39] = 2;
    return 40;
}

static void test_ipv6(void)
{
    uint8_t f[256];
    nx_frame_info fi;
    /* IPv6 + hop-by-hop (8 bytes) + TCP */
    size_t o = eth(f, 0x86DD, 0, 0, 0);
    o += ipv6_hdr(f + o, 0, 8 + 20);
    memset(f + o, 0, 8);
    f[o] = 6; /* next header TCP */
    f[o + 1] = 0; /* (0+1)*8 bytes */
    o += 8;
    o += l4ports(f + o, 50000, 22, 20);
    nx_parse_frame(f, o, &fi);
    CHECK(fi.flags & NX_F_IPV6);
    CHECK_EQ(fi.ip_proto, 6);
    CHECK_EQ(fi.dst_port, 22);
    CHECK_EQ(fi.src_ip[15], 1);
    CHECK_EQ(fi.ip_ttl, 255);
    CHECK_EQ(fi.l4_offset, 14 + 40 + 8);

    /* non-first fragment: proto known, no ports */
    o = eth(f, 0x86DD, 0, 0, 0);
    o += ipv6_hdr(f + o, 44, 8 + 8);
    memset(f + o, 0, 8);
    f[o] = 17;
    put16(f + o + 2, (uint16_t)(185 << 3));
    o += 16;
    nx_parse_frame(f, o, &fi);
    CHECK(fi.flags & NX_F_FRAGMENT);
    CHECK_EQ(fi.ip_proto, 17);
    CHECK(!(fi.flags & NX_F_HAS_PORTS));

    /* extension header chain that runs off the end of the packet */
    o = eth(f, 0x86DD, 0, 0, 0);
    o += ipv6_hdr(f + o, 60, 8);
    memset(f + o, 0, 8);
    f[o] = 17;
    f[o + 1] = 4; /* claims 40 bytes */
    o += 8;
    nx_parse_frame(f, o, &fi);
    CHECK(fi.flags & NX_F_TRUNCATED);

    /* ICMPv6 */
    o = eth(f, 0x86DD, 0, 0, 0);
    o += ipv6_hdr(f + o, 58, 8);
    memset(f + o, 0, 8);
    o += 8;
    nx_parse_frame(f, o, &fi);
    CHECK_EQ(fi.ip_proto, 58);
    CHECK(!(fi.flags & (NX_F_HAS_PORTS | NX_F_TRUNCATED)));
}

static void test_truncation_every_length(void)
{
    uint8_t f[128];
    size_t n = udp4_frame(f, 1000, 2000);
    for (size_t len = 0; len < n; len++) {
        /* copy to an exact-size heap buffer so ASan catches any over-read */
        uint8_t *exact = malloc(len ? len : 1);
        memcpy(exact, f, len);
        nx_frame_info fi;
        CHECK_EQ(nx_parse_frame(len ? exact : NULL, len, &fi), NX_OK);
        CHECK(fi.flags & NX_F_TRUNCATED);
        CHECK(!(fi.flags & NX_F_HAS_PORTS) || len >= 14 + 20 + 4);
        free(exact);
    }
    nx_frame_info fi;
    CHECK_EQ(nx_parse_frame(NULL, 10, &fi), NX_ERR_ARG);
    CHECK_EQ(nx_parse_frame(f, 10, NULL), NX_ERR_ARG);
}

static void test_arp(void)
{
    uint8_t f[64];
    size_t o = eth(f, 0x0806, 0, 0, 0);
    memset(f + o, 0, 28);
    nx_frame_info fi;
    nx_parse_frame(f, o + 28, &fi);
    CHECK(fi.flags & NX_F_ARP);
    CHECK(!(fi.flags & NX_F_TRUNCATED));
    nx_parse_frame(f, o + 10, &fi);
    CHECK(fi.flags & NX_F_TRUNCATED);
}

/* ---- pcap images ------------------------------------------------------ */

typedef struct img {
    uint8_t buf[4096];
    size_t len;
    int be;
} img;

static void img_put32(img *m, uint32_t v)
{
    if (m->be)
        put32be(m->buf + m->len, v);
    else
        put32le(m->buf + m->len, v);
    m->len += 4;
}

static void img_global(img *m, uint32_t magic, uint32_t linktype)
{
    m->len = 0;
    img_put32(m, magic);
    m->buf[m->len] = 0; m->buf[m->len + 1] = 2; /* version fields: unchecked */
    m->buf[m->len + 2] = 0; m->buf[m->len + 3] = 4;
    m->len += 4;
    img_put32(m, 0);
    img_put32(m, 0);
    img_put32(m, 65535);
    img_put32(m, linktype);
}

static void img_rec(img *m, uint32_t sec, uint32_t frac, const uint8_t *d, uint32_t caplen,
                    uint32_t wire)
{
    img_put32(m, sec);
    img_put32(m, frac);
    img_put32(m, caplen);
    img_put32(m, wire);
    memcpy(m->buf + m->len, d, caplen);
    m->len += caplen;
}

static void build_three(img *m, uint32_t magic)
{
    uint8_t f[128];
    size_t n = udp4_frame(f, 1111, 53);
    img_global(m, magic, 1);
    img_rec(m, 100, 5, f, (uint32_t)n, (uint32_t)n);
    img_rec(m, 100, 6, f, (uint32_t)n, (uint32_t)n);
    img_rec(m, 101, 7, f, 20, (uint32_t)n); /* snaplen-truncated */
}

static void test_pcap_buffer(void)
{
    static img m;
    nx_pcap_stats s;
    nx_flow slots[16];
    nx_flow_table t;

    m.be = 0;
    build_three(&m, 0xA1B2C3D4u);
    CHECK_EQ(nx_flow_table_init(&t, slots, 16), NX_OK);
    CHECK_EQ(nx_pcap_parse_buffer(m.buf, m.len, &s, &t), NX_OK);
    CHECK_EQ(s.packets, 3);
    CHECK_EQ(s.ipv4, 2);
    CHECK_EQ(s.udp, 2);
    CHECK_EQ(s.other_l3, 1); /* the truncated frame never reached L3 */
    CHECK_EQ(s.truncated, 1);
    CHECK_EQ(s.bytes_wire, 3 * 42);
    CHECK_EQ(s.bytes_captured, 42 + 42 + 20);
    CHECK_EQ(s.first_ts_ns, 100000005000ull);
    CHECK_EQ(s.last_ts_ns, 101000007000ull);
    CHECK_EQ(s.min_wire_len, 42);
    CHECK_EQ(t.used, 1);
    CHECK_EQ(t.dropped, 0);

    /* byte-swapped writer + nanosecond timestamps */
    m.be = 1;
    build_three(&m, 0xA1B23C4Du);
    CHECK_EQ(nx_pcap_parse_buffer(m.buf, m.len, &s, NULL), NX_OK);
    CHECK_EQ(s.packets, 3);
    CHECK_EQ(s.first_ts_ns, 100000000005ull);

    m.be = 0;
    build_three(&m, 0xA1B2C3D4u);
    CHECK_EQ(nx_pcap_parse_buffer(m.buf, m.len - 5, &s, NULL), NX_ERR_TRUNCATED);
    CHECK_EQ(s.packets, 2); /* counters cover the readable part */

    img_global(&m, 0xA1B2C3D4u, 101); /* LINKTYPE_RAW */
    CHECK_EQ(nx_pcap_parse_buffer(m.buf, m.len, &s, NULL), NX_ERR_LINKTYPE);
    img_global(&m, 0x0A0D0D0Au, 1); /* pcapng section header */
    CHECK_EQ(nx_pcap_parse_buffer(m.buf, m.len, &s, NULL), NX_ERR_BAD_MAGIC);
    CHECK_EQ(nx_pcap_parse_buffer(m.buf, 3, &s, NULL), NX_ERR_BAD_MAGIC);
    img_global(&m, 0xA1B2C3D4u, 1);
    CHECK_EQ(nx_pcap_parse_buffer(m.buf, 10, &s, NULL), NX_ERR_TRUNCATED);

    img_global(&m, 0xA1B2C3D4u, 1);
    img_put32(&m, 0);
    img_put32(&m, 0);
    img_put32(&m, NX_MAX_CAPLEN + 1);
    img_put32(&m, NX_MAX_CAPLEN + 1);
    CHECK_EQ(nx_pcap_parse_buffer(m.buf, m.len, &s, NULL), NX_ERR_BAD_RECORD);

    /* caplen > wire length is internally inconsistent */
    uint8_t f[64];
    size_t n = udp4_frame(f, 1, 2);
    img_global(&m, 0xA1B2C3D4u, 1);
    img_rec(&m, 1, 0, f, (uint32_t)n, 10);
    CHECK_EQ(nx_pcap_parse_buffer(m.buf, m.len, &s, NULL), NX_OK);
    CHECK_EQ(s.malformed, 1);

    CHECK_EQ(nx_pcap_parse_buffer(NULL, 5, &s, NULL), NX_ERR_ARG);
    CHECK_EQ(nx_pcap_parse_buffer(m.buf, m.len, NULL, NULL), NX_ERR_ARG);
}

static void test_flow_table(void)
{
    nx_flow slots[8];
    nx_flow_table t;
    CHECK_EQ(nx_flow_table_init(&t, slots, 6), NX_ERR_ARG);
    CHECK_EQ(nx_flow_table_init(&t, NULL, 8), NX_ERR_ARG);
    CHECK_EQ(nx_flow_table_init(&t, slots, 8), NX_OK);
    uint8_t f[128];
    nx_frame_info fi;
    for (uint16_t sp = 1; sp <= 20; sp++) {
        size_t n = udp4_frame(f, sp, 53);
        nx_parse_frame(f, n, &fi);
        nx_flow_table_add(&t, &fi, (uint32_t)n);
        nx_flow_table_add(&t, &fi, (uint32_t)n);
    }
    CHECK_EQ(t.used, 7); /* 8 slots minus 12.5% headroom */
    CHECK_EQ(t.dropped, 26);
    uint64_t pk = 0;
    for (int i = 0; i < 8; i++)
        if (slots[i].ip_version) {
            pk += slots[i].packets;
            CHECK_EQ(slots[i].packets, 2);
            CHECK_EQ(slots[i].bytes, 84);
        }
    CHECK_EQ(pk, 14);
    /* non-IP frames are ignored, not counted as drops */
    size_t o = eth(f, 0x0806, 0, 0, 0);
    nx_parse_frame(f, o + 28, &fi);
    nx_flow_table_add(&t, &fi, 42);
    CHECK_EQ(t.dropped, 26);
}

static void test_pcap_file(const char *dir)
{
    static img m;
    char path[1024];
    snprintf(path, sizeof(path), "%s/nx_test.pcap", dir);
    m.be = 0;
    build_three(&m, 0xA1B2C3D4u);
    FILE *fp = fopen(path, "wb");
    CHECK(fp != NULL);
    if (!fp)
        return;
    fwrite(m.buf, 1, m.len, fp);
    fclose(fp);
    nx_pcap_stats a, b;
    CHECK_EQ(nx_pcap_parse_file(path, &a, NULL), NX_OK);
    CHECK_EQ(nx_pcap_parse_buffer(m.buf, m.len, &b, NULL), NX_OK);
    CHECK(memcmp(&a, &b, sizeof(a)) == 0);

    fp = fopen(path, "wb");
    fwrite(m.buf, 1, m.len - 3, fp);
    fclose(fp);
    CHECK_EQ(nx_pcap_parse_file(path, &a, NULL), NX_ERR_TRUNCATED);
    CHECK_EQ(a.packets, 2);
    remove(path);
    CHECK_EQ(nx_pcap_parse_file("/nonexistent/x.pcap", &a, NULL), NX_ERR_IO);
}

/* Deterministic garbage: the parser must never crash or over-read. */
static void test_random_input(void)
{
    uint32_t x = 0x12345678u;
    uint8_t *buf = malloc(512);
    nx_flow slots[64];
    nx_flow_table t;
    nx_flow_table_init(&t, slots, 64);
    for (int iter = 0; iter < 20000; iter++) {
        size_t len = 0;
        x = x * 1664525u + 1013904223u;
        len = (x >> 8) % 512;
        for (size_t i = 0; i < len; i++) {
            x = x * 1664525u + 1013904223u;
            buf[i] = (uint8_t)(x >> 24);
        }
        if (len > 13 && (iter & 1)) { /* bias towards IP ethertypes */
            buf[12] = (iter & 2) ? 0x86 : 0x08;
            buf[13] = (iter & 2) ? 0xDD : 0x00;
            if (len > 14)
                buf[14] = (iter & 2) ? 0x60 : 0x45;
        }
        uint8_t *exact = malloc(len ? len : 1);
        memcpy(exact, buf, len);
        nx_frame_info fi;
        nx_parse_frame(len ? exact : NULL, len, &fi);
        nx_flow_table_add(&t, &fi, (uint32_t)len);
        free(exact);
    }
    free(buf);
    CHECK(t.used <= 64);
}

int main(int argc, char **argv)
{
    const char *dir = argc > 1 ? argv[1] : ".";
    CHECK_EQ(nx_abi_version(), NX_ABI_VERSION);
    CHECK(strcmp(nx_strerror(NX_ERR_LINKTYPE), "unknown error") != 0);
    test_checksum();
    test_ipv4_udp();
    test_vlan_qinq();
    test_ipv4_fragments_and_malformed();
    test_ipv6();
    test_truncation_every_length();
    test_arp();
    test_pcap_buffer();
    test_flow_table();
    test_pcap_file(dir);
    test_random_input();
    printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
