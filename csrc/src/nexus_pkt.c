/* nexus_pkt.c - see nexus_pkt.h for the contract. */
#include "nexus_pkt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ETH_HDR_LEN 14u
#define VLAN_TAG_LEN 4u
#define MAX_VLAN_TAGS 2u
#define MAX_V6_EXT_HDRS 8u

#define ETHERTYPE_IPV4 0x0800u
#define ETHERTYPE_ARP 0x0806u
#define ETHERTYPE_VLAN 0x8100u
#define ETHERTYPE_QINQ 0x88A8u
#define ETHERTYPE_IPV6 0x86DDu

#define PCAP_GLOBAL_HDR_LEN 24u
#define PCAP_REC_HDR_LEN 16u
#define LINKTYPE_ETHERNET 1u

static inline uint16_t rd16be(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }

static inline uint32_t rd32(const uint8_t *p, int swap)
{
    uint32_t le = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
                  ((uint32_t)p[3] << 24);
    if (!swap)
        return le;
    return (le >> 24) | ((le >> 8) & 0x0000FF00u) | ((le << 8) & 0x00FF0000u) | (le << 24);
}

int nx_abi_version(void) { return NX_ABI_VERSION; }

const char *nx_strerror(int status)
{
    switch (status) {
    case NX_OK: return "ok";
    case NX_ERR_ARG: return "invalid argument";
    case NX_ERR_IO: return "i/o error";
    case NX_ERR_BAD_MAGIC: return "not a classic pcap file (bad magic)";
    case NX_ERR_LINKTYPE: return "unsupported link type (only Ethernet is supported)";
    case NX_ERR_TRUNCATED: return "file truncated mid-record";
    case NX_ERR_NOMEM: return "flow table storage too small";
    case NX_ERR_BAD_RECORD: return "record length exceeds maximum capture length";
    default: return "unknown error";
    }
}

uint16_t nx_inet_checksum(const uint8_t *data, size_t len)
{
    uint32_t sum = 0;
    size_t i = 0;
    for (; i + 1 < len; i += 2)
        sum += rd16be(data + i);
    if (i < len)
        sum += (uint32_t)data[i] << 8;
    while (sum >> 16)
        sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)~sum;
}

static void parse_ports(const uint8_t *l4, size_t avail, nx_frame_info *info)
{
    if (info->ip_proto != 6 && info->ip_proto != 17)
        return;
    if (avail < 4) {
        info->flags |= NX_F_TRUNCATED;
        return;
    }
    info->src_port = rd16be(l4);
    info->dst_port = rd16be(l4 + 2);
    info->flags |= NX_F_HAS_PORTS;
}

static void parse_ipv4(const uint8_t *frame, size_t caplen, size_t off, nx_frame_info *info)
{
    size_t avail = caplen - off;
    const uint8_t *ip = frame + off;
    if (avail < 20) {
        info->flags |= NX_F_TRUNCATED;
        return;
    }
    if ((ip[0] >> 4) != 4) {
        info->flags |= NX_F_MALFORMED;
        return;
    }
    size_t ihl = (size_t)(ip[0] & 0x0F) * 4u;
    uint16_t total = rd16be(ip + 2);
    if (ihl < 20 || total < ihl) {
        info->flags |= NX_F_MALFORMED;
        return;
    }
    if (avail < ihl) {
        info->flags |= NX_F_TRUNCATED;
        return;
    }
    info->flags |= NX_F_IPV4;
    info->l3_offset = (uint16_t)off;
    info->l3_len = total;
    info->ip_ttl = ip[8];
    info->ip_proto = ip[9];
    memcpy(info->src_ip, ip + 12, 4);
    memcpy(info->dst_ip, ip + 16, 4);
    if (nx_inet_checksum(ip, ihl) != 0)
        info->flags |= NX_F_BAD_CSUM;

    uint16_t frag = rd16be(ip + 6);
    uint16_t frag_off = frag & 0x1FFFu;
    if ((frag & 0x2000u) || frag_off)
        info->flags |= NX_F_FRAGMENT;

    /* Ethernet may pad short frames; trust the IP total length, but never
     * read beyond what was captured. */
    size_t l3_avail = avail < total ? avail : total;
    if (total > avail)
        info->flags |= NX_F_TRUNCATED;
    if (frag_off)
        return; /* non-first fragment: no L4 header */
    info->l4_offset = (uint16_t)(off + ihl);
    parse_ports(ip + ihl, l3_avail - ihl, info);
}

static int is_v6_ext(uint8_t nh) { return nh == 0 || nh == 43 || nh == 44 || nh == 60; }

static void parse_ipv6(const uint8_t *frame, size_t caplen, size_t off, nx_frame_info *info)
{
    size_t avail = caplen - off;
    const uint8_t *ip = frame + off;
    if (avail < 40) {
        info->flags |= NX_F_TRUNCATED;
        return;
    }
    if ((ip[0] >> 4) != 6) {
        info->flags |= NX_F_MALFORMED;
        return;
    }
    uint16_t payload = rd16be(ip + 4);
    info->flags |= NX_F_IPV6;
    info->l3_offset = (uint16_t)off;
    info->l3_len = 40u + payload;
    info->ip_ttl = ip[7];
    memcpy(info->src_ip, ip + 8, 16);
    memcpy(info->dst_ip, ip + 24, 16);

    size_t l3_avail = avail;
    if ((size_t)payload + 40u > avail)
        info->flags |= NX_F_TRUNCATED;
    else
        l3_avail = (size_t)payload + 40u;

    uint8_t nh = ip[6];
    size_t pos = 40;
    for (unsigned n = 0; is_v6_ext(nh); n++) {
        if (n >= MAX_V6_EXT_HDRS) {
            info->flags |= NX_F_MALFORMED;
            info->ip_proto = nh;
            return;
        }
        if (pos + 8 > l3_avail) {
            info->flags |= NX_F_TRUNCATED;
            info->ip_proto = nh;
            return;
        }
        const uint8_t *ext = ip + pos;
        if (nh == 44) {
            info->flags |= NX_F_FRAGMENT;
            uint16_t fo = rd16be(ext + 2) >> 3;
            nh = ext[0];
            pos += 8;
            if (fo) {
                info->ip_proto = nh;
                return;
            }
            continue;
        }
        size_t hlen = ((size_t)ext[1] + 1u) * 8u;
        nh = ext[0];
        pos += hlen;
        if (pos > l3_avail) {
            info->flags |= NX_F_TRUNCATED;
            info->ip_proto = nh;
            return;
        }
    }
    info->ip_proto = nh;
    info->l4_offset = (uint16_t)(off + pos);
    parse_ports(ip + pos, l3_avail - pos, info);
}

int nx_parse_frame(const uint8_t *frame, size_t caplen, nx_frame_info *info)
{
    if (!info)
        return NX_ERR_ARG;
    memset(info, 0, sizeof(*info));
    if (!frame && caplen)
        return NX_ERR_ARG;
    if (caplen < ETH_HDR_LEN) {
        info->flags |= NX_F_TRUNCATED;
        return NX_OK;
    }
    size_t off = 12;
    uint16_t et = rd16be(frame + off);
    unsigned tags = 0;
    while (et == ETHERTYPE_VLAN || et == ETHERTYPE_QINQ) {
        if (tags >= MAX_VLAN_TAGS) {
            info->flags |= NX_F_MALFORMED;
            break;
        }
        if (off + 2 + VLAN_TAG_LEN > caplen) {
            info->flags |= NX_F_TRUNCATED;
            info->ethertype = et;
            return NX_OK;
        }
        uint16_t vid = rd16be(frame + off + 2) & 0x0FFFu;
        if (tags == 0)
            info->vlan_outer = vid;
        else
            info->vlan_inner = vid;
        tags++;
        off += VLAN_TAG_LEN;
        et = rd16be(frame + off);
    }
    if (tags)
        info->flags |= NX_F_VLAN;
    if (tags > 1)
        info->flags |= NX_F_QINQ;
    info->ethertype = et;
    if (info->flags & NX_F_MALFORMED)
        return NX_OK;
    off += 2; /* past the ethertype field */

    switch (et) {
    case ETHERTYPE_IPV4: parse_ipv4(frame, caplen, off, info); break;
    case ETHERTYPE_IPV6: parse_ipv6(frame, caplen, off, info); break;
    case ETHERTYPE_ARP:
        info->flags |= NX_F_ARP;
        if (caplen - off < 28)
            info->flags |= NX_F_TRUNCATED;
        break;
    default: break;
    }
    return NX_OK;
}

/* ---- flow table ------------------------------------------------------- */

int nx_flow_table_init(nx_flow_table *t, nx_flow *slots, uint32_t capacity)
{
    if (!t || !slots || capacity == 0 || (capacity & (capacity - 1)) != 0)
        return NX_ERR_ARG;
    memset(slots, 0, sizeof(*slots) * capacity);
    t->slots = slots;
    t->capacity = capacity;
    t->used = 0;
    t->dropped = 0;
    return NX_OK;
}

static uint32_t fnv1a(const uint8_t *p, size_t n, uint32_t h)
{
    for (size_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}

void nx_flow_table_add(nx_flow_table *t, const nx_frame_info *info, uint32_t wire_len)
{
    if (!t || !info || !t->slots)
        return;
    uint8_t ver = (info->flags & NX_F_IPV4) ? 4 : (info->flags & NX_F_IPV6) ? 6 : 0;
    if (!ver)
        return;
    size_t alen = ver == 4 ? 4 : 16;
    uint16_t sp = (info->flags & NX_F_HAS_PORTS) ? info->src_port : 0;
    uint16_t dp = (info->flags & NX_F_HAS_PORTS) ? info->dst_port : 0;
    uint8_t ports[5] = {(uint8_t)(sp >> 8), (uint8_t)sp, (uint8_t)(dp >> 8), (uint8_t)dp,
                        info->ip_proto};
    uint32_t h = 2166136261u;
    h = fnv1a(info->src_ip, alen, h);
    h = fnv1a(info->dst_ip, alen, h);
    h = fnv1a(ports, sizeof(ports), h);

    uint32_t mask = t->capacity - 1;
    for (uint32_t probe = 0; probe < t->capacity; probe++) {
        nx_flow *f = &t->slots[(h + probe) & mask];
        if (f->ip_version == 0) {
            if (t->used >= t->capacity - (t->capacity >> 3) && t->capacity > 1) {
                /* keep ~12.5% headroom so probe chains stay short */
                t->dropped++;
                return;
            }
            memcpy(f->src_ip, info->src_ip, alen);
            memcpy(f->dst_ip, info->dst_ip, alen);
            f->src_port = sp;
            f->dst_port = dp;
            f->ip_proto = info->ip_proto;
            f->ip_version = ver;
            f->packets = 1;
            f->bytes = wire_len;
            t->used++;
            return;
        }
        if (f->ip_version == ver && f->ip_proto == info->ip_proto && f->src_port == sp &&
            f->dst_port == dp && memcmp(f->src_ip, info->src_ip, alen) == 0 &&
            memcmp(f->dst_ip, info->dst_ip, alen) == 0) {
            f->packets++;
            f->bytes += wire_len;
            return;
        }
    }
    t->dropped++;
}

/* ---- pcap ------------------------------------------------------------- */

typedef struct pcap_ctx {
    int swap;
    int nsec;
} pcap_ctx;

static int parse_global(const uint8_t *g, pcap_ctx *ctx)
{
    uint32_t magic = rd32(g, 0);
    switch (magic) {
    case 0xA1B2C3D4u: ctx->swap = 0; ctx->nsec = 0; break;
    case 0xA1B23C4Du: ctx->swap = 0; ctx->nsec = 1; break;
    case 0xD4C3B2A1u: ctx->swap = 1; ctx->nsec = 0; break;
    case 0x4D3CB2A1u: ctx->swap = 1; ctx->nsec = 1; break;
    default: return NX_ERR_BAD_MAGIC;
    }
    uint32_t linktype = rd32(g + 20, ctx->swap) & 0x0FFFFFFFu;
    if (linktype != LINKTYPE_ETHERNET)
        return NX_ERR_LINKTYPE;
    return NX_OK;
}

static void account(nx_pcap_stats *s, nx_flow_table *flows, const pcap_ctx *ctx,
                    const uint8_t *rec, const uint8_t *data, uint32_t caplen, uint32_t wire)
{
    uint64_t sec = rd32(rec, ctx->swap);
    uint64_t frac = rd32(rec + 4, ctx->swap);
    uint64_t ts = sec * 1000000000ull + (ctx->nsec ? frac : frac * 1000ull);
    if (s->packets == 0) {
        s->first_ts_ns = ts;
        s->min_wire_len = wire;
        s->max_wire_len = wire;
    }
    s->last_ts_ns = ts;
    s->packets++;
    s->bytes_captured += caplen;
    s->bytes_wire += wire;
    if (wire < s->min_wire_len)
        s->min_wire_len = wire;
    if (wire > s->max_wire_len)
        s->max_wire_len = wire;

    nx_frame_info fi;
    nx_parse_frame(data, caplen, &fi);
    if (caplen > wire)
        fi.flags |= NX_F_MALFORMED;
    if (caplen < wire || (fi.flags & NX_F_TRUNCATED))
        s->truncated++;
    if (fi.flags & NX_F_MALFORMED)
        s->malformed++;
    if (fi.flags & NX_F_VLAN)
        s->vlan_tagged++;
    if (fi.flags & NX_F_QINQ)
        s->qinq++;
    if (fi.flags & NX_F_FRAGMENT)
        s->fragments++;
    if (fi.flags & NX_F_BAD_CSUM)
        s->bad_ipv4_csum++;
    if (fi.flags & NX_F_ARP) {
        s->arp++;
    } else if (fi.flags & (NX_F_IPV4 | NX_F_IPV6)) {
        if (fi.flags & NX_F_IPV4)
            s->ipv4++;
        else
            s->ipv6++;
        switch (fi.ip_proto) {
        case 6: s->tcp++; break;
        case 17: s->udp++; break;
        case 1:
        case 58: s->icmp++; break;
        default: s->other_l4++; break;
        }
    } else {
        s->other_l3++;
    }
    if (flows)
        nx_flow_table_add(flows, &fi, wire);
}

int nx_pcap_parse_buffer(const uint8_t *buf, size_t len, nx_pcap_stats *stats,
                         nx_flow_table *flows)
{
    if (!stats || (!buf && len))
        return NX_ERR_ARG;
    memset(stats, 0, sizeof(*stats));
    pcap_ctx ctx;
    if (len < PCAP_GLOBAL_HDR_LEN) {
        uint8_t padded[PCAP_GLOBAL_HDR_LEN] = {0};
        if (len < 4)
            return NX_ERR_BAD_MAGIC;
        memcpy(padded, buf, len);
        return parse_global(padded, &ctx) == NX_ERR_BAD_MAGIC ? NX_ERR_BAD_MAGIC
                                                               : NX_ERR_TRUNCATED;
    }
    int rc = parse_global(buf, &ctx);
    if (rc != NX_OK)
        return rc;
    size_t pos = PCAP_GLOBAL_HDR_LEN;
    while (pos < len) {
        if (len - pos < PCAP_REC_HDR_LEN)
            return NX_ERR_TRUNCATED;
        const uint8_t *rec = buf + pos;
        uint32_t caplen = rd32(rec + 8, ctx.swap);
        uint32_t wire = rd32(rec + 12, ctx.swap);
        if (caplen > NX_MAX_CAPLEN)
            return NX_ERR_BAD_RECORD;
        pos += PCAP_REC_HDR_LEN;
        if (len - pos < caplen)
            return NX_ERR_TRUNCATED;
        account(stats, flows, &ctx, rec, buf + pos, caplen, wire);
        pos += caplen;
    }
    return NX_OK;
}

int nx_pcap_parse_file(const char *path, nx_pcap_stats *stats, nx_flow_table *flows)
{
    if (!path || !stats)
        return NX_ERR_ARG;
    memset(stats, 0, sizeof(*stats));
    FILE *fp = fopen(path, "rb");
    if (!fp)
        return NX_ERR_IO;
    int rc = NX_OK;
    uint8_t *data = NULL;
    uint8_t g[PCAP_GLOBAL_HDR_LEN];
    size_t got = fread(g, 1, sizeof(g), fp);
    if (got < sizeof(g)) {
        rc = got < 4 ? NX_ERR_BAD_MAGIC : NX_ERR_TRUNCATED;
        if (got >= 4) {
            pcap_ctx tmp;
            /* report a bad magic in preference to truncation */
            uint8_t padded[PCAP_GLOBAL_HDR_LEN] = {0};
            memcpy(padded, g, got);
            if (parse_global(padded, &tmp) == NX_ERR_BAD_MAGIC)
                rc = NX_ERR_BAD_MAGIC;
        }
        goto out;
    }
    pcap_ctx ctx;
    rc = parse_global(g, &ctx);
    if (rc != NX_OK)
        goto out;
    data = malloc(NX_MAX_CAPLEN);
    if (!data) {
        rc = NX_ERR_NOMEM;
        goto out;
    }
    for (;;) {
        uint8_t rec[PCAP_REC_HDR_LEN];
        got = fread(rec, 1, sizeof(rec), fp);
        if (got == 0)
            break;
        if (got < sizeof(rec)) {
            rc = NX_ERR_TRUNCATED;
            break;
        }
        uint32_t caplen = rd32(rec + 8, ctx.swap);
        uint32_t wire = rd32(rec + 12, ctx.swap);
        if (caplen > NX_MAX_CAPLEN) {
            rc = NX_ERR_BAD_RECORD;
            break;
        }
        if (fread(data, 1, caplen, fp) != caplen) {
            rc = NX_ERR_TRUNCATED;
            break;
        }
        account(stats, flows, &ctx, rec, data, caplen, wire);
    }
    if (rc == NX_OK && ferror(fp))
        rc = NX_ERR_IO;
out:
    free(data);
    fclose(fp);
    return rc;
}
