#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u8);
} blocked_ports SEC(".maps");

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_DROP;

    __u32 ihl_bytes = (__u32)iph->ihl * 4;
    if (ihl_bytes < sizeof(*iph))
        return XDP_PASS;
    if ((void *)iph + ihl_bytes > data_end)
        return XDP_PASS;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + ihl_bytes;
        if ((void *)(tcph + 1) > data_end)
            return XDP_PASS;

        __u32 dport = bpf_ntohs(tcph->dest);
        __u8 *blocked = bpf_map_lookup_elem(&blocked_ports, &dport);
        if (blocked && *blocked)
            return XDP_DROP;
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (void *)iph + ihl_bytes;
        if ((void *)(udph + 1) > data_end)
            return XDP_PASS;

        __u32 dport = bpf_ntohs(udph->dest);
        __u8 *blocked = bpf_map_lookup_elem(&blocked_ports, &dport);
        if (blocked && *blocked)
            return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";