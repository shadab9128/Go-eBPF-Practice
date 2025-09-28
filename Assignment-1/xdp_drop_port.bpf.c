#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>   // For __bpf_htons

#define IPPROTO_TCP 6         // Define TCP protocol manually

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} drop_port_map SEC(".maps");

SEC("xdp")
int xdp_drop_port_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void*)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void*)ip + ip->ihl * 4;
    if ((void*)(tcp + 1) > data_end)
        return XDP_PASS;

    __u32 key = 0;
    __u16 *drop_port = bpf_map_lookup_elem(&drop_port_map, &key);
    if (!drop_port)
        return XDP_PASS;

    if (tcp->dest == __bpf_htons(*drop_port))
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

