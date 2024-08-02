#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define MAX_SOCKS 64
#define IPPROTO_UDP 17

struct {
        __uint(type, BPF_MAP_TYPE_XSKMAP);
        __type(key, __u32);
        __type(value, __u32);
        __uint(max_entries, MAX_SOCKS);
} xsks_map SEC(".maps");

SEC("xdp")
int xsk_redir_prog(struct xdp_md *ctx)
{
        __u32 index = ctx->rx_queue_index;

        void* data_start = (void*)(long)ctx->data;
        void* data_end = (void*)(long)ctx->data_end;

        if(data_start + sizeof(struct ethhdr) > data_end)
            return XDP_PASS;

        struct ethhdr eth;
        if (bpf_core_read(&eth, sizeof(eth), data_start))
            return XDP_ABORTED;

        // Check that the packet is an IPV4 packet
        if (eth.h_proto != __bpf_htons(ETH_P_IP))
            return XDP_PASS;

        if (data_start + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
            return XDP_PASS;

        struct iphdr ip;
        if (bpf_core_read(&ip, sizeof(ip), data_start + sizeof(struct ethhdr)))
            return XDP_ABORTED;

        // Check that the packet is an UDP packet
        if (ip.protocol != IPPROTO_UDP)
            return XDP_PASS;

        if (data_start + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
            return XDP_PASS;

        struct udphdr udp;
        if (bpf_core_read(&udp, sizeof(udp), data_start + sizeof(struct ethhdr) + sizeof(struct iphdr)))
            return XDP_ABORTED;

        // Check that the packet is a DNS packet (source port 53)
        if (bpf_ntohs(udp.source) != 53)
            return XDP_PASS;

        // Destination port should be between 1024 and 32767
        if (bpf_ntohs(udp.dest) < 1024 || bpf_ntohs(udp.dest) >= 32768)
            return XDP_PASS;

        if (bpf_map_lookup_elem(&xsks_map, &index))
            return bpf_redirect_map(&xsks_map, index, 0);

        return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
