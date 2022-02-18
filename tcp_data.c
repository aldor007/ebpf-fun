

#include <linux/bpf.h>
#include <bpf_helpers.h>

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ipv6.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>

__u32 _version SEC("version") = 1;

char LICENSE[] SEC("license") = "Dual MIT/GPL";


#ifndef __packed
#define __packed __attribute__((packed))
#endif

#define min(x, y) ((x) < (y) ? (x) : (y))

#define bpf_printk(fmt, ...)					\
({								\
	       char ____fmt[] = fmt;				\
	       bpf_trace_printk(____fmt, sizeof(____fmt),	\
				##__VA_ARGS__);			\
})

// FIXME: use ringbufer
// struct {
// 	__uint(type, BPF_MAP_TYPE_RINGBUF);
// 	__uint(max_entries, 256 * 1024);
// } events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    // __uint(max_entries, 1);
	// __uint(key_size, sizeof(int));
	// __uint(value_size, 4);
} events SEC(".maps");


SEC("xdp_sample")
int xdp_sample_prog(struct xdp_md *ctx) {
    struct event_t {
        __u16 sport;
        __u16 dport;
        __be32 saddr;
        __be32 daddr;
    } __packed;

    struct event_t connection_info;
    __builtin_memset(&connection_info, 0, sizeof(struct event_t));

	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
    int rc_default = XDP_PASS;

	if (data < data_end) {
        __u16 h_proto;
        __u64 nh_off = 0;

        struct ethhdr *eth = data;
        nh_off = sizeof(*eth);


        h_proto = eth->h_proto;
        if (data + nh_off > data_end) {
            return rc_default;
        }
        if (h_proto == htons(ETH_P_IP)) {
            struct iphdr *iph = (void*)eth + nh_off;
             if (data + nh_off + sizeof(struct iphdr) > data_end) {
                return rc_default;
            }
            h_proto = iph->protocol;
            connection_info.saddr = iph->saddr;
            connection_info.daddr= iph->daddr;
            nh_off += sizeof(struct iphdr);
        } else if (h_proto == htons(ETH_P_IPV6)) {
             if (data + nh_off + sizeof(struct ipv6hdr) > data_end) {
                return rc_default;
            }
            struct ipv6hdr *ip6h = data + nh_off;
            h_proto = ip6h->nexthdr;
            // FIXME: convert IPv6 to number
            // connection_info->saddr = ip6h->saddr;
            // connection_info->daddr = ip6h->daddr;
            nh_off += sizeof(struct ipv6hdr);
        } else {
            return rc_default;
        }

        if (h_proto == IPPROTO_TCP) {
            struct tcphdr *tcph = data + nh_off;
             if (data + nh_off + sizeof(struct tcphdr) > data_end) {
                return rc_default;
            }

            connection_info.dport = tcph->dest;
            connection_info.sport = tcph->source;
        } else if (h_proto == IPPROTO_UDP) {
            struct udphdr *udph = data + nh_off;
             if (data + nh_off + sizeof(struct udphdr) > data_end) {
                return rc_default;
            }
            connection_info.dport = udph->dest;
            connection_info.sport = udph->source;

        }

        int ret = bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &connection_info, sizeof(struct event_t));
		if (ret)
			bpf_printk("perf_event_output failed: %d\n", ret);
	}

	return rc_default;

}