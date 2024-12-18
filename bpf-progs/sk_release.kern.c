#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

#define ITERS 1 << 5

static int simple()
{
	bpf_printk("Hello world ;)\n");
	return 0;
}


static int loop3()
{
	bpf_loop(ITERS, simple, NULL, 0);
	return 0;
}

static int loop2()
{
	bpf_loop(ITERS, loop3, NULL, 0);
	return 0;
}

static int loop1()
{
	bpf_loop(ITERS, loop2, NULL, 0);
	return 0;
}


SEC("tc/ingress")
int big(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // invalid ethernet header then drop the packet
    if (data + sizeof(struct ethhdr) > data_end) {
        return BPF_DROP;
    }

    struct ethhdr *eth = data;

    // everything but IPV4 should not drop
    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return BPF_OK;
    }

    // invalid ip header should drop
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
        return BPF_DROP;
    }

    
    struct tcphdr *tcp;
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end) {
        return BPF_DROP;
    }

    tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    struct bpf_sock_tuple tuple;
	tuple.ipv4.daddr = ip->daddr;
	tuple.ipv4.saddr = ip->saddr;
	tuple.ipv4.sport = tcp->source;
	tuple.ipv4.dport = tcp->dest;

    long tuplen = sizeof(tuple.ipv4);
    bpf_printk("WE ARE HEREEEEEE - 1");
    struct bpf_sock *sk =
		bpf_skc_lookup_tcp(skb, &tuple, tuplen, BPF_F_CURRENT_NETNS, 0);
	if (sk == NULL) {
        bpf_printk("WE ARE HEREEEEEE - 2");
		return BPF_DROP;
	}
    loop1();

    bpf_printk("WE ARE HEREEEEEE - 3");
	bpf_sk_release(sk);
		


    return BPF_OK; //ACCEPT packet
}

char _license[] SEC("license") = "GPL";
