#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/bpf.h>
#include <linux/in.h>

#define MAX_LEN 40
#define IP_TCP 6
#define ETH_SIZE sizeof(struct ethhdr)
#define IP_SIZE sizeof(struct iphdr)
#define TCP_SIZE sizeof(struct tcphdr)
#define TCP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check))

struct addr {
    __be32 ip;
    __be16 port;
};

static __always_inline struct tcphdr* try_parse_tcphdr(void* data, void* data_end) {
    if (data + ETH_SIZE > data_end)
        return NULL;
    struct ethhdr* ethhdr = data;

    if (bpf_ntohs(ethhdr->h_proto) != ETH_P_IP)
        return NULL;

    if (data + ETH_SIZE + IP_SIZE > data_end)
        return NULL;

    struct iphdr* iphdr = data + ETH_SIZE;

    if (iphdr->protocol != IPPROTO_TCP)
        return NULL;

    if (data + ETH_SIZE + IP_SIZE + TCP_SIZE > data_end)
        return NULL;

    return (struct tcphdr*)(data + ETH_SIZE + IP_SIZE);
}

static __always_inline void modify_dest_ip(struct __sk_buff *skb, struct iphdr *iph) {
    if (iph->daddr == htonl(0x7F000002)) { // 127.0.0.2
        __be32 old_daddr = iph->daddr;
        __be32 new_daddr = htonl(0x7F000001); // 127.0.0.1

        // Modify the destination IP address
        iph->daddr = new_daddr;

        // Recalculate IP checksum
        int ret = bpf_l3_csum_replace(skb, offsetof(struct iphdr, check), old_daddr, new_daddr, sizeof(new_daddr));
        if (ret) {
            bpf_trace_printk("Checksum replacement failed with code %d\n", ret);
        } else {
            bpf_trace_printk("Checksum replacement succeeded\n");
        }

        // Recalculate TCP checksum
        ret = bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_daddr, new_daddr, sizeof(new_daddr));
        if (ret) {
            bpf_trace_printk("TCP checksum replacement failed with code %d\n", ret);
        } else {
            bpf_trace_printk("TCP checksum replacement succeeded\n");
        }

        // Redirect the packet
        int redirect_ret = bpf_clone_redirect(skb, skb->ifindex, 0);
        if (redirect_ret) {
            bpf_trace_printk("Packet redirection failed with code %d\n", redirect_ret);
        } else {
            bpf_trace_printk("Packet redirected successfully\n");
        }
    }
}

int socket_filter(struct __sk_buff *skb) {
    void *data = (void*)(long)skb->data;
    void *data_end = (void*)(long)skb->data_end;

    struct tcphdr* tcphdr = try_parse_tcphdr(data, data_end);
    if (!tcphdr) {
        return TC_ACT_OK;
    }

    struct iphdr* iph = data + ETH_SIZE;
    modify_dest_ip(skb, iph);
    return TC_ACT_OK;
}

