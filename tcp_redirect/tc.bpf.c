#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/bpf.h>

typedef unsigned long uintptr_t;

#define cursor_advance(_cursor, _len) \
  ({ void *_tmp = _cursor; _cursor += _len; _tmp; })

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

#define MAX_LEN 40
#define IP_TCP 6
#define ETH_SIZE sizeof(struct ethhdr)
#define IP_SIZE sizeof(struct iphdr)
#define TCP_SIZE sizeof(struct tcphdr)

static __always_inline struct tcphdr* try_parse_tcphdr(void* data, void* data_end) {
    if (data + ETH_SIZE > data_end)
        return 0;
    struct ethhdr* ethhdr = data;

    if (bpf_ntohs(ethhdr->h_proto) != ETH_P_IP)
        return 0;

    if (data + ETH_SIZE + IP_SIZE > data_end)
        return 0;

    struct iphdr* iphdr = data + ETH_SIZE;

    if (iphdr->protocol != IP_TCP)
        return 0;

    if (data + ETH_SIZE + IP_SIZE + TCP_SIZE > data_end)
        return 0;

    return data + ETH_SIZE + IP_SIZE;
}

/*static __always_inline void redirect(struct __sk_buff *skb, struct tcphdr* tcphdr) {
    u16 source_port = tcphdr->source;
    int ret;
    u16 update_dst;

    bpf_trace_printk("[tc] received %u from %d to %u\n", ntohs(source_port), ntohs(tcphdr->dest));
    u16 new_dest = ntohs(12345);
    ret = bpf_skb_store_bytes(skb, ETH_SIZE + IP_SIZE + offsetof(struct tcphdr, dest), &new_dest, sizeof(u16), BPF_F_RECOMPUTE_CSUM);
    bpf_trace_printk("store_bytes %d", ret);
    ret = bpf_clone_redirect(skb, skb->ifindex, 0);
    bpf_trace_printk("return code %d", ret);
    bpf_trace_printk("[tc] update received from %u", ntohs(tcphdr->dest));
    //bpf_skb_load_bytes(skb, ETH_SIZE + IP_SIZE + offsetof(struct tcphdr, dest), &update_dst, sizeof(u16));
    //bpf_trace_printk("new dst: %d", update_dst);
    return;
}*/
/*static __always_inline void redirect(struct __sk_buff *skb, struct tcphdr* tcphdr) {
    u16 source_port = bpf_ntohs(tcphdr->source);
    int ret;
    u16 new_dest = bpf_htons(12345); // New destination port in network byte order
    u16 updated_dst;

    bpf_trace_printk("[tc] received %u from %u to %u\n", source_port, bpf_ntohs(tcphdr->dest));

    // Store the new destination port in the skb
    ret = bpf_skb_store_bytes(skb, ETH_SIZE + IP_SIZE + offsetof(struct tcphdr, dest), &new_dest, sizeof(u16), BPF_F_RECOMPUTE_CSUM);
    bpf_trace_printk("store_bytes result: %d\n", ret);

    // Load the updated destination port to verify
    ret = bpf_skb_load_bytes(skb, ETH_SIZE + IP_SIZE + offsetof(struct tcphdr, dest), &updated_dst, sizeof(u16));
    if (ret == 0) {
        bpf_trace_printk("updated destination port: %u\n", bpf_ntohs(updated_dst));
    } else {
        bpf_trace_printk("failed to load updated destination port\n");
    }

    // Redirect the packet
    ret = bpf_clone_redirect(skb, skb->ifindex, 0);
    bpf_trace_printk("clone_redirect result: %d\n", ret);

    return;
}*/
static __always_inline void redirect(struct __sk_buff *skb, struct tcphdr* tcphdr) {
    u16 source_port = bpf_ntohs(tcphdr->source);
    int ret;
    u16 new_dest = bpf_htons(12345); // 设置新的目标端口为 12345
    u16 updated_dst;

    bpf_trace_printk("[tc] received %u from %u to %u\n", source_port, bpf_ntohs(tcphdr->dest));

    // 存储新的目标端口
    ret = bpf_skb_store_bytes(skb, ETH_SIZE + IP_SIZE + offsetof(struct tcphdr, dest), &new_dest, sizeof(u16), BPF_F_RECOMPUTE_CSUM);
    bpf_trace_printk("store_bytes result: %d\n", ret);

    // 读取更新后的目标端口进行验证
    ret = bpf_skb_load_bytes(skb, ETH_SIZE + IP_SIZE + offsetof(struct tcphdr, dest), &updated_dst, sizeof(u16));
    if (ret == 0) {
        bpf_trace_printk("updated destination port: %u\n", bpf_ntohs(updated_dst));
    } else {
        bpf_trace_printk("failed to load updated destination port\n");
    }

    // 重定向数据包
    ret = bpf_clone_redirect(skb, skb->ifindex, 0);
    bpf_trace_printk("clone_redirect result: %d\n", ret);

    return;
}

int socket_filter(struct __sk_buff *skb) {
    long result = bpf_skb_pull_data(skb, skb->len);
    void *data = (void*) skb->data;
    void *data_end = (void*) skb->data_end;

    struct tcphdr* tcphdr =  try_parse_tcphdr(data, data_end);
    if (!tcphdr) {
        return TC_ACT_OK;
    }

    if (tcphdr->dest != ntohs(12346)) {
        return TC_ACT_OK;
    }

    bpf_trace_printk("Received packet to 12346");
    redirect(skb, tcphdr);

    return TC_ACT_OK;
}

