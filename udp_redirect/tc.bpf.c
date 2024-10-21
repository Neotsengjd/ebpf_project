#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/bpf.h>
//#include <bpf/bpf_helpers.h>

typedef unsigned long uintptr_t;

#define cursor_advance(_cursor, _len) \
  ({ void *_tmp = _cursor; _cursor += _len; _tmp; })

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

#define MAX_LEN 40
#define IP_UDP 17
#define ETH_SIZE sizeof(struct ethhdr)
#define IP_SIZE sizeof(struct iphdr)
#define UDP_SIZE sizeof(struct udphdr)


struct addr {
    u8 ip[4];
    u16 port;
};



static __always_inline struct udphdr* try_parse_udphdr(void* data, void* data_end) {
    if (data + ETH_SIZE > data_end)
        return 0;
    struct ethhdr* ethhdr = data;

    if (bpf_ntohs(ethhdr->h_proto) != ETH_P_IP)
        return 0;

    if (data + ETH_SIZE + IP_SIZE > data_end)
        return 0;

    struct iphdr* iphdr = data + ETH_SIZE;

    if (iphdr->protocol != IP_UDP)
        return 0;

    if (data + ETH_SIZE + IP_SIZE + UDP_SIZE > data_end)
        return 0;

    return data + ETH_SIZE + IP_SIZE;
}

#define IS_MAGIC_NUM(str) (str[0] == '5' && str[1] == '9' && str[2] == '1' && str[3] == '2' && str[4] == '3')


static __always_inline void redirect(struct __sk_buff *skb, struct udphdr* udphdr) {
    u16 source_port = udphdr->source;
    int ret;

    bpf_trace_printk("[tc] received %u from %d to %u\n", ntohs(source_port), ntohs(udphdr->dest));
    u16 new_dest = ntohs(12345);
    ret = bpf_skb_store_bytes(skb, ETH_SIZE + IP_SIZE + offsetof(struct  udphdr, dest), &new_dest, sizeof(u16), BPF_F_RECOMPUTE_CSUM);
    bpf_trace_printk("store_bytes %d", ret);
    ret = bpf_clone_redirect(skb, skb->ifindex, 0);
    bpf_trace_printk("return code %d", ret);
    return;
}



int socket_filter(struct __sk_buff *skb) {
    long result = bpf_skb_pull_data(skb, skb->len);
    void *data = (void*) skb->data;
    void *data_end = (void*) skb->data_end;

    struct udphdr* udphdr =  try_parse_udphdr(data, data_end);
    if (!udphdr) {
        return TC_ACT_OK;
    }

    
    if(udphdr->dest != ntohs(12346)){
        return TC_ACT_OK;
    }

    bpf_trace_printk("Recieved packet to 12346");
    redirect(skb, udphdr);

    return TC_ACT_OK;
}
