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


#define NO_OP 'n'
#define BC 'b'



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

static __always_inline char get_action(void* data, void* data_end){
    if(data + ETH_SIZE + IP_SIZE + UDP_SIZE + 6 > data_end){
        return 0;
    }
    const int offset = ETH_SIZE + IP_SIZE + UDP_SIZE;
    char* payload = (char*) (data + offset);
    if(payload [0] == '5' && payload[1] == '9' && payload[2] == '1' && payload [3] == '2' && payload[4] == '3'){
        return payload[5];
    }
    return NO_OP;
}


static __always_inline void broadcast(struct __sk_buff *skb, struct udphdr* udphdr) {
    u16 source_port = udphdr->source;
    int ret;
    const int offset = ETH_SIZE + IP_SIZE + UDP_SIZE + 6;
    void *data = (void*) skb->data;
    void *data_end = (void*) skb->data_end;
    if(data + offset + 1 > data_end){
        return;
    }
    u8 n;
    n = *(u8*)(data + offset);
    bpf_trace_printk("[tc] received %u from %d to %u\n",n , ntohs(source_port), ntohs(udphdr->dest));

    
    for (int i = 1; i < 4; i++) {
        data = (void*) skb->data;
        data_end = (void*) skb->data_end;
        if(i > n){
            continue;
        }
        if(data + offset + 1 + i*6 > data_end){
            bpf_trace_printk("[tc] too large");
            continue;
        }
        u8* cursor = data+offset+1 + (i-1)*6;
        u16 port_1 = (u8) cursor[4];
        u16 port_2 = (u8) cursor[5];
        bpf_trace_printk("[tc] port1:%u port2:%u\n", port_1, port_2);
        u16 port = (port_1 << 8) | port_2;
        bpf_trace_printk("[tc] redirecting to %u\n", port);

        u16 new_dest = ntohs(port);
        ret = bpf_skb_store_bytes(skb, ETH_SIZE + IP_SIZE + offsetof(struct  udphdr, dest), &new_dest, sizeof(u16), BPF_F_RECOMPUTE_CSUM);
        bpf_trace_printk("store_bytes %d", ret);
        ret = bpf_clone_redirect(skb, skb->ifindex, 0);
        bpf_trace_printk("return code %d", ret);
    }
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

    char action = get_action(data, data_end);
    if(action == NO_OP){
        return TC_ACT_OK;
    }
    

    switch (action)
    {
        case BC: {
            u8 c = 0;
            bpf_skb_store_bytes(skb, ETH_SIZE + IP_SIZE + UDP_SIZE, &c, sizeof(char), BPF_F_RECOMPUTE_CSUM);
            void *data = (void*) skb->data;
            void *data_end = (void*) skb->data_end;
            struct udphdr* udphdr =  try_parse_udphdr(data, data_end);
            if (!udphdr) {
                return TC_ACT_OK;
            }
            broadcast(skb, udphdr);
            return TC_ACT_SHOT;
        }
        default:
            return TC_ACT_OK;
    }

    return TC_ACT_OK;
}

