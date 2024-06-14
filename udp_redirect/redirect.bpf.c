#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

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

struct addr{
        u8 ip[4];
        u16 port;
};

static __always_inline struct iphdr* try_parse_ipphdr(void* data, void* data_end){
        if(data + ETH_SIZE > data_end)
                return 0;
        struct ethhdr*  ethhdr = data;

        if (bpf_ntohs(ethhdr->h_proto) != ETH_P_IP)
                return 0;
        
        if(data + ETH_SIZE + IP_SIZE > data_end) 
                return 0;
        
        
        struct iphdr* iphdr = data + ETH_SIZE;

        if(iphdr->protocol != IP_TCP)
                return 0;
        
        return iphdr;
}



int socket_filter(struct __sk_buff *skb) {
        long result = bpf_skb_pull_data(skb, skb->len);
        //bpf_trace_printk("[tc] recieved packet\n");
        void *data = (void*) skb->data;
        void *data_end = (void*) skb->data_end;


        struct iphdr* iphdr = try_parse_iphdr(data, data_end);
        
        if(!iphdr){
                return TC_ACT_OK;
        }

        char daddr[4] = iphdr->daddr;

        
        
        
        bpf_skb_store_bytes(skb, ETH_SIZE + offsetof(struct iphdr, saddr), &str[i*6 + 1], 4, 0);
                //bpf_skb_store_bytes(skb, ETH_SIZE + IP_SIZE + offsetof(struct tcphdr, dest), &port, 2, 0);
        bpf_clone_redirect(skb, skb->ifindex, 0);

        


        return TC_ACT_OK;
}

