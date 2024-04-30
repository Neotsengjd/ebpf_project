#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

typedef unsigned long uintptr_t;


#define cursor_advance(_cursor, _len) \ ({ void *_tmp = _cursor; _cursor += _len; _tmp; })

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;


#define IP_TCP 6
#define ETH_SIZE sizeof(struct ethhdr)
#define IP_SIZE sizeof(struct iphdr)
#define TCP_SIZE sizeof(struct tcphdr)

static __always_inline  struct tcphdr* try_parse_tcphdr(void* data, void* data_end){
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
        
        if(data + ETH_SIZE + IP_SIZE + TCP_SIZE> data_end)
                return 0;
        
        return data + ETH_SIZE + IP_SIZE;
}



int socket_filter(struct __sk_buff *skb) {
        long result = bpf_skb_pull_data(skb, skb->len);
        //bpf_trace_printk("[tc] recieved packet\n");
        void *data = (void*) skb->data;
        void *data_end = (void*) skb->data_end;

        struct tcphdr* tcphdr = try_parse_tcphdr(data, data_end);
        
        if(!tcphdr){
                return TC_ACT_OK;
        }

        //bpf_trace_printk("[tc] got tcp packet\n");

        int payload_offset = ETH_SIZE + IP_SIZE + tcphdr->doff * 4;
        if(data + payload_offset > data_end){
                return TC_ACT_OK;
        }

        int payload_len = skb->len - payload_offset;

        if(payload_len == 0){
                return TC_ACT_OK;
        }

        bpf_trace_printk("result: %ld", result);
        if(data_end - data == skb->len)
                bpf_trace_printk("yess");
        else bpf_trace_printk("%d %d", data_end - data, skb->len);

        bpf_trace_printk("len: %d, %x, %x", payload_len, data, data_end);
        bpf_trace_printk("%x", data+payload_offset);
        char* payload = (char *)(data + payload_offset);

        #define MAX_LEN 20
        char str[MAX_LEN] = {0};
        
        for (int i=0;i<MAX_LEN; i++){
                if(payload + i+1 < (char*) data_end){
                        str[i] = payload[i];
                }
                else{
                        str[i] = '\0';
                        break;
                }
        }

        str[MAX_LEN-1] = '\0';
        bpf_trace_printk("[tc] payload: %s\n", str);
        return TC_ACT_OK;
}
