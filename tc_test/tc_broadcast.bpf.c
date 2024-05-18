#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
typedef unsigned long uintptr_t;

#define cursor_advance(_cursor, _len) \
  ({ void *_tmp = _cursor; _cursor += _len; _tmp; })

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;


#define IP_TCP 6
#define ETH_SIZE sizeof(struct ethhdr)
#define IP_SIZE sizeof(struct iphdr)
#define TCP_SIZE sizeof(struct tcphdr)
#define MAX_LEN 40


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

#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
/*static __always_inline void change_dst_ip(struct __sk_buff skb, char dst_ip) {
  bpf_skb_store_bytes(skb, IP_DST_OFF, dst_ip, 4, 0);
}*/

static __always_inline int  broadcast(struct __sk_buff *skb, char *str){
    unsigned char src_ip[4] = {0};
    unsigned char dst_ip[4] = {0};
    bpf_skb_load_bytes(skb, IP_SRC_OFF, src_ip, 4);
    bpf_skb_load_bytes(skb, IP_DST_OFF, dst_ip, 4); 
    bpf_trace_printk("Before src IP: %u.%u.",src_ip[0], src_ip[1]);
    bpf_trace_printk("%u.%u\n",src_ip[2], src_ip[3]);
    bpf_trace_printk("Before dst IP: %u.%u.",dst_ip[0], dst_ip[1]);
    bpf_trace_printk("%u.%u\n",dst_ip[2], dst_ip[3]);
       if(str[0] == '1' && str[1] == '3' && str[2] == '2'){
           int i=4, j=0, num =0;
               if(str[3] == 'b'){
                        while(str[i] != '\0'){
                                if(str[i] == '.'){
                                        num = 0;
                                }
                                else{
                                        if(str[i] == ','){
                                                dst_ip[j++] = num;
                                                num = 0;
                                        }
                                        else{
                                                num = (num*10) + ((unsigned char)str[i] - '0');
                                        }

                                }
                                bpf_trace_printk("%d", num);
                                i++;
                        }
                        bpf_trace_printk("%d\n", j);
                }
                else{
                        return TC_ACT_OK;
                }
        }
        else{
                return TC_ACT_OK;
        }

}

int socket_filter(struct __sk_buff *skb) {

        bpf_trace_printk("[tc] recieved packet\n");

        long result = bpf_skb_pull_data(skb, skb->len);
        void *data = (void *)skb->data;
        void *data_end = (void *)skb->data_end;

        struct tcphdr* tcphdr = try_parse_tcphdr(data, data_end);
 
 // ingress packet
 // skb->data_end-skb->data = IP + TCP +  ETH + Payload 
 
 // exgress packet 
 // skb->data_end-skb->data = IP + TCP + ETH 
        if(!tcphdr){
                return TC_ACT_OK;
        }

        bpf_trace_printk("[tc] got tcp packet\n");

        int payload_offset = ETH_SIZE + IP_SIZE + tcphdr->doff * 4;
        if(data + payload_offset > data_end){
                return TC_ACT_OK;
        }

        int payload_len = skb->len - payload_offset;

        if(payload_len == 0){
                return TC_ACT_OK;
        }


        char* payload = (char *)(data + payload_offset);

        char str[MAX_LEN] = {0};
        
        for (int i=0;i<MAX_LEN; i++){
                if(payload + i +1< (char*) data_end){
                        str[i] = payload[i];
                }
                else{
			//bpf_trace_printk("%d\n", i);
                        //str[i] = '\0';
                        break;
                }
        }
 	str[MAX_LEN-1] = '\0';
        bpf_trace_printk("[tc] payload: %s\n", str);
	bpf_trace_printk("%d\n", payload_len);
 //broadcast(skb, str); 
    	unsigned char src_ip[4] = {0};
    	unsigned char dst_ip[4] = {0};
    	bpf_skb_load_bytes(skb, IP_SRC_OFF, src_ip, 4);
    	bpf_skb_load_bytes(skb, IP_DST_OFF, dst_ip, 4); 
    bpf_trace_printk("Before src IP: %u.%u.",src_ip[0], src_ip[1]);
    bpf_trace_printk("%u.%u\n",src_ip[2], src_ip[3]);
    bpf_trace_printk("Before dst IP: %u.%u.",dst_ip[0], dst_ip[1]);
    bpf_trace_printk("%u.%u\n",dst_ip[2], dst_ip[3]);
 /*
        bpf_skb_load_bytes(skb, IP_SRC_OFF, src_ip, 4);
        bpf_skb_load_bytes(skb, IP_DST_OFF, dst_ip, 4);
        bpf_trace_printk("Src IP: %u.%u.",src_ip[0], src_ip[1]);
        bpf_trace_printk("%u.%u\n",src_ip[2], src_ip[3]);
 bpf_trace_printk("Dst IP: %u.%u.",dst_ip[0], dst_ip[1]);
        bpf_trace_printk("%u.%u\n",dst_ip[2], dst_ip[3]);
 */
        return TC_ACT_OK;
}
