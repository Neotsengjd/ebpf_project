#include <bcc/proto.h>
#include <linux/pkt_cls.h>
#include <uapi/linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>


 

static __always_inline unsigned short is_tcp(void *data,
		void *data_end) {
	struct ethhdr *eth = data;
	if (data + sizeof(struct ethhdr) > data_end)
		return 0;

	if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
		return 0;

	struct iphdr *iph = data + sizeof(struct ethhdr);
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
		return 0;

	return iph->protocol == 0x06;
}

int tc_pingpong(struct __sk_buff *skb) {
	bpf_trace_printk("[tc] ingress got packet");

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (!is_tcp(data, data_end)) {
		bpf_trace_printk("[tc] ingress not a tcp request: %s", data);
		return TC_ACT_OK;
	}

	struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	if(data + sizeof(struct ethhdr) + sizeof(struct iphdr) +sizeof(struct tcphdr) > data_end)
		return TC_ACT_OK;
	int tcp_header_len = tcph->doff * 4;
		
	bpf_trace_printk("tcp_hdr_len: %d", tcp_header_len);
	
	u32 payload_offset = sizeof(struct ethhdr) + sizeof(struct iphdr);
			
	if(skb->len <= payload_offset){
		return 0;
	}
	
	bpf_trace_printk("=============================================");
	bpf_trace_printk("payload_offset: %d", (skb->len - payload_offset));	
	char p[100] = {0};
	u32 payload_len = skb->len - payload_offset;
	if (payload_len > 100){
		payload_len = 100;
	}
	if(payload_len < 0) payload_len = 0;
	if(skb->len - payload_offset > 0)
	bpf_trace_printk("returncode %d", bpf_skb_load_bytes(skb, payload_offset, p, payload_len));
		
	//bpf_trace_printk("payload: %s", p);
	bpf_trace_printk("payload_offset: %d", payload_offset);	
	bpf_trace_printk("skb_len: %d", skb->len);	
	
		
	
	// Copy the payload into the buffer
	/*for (i = 0; i < 89; i++) {
		payload_buffer[i] = payload[i];
		int c = payload_buffer[i];	
		if(c == '\0') break;	
	}*/
	int w = 2;
	bpf_trace_printk("w: %d/n", w);
	//payload_buffer[89] = '\0';
	//bpf_trace_printk("%s\n", payload_buffer);
	// Print the null-terminated payload buffer
	//bpf_trace_printk("[tc] data: %s\n", payload_buffer); 
	return TC_ACT_OK;
} 



