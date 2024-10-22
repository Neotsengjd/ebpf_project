/*#include <linux/udp.h>
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

    //return data + ETH_SIZE + IP_SIZE;
    return data + ETH_SIZE;
}

#define IS_MAGIC_NUM(str) (str[0] == '5' && str[1] == '9' && str[2] == '1' && str[3] == '2' && str[4] == '3')

static __always_inline void redirect(struct __sk_buff *skb, struct udphdr* udphdr, struct iphdr* iphdr) {
    u16 source_port = udphdr->source;
    int ret;

    bpf_trace_printk("[tc] received %u from %d to %u\n", ntohs(source_port), ntohs(udphdr->dest));

    // Change the destination IP address
    u32 new_dest_ip = bpf_htonl((127 << 24) | (0 << 16) | (0 << 8) | 1); // 127.0.0.1
    ret = bpf_skb_store_bytes(skb, ETH_SIZE + offsetof(struct iphdr, daddr), &new_dest_ip, sizeof(u32), BPF_F_RECOMPUTE_CSUM);
    bpf_trace_printk("store_bytes ip %d", ret);

    ret = bpf_clone_redirect(skb, skb->ifindex, 0);
    bpf_trace_printk("return code %d", ret);
    return;
}

int socket_filter(struct __sk_buff *skb) {
    long result = bpf_skb_pull_data(skb, skb->len);
    void *data = (void*) skb->data;
    void *data_end = (void*) skb->data_end;

    struct udphdr* udphdr = try_parse_udphdr(data, data_end);
    if (!udphdr) {
        return TC_ACT_OK;
    }

    bpf_trace_printk("2");
    struct iphdr* iphdr = data + ETH_SIZE;

    // Check if the destination IP is 127.0.0.2
    u32 dest_ip = iphdr->daddr;
    if (dest_ip != bpf_htonl((127 << 24) | (0 << 16) | (0 << 8) | 2)) {
        return TC_ACT_OK;
    }

    if (udphdr->dest != ntohs(12345)) {
        return TC_ACT_OK;
    }

    bpf_trace_printk("Received packet to 12345 with IP 127.0.0.2");
    redirect(skb, udphdr, iphdr);

    return TC_ACT_OK;
}
*/
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/bpf.h>

typedef unsigned long uintptr_t;

#define cursor_advance(_cursor, _len) \
  ({ void *_tmp = _cursor; _cursor += _len; _tmp; })

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

#define IP_UDP 17
#define ETH_SIZE sizeof(struct ethhdr)
#define IP_SIZE sizeof(struct iphdr)
#define UDP_SIZE sizeof(struct udphdr)

static __always_inline struct udphdr* try_parse_udphdr(void* data, void* data_end) {
    if (data + ETH_SIZE > data_end){
	bpf_trace_printk("Failed1");
        return 0;
	}
    struct ethhdr* ethhdr = data;
    bpf_trace_printk("ethhdr%d", ethhdr);

    if (bpf_ntohs(ethhdr->h_proto) != ETH_P_IP){
	bpf_trace_printk("Failed2");
        return 0;
}
    if (data + ETH_SIZE + IP_SIZE > data_end){
	bpf_trace_printk("Failed3");
        return 0;
}
    struct iphdr* iphdr = data + ETH_SIZE;
    bpf_trace_printk("iphdr%d", iphdr);

    if (iphdr->protocol != IP_UDP){
	bpf_trace_printk("protocal%d", iphdr->protocol);
	bpf_trace_printk("Failed4");
        return 0;
}

    if (data + ETH_SIZE + IP_SIZE + UDP_SIZE > data_end){
	bpf_trace_printk("Failed5");
        return 0;
	}
    bpf_trace_printk("success");
    return data + ETH_SIZE + IP_SIZE; 
}

static __always_inline void redirect(struct __sk_buff *skb, struct udphdr* udphdr, struct iphdr* iphdr) {
    u32 new_dest_ip = bpf_htonl((127 << 24) | (0 << 16) | (0 << 8) | 1); //new ip address 127.0.0.1
    u32 bload_daddr;
    bpf_skb_load_bytes(skb, ETH_SIZE + offsetof(struct iphdr, daddr), &bload_daddr, sizeof(bload_daddr));
    bpf_trace_printk("before: %d\n", bload_daddr);
	
    // new ip address to skb
    int ret = bpf_skb_store_bytes(skb, ETH_SIZE + offsetof(struct iphdr, daddr), &new_dest_ip, sizeof(new_dest_ip), BPF_F_RECOMPUTE_CSUM);
    if (ret < 0) {
        bpf_trace_printk("Failed to store new IP: %d\n", ret);
    }

    ret = bpf_clone_redirect(skb, skb->ifindex, 0);
    if (ret < 0) {
        bpf_trace_printk("Failed to redirect: %d\n", ret);
    }
    u32 load_daddr;
    ret = bpf_skb_load_bytes(skb, ETH_SIZE + offsetof(struct iphdr, daddr), &load_daddr, sizeof(load_daddr));
    bpf_trace_printk("%d\n", load_daddr);
    if (ret != 0) {
	bpf_trace_printk("Failed");
    }
}

int socket_filter(struct __sk_buff *skb) {
    long result = bpf_skb_pull_data(skb, skb->len);
    void *data = (void*) skb->data;
    void *data_end = (void*) skb->data_end;
    
    bpf_trace_printk("dccccccccccc");

    struct udphdr* udphdr = try_parse_udphdr(data, data_end);
    if (!udphdr) {
	bpf_trace_printk("udphdr%d\n", udphdr);
    	bpf_trace_printk("aaaaaaaaacccc");

        return TC_ACT_OK;
    }

    struct iphdr* iphdr = data + ETH_SIZE;

    bpf_trace_printk("ddddddddddddddddddd");

    if (iphdr->daddr == bpf_htonl((127 << 24) | (0 << 16) | (0 << 8) | 2) && udphdr->dest == ntohs(12345)) {
        bpf_trace_printk("Received packet to 12345 with IP 127.0.0.2");
        redirect(skb, udphdr, iphdr);
    }

    return TC_ACT_OK;
}

