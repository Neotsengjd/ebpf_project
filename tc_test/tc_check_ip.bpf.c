#include <linux/tcp.h>
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
#define IP_TCP 6
#define ETH_SIZE sizeof(struct ethhdr)
#define IP_SIZE sizeof(struct iphdr)
#define TCP_SIZE sizeof(struct tcphdr)
#define TCP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check))
#define IP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))

#define IS_PSEUDO 0x10

struct addr {
    u8 ip[4];
    u16 port;
};

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

static __always_inline void modify_dest_ip(struct __sk_buff *skb, struct iphdr *iph) {
    if (iph->daddr == htonl(0x7F000002)) { // 127.0.0.2
        __sum16 old_check = iph->check;
        __be32 old_daddr = iph->daddr;
        iph->daddr = htonl(0x7F000001); // 127.0.0.1
        // Recalculate IP checksum
        //iph->check = 0;
        //int diff = bpf_csum_diff((__be32 *)&old_daddr, sizeof(old_daddr), (__be32 *)&iph->daddr, sizeof(iph->daddr), 0);
        int diff =1;
        //iph->check = ~((~old_check) + diff);
        bpf_trace_printk("before diff %d", diff);
        bpf_trace_printk("old check %d", old_check);
        iph->check = old_check + diff;
        //iph->check = bpf_csum_diff(0, 0, (void *)iph, sizeof(*iph), 0);
        bpf_trace_printk("New IP address: %u.%u", ((unsigned char *)&iph->daddr)[0],((unsigned char *)&iph->daddr)[1]);
        bpf_trace_printk("New IP address: %u.%u\n", ((unsigned char *)&iph->daddr)[2],((unsigned char *)&iph->daddr)[3]);

        bpf_trace_printk("New checksum: %u\n", iph->check);
        if (iph->check == 0) {
           iph->check = 0xFFFF;
        }

        bpf_trace_printk("iph->check: %d\n", iph->check);
        bpf_trace_printk("connected %d",skb->ifindex);
        int ret = bpf_clone_redirect(skb, skb->ifindex, 1);
        bpf_trace_printk("return code %d", ret);
    }
    else{
	__sum16 check = iph->check;
	bpf_trace_printk("checksum = %d\n", check);
    }
}

int socket_filter(struct __sk_buff *skb) {
    long result = bpf_skb_pull_data(skb, skb->len);
    void *data = (void*) skb->data;
    void *data_end = (void*) skb->data_end;

    struct tcphdr* tcphdr = try_parse_tcphdr(data, data_end);
    if (!tcphdr) {
        return TC_ACT_OK;
    }

    struct iphdr* iph = data + ETH_SIZE;
    modify_dest_ip(skb, iph);
    return TC_ACT_OK;

    int payload_offset = ETH_SIZE + IP_SIZE + tcphdr->doff * 4;
    if (data + payload_offset > data_end) {
        return TC_ACT_OK;
    }
    bpf_trace_printk("1");

    int payload_len = skb->len - payload_offset;
    bpf_trace_printk("payload_len: %d\n", payload_len);
    if (payload_len == 0) {
        return TC_ACT_OK;
    }
    bpf_trace_printk("2");

    char* payload = (char *)(data + payload_offset);
    char str[MAX_LEN] = {0};

    for (int i = 0; i < MAX_LEN; i++) {
        if (payload + i + 1 < (char*) data_end) {
            str[i] = payload[i];
            bpf_trace_printk(" str[%d] = %d\n", i, str[i]);
        } else {
            str[i] = '\0';
            break;
        }
    }
    bpf_trace_printk("str[6] - '0' = %u\n", str[6] - '0');

    str[MAX_LEN - 1] = '\0';
}


