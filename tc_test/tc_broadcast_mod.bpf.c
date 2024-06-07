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

#define IS_MAGIC_NUM(str) (str[0] == '5' && str[1] == '9' && str[2] == '1' && str[3] == '2' && str[4] == '3')

static __always_inline void broad_cast(struct __sk_buff *skb, struct tcphdr *tcphdr, char* payload, char* str) {
    u16 origin_port = tcphdr->source;
    u8 n = (u8) str[0];
    bpf_trace_printk("n = %d\n", n);
    bpf_trace_printk("[tc] received %d from %d to %d\n", n, origin_port, tcphdr->dest);
    //return;

    bpf_trace_printk("in broadcast\n");

    if (skb->data_end > payload + 4) {
        bpf_trace_printk("update payload\n");
        payload[0] = 'H';
        payload[1] = 'I';
        payload[2] = '!';
        payload[3] = '\0';
    }

    for (int i = 0; i < 3; i++) {
        bpf_trace_printk("%d %d\n", i*6 + 4, MAX_LEN - 6);
        if (i*6 + 4 >= MAX_LEN - 6) {
            break;
        }
        if (i >= n) continue;

        u8 a = str[i*6 + 1];
        u8 b = str[i*6 + 2];
        u8 c = str[i*6 + 3];
        u8 d = str[i*6 + 4];
        str[i*6 + 4] = (u8)2;
        bpf_trace_printk("================");
        bpf_trace_printk("a = %u, b = %u\n", a, b);
        bpf_trace_printk("c = %u, d = %u\n", c, d);
        bpf_trace_printk("================");
        u8 b_port[2];
        b_port[0] = str[i*6 + 5];
        b_port[1] = str[i*6 + 6];

        u16 port = *b_port;
        bpf_trace_printk("[tc] redirecting to %d\n", port);
        bpf_skb_store_bytes(skb, ETH_SIZE + offsetof(struct iphdr, saddr), &str[i*6 + 1], 4, 0);
        u8 dst_ip[4];
        bpf_skb_load_bytes(skb, ETH_SIZE + offsetof(struct iphdr, saddr), dst_ip, 4);
        bpf_trace_printk("dst_ip[3] = %u\n", dst_ip[3]);
        //bpf_skb_store_bytes(skb, ETH_SIZE + IP_SIZE + offsetof(struct tcphdr, dest), &port, 2, 0);
        //bpf_redirect(skb->ifindex, 0);
    }
    return;
}

/*static __always_inline void modify_dest_ip(struct __sk_buff *skb, struct iphdr *iph) {
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
}*/
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
	
	//Recalculate IP checksum
	ret = bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_daddr, new_daddr, IS_PSEUDO | sizeof(new_daddr));
        if (ret) {
            bpf_trace_printk("TCP checksum replacement failed with code %d\n", ret);
        } else {
            bpf_trace_printk("TCP checksum replacement succeeded\n");
        }

        // Redirect the packet
        int redirect_ret = bpf_clone_redirect(skb, skb->ifindex, 1);
        if (redirect_ret) {
            bpf_trace_printk("Packet redirection failed with code %d\n", redirect_ret);
        } else {
            bpf_trace_printk("Packet redirected successfully\n");
        }
    }
}

/*static __always_inline void modify_dest_ip(struct __sk_buff *skb, struct iphdr *iph) {
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

        //bpf_trace_printk("New IP address last two: %u.%u\n",((unsigned char *)&iph->daddr)[2], ((unsigned char *)&iph->daddr)[3]);

        bpf_trace_printk("New checksum: %u\n", iph->check);

        if (iph->check == 0) {
            iph->check = 0xFFFF;
        }

        bpf_trace_printk("iph->check: %d\n", iph->check);
        bpf_trace_printk("connected %d\n", skb->ifindex);

        // Redirect the packet
        int redirect_ret = bpf_clone_redirect(skb, skb->ifindex, 1);
        bpf_trace_printk("return code %d\n", redirect_ret);
    }
}*/
/*static inline void set_tcp_ip_dst(struct __sk_buff *skb, __u32 new_ip)
{
    __u32 old_ip = htonl(load_word(skb, IP_DST_OFF));
    int retl4 = bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_ip, new_ip, IS_PSEUDO | sizeof(new_ip));
    //bpf_skb_store_bytes(skb, TCP_DST_OFF, &new_ip, sizeof(new_ip), BPF_F_RECOMPUTE_CSUM);
    //u8 dst_ip[4];
    //bpf_skb_load_bytes(skb, ETH_SIZE + offsetof(struct iphdr, saddr), dst_ip, 4);
    //bpf_trace_printk("%d.%d", dst_ip[2], dst_ip[3]);
    int retl3 = bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_ip, new_ip, sizeof(new_ip));
    bpf_skb_store_bytes(skb, IP_DST_OFF, &new_ip, sizeof(new_ip), BPF_F_RECOMPUTE_CSUM);
    //int ret = bpf_clone_redirect(skb, skb->ifindex, 0);
    
}*/


int socket_filter(struct __sk_buff *skb) {
    long result = bpf_skb_pull_data(skb, skb->len);
    void *data = (void*) skb->data;
    void *data_end = (void*) skb->data_end;

    struct tcphdr* tcphdr = try_parse_tcphdr(data, data_end);
    if (!tcphdr) {
        return TC_ACT_OK;
    }

    struct iphdr* iph = data + ETH_SIZE;
    //__u32 new_ip = htonl(0x7F000001);
    //set_tcp_ip_dst(skb, new_ip);
    modify_dest_ip(skb, iph);
    return TC_ACT_OK;

    int payload_offset = ETH_SIZE + IP_SIZE + tcphdr->doff * 4;
    if (data + payload_offset > data_end) {
        return TC_ACT_OK;
    }
    bpf_trace_printk("1");
    int ret = bpf_clone_redirect(skb, skb->ifindex, 0);
    bpf_trace_printk("redirect ret = %d\n", ret);

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
    int should_process = IS_MAGIC_NUM(str);
    bpf_trace_printk("should_process = %d\n", should_process);
    if (!should_process) {
        return TC_ACT_OK;
    }
    switch (str[5]) {
        case 'b':
            broad_cast(skb, tcphdr, data + payload_offset, str + 6);
            return TC_ACT_SHOT;
        default:
            return TC_ACT_OK;
    }

    return TC_ACT_OK;
}
   

