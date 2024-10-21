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

static __always_inline void redirect(struct xdp_md *ctx, struct udphdr* udphdr, void* data, void* data_end) {
    u16 source_port = udphdr->source;
    u16 new_dest = ntohs(12345);
    
    bpf_trace_printk("[xdp] received %u from %d to %u\n", ntohs(source_port), ntohs(udphdr->dest));

    if ((void*)udphdr + offsetof(struct udphdr, dest) + sizeof(u16) > data_end)
        return;

    // 修改目的端口号
    udphdr->dest = new_dest;
    
    bpf_trace_printk("Redirected to new destination port %u\n", ntohs(new_dest));

    // 使用 XDP_TX 重定向
    bpf_redirect(ctx->ingress_ifindex, 0);
}

int xdp_prog(struct xdp_md *ctx) {
    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;

    struct udphdr* udphdr = try_parse_udphdr(data, data_end);
    if (!udphdr) {
        return XDP_PASS;
    }

    if(udphdr->dest != ntohs(12346)){
        return XDP_PASS;
    }

    bpf_trace_printk("Received packet to 12346");
    redirect(ctx, udphdr, data, data_end);

    return XDP_TX;
}

