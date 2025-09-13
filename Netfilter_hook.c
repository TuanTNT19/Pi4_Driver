#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/skbuff.h>
#include <linux/inet.h>

// Biến để lưu IP cần chặn, kiểu chuỗi (giữ lại nhưng không dùng)
static char *blocked_ip = "192.168.2.9"; // Giá trị mặc định
module_param(blocked_ip, charp, 0644); // Định nghĩa tham số module
MODULE_PARM_DESC(blocked_ip, "IP address to block (e.g., 192.168.2.9)");

static int my_hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    // In ra giai đoạn hook hiện tại
    const char *hook_name;
    switch (state->hook) {
        case NF_INET_PRE_ROUTING:
            hook_name = "PRE_ROUTING";
            break;
        case NF_INET_FORWARD:
            hook_name = "FORWARD";
            break;
        case NF_INET_LOCAL_IN:
            hook_name = "LOCAL_IN";
            break;
        case NF_INET_POST_ROUTING:
            hook_name = "POST_ROUTING";
            break;
        case NF_INET_LOCAL_OUT:
            hook_name = "LOCAL_OUT";
            break;
        default:
            hook_name = "UNKNOWN";
            break;
    }

    struct iphdr *iph = (struct iphdr *)skb_network_header(skb);
    if (!iph) {
        return NF_ACCEPT; // Bỏ qua nếu không có IP header
    }

    // Chỉ xử lý khi là ICMP
    if (iph->protocol != IPPROTO_ICMP) {
        return NF_ACCEPT; // Bỏ qua các giao thức khác
    }

    printk(KERN_INFO "Processing packet at stage: %s (%s)\n", hook_name, state->in ? state->in->name : "N/A");

    __be32 src_ip = iph->saddr;
    __be32 des_ip = iph->daddr;
    __u8 proto = iph->protocol;
    char src_ip_str[16], des_ip_str[16];
    snprintf(src_ip_str, sizeof(src_ip_str), "%pI4", &src_ip);
    snprintf(des_ip_str, sizeof(des_ip_str), "%pI4", &des_ip);

    // Kiểm tra và in Ethernet header
    char mac_src[18] = "N/A", mac_dst[18] = "N/A";
    struct ethhdr *ethh = skb_mac_header(skb) ? (struct ethhdr *)skb_mac_header(skb) : NULL;
    if (ethh) {
        snprintf(mac_src, sizeof(mac_src), "%02x:%02x:%02x:%02x:%02x:%02x",
                 ethh->h_source[0], ethh->h_source[1], ethh->h_source[2],
                 ethh->h_source[3], ethh->h_source[4], ethh->h_source[5]);
        snprintf(mac_dst, sizeof(mac_dst), "%02x:%02x:%02x:%02x:%02x:%02x",
                 ethh->h_dest[0], ethh->h_dest[1], ethh->h_dest[2],
                 ethh->h_dest[3], ethh->h_dest[4], ethh->h_dest[5]);
        printk(KERN_INFO "Hook %u (%s): Ethernet Info - Src MAC: %s, Dst MAC: %s\n",
           state->hook, state->in ? state->in->name : "N/A", mac_src, mac_dst);
    } else {
        printk(KERN_INFO "Hook %u (%s): No Ethernet header available\n", state->hook, state->in ? state->in->name : "N/A");
    }

    // In chi tiết IP header
    printk(KERN_INFO "Hook %u (%s): IP Info - Src IP: %s, Dst IP: %s, Proto: %u, TTL: %u, Length: %u, ID: %u, Frag Offset: %u\n",
           state->hook, state->in ? state->in->name : "N/A",
           src_ip_str, des_ip_str, proto, iph->ttl, ntohs(iph->tot_len), ntohs(iph->id), ntohs(iph->frag_off));

    // Kiểm tra và in ICMP header
    if (proto == IPPROTO_ICMP && skb->len > (iph->ihl * 4)) {
        struct icmphdr *icmph = (struct icmphdr *)(skb->data + (iph->ihl * 4));
        printk(KERN_INFO "Hook %u: ICMP Info - Type: %u, Code: %u, ID: %u, Seq: %u\n",
               state->hook, icmph->type, icmph->code, ntohs(icmph->un.echo.id), ntohs(icmph->un.echo.sequence));
    }

    // In payload (nếu có)
    unsigned char *payload = skb->data + (iph->ihl * 4) + (proto == IPPROTO_ICMP ? sizeof(struct icmphdr) : 0);
    int payload_len = skb->len - (iph->ihl * 4) - (proto == IPPROTO_ICMP ? sizeof(struct icmphdr) : 0);
    if (payload_len > 0) {
        printk(KERN_INFO "Hook %u: Payload (đầu 10 byte): ", state->hook);
        for (int i = 0; i < (payload_len > 10 ? 10 : payload_len); i++) {
            printk("%02x ", payload[i]);
        }
        printk("\n");
    }

    return NF_ACCEPT;
}

// Định nghĩa các hook cho từng thời điểm
static struct nf_hook_ops my_hooks[] = {
    {
        .hook = (nf_hookfn *)my_hook_func,
        .hooknum = NF_INET_PRE_ROUTING,
        .pf = NFPROTO_IPV4,
        .priority = NF_IP_PRI_FIRST,
    },
    {
        .hook = (nf_hookfn *)my_hook_func,
        .hooknum = NF_INET_FORWARD,
        .pf = NFPROTO_IPV4,
        .priority = NF_IP_PRI_FIRST,
    },
    {
        .hook = (nf_hookfn *)my_hook_func,
        .hooknum = NF_INET_LOCAL_IN,
        .pf = NFPROTO_IPV4,
        .priority = NF_IP_PRI_FIRST,
    },
    {
        .hook = (nf_hookfn *)my_hook_func,
        .hooknum = NF_INET_POST_ROUTING,
        .pf = NFPROTO_IPV4,
        .priority = NF_IP_PRI_FIRST,
    },
    {
        .hook = (nf_hookfn *)my_hook_func,
        .hooknum = NF_INET_LOCAL_OUT,
        .pf = NFPROTO_IPV4,
        .priority = NF_IP_PRI_FIRST,
    },
};

static int __init my_module_init(void) {
    int ret;
    int i; // Khai báo i ngoài vòng for
    printk(KERN_INFO "Netfilter module loaded\n");
    for (i = 0; i < ARRAY_SIZE(my_hooks); i++) {
        ret = nf_register_net_hook(&init_net, &my_hooks[i]);
        if (ret < 0) {
            printk(KERN_ERR "Failed to register hook %d\n", my_hooks[i].hooknum);
            goto cleanup;
        }
    }
    return 0;

cleanup:
    while (--i >= 0) {
        nf_unregister_net_hook(&init_net, &my_hooks[i]);
    }
    return ret;
}

static void __exit my_module_exit(void) {
    for (int i = 0; i < ARRAY_SIZE(my_hooks); i++) {
        nf_unregister_net_hook(&init_net, &my_hooks[i]);
    }
    printk(KERN_INFO "Netfilter module unloaded\n");
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TuanTNT19");
MODULE_DESCRIPTION("Netfilter Module for ICMP Packet Logging");