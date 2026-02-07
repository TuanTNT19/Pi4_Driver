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

static unsigned int my_hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
static struct nf_hook_ops my_hook = {
    .hook = (nf_hookfn *)my_hook_func,
    .hooknum = NF_INET_PRE_ROUTING,
    .pf = NFPROTO_IPV4,
    .priority = NF_IP_PRI_FIRST,
};

static int __init my_module_init(void) {
    int ret ;
    ret = nf_register_net_hook(&init_net, &my_hook);
    if (ret < 0) {
        printk("------ Kernel Netfilter module loading failed-----");
        return ret;
    }
    printk("------ Kernel Netfilter module loaded -----\n");
    return ret ;
}

static void __exit my_module_exit(void) {
    nf_unregister_net_hook(&init_net, &my_hook);
    printk("------ Kernel Netfilter module unloaded -----\n");
}

static unsigned int my_hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
    char *hook_name;
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

    struct iphdr *iph = ip_hdr(skb);
    __u8 L3_proto = iph->protocol;
    if (L3_proto == IPPROTO_ICMP) {
        printk ("This is ICMP \n");
        return NF_DROP;
    }

    return NF_ACCEPT;
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TuanTNT19");
MODULE_DESCRIPTION("Netfilter Module for ICMP");