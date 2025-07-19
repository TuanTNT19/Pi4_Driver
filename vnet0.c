#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/if_arp.h>
#include <linux/in.h>
#include <linux/inetdevice.h>

static struct net_device *vnet0_dev;
static struct timer_list vnet0_timer;

/* Open interface */
static int vnet0_open(struct net_device *dev)
{
    pr_info ("vnet0: Interface opened\n ");
    netif_start_queue(dev);
    mod_timer(&vnet0_timer, jiffies + msecs_to_jiffies(1000));
    return 0;
}

/* Stop interface*/
static int vnet0_stop (struct net_device *dev){
    pr_info ("vnet0: Interface stop\n");
    netif_stop_queue(dev);
    del_timer_sync(&vnet0_timer);
    return 0;
}

/* Send packet vie interface*/
static netdev_tx_t vnet0_xmit(struct sk_buff *skb, struct net_device *dev)
{
    pr_info("vnet0: Sending packet, len = %d\n", skb->len);

    /* In thông tin gói tin (giả lập gửi) */
    if (skb->protocol == htons(ETH_P_IP)) {
        struct iphdr *iph = ip_hdr(skb);
        pr_info("vnet0: IP packet, src=%pI4, dst=%pI4\n", &iph->saddr, &iph->daddr);
    }

    /* Giả lập gửi thành công, giải phóng skb */
    dev_kfree_skb(skb);
    dev->stats.tx_packets++;
    dev->stats.tx_bytes += skb->len;

    return NETDEV_TX_OK;
}

static const struct net_device_ops vnet0_ops = {
    .ndo_open = vnet0_open,
    .ndo_stop = vnet0_stop,
    .ndo_start_xmit = vnet0_xmit,
};

/* Receive packet via interface */
static void vnet0_receive_packet(struct net_device *dev)
{
    struct sk_buff *skb;
    struct iphdr *iph;
    struct icmphdr *icmph;
    struct ethhdr *eth;
    char *data;
    int len = 64;
    __be32 daddr = 0;

    /* Lấy IP của giao diện vnet0*/
    struct in_device *in_dev = dev->ip_ptr;
    if (in_dev && in_dev->ifa_list) {
        daddr = in_dev->ifa_list->ifa_address; /* IP của vnet0 */
    } else {
        pr_err("vnet0: No IP address configured\n");
        return;
    }

    /* Tạo skb */
    skb = alloc_skb(ETH_HLEN + sizeof(struct iphdr) + sizeof(struct icmphdr) + len, GFP_KERNEL);
    if (!skb) {
        pr_err("vnet0: Failed to allocate skb\n");
        return;
    }

    /* Tạo ethernet header */
    skb_reserve(skb, ETH_HLEN); /* Dự trữ cho Ethernet header */
    eth = (struct ethhdr *)skb_push(skb, ETH_HLEN); /* Thêm Ethernet header */
    memcpy(eth->h_dest, dev->dev_addr, ETH_ALEN); /* MAC đích */
    eth_random_addr(eth->h_source); /* MAC nguồn ngẫu nhiên */
    eth->h_proto = htons(ETH_P_IP); /* Giao thức IPv4 */
    skb->dev = dev;
    skb->protocol = htons(ETH_P_IP);

    /* Tạo IP header */
    iph = (struct iphdr *)skb_put(skb, sizeof(struct iphdr));
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + len);
    iph->id = 0;
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_ICMP;
    iph->saddr = htonl(0xC0A80001); /* 192.168.0.1 */
    iph->daddr = daddr; /* e.g., 192.168.0.128 */
    iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl); /* Có thể gán luôn = 0 nếu k cần checksum*/

    /* Tạo ICMP header */
    icmph = (struct icmphdr *)skb_put(skb, sizeof(struct icmphdr));
    icmph->type = ICMP_ECHO; /* Echo Request */
    icmph->code = 0;
    icmph->un.echo.id = htons(12); /* Nếu k gán, thì kernel sẽ tự chọn 22*/
    icmph->un.echo.sequence = htons(1); /* Nếu k gán, thì kernel sẽ để là 0*/

    /* Tạo dữ liệu */
    data = skb_put(skb, len);
    memset(data, 0xAA, len);

    icmph->checksum = ip_compute_csum(icmph, sizeof(struct icmphdr) + len); /* CÓ thể gán =0 nếu k cần checksum icmp*/

    /* Đẩy gói tin vào network stack */
    dev->stats.rx_packets++;
    dev->stats.rx_bytes += skb->len;
    netif_rx(skb);

    pr_info("vnet0: Received fake ICMP packet\n");
}


/*Khởi tạo net_device */
static void vnet0_setup (struct net_device *dev) {
    dev->netdev_ops = &vnet0_ops;
    dev->type = ARPHRD_ETHER; /*chỉ định vnet0 mô phỏng giao diện Ethernet*/
    dev->mtu = ETH_DATA_LEN; /* Kích thước tối đa của gói tin, không tính header nào mà giao diện vnet0 có thể xử lý*/
    dev->flags = IFF_NOARP; /* Interface ảo, không cần ARP */
    eth_hw_addr_random(dev); /* Gán MAC ngẫu nhiên */
    pr_info("vnet0: MAC assigned=%pM\n", dev->dev_addr);
}


/* Hàm callback timer*/
static void vnet0_timer_callback(struct timer_list *t) {
    if (netif_running(vnet0_dev)) {
        vnet0_receive_packet(vnet0_dev);
        mod_timer(&vnet0_timer, jiffies + msecs_to_jiffies(1000));
    }
}

/* Hàm init module*/
static int __init vnet0_init(void) {
    pr_info ("vnet0: Initializing module\n");

    /* Cấp phát vùng nhớ cho vnet0*/
    vnet0_dev = alloc_netdev(0, "vnet0", NET_NAME_UNKNOWN, vnet0_setup);
    if (!vnet0_dev) {
        pr_err("vnet0: Failed to allocate net_device\n");
        return -ENOMEM;
    }

    /* Đăng ký net_device */
    if (register_netdev(vnet0_dev)) {
        pr_err("vnet0: Failed to register net_device\n");
        free_netdev(vnet0_dev);
        return -ENODEV;
    }
    /* Cài timer để gọi hàm vnet0_receive_packet */
    timer_setup(&vnet0_timer, vnet0_timer_callback, 0);
    
    return 0;
}

/* Hàm cleanup module */
static void __exit vnet0_exit(void) {
    pr_info("vnet0: Unloading module\n");
    unregister_netdev(vnet0_dev);
    free_netdev(vnet0_dev);
}

module_init(vnet0_init);
module_exit(vnet0_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tuan Truong Nho");
MODULE_DESCRIPTION("Simple virtual network device driver");

