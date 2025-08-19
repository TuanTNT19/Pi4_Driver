#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/timer.h>

// Biến để lưu IP cần chặn, kiểu chuỗi
static char *blocked_ip = "192.168.2.9"; // Giá trị mặc định
module_param(blocked_ip, charp, 0644); // Định nghĩa tham số module
MODULE_PARM_DESC(blocked_ip, "IP address to block (e.g., 192.168.2.9)");
struct timer_list my_timer;
bool block_active = 0;

/* .dev, .priv, .hook_ops_type: Không được khai báo trong ví dụ của bạn,
 nghĩa là chúng để mặc định (thường là NULL cho .dev và .priv, .hook_ops_type có thể là NF_HOOK_OP_NOT_PASSED nếu không chỉ định).

.dev: Để NULL nếu áp dụng cho tất cả giao diện.
.priv: Để NULL nếu không cần dữ liệu tùy chỉnh.
.hook_ops_type: Ít dùng trong module cơ bản, thường để mặc định.*/

void timer_callback (struct timer_list *t) {
    printk(KERN_INFO "Timer expired, disabling block for IP %s\n", blocked_ip);
    block_active = 0; // Tắt chế độ chặn
}

int my_hook_func (void *priv,
			       struct sk_buff *skb,
			       const struct nf_hook_state *state) {
    
    struct iphdr *iph = (struct iphdr *)skb_network_header(skb);
    if (!iph) return NF_ACCEPT;

    __be32 src_ip = iph->saddr; // Lấy ra địa chỉ IP nguồn của gói tin
    __be32 des_ip = iph->daddr; // Lấy ra địa chỉ IP đích của gói tin
    __u8 proto = iph->protocol; // Lấy ra giao thức tầng trên ( tầng 4 ) của gói tin
    char src_ip_str[16], des_ip_str[16];
    snprintf(src_ip_str, sizeof(src_ip_str), "%pI4", &src_ip);
    snprintf(des_ip_str, sizeof(des_ip_str), "%pI4", &des_ip);

    struct ethhdr *ethh = (struct ethhdr *)skb_mac_header(skb);
    if (!ethh) return NF_ACCEPT;

    char mac_src[18], mac_dst[18];
    // Parse địa chỉ MAC nguồn của gói tin vào mac_src
    snprintf(mac_src, sizeof(mac_src), "%02x:%02x:%02x:%02x:%02x:%02x",
        ethh->h_source[0], ethh->h_source[1], ethh->h_source[2],
        ethh->h_source[3], ethh->h_source[4], ethh->h_source[5]);

    // Parse địa chỉ MAC đích của gói tin vào mac_dst
    snprintf(mac_dst, sizeof(mac_dst), "%02x:%02x:%02x:%02x:%02x:%02x", 
        ethh->h_dest[0], ethh->h_dest[1], ethh->h_dest[2], 
        ethh->h_dest[3], ethh->h_dest[4], ethh->h_dest[5]);

    if ( !strcmp (src_ip_str, blocked_ip) && proto == IPPROTO_ICMP) {
        if (!block_active) {
            printk(KERN_INFO "Enable blocking for IP %s |||\n", blocked_ip);
            block_active = 1;
            mod_timer(&my_timer, jiffies + msecs_to_jiffies(5000));
        }

        if (block_active) {
            printk(KERN_INFO "Blocked packet with src ip : %s , des ip : %s\n", src_ip_str, des_ip_str);
            printk(KERN_INFO "Source MAC: %s, Destination MAC: %s \n", mac_src, mac_dst);
            return NF_DROP; // Chặn gói tin
        }
    }

    return NF_ACCEPT; // Cho qua
}

static struct nf_hook_ops my_hook = {
    .hook =  (nf_hookfn *)my_hook_func,
    .hooknum = NF_INET_PRE_ROUTING,
    .pf = NFPROTO_IPV4,
    .priority = NF_IP_PRI_FIRST,
};

static int __init my_module_init(void) {
    printk(KERN_INFO "Netfilter module loaded\n");
    timer_setup (&my_timer, timer_callback); // Khởi tạo timer
    nf_register_net_hook(&init_net, &my_hook); // Đăng ký my_hook với netfilter
    return 0;
}

static void __exit my_module_exit(void) {
    nf_unregister_net_hook(&init_net, &my_hook); // Húy Đăng ký my_hook với netfilter
    del_timer_sync(&my_timer);
    printk(KERN_INFO "Netfilter module unloaded\n");
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TuanTNT19");
MODULE_DESCRIPTION("Block IP Netfilter Module");

