#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/timer.h>
#include <linux/random.h> // Để tạo số ngẫu nhiên giả lập nhiệt độ

// Biến toàn cục
static struct timer_list temp_monitor_timer;
static int temp_threshold = 70; // Ngưỡng nhiệt độ (70°C)
static int temp_count_over_threshold = 0; // Đếm số lần vượt ngưỡng
static const int max_count_over_threshold = 3; // 3 lần x 5 giây = 15 giây
static int simulated_temp = 50; // Nhiệt độ giả lập, khởi tạo 50°C

// Callback timer
void temp_monitor_callback(struct timer_list *t) {
    // Giả lập nhiệt độ ngẫu nhiên (50-80°C)
    get_random_bytes(&simulated_temp, sizeof(simulated_temp));
    simulated_temp = (simulated_temp % 31) + 50; // Giới hạn 50-80°C

    printk(KERN_INFO "Current simulated temperature: %d°C\n", simulated_temp);

    if ( simulated_temp >= temp_threshold) {
        temp_count_over_threshold ++;

        printk(KERN_INFO "Temperature above %d°C for %d/%d intervals (5s each)\n",
               temp_threshold, temp_count_over_threshold, max_count_over_threshold); 

        if (temp_count_over_threshold == max_count_over_threshold) {
            printk(KERN_WARNING "WARNING: Temperature %d°C exceeded %d°C for 15s! Monitoring stopped.\n",
                   simulated_temp, temp_threshold);
            del_timer(&temp_monitor_timer); // Hủy timer
            return ; 
        }
    }
    else {
        temp_count_over_threshold = 0;
    }

    // Lên lịch lại timer sau 5 giây
    mod_timer(&temp_monitor_timer, jiffies + msecs_to_jiffies(5000));
}

// Hàm khởi tạo module
static int __init temp_monitor_init(void) {
    printk(KERN_INFO "Temperature monitor module loaded\n");

    // Khởi tạo timer
    timer_setup(&temp_monitor_timer, temp_monitor_callback, 0);

    // Lên lịch timer chạy lần đầu sau 5 giây
    mod_timer(&temp_monitor_timer, jiffies + msecs_to_jiffies(5000));

    return 0;
}

// Hàm thoát module
static void __exit temp_monitor_exit(void) {
    del_timer_sync(&temp_monitor_timer); // Hủy timer an toàn
    printk(KERN_INFO "Temperature monitor module unloaded\n");
}

// Định nghĩa điểm nhập và thoát
module_init(temp_monitor_init);
module_exit(temp_monitor_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Temperature Monitoring Module for Raspberry Pi 4");

