#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <sys/types.h>
#include "packet_sniffer.h"
// 回调函数，用于处理抓取到的每一个数据包
void packet_handler(u_char *user_data, const struct pcap_pkthdr *packet_header, const u_char *packet_data)
{
    // 以太网头部长度
    const struct ether_header *eth_header = (struct ether_header *)packet_data;

    // 仅处理 IPv4 数据包
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP)
    {
        const struct ip *ip_header = (struct ip *)(packet_data + sizeof(struct ether_header));
        printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
        printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));

        // 仅处理 TCP 数据包
        if (ip_header->ip_p == IPPROTO_TCP)
        {
            const struct tcphdr *tcp_header = (struct tcphdr *)(packet_data + sizeof(struct ether_header) + ip_header->ip_hl * 4);
            printf("Source Port: %d\n", ntohs(tcp_header->source));
            printf("Destination Port: %d\n", ntohs(tcp_header->dest));
        }
        printf("-----\n");
    }
}

int run_pcap()
{
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces, *device;

    // 获取所有网络接口列表
    if (pcap_findalldevs(&interfaces, error_buffer) == -1)
    {
        fprintf(stderr, "Error finding devices: %s\n", error_buffer);
        return 1;
    }

    // 选择第一个网络接口
    device = interfaces;
    if (device == NULL)
    {
        printf("No devices found.\n");
        return 1;
    }
    printf("Using device: %s\n", device->name);

    // 打开设备进行抓包
    pcap_t *handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, error_buffer);
    if (handle == NULL)
    {
        fprintf(stderr, "Could not open device %s: %s\n", device->name, error_buffer);
        return 2;
    }

    // 开始捕获数据包
    pcap_loop(handle, 10, packet_handler, NULL);

    // 释放资源
    pcap_freealldevs(interfaces);
    pcap_close(handle);

    return 0;
}
