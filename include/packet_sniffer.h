#ifndef __PCAP_SNIFFER__
#define __PCAP_SNIFFER__
#include <pcap.h>

void packet_handler(u_char *user_data, const struct pcap_pkthdr *packet_header, const u_char *packet_data);

int run_pcap();

#endif