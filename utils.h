#ifndef UTILS_H
#define UTILS_H

int check_local_capture();
void my_packet_handler(u_char *args,const struct pcap_pkthdr *header,const u_char *packet);

#endif
