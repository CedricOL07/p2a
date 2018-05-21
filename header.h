#include <stdbool.h>

//extern bool loop_local_capt; /*compteur of packets*/

// SIGNATURES
void my_packet_handler(u_char *args,const struct pcap_pkthdr *header,const u_char *packet);

u_int16_t handle_ethernet(const struct pcap_pkthdr* pkthdr, const u_char* packet);
