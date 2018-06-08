#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <time.h>

#include <pcap.h>

#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <linux/tcp.h> // TCP

#include "utils.h" // not necessary

//#define D_HOST_MAC_ADDR 6
#define MAX_STRING_LEN 4
#define TTL_THRESHOLD 10 // 0 <= TTL <= 255
#define RED   "\033[1m\033[31m"
#define GRN   "\033[1m\033[32m"
#define RESET "\x1B[0m"

bool loop_local_capt = false; // define if there is linux cooked capture or not for the ethernet layer.
bool verbose = false;// mode verbose unabled by default

int help() {
  printf("Usage: ./pacapp [-l] ./pcap_file.pcapng\n");
  printf("\t-l: if the capture is a Linux Cooked Capture\n");
  printf("\t-h: display this help message\n");
  return 1;
}

void activate_verbose(){
  verbose = true;
}
/*
* Name : activate_linux_cooked
* function :  asks the user if the capture was done on local loop (127.0.0.1)
*             and sets up the loop_local_capt variable accordingly
*/
void activate_linux_cooked() {
  loop_local_capt = true;
}

/*
* Name : my_packet_handler
* function :  function is the callback to be run on every packet captured (called by <pcap_loop>)
*             then display packet info
*
*/
void my_packet_handler(u_char *args,const struct pcap_pkthdr *header,const u_char *packet)
{

      static int count = 1; // packet counter
      /*intiatilisation of previous packet information*/
      static int sequenceprev = 1 ;
      static int ackprev = 1;
      static int src_port_prev = 1;
      static int dest_port_prev = 1;
      static int flags_prev = 1;
      typedef uint32_t tcp_seq; // define th_seq and th_ack in sniff_ip
      /*Pointers to initialze the structures*/
      const struct ether_header *eth_header;
      const struct sniff_ethernet *ethernet;
      const struct sniff_tcp *tcp;
      /* Pointers to start point of various headers */
      const u_char *ip_header;
      const u_char *tcp_header;
      const u_char *udp_header;
      /*variables indicating the length of a packet part*/
      int ethernet_header_length;
      int ip_header_length;

      count++;
      printf("\nPacket number %d:\n", count);

      if (loop_local_capt == true){eth_header = (struct ether_header *) (packet + 2);} // add 2 byte in the packet because we work with  linux cooked capture
      else {eth_header = (struct ether_header *) (packet);}
      ethernet = (struct sniff_ethernet*)(packet);

      printf("Source MAC address is : %s\n", ether_ntoa(&ethernet->ether_shost));
      printf("Destination MAC address is : %s\n", ether_ntoa(&ethernet->ether_dhost));


      if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
          printf("Not an IP packet. Skipping...\n\n");
          return;
      }

      /* Header lengths in bytes */
      if (loop_local_capt == 1){ethernet_header_length = 16;} /* Doesn't change */// add 2 byte in the packet because we work with  linux cooked capture
      else {ethernet_header_length = 14; }

      /* Find start of IP header */
      ip_header = packet + ethernet_header_length;
      /* The second-half of the first byte in ip_header
         contains the IP header length (IHL). */
      ip_header_length = ((*ip_header) & 0x0F);
      /* The IHL is number of 32-bit segments. Multiply
         by four to get a byte count for pointer arithmetic */
      ip_header_length = ip_header_length * 4;

      ip_layer = (struct ip_layer*)(ip_header);
      printf("TTL : %d\n", (ip_layer->ip_ttl)); //ntohs

      if (ip_layer->ip_ttl<TTL_THRESHOLD) {
        printf(RED "[TTL] Low TTL encountered.\n" RESET);
      }

      /* Now that we know where the IP header is, we can
         inspect the IP header for a protocol number to
         make sure it is TCP before going any further.
         Protocol is always the 10th byte of the IP header */
      u_char protocol = *(ip_header + 9);

      if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) {
          printf("Not a TCP or UDP packet. Skipping...\n\n");
          return;
      }
      else if(protocol == IPPROTO_UDP && protocol != IPPROTO_TCP){
        printf("It is a UDP packet\n");
        printf("Total length : %d\n", ntohs(ip_layer->ip_len));
        int total_length = ntohs(ip_layer->ip_len);
        int udp =  *(int *)(udp_header + 4);// showing the length of udp packet and add 4 to place the pointer at "the length of the packet"
        int udp_length = ntohs(udp);
        /* Find start of UDP header */
        udp_header = packet + ethernet_header_length + ip_header_length;
        printf("udp length : %d\n", ntohs(udp));

        if (udp_length > total_length ){
          printf(RED "/!\\ OVERLAPPING FRAGLENT /!\\\n" RESET);
        }

      }
      else { printf("It is a TCP packet\n");

      /* Find start of TCP header */
      tcp_header = packet + ethernet_header_length + ip_header_length;
      tcp =  (struct tcp*)(tcp_header);// move to the tcp layer  and we can get the informations

      int sequence = ntohl(tcp->th_seq);
      int ack = ntohl(tcp->th_ack);
      int src_port = ntohs(tcp->th_sport);
      int dest_port = ntohs(tcp->th_dport);
      int flags = tcp->th_flags;

      printf("Src port: %u\n", src_port);
      printf("Dst port: %u\n", dest_port);

      printf("sequence number: %u\n", sequence);
      printf("acknowledge number: %u\n", ack);

      if (count > 1 && sequence == sequenceprev && ack == ackprev && src_port == src_port_prev && dest_port == dest_port_prev && flags == flags_prev)
       {printf(RED "/!\\ TCP retransmission /!\\\n" RESET);}

      if (count == 1 ) {
        sequenceprev = sequence;
        ackprev = ack;
        src_port_prev = src_port;
        dest_port_prev = dest_port;
        flags_prev = flags;

      }

      switch (tcp->th_flags) {
        case TH_SYN:
          printf("Flag: TH_SYN\n");
          break;
        case TH_PHACK:
          printf("Flag: TH_PHACK\n");
          break;
        case TH_ACK:
          printf("Flag: TH_ACK\n");
          break;
        case TH_RST:
          printf("Flag: TH_RST\n");
          break;
        case TH_SYNACK:
          printf("Flag: TH_SYNACK\n");
          break;
        case TH_RSTACK:
          printf("Flag: TH_RSTACK\n");
          break;
        case TH_FIN:
          printf("Flag: TH_FIN\n");
          break;
      }

      if (count > 1 ) {
        sequenceprev = sequence;
        ackprev = ack;
        src_port_prev = src_port;
        dest_port_prev = dest_port;
        flags_prev = flags;
      }
    }

}
