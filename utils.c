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
bool verbose = false;         // mode verbose unabled by default
int errors=0;                 // nbr of errors for a given packet, global so that we can use it in check_host()

int help() {
  printf("Usage: ./p2a [OPTIONS] FILE\n");
  printf("\t-l: if the capture is a Linux Cooked Capture\n");
  printf("\t-h: display this help message\n");
  printf("\t-v: verbose option\n");
  printf("Example: ./p2a -v ./pcap_files/some_pcap_file.pcapng\n");
  return 1;
}

/*
* Name : activate_verbose
* function :  set the variable verbose to true
*/
void activate_verbose(){
  verbose = true;
  printf(GRN "Verbose option: ON\n" RESET);
}

/*
* Name : activate_linux_cooked
* function :  set the variable loop_local_capt to true
*/
void activate_linux_cooked() {
  loop_local_capt = true;
  printf(GRN "Linux Cooked Capture: ON\n" RESET);
}

 /*
 * Name : check_host
 * function :  for a given host (MAC and IP addresses), checks whether one of the address was already
 *             entered in the MAC/IP linked list:
 *             - if MAC and IP are already present, skip
 *             - if only MAC matches an entry (but different IP), then raise flag
 *             - if only IP matches an entry (but different MAC), then raise flag
 *
 */
int check_host(struct Node *n, char mac[20], char ip[20]) {
  int ret=0;
  while (n != NULL) {
     if (strcmp(n->ip, ip)==0 && strcmp(n->mac, mac)==0) {
       ret++;
     } else if (strcmp(n->ip, ip)==0 && strcmp(n->mac, mac)!=0 && strcmp(ip, "127.0.0.1")!=0) {
       printf(RED "/!\\ IP address associated to different MAC's /!\\\n" RESET);
       errors++;
       if (verbose) {
         printf(RED "\t%s <---> %s\n" RESET, ip, n->mac);
         printf(RED "\t%s <---> %s\n" RESET, ip, mac);
       }
     }
     n = n->previous;
  }
  return ret;
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
      //typedef uint32_t tcp_seq; // define th_seq and th_ack in sniff_ip
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
      /* UDP packet variables */
      int total_length, udp, udp_length;
      /* TCP packet variables */
      int sequence, ack, src_port, dest_port, flags;
      /* initiate new nodes and arrays for MAC/IP linked list */
      struct Node* new_node_dst = NULL;
      struct Node* new_node_src = NULL;
      static struct Node* previous_node = NULL;
      char mac_src[20], mac_dst[20];
      char ip_src[20], ip_dst[20];

      errors=0; // nbr of errors per packet
      static int nbr_retransmissions = 0; // re-initialized everytime we encounter a packet different from the previous one
      int packet_nbr = count++;
      if (packet_nbr==1) {printf("\n");} // just a display preference

      if (loop_local_capt == true) {
        eth_header = (struct ether_header *) (packet + 2); // add 2 bytes in the packet because of linux cooked capture
      } else {
        eth_header = (struct ether_header *) (packet);
      }

      ethernet = (struct sniff_ethernet*)(packet);

      // recover the MAC addresses
      ether_ntoa_r(&ethernet->ether_shost, &mac_src);
      ether_ntoa_r(&ethernet->ether_dhost, &mac_dst);

      /*if (ntohs(eth_header->ether_type)==ETHERTYPE_ARP) {
        printf(GRN "ARP\n" RESET);
      }*/

      if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
          return;
      }

      /* Header lengths in bytes */
      ethernet_header_length = 14;
      if (loop_local_capt == 1) {
        ethernet_header_length+= 2;  // add 2 bytes in the packet because of linux cooked capture
      }

      /* Find start of IP header */
      ip_header = packet + ethernet_header_length;
      /* The second-half of the first byte in ip_header
         contains the IP header length (IHL). */
      ip_header_length = ((*ip_header) & 0x0F);
      /* The IHL is number of 32-bit segments. Multiply
         by four to get a byte count for pointer arithmetic */
      ip_header_length *= 4;
      ip_layer = (struct ip_layer*)(ip_header);


      // recover IP addresses
      snprintf(ip_src, 20, "%s", inet_ntoa(ip_layer->ip_src));
      snprintf(ip_dst, 20, "%s", inet_ntoa(ip_layer->ip_dst));

      /* Now that we know where the IP header is, we can
         inspect the IP header for a protocol number to
         make sure it is TCP before going any further.
         Protocol is always the 10th byte of the IP header */
      u_char protocol = *(ip_header + 9);

      // check if the TTL is not too low
      if (ip_layer->ip_ttl<TTL_THRESHOLD && protocol==IPPROTO_TCP) {
        printf(RED "/!\\ Low TTL encountered./!\\\n" RESET);
        // TODO - do not print this if SSDP inside UDP (TTL values usually equal to 1 or 2)
        // TODO - so we can study other UDP packets
        errors++;
        if (verbose) {
          printf(RED "\tTTL = %d\n" RESET, (ip_layer->ip_ttl));
          printf("Errors: %d\n", errors);
          printf("Packet nbr: %d\n", packet_nbr);
        }
      }

      if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) {
        return;
      } else if(protocol == IPPROTO_UDP){
        // UDP PACKET
        total_length = ntohs(ip_layer->ip_len);
        udp_header = packet + ethernet_header_length + ip_header_length;
        udp =  *(int *)(udp_header + 4);// showing the length of udp packet and add 4 to place the pointer at "the length of the packet"
        udp_length = ntohs(udp);
        if (udp_length > total_length ){
          printf(RED "/!\\ Overlapping Fragment /!\\\n" RESET);
          errors++;
          if (verbose) {
            printf(RED "\tUDP Length: %d\n\tTotal Length: %d\n" RESET, ntohs(udp), ntohs(ip_layer->ip_len));
          }
        }
      } else {
        // TCP PACKET
        tcp_header = packet + ethernet_header_length + ip_header_length; // Find start of TCP header
        tcp =  (struct tcp*)(tcp_header);// move to the tcp layer  and we can get the informations

        sequence = ntohl(tcp->th_seq);
        ack = ntohl(tcp->th_ack);
        src_port = ntohs(tcp->th_sport);
        dest_port = ntohs(tcp->th_dport);
        flags = tcp->th_flags;

        if (count > 1 && sequence == sequenceprev && ack == ackprev && src_port == src_port_prev && dest_port == dest_port_prev && flags == flags_prev)
        {
           // RETRANSMISSION
           if (++nbr_retransmissions>1) {
             printf(RED "/!\\ TCP Retransmission /!\\\n" RESET);
             errors++;
             if (verbose) {
               printf(RED "For this packet and the TWO previous one:\n\tSeq: %u\n\tAck: %u\n" RESET, sequence, ack);
             }
           }
        } else {
          nbr_retransmissions=0; // packet is not a retransmission so re-initialize the static variable
        }

        /*
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
        */
        sequenceprev = sequence;
        ackprev = ack;
        src_port_prev = src_port;
        dest_port_prev = dest_port;
        flags_prev = flags;
      }

      // initiate MAC/IP linked list with first source MAC/IP addresses
      if (count==2) {
        new_node_src = (struct Node*)malloc(sizeof(struct Node)); // allocate node in the heap
        strcpy(new_node_src->mac, mac_src);
        strcpy(new_node_src->ip, ip_src);
        new_node_src->previous = NULL;
      }

      // check SRC addresses (MAC & IP)
      if (check_host(previous_node, mac_src, ip_src)==0) {
        // enter MAC_DST and IP_DST in the MAC/IP linked list
        new_node_src = (struct Node*)malloc(sizeof(struct Node)); // allocate node in the heap
        strcpy(new_node_src->mac, mac_src);
        strcpy(new_node_src->ip, ip_src);
        new_node_src->previous = previous_node;
        previous_node = new_node_src;
      }

      // check DST addresses (MAC & IP)
      if (check_host(previous_node, mac_dst, ip_dst)==0) {
        // enter MAC_SRC and IP_SRC in the MAC/IP linked list
        new_node_dst = (struct Node*)malloc(sizeof(struct Node)); // allocate node in the heap
        strcpy(new_node_dst->mac, mac_dst);
        strcpy(new_node_dst->ip, ip_dst);
        new_node_dst->previous = previous_node;
        previous_node = new_node_dst;
      }

      // print results if errors were found in packet
      if (errors>0) {
        printf("Packet number: %d\n", packet_nbr);
        if (verbose) {
          printf("MAC src: %s\n", mac_src);
          printf("MAC dst: %s\n", mac_dst);
          printf("IP src: %s\n", ip_src);
          printf("IP dst: %s\n", ip_dst);
          if (protocol == IPPROTO_TCP) {
            printf("Protocol: TCP\n");
            printf("Src port: %u\n", src_port);
            printf("Dst port: %u\n", dest_port);
          } else if (protocol == IPPROTO_UDP) {
            printf("Protocol: UDP\n");
          }
        }
        printf("\n");
      }
}
