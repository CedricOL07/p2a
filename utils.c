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

#define D_HOST_MAC_ADDR 6
#define MAX_STRING_LEN 4
#define TTL_THRESHOLD 10 // 0 <= TTL <= 255
#define RED   "\x1B[31m"
#define GRN   "\x1B[32m"
#define YEL   "\x1B[33m"
#define BLU   "\x1B[34m"
#define MAG   "\x1B[35m"
#define CYN   "\x1B[36m"
#define WHT   "\x1B[37m"
#define RESET "\x1B[0m"

bool loop_local_capt = false; // define if there is linux cooked capture or not for the ethernet layer.

int help() {
  printf("Usage: ./pacapp [-l] ./pcap_file.pcapng\n");
  printf("\t-l: if the capture is a Linux Cooked Capture\n");
  printf("\t-h: display this help message\n");
  return 1;
}

void activate_linux_cooked() {
  loop_local_capt = true;
}

/*
* Name : check_local_capture
* function :  asks the user if the capture was done on local loop (127.0.0.1)
*             and sets up the loop_local_capt variable accordingly
*/
int check_local_capture()
{
  char check[MAX_STRING_LEN];

  printf("Is your pcap file a 'Linux cooked capture'? (yes or no): ");

  // check if the condition is valid or not
  do {
    scanf(" %s", check);
    //printf("no : %d", strcmp(check,"no"));
    if (strcmp(check,"no") != 0 && strcmp(check,"yes") !=0){
      printf("\nYou have to write either yes or no. Please try again : ");
      scanf("value : %s", check);
    }
  } while (strcmp(check,"no") != 0 && strcmp(check,"yes") != 0);

  if (strcmp(check,"yes") == 0) {
    loop_local_capt = true;
  } else {
    loop_local_capt = false;
  }
  return 0;
}

/*
* Name : my_packet_handler
* function :  function is the callback to be run on every packet captured (called by <pcap_loop>)
*             then display packet info
*
*/
void my_packet_handler(u_char *args,const struct pcap_pkthdr *header,const u_char *packet)
{

      static int count = 1; /* packet counter */
      static int sequenceprev = 1 ;
      static int ackprev = 1;
      static int src_port_prev = 1;
      static int dest_port_prev = 1;
      static int flags_prev = 1;
      struct ether_header *eth_header;

      /* Ethernet header */
      struct sniff_ethernet {
              u_char  ether_dhost[D_HOST_MAC_ADDR];    /* destination host address */
              u_char  ether_shost;    /* source host address */
              u_short ether_type;                     /* IP? ARP? RARP? etc */
      };
      const struct sniff_ethernet *ethernet;

      /* First, lets make sure we have an IP packet */
      /* IPv6 header. RFC 2460, section3.
      Reading /usr/include/netinet/ip6.h is interesting */
      /* IP header */
      const struct sniff_ip *ip_layer;
      struct sniff_ip {
              u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
              u_char  ip_tos;                 /* type of service */
              u_short ip_len;                 /* total length */
              u_short ip_id;                  /* identification */
              u_short ip_off;                 /* fragment offset field */
              #define IP_RF 0x8000            /* reserved fragment flag */
              #define IP_DF 0x4000            /* dont fragment flag */
              #define IP_MF 0x2000            /* more fragments flag */
              #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
              u_char  ip_ttl;                 /* time to live */
              u_char  ip_p;                   /* protocol */
              u_short ip_sum;                 /* checksum */
              struct  in_addr ip_src,ip_dst;  /* source and dest address */
      };
      #define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
      #define IP_V(ip)                (((ip)->ip_vhl) >> 4)



      /* TCP header */
      const struct sniff_tcp *tcp;
    	typedef uint32_t tcp_seq;
    	struct sniff_tcp {
    		u_short th_sport;	/* source port */
    		u_short th_dport;	/* destination port */
        tcp_seq th_seq;     /* sequence number */
        tcp_seq th_ack;		/* acknowledgement number */
    		u_char th_offx2;	/* data offset, rsvd */
      	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
      	u_char th_flags;
      	#define TH_FIN 0x01
      	#define TH_SYN 0x02
      	#define TH_RST 0x04
      	#define TH_PUSH 0x08
      	#define TH_ACK 0x10
      	#define TH_URG 0x20
      	#define TH_ECE 0x40
      	#define TH_CWR 0x80
        #define TH_SYNACK 0x12
        #define TH_RSTACK 0x14
        #define TH_PHACK 0x18
      	#define TH_FLAGS (TH_PHACK |TH_RSTACK| TH_SYNACK|TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR| )
    		u_short th_win;		/* window */
    		u_short th_sum;		/* checksum */
    		u_short th_urp;		/* urgent pointer */
      };

	    count++;

      if (loop_local_capt == true){
      eth_header = (struct ether_header *) (packet + 2); // add 2 byte in the packet because we work with  linux cooked capture
      }
      else {eth_header = (struct ether_header *) (packet);}

      ethernet = (struct sniff_ethernet*)(packet);
      printf("\nPacket number %d:\n", count);
      printf("Source MAC address is : %s\n", ether_ntoa(&ethernet->ether_shost));
      printf("Destination MAC address is : %s\n", ether_ntoa(&ethernet->ether_dhost));
      // guess a condition which take apart of the name of the file anf there is linuxcookcap we need to add 2 bits to the packets.
      // i
      if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
          printf("Not an IP packet. Skipping...\n\n");
          return;
      }

      /* The total packet length, including all headers
         and the data payload is stored in
         header->len and header->caplen. Caplen is
         the amount actually available, and len is the
         total packet length even if it is larger
         than what we currently have captured. If the snapshot
         length set with pcap_open_live() is too small, you may
         not have the whole packet. */
      /*printf("Total packet available: %d bytes\n", header->caplen);
      printf("Expected packet size: %d bytes\n", header->len);*/

      /* Pointers to start point of various headers */
      const u_char *ip_header;
      const u_char *tcp_header;
      const u_char *udp_header;
      //const u_char *payload;
      int ethernet_header_length;

      /* Header lengths in bytes */
      if (loop_local_capt == 1){
      ethernet_header_length = 16; /* Doesn't change */// add 2 byte in the packet because we work with  linux cooked capture
      }
      else {ethernet_header_length = 14; }
      int ip_header_length;
      //int tcp_header_length;
      //int payload_length;

      /* Find start of IP header */
      ip_header = packet + ethernet_header_length;
      /* The second-half of the first byte in ip_header
         contains the IP header length (IHL). */
      ip_header_length = ((*ip_header) & 0x0F);
      /* The IHL is number of 32-bit segments. Multiply
         by four to get a byte count for pointer arithmetic */
      ip_header_length = ip_header_length * 4;
      //printf("IP header length (IHL) in bytes: %d\n", ip_header_length);
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
        int udp =  *(int *)(udp_header + 4);// showing the length of udp packet and add 4 to place us at the length of the packet
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

      /*for (int i = 0 ; i < taille; i++)
      {
        if (stockseqnumber[i-1] == stockseqnumber[i] && &stockseqnumber[i-1] != NULL)
        {
          printf("We have the same consecutive sequence number");
        }

      }*/

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
