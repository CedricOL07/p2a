#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <time.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <linux/tcp.h> // TCP
#include <stdbool.h>
#include "header.h"
#include<string.h>
#define MAX_STRING_LEN 4
bool loop_local_capt = false; // define there is linux cooked capture or not for the ethernet layerµ.
// MAIN
int main(int argc, char **argv)
{
  fflush(stdin);
  char errbuf[PCAP_ERRBUF_SIZE];// tell us if there is an error

  char check[MAX_STRING_LEN];
  //printf("check : %s\n",check );
  if(argc<2) {
    printf("[ERROR] Missing the pcap file as argument!\nUsage: ./a.out my_file.pcap\n");
    return 1;
  }

  printf("Does Your pcap file have been done with the local loop (127.0.0.1)? (yes or no)");

  // check if the condition is valid or not
   do{
    scanf(" %s", check);
    //printf("no : %d", strcmp(check,"no"));
    if (strcmp(check,"no") != 0 && strcmp(check,"yes") !=0){
      printf("\nYou have to write either yes or no. Please try again : ");
      scanf("value : %s", check);
    }
  }while (strcmp(check,"no") != 0 && strcmp(check,"yes") != 0);


  if (strcmp(check,"yes") == 0)
  {
    loop_local_capt = true;

  }
  else{ loop_local_capt = false;}

  pcap_t *handle = pcap_open_offline(argv[1], errbuf);// to retrieve a pcap file pass in argument

  if(handle == NULL){
    printf("[ERROR] %s\n", errbuf);
  }
  // allow to parse a pcap file, 0 show that unlimited loop, callback function, we don't have argument for the callbal function
  pcap_loop(handle, 0, my_packet_handler, NULL);

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
      //printf("Packet capture length: %d\n", header->caplen);
      //printf("Packet:\nTotal length: %d\n", header->len);
      struct ether_header *eth_header;
      /* First, lets make sure we have an IP packet */

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

      // guess a condition which take apart of the name of the file anf there is linuxcookcap we need to add 2 bits to the packets.
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
      const u_char *payload;
      int ethernet_header_length;

      /* Header lengths in bytes */
      if (loop_local_capt == 1){
      ethernet_header_length = 16; /* Doesn't change */// add 2 byte in the packet because we work with  linux cooked capture
      }
      else {ethernet_header_length = 14; }
      int ip_header_length;
      int tcp_header_length;
      int payload_length;

      /* Find start of IP header */
      ip_header = packet + ethernet_header_length;
      /* The second-half of the first byte in ip_header
         contains the IP header length (IHL). */
      ip_header_length = ((*ip_header) & 0x0F);
      /* The IHL is number of 32-bit segments. Multiply
         by four to get a byte count for pointer arithmetic */
      ip_header_length = ip_header_length * 4;
      //printf("IP header length (IHL) in bytes: %d\n", ip_header_length);

      /* Now that we know where the IP header is, we can
         inspect the IP header for a protocol number to
         make sure it is TCP before going any further.
         Protocol is always the 10th byte of the IP header */
      u_char protocol = *(ip_header + 9);
      if (protocol != IPPROTO_TCP) {
          printf("\nNot a TCP packet. Skipping...\n\n");
          return;
      }
      else { printf("\nIt is a TCP packet\n");}
      printf("Packet number %d:\n", count);
      /* Find start of TCP header */
      tcp_header = packet + ethernet_header_length + ip_header_length;
      tcp =  (struct tcp*)(tcp_header);// move to the tcp layer  and we can get the information
      /*int *stockseqnumber;
      stockseqnumber = (int*) malloc(50 * sizeof(int));
      int taille = size_t malloc_usable_size (void *stockseqnumber);

      if (taille >3 ){ free (stockseqnumber); }
      */
      printf("Src port: %u\n", ntohs(tcp->th_sport));
      printf("Dst port: %u\n", ntohs(tcp->th_dport));

      printf("sequence number: %u\n", ntohl(tcp->th_seq));
      printf("acknowledge number: %u\n", ntohl(tcp->th_ack));
      int sequence = ntohl(tcp->th_ack);
      if (count > 1 && sequence == sequenceprev ) {printf("Be careful, there is 2 consecutive sequences that are the same sequence number.\n");}

      if (count == 1 ) {sequenceprev = ntohl(tcp->th_ack);};

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

      if (count >1 ) {sequenceprev = ntohl(tcp->th_ack);}

}
