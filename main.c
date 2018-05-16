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
#include "header.h"
//int cpt = 0;

// SIGNATURES
void my_packet_handler(u_char *args,const struct pcap_pkthdr *header,const u_char *packet);
u_int16_t handle_ethernet(const struct pcap_pkthdr* pkthdr, const u_char* packet);

// MAIN
int main(int argc, char **argv)
{

  char errbuf[PCAP_ERRBUF_SIZE];// tell us if there is an error

  if(argc<2) {
    printf("[ERROR] Missing the pcap file as argument!\nUsage: ./a.out my_file.pcap\n");
    return 1;
  }

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
      //printf("Packet capture length: %d\n", packet_header->caplen);
      //printf("Packet:\nTotal length: %d\n", header->len);
      /* First, lets make sure we have an IP packet */
      const struct sniff_tcp *tcp; /* The TCP header */
      struct tcphdr *tcphdr = NULL;
      struct ether_header *eth_header;

        /* TCP header */
    	typedef u_int tcp_seq;

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
      	#define TH_FLAGS (TH_RSTACK| TH_SYNACK|TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    		u_short th_win;		/* window */
    		u_short th_sum;		/* checksum */
    		u_short th_urp;		/* urgent pointer */
      };

	    count++;

      eth_header = (struct ether_header *) packet;
      if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
          //printf("Not an IP packet. Skipping...\n\n");
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

      /* Header lengths in bytes */
      int ethernet_header_length = 14; /* Doesn't change */
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
      tcp_header = packet + ethernet_header_length +ip_header_length;

      tcp = (struct tcp *)(tcp_header);// move to the tcp layer  and we can get the information

      printf("Src port: %d\n", ntohs(tcp->th_sport));
      printf("Dst port: %d\n", ntohs(tcp->th_dport));
      printf("sequence number: %ld\n", ntohl(tcp->th_seq));
      printf("acknowledge number: %ld\n", ntohl(tcp->th_ack));


      if (tcp->th_flags & TH_SYN){
          printf("Flag: TH_SYN\n");
      }
      else if (tcp->th_flags & TH_ACK){
          printf("Flag: TH_ACK\n");
      }
      else if (tcp->th_flags & TH_RST){
          printf("Flag: TH_RST\n");
      }
      else if (tcp->th_flags & TH_SYNACK){
          printf("Flag: TH_SYNACK\n");
      }
      else if (tcp->th_flags & TH_RSTACK){
          printf("Flag: TH_RSTACK\n");
      }

}

u_int16_t handle_ethernet(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    // http://yuba.stanford.edu/~casado/pcap/section4.html
    struct ether_header *eptr;  /* net/ethernet.h */
    const struct ip* ipHeader;
    const struct tcphdr* tcpHeader;
    char sourceIp[INET_ADDRSTRLEN];
    char destIp[INET_ADDRSTRLEN];
    u_int sourcePort, destPort;

    /* lets start with the ether header... */
    eptr = (struct ether_header *) packet;

    fprintf(stdout,"[Ethernet] %s -> %s\n"
            ,ether_ntoa((const struct ether_addr *)&eptr->ether_shost)
            ,ether_ntoa((const struct ether_addr *)&eptr->ether_dhost));

    /* check to see if we have an ip packet */
    fprintf(stdout, "[Protocol] ");
    if (ntohs(eptr->ether_type) == ETHERTYPE_IP) {
        // IPv4
        fprintf(stdout,"IPv4\n");
        ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
        inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);
        if (ipHeader->ip_p == IPPROTO_TCP) {
          //tcpHeader = (tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
          //sourcePort = ntohs(tcpHeader->source);
          //destPort = ntohs(tcpHeader->dest);
          printf("[TCP] %s -> %s\n", sourceIp, destIp);
        }
    } else if (ntohs(eptr->ether_type) == ETHERTYPE_ARP) {
        fprintf(stdout,"ARP");
    } else if (ntohs(eptr->ether_type) == ETHERTYPE_REVARP) {
        fprintf(stdout,"RARP");
    } else if (ntohs(eptr->ether_type)==34525){
        // IPv6
        fprintf(stdout,"IPv6\n");
        ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
        if (ipHeader->ip_p == IPPROTO_TCP) {
          printf("TCP\n");
        }
    } else {
        fprintf(stdout,"?");
        // exit(1);
    }
    fprintf(stdout,"\n\n");
    return eptr->ether_type;
}

/* ask pcap to find a valid device for use to sniff on */
/*  dev = pcap_lookupdev(errbuf);

 error checking
if(dev == NULL)
{
 printf("%s\n",errbuf);
 exit(1);
}

/* print out device name
printf("DEV: %s\n",dev);

/* ask pcap for the network address and mask of the device *
ret = pcap_lookupnet(dev,&netp,&maskp,errbuf);

if(ret == -1)
{
 printf("%s\n",errbuf);
 exit(1);
}

/* get the network address in a human readable form
addr.s_addr = netp;
net = inet_ntoa(addr);

if(net == NULL)/* thanks Scott :-P
{
  perror("inet_ntoa");
  exit(1);
}

printf("NET: %s\n",net);

/* do the same as above for the device's mask
addr.s_addr = maskp;
mask = inet_ntoa(addr);

if(mask == NULL)
{
  perror("inet_ntoa");
  exit(1);
}

printf("MASK: %s\n",mask);
*/
