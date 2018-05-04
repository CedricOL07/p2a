#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>  /* GIMME a libpcap plz! */
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <time.h>

/* Convert 48 bit Ethernet ADDRess to ASCII.  */
extern char *ether_ntoa (__const struct ether_addr *__addr) __THROW;
extern char *ether_ntoa_r (__const struct ether_addr *__addr, char *__buf)
     __THROW;

/* Convert ASCII string S to 48 bit Ethernet address.  */
extern struct ether_addr *ether_aton (__const char *__asc) __THROW;
extern struct ether_addr *ether_aton_r (__const char *__asc,
					struct ether_addr *__addr) __THROW;

/* Map HOSTNAME to 48 bit Ethernet address.  */
/* Map HOSTNAME to 48 bit Ethernet address.  */
extern int ether_hostton (__const char *__hostname, struct ether_addr *__addr)
     __THROW;

void my_packet_handler(u_char *args,const struct pcap_pkthdr *header,const u_char *packet);
u_int16_t handle_ethernet(const struct pcap_pkthdr* pkthdr, const u_char* packet);

int main(int argc, char **argv)
{

  char errbuf[PCAP_ERRBUF_SIZE];// tell us if there is an error


  pcap_t *handle = pcap_open_offline(argv[1], errbuf);// to retrieve a pcap file pass in argument

  if(handle == NULL){
    printf("Error : %s\n", errbuf);
  }

  // allow to parse a pcap file, 0 show that unlimited loop, callback function, we don't have argument for the callbal function
  pcap_loop(handle, 0, my_packet_handler, NULL);

  return 0;
}

/*
* Name : my_packet_handler
* function :  function name that is the callback to be run on every packet captured
*             then display packet info
*
*/
void my_packet_handler(u_char *args,const struct pcap_pkthdr *packet_header,const u_char *packet_body)
{
  //printf("Packet capture length: %d\n", packet_header->caplen);
  printf("Packet total length %d\n", packet_header->len);

  u_int16_t type = handle_ethernet(packet_header, packet_body);
  
  if(ntohs(type) == ETHERTYPE_IP) {
    /* handle IP packet */
    printf("IP Packet!\n");
  }
}

u_int16_t handle_ethernet(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    // http://yuba.stanford.edu/~casado/pcap/section4.html
    struct ether_header *eptr;  /* net/ethernet.h */

    /* lets start with the ether header... */
    eptr = (struct ether_header *) packet;

    fprintf(stdout,"ethernet header source: %s"
            ,ether_ntoa((const struct ether_addr *)&eptr->ether_shost));
    fprintf(stdout," destination: %s "
            ,ether_ntoa((const struct ether_addr *)&eptr->ether_dhost));

    /* check to see if we have an ip packet */
    if (ntohs (eptr->ether_type) == ETHERTYPE_IP)
    {
        fprintf(stdout,"(IP)");
    }else  if (ntohs (eptr->ether_type) == ETHERTYPE_ARP)
    {
        fprintf(stdout,"(ARP)");
    }else  if (ntohs (eptr->ether_type) == ETHERTYPE_REVARP)
    {
        fprintf(stdout,"(RARP)");
    }else {
        fprintf(stdout,"(?)");
        // exit(1);
    }
    fprintf(stdout,"\n");

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
