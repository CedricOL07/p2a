#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>  /* GIMME a libpcap plz! */
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <time.h>



void my_packet_handler(u_char *args,const struct pcap_pkthdr *header,const u_char *packet);
void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header);

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
*
*/
void my_packet_handler(u_char *args,const struct pcap_pkthdr *packet_header,const u_char *packet_body)
{
    print_packet_info(packet_body, *packet_header);
    return;
}

/*
* Name : print_packet_info
* function :  display packet info
*
*/
void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
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
