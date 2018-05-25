#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <pcap.h>

#include "utils.h"

// MAIN
int main(int argc, char **argv)
{
  fflush(stdin);
  char errbuf[PCAP_ERRBUF_SIZE];// tell us if there is an error

  if(argc<2) {
    printf("[ERROR] Missing the pcap file as argument!\nUsage: ./a.out my_file.pcap\n");
    return 1;
  }

  if (check_local_capture()!=0) {
    printf("[ERROR] An error occured while trying to understand if the capture was local or not.\n");
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
