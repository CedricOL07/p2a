#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

#include <pcap.h>

#include "utils.h"

// MAIN
int main(int argc, char **argv)
{
  int arg_nbr;
  fflush(stdin);
  char errbuf[PCAP_ERRBUF_SIZE];// tell us if there is an error

  if (argc==1) {
    return help();
  }
  /* iterate over all arguments */
  for (int i = 1; i < argc; i++) {
      if (strcmp("-h", argv[i]) == 0) {
         return help();
      }
      if (strcmp("-l", argv[i]) == 0) {
         printf("Linux Cooked Capture: ON\n");
         activate_linux_cooked();
         continue;
      }
      //const char *filename = "/tmp/myfile";
      if (access(argv[i], F_OK)==0) {
        arg_nbr=i;
        printf("Capture file: %s\n", argv[i]);
        continue;
      }
      return help();
  }
  /*
  if (check_local_capture()!=0) {
    printf("[ERROR] An error occured while trying to understand if the capture was local or not.\n");
    return 1;
  }
  */
  pcap_t *handle = pcap_open_offline(argv[arg_nbr], errbuf);// to retrieve a pcap file pass in argument

  if(handle == NULL){
    printf("[ERROR] %s\n", errbuf);
  }
  // allow to parse a pcap file, 0 show that unlimited loop, callback function, we don't have argument for the callbal function
  pcap_loop(handle, 0, my_packet_handler, NULL);

  return 0;
}
