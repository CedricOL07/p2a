#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>

#include <pcap.h>

#include "utils.h"

int main(int argc, char **argv) {
  int arg_nbr=-1;
  char file_out[50];
  int opt=0;
  fflush(stdin);
  char errbuf[PCAP_ERRBUF_SIZE];
  if (argc==1) {
    return help();
  }
  static struct option long_options[] = {
        {"help",          no_argument,       0, 'h'},
        {"verbose",       no_argument,       0, 'v'},
        {"debug",         no_argument,       0, 'd'},
        {"linux-cooked",  no_argument,       0, 'l'},
        {"exclude",       required_argument, 0, 'x'},
        {"save",          required_argument, 0, 's'},
        {0,               0,                 0,  0}

  };
  int long_index = 0;
  while ((opt = getopt_long(argc, argv,"hvdlxs", long_options, &long_index)) != -1) {
    switch (opt) {
      case 'h': help();
        break;
      case 'v': activate_verbose();
        break;
      case 'd': activate_debug();
        break;
      case 'l': activate_linux_cooked();
        break;
      case 'x':
        if (optarg==NULL) {
          exclude(argv[optind++]);
        } else {
          exclude(optarg);
        }
        break;
      case 's':
        if (optarg==NULL) {
          printf("OPT: %d %s\n", optind, argv[optind]);
          if (strlen(argv[optind])>45) {
            printf(YLW "[ERROR]" RESET "Please choose a shorter filename where to save the results..\n");
            exit(1);
          }
          strncpy(file_out, argv[optind], strlen(argv[optind]));
          optind++;
        } else {
          printf("OPT: %d %s %ld\n", optind, optarg, strlen(optarg));
          if (strlen(optarg)>45) {
            printf(YLW "[ERROR]" RESET "Please choose a shorter filename where to save the results..\n");
            exit(1);
          }
          strncpy(file_out, optarg, strlen(optarg));
        }
        save_json(file_out);
        break;
      default: return help();
    }
  }
  // check for leftover arguments (pcap file as well)
  while (optind < argc) {
    if (access(argv[optind], F_OK)==0 && arg_nbr==-1) {
      arg_nbr=optind;
      printf(GRN "[INFO]" RESET " Capture file: %s\n", argv[optind++]);
    } else {
      printf (RED "[ERROR]" RESET " Unexpected argument(s): ");
      while (optind < argc) printf ("%s ", argv[optind++]);
      putchar ('\n');
      return help();
    }
  }
  // check if pcap file among arguments
  if (arg_nbr==-1) {
    printf(RED "[Error]" RESET " Missing capture file\n!");
    return help();
  }

  printf(GRN "[INFO]" RESET " Parsing pcap file...\n");
  pcap_t *handle = pcap_open_offline(argv[arg_nbr], errbuf); // retrieve PCAP file passed as argument
  if(handle == NULL){
    printf(RED "[ERROR]" RESET " %s\n", errbuf);
    help();
    exit(1);
  }
  pcap_loop(handle, 0, my_packet_handler, NULL); // int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)

  analysis(argv[arg_nbr], file_out);

  return 0;
}
