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
#include <netinet/if_ether.h> //
#include <net/ethernet.h>     //
#include <netinet/ether.h>    //
#include <netinet/ip.h>
#include <linux/tcp.h>        // TCP
#include <openssl/sha.h>      // For SHA1 - to identify sessions

#include "utils.h"            // not necessary

#define MAX_STRING_LEN 4
#define TTL_THRESHOLD 10      // 0 <= TTL <= 255
/*#define RED   "\033[1m\033[31m"
#define GRN   "\033[1m\033[32m"
#define YLW   "\033[1m\033[33m"
#define RESET "\x1B[0m"*/

void add_packet_to_session(struct Session *s, struct TCP_Packet *new_packet, char mac_src[20], char mac_dst[20]);
void print_session(struct Session *s);

bool loop_local_capt = false; // DEPRECIATED - define if there is linux cooked capture or not for the ethernet layer.
bool VERBOSE_ON = false;         // mode VERBOSE_ON unabled by default
bool DEBUG_ON = false;           // mode debug unabled by default
bool EXCLUDE_RET = false;
bool EXCLUDE_TTL = false;
bool EXCLUDE_MAC = false;

struct Session* previous_session = NULL;

int help() {
  // prints usage
  printf("Usage: ./p2a [OPTIONS] FILE\n");
  //printf("\t-l: if the capture is a Linux Cooked Capture\n");
  printf("\t-h: display this help message\n");
  printf("\t-v: verbose option\n");
  printf("\t-d: debug option\n");
  printf("Example: ./p2a -v ./pcap_files/some_pcap_file.pcapng\n");
  return 1;
}

void activate_verbose(){
  // sets the global variable VERBOSE_ON to true
  VERBOSE_ON = true;
  printf(GRN "Verbose option: ON\n" RESET);
}

void activate_debug(){
  // sets the global variable DEBUG_ON to true
  DEBUG_ON = true;
  printf(GRN "Debug option: ON\n" RESET);
}

void activate_linux_cooked() {
  // DEPRECIATED
  loop_local_capt = true;
  //printf(GRN "Linux Cooked Capture: ON\n" RESET);
  printf(RED "[ERROR] " RESET "Linux Cooked Captures not yet implemented. Working on it though!\n");
  exit(1);
}

int nbr_digits(int a) {
  /*
   * Returns the number of digits in a relatively small positive integer.
   * Yep, pretty ugly but oh well..
   */
  if (a<0) return -1;
  if (a<10) return 1;
  if (a<100) return 2;
  if (a<1000) return 3;
  if (a<10000) return 4;
  if (a<100000) return 5;
  if (a<1000000) return 6;
  if (a<10000000) return 7;
  if (a<100000000) return 8;
  if (a<1000000000) return 9;
  if (a<10000000000) return 10;
  return -1;
}

void sha(char ip[20], int port, char* hash_string) {
  /*
   * Returns sha1(<ip>, <port>) in <hash_string>
   */
  unsigned char hash[SHA_DIGEST_LENGTH];
  char port_str[nbr_digits(port)];
  sprintf(port_str, "%d", port);
  SHA_CTX ctx;
  SHA1_Init(&ctx);
  SHA1_Update(&ctx, ip, strlen(ip));
  SHA1_Update(&ctx, port_str, strlen(port_str));
  SHA1_Final(hash, &ctx);
  for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
    sprintf(&hash_string[i*2], "%02x", (unsigned int)hash[i]);
  }
}


void print_sessions(struct Session *s) {
  /*
   * Given the last session <s>, goes up the Session linked list and prints a summary of all of them.
   */
  int nbr_packets;
  struct TCP_Packet *p;
  while (s != NULL) {
    printf("\n");
    if (DEBUG_ON) printf("Session IDs: %s %s\n", s->hash_src, s->hash_dst);
    printf("MAC src: %s | MAC dst: %s\n", s->last_mac_src->address, s->last_mac_dst->address);
    printf("IP src: %s:%d | IP dst: %s:%d\n", s->ip_src, s->port_src, s->ip_dst, s->port_dst);
    p = s->first_p;
    nbr_packets = 0;
    while (p != NULL) {
      p = p->next_p;
      nbr_packets++;
    }
    printf("Nbr packets: %d\n", nbr_packets);
    s = s->previous_s;
  }
}


void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
  /*
   * "callback" function to be run on every packet captured (called by <pcap_loop> in main)
   */
  static int count = 1; // packet counter
  /*Pointers to initialze the structures*/
  const struct ether_header *eth_header;
  const struct sniff_ethernet *ethernet;
  const struct sniff_tcp *tcp;
  /* Pointers to start point of various headers */
  const u_char *ip_header;
  const u_char *tcp_header;
  //const u_char *udp_header; // not yet
  /* Variables indicating the length of a packet parts */
  int ethernet_header_length;
  int ip_header_length;
  int length_ip, ip_ttl;
  /* UDP packet variables */
  //int total_length, udp, udp_length; // not used for now
  /* TCP packet variables */
  long int sequence, ack;
  int port_src, port_dst, flags;
  /* initiate new arrays for MAC/IP addresses */
  char mac_src[20], mac_dst[20];
  char ip_src[20], ip_dst[20];
  /* Session and TCP_Packet initialization */
  struct Session* new_session = NULL;
  struct Session* s = NULL;
  struct TCP_Packet* new_packet = NULL;
  //struct MAC_address* m_src = NULL;
  //struct MAC_address* m_dst = NULL;
  struct MAC_address* new_mac_dst = NULL;
  struct MAC_address* new_mac_src = NULL;
  struct TTL* new_ttl;
  char hash_string_src[SHA_DIGEST_LENGTH*2+1];
  char hash_string_dst[SHA_DIGEST_LENGTH*2+1];
  bool found_packet = false;
  /* Packet nbr info */
  int packet_nbr = count++;          // global packet number in the capture

  // Get Ethernet packet.
  if (loop_local_capt == true) {
    eth_header = (struct ether_header *) (packet + 2); // add 2 bytes in the packet because of linux cooked capture
  } else {
    eth_header = (struct ether_header *) (packet);
  }

  ethernet = (struct sniff_ethernet*)(packet);

  // Recover MAC addresses.
  ether_ntoa_r((const struct ether_addr *)&ethernet->ether_shost, (char *)&mac_src);
  ether_ntoa_r((const struct ether_addr *)&ethernet->ether_dhost, (char *)&mac_dst);

  /*if (ntohs(eth_header->ether_type)==ETHERTYPE_ARP) {
    printf(GRN "ARP\n" RESET);
  }*/

  if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {return;}

  /* Header lengths in bytes */
  ethernet_header_length = 14;
  if (loop_local_capt == 1) {
    ethernet_header_length+= 2;  // add 2 bytes in the packet for Linux cooked captures - DEPRECIATED
  }

  // Find start of IP header.
  ip_header = packet + ethernet_header_length;
  /* The second-half of the first byte in ip_header
     contains the IP header length (IHL). */
  ip_header_length = ((*ip_header) & 0x0F);
  /* The IHL is number of 32-bit segments. Multiply
     by four to get a byte count for pointer arithmetic */
  ip_header_length *= 4;
  ip_layer = (struct sniff_ip*)(struct ip_layer*)(ip_header);

  // Recover IP addresses.
  snprintf(ip_src, 20, "%s", inet_ntoa(ip_layer->ip_src));
  snprintf(ip_dst, 20, "%s", inet_ntoa(ip_layer->ip_dst));
  length_ip = ntohs(ip_layer->ip_len);
  ip_ttl = ip_layer->ip_ttl;

  /* Now that we know where the IP header is, we can
     inspect the IP header for a protocol number to
     make sure it is TCP before going any further.
     Protocol is always the 10th byte of the IP header */
  u_char protocol = *(ip_header + 9);

  if (protocol!=IPPROTO_TCP) {return;} // TODO - UDP protocol

  tcp_header = packet + ethernet_header_length + ip_header_length; // Find start of TCP header
  tcp = (struct sniff_tcp*)(struct tcp*)(tcp_header);

  // Recover TCP packet info.
  port_src = ntohs(tcp->th_sport);
  port_dst = ntohs(tcp->th_dport);
  sequence = ntohl(tcp->th_seq);
  ack = ntohl(tcp->th_ack);
  flags = tcp->th_flags;

  // Compute SHA1 of <IP|Port> for destination and source addresses.
  sha(ip_dst, port_dst, hash_string_dst);
  sha(ip_src, port_src, hash_string_src);

  // Create new <TCP_Packet>.
  new_packet = (struct TCP_Packet*)malloc(sizeof(struct TCP_Packet)); // allocate packet in the heap
  new_packet->seq = sequence;
  new_packet->ack = ack;
  new_packet->flags = flags;
  new_packet->number = packet_nbr;
  new_packet->len = length_ip-52;
  new_packet->ttl = ip_ttl;
  new_packet->keepalive = false;
  new_packet->retransmitted = false;
  strncpy(new_packet->hash_src, hash_string_src, sizeof(new_packet->hash_src));
  strncpy(new_packet->hash_dst, hash_string_dst, sizeof(new_packet->hash_dst));
  new_packet->next_p = NULL;

  // Looks for hash of <new_packet> in current sessions to try to add it to one of them.
  s = previous_session;
  while (s!=NULL) {
    if (strcmp(hash_string_dst, s->hash_dst)==0 && strcmp(hash_string_src, s->hash_src)==0) {
      found_packet = true;
      add_packet_to_session(s, new_packet, mac_src, mac_dst);
      break;
    } else if (strcmp(hash_string_dst, s->hash_src)==0 && strcmp(hash_string_src, s->hash_dst)==0) {
      found_packet = true;
      add_packet_to_session(s, new_packet, mac_dst, mac_src);
      break;
    }
    s = s->previous_s;
  }

  // If hash of <new_packet> not in current session, creates a new <Session> with <new_packet> as initial packet.
  if (!found_packet) {
    new_session = (struct Session*)malloc(sizeof(struct Session)); // allocate session in the heap
    new_mac_src = (struct MAC_address*)malloc(sizeof(struct MAC_address)); // allocate mac struct in the heap
    new_mac_dst = (struct MAC_address*)malloc(sizeof(struct MAC_address)); // allocate mac struct in the heap
    strncpy(new_mac_src->address, mac_src, sizeof(new_mac_src->address));
    strncpy(new_mac_dst->address, mac_dst, sizeof(new_mac_dst->address));
    new_mac_src->previous_mac = NULL;
    new_mac_dst->previous_mac = NULL;
    new_session->last_mac_dst = new_mac_dst;
    new_session->last_mac_src = new_mac_src;
    strncpy(new_session->ip_src, ip_src, sizeof(new_session->ip_src));
    strncpy(new_session->ip_dst, ip_dst, sizeof(new_session->ip_dst));
    strncpy(new_session->hash_src, hash_string_src, sizeof(new_session->hash_src));
    strncpy(new_session->hash_dst, hash_string_dst, sizeof(new_session->hash_dst));
    new_ttl = (struct TTL*)malloc(sizeof(struct TTL)); // allocate TTL struct in heap
    new_ttl->previous_ttl = NULL;
    new_ttl->val = ip_ttl;
    new_session->last_ttl = new_ttl;
    new_session->port_dst = port_dst;
    new_session->port_src = port_src;
    new_session->seq_keepalive = 0;
    new_session->first_p = new_packet;
    new_session->last_p = new_packet;
    new_session->previous_s = previous_session;
    previous_session = new_session;
  }

}

void add_packet_to_session(struct Session *s, struct TCP_Packet *new_packet, char mac_src[20], char mac_dst[20]) {
  struct MAC_address* m_src = NULL;
  struct MAC_address* m_dst = NULL;
  struct MAC_address* new_mac_dst = NULL;
  struct MAC_address* new_mac_src = NULL;
  struct TTL* ttl = NULL;
  struct TTL* new_ttl = NULL;
  bool found_mac_src = false;
  bool found_mac_dst = false;
  bool found_ttl = false;
  // check if packet is keepalive (ack)
  if (s->seq_keepalive==0) {
    struct TCP_Packet* previous = s->last_p;
    while (previous != NULL && strcmp(new_packet->hash_src, previous->hash_src) != 0) {
      previous = previous->next_p;
    }
    if (previous != NULL) {
      if (previous->seq-1 == new_packet->seq && new_packet->len==0 && new_packet->flags == TH_ACK) {
        new_packet->keepalive = true;
        s->seq_keepalive = new_packet->seq;
      }
    }
  } else {
    if (new_packet->seq == s->seq_keepalive && new_packet->flags == TH_ACK && new_packet->len == 0) {
      new_packet->keepalive = true; // KeepAlive
    } else if (new_packet->ack == s->seq_keepalive+1 && new_packet->flags == TH_ACK) {
      new_packet->keepalive = true; // KeepAlive ACK
    }
  }
  // add packet to session
  s->last_p->next_p = new_packet;
  s->last_p = new_packet;
  // check for different MAC addresses
  m_src = s->last_mac_src;
  m_dst = s->last_mac_dst;
  while (m_dst!=NULL) {
    if (strcmp(m_dst->address, mac_dst)==0) {
      found_mac_dst=true;
      break;
    }
    m_dst=m_dst->previous_mac;
  }
  while (m_src!=NULL) {
    if (strcmp(m_src->address, mac_src)==0) {
      found_mac_src=true;
      break;
    }
    m_src=m_src->previous_mac;
  }
  // check for different TTL values
  ttl = s->last_ttl;
  while (ttl!=NULL) {
    if (ttl->val == new_packet->ttl) {
      found_ttl=true;
      break;
    }
    ttl=ttl->previous_ttl;
  }
  // if MAC address of Packet is not already among Session's MAC addresses, add it to list of MAC addresses
  if (!found_mac_dst) {
    new_mac_dst = (struct MAC_address*)malloc(sizeof(struct MAC_address)); // allocate mac struct in the heap
    new_mac_dst->previous_mac = s->last_mac_dst;
    strncpy(new_mac_dst->address, mac_dst, sizeof(new_mac_dst->address));
    s->last_mac_dst=new_mac_dst;
  }
  if (!found_mac_src) {
    new_mac_src = (struct MAC_address*)malloc(sizeof(struct MAC_address)); // allocate mac struct in the heap
    new_mac_src->previous_mac = s->last_mac_src;
    strncpy(new_mac_src->address, mac_src, sizeof(new_mac_src->address));
    s->last_mac_src=new_mac_src;
  }
  // if TTL not found, add if to the list of TTLs
  if (!found_ttl) {
    new_ttl = (struct TTL*)malloc(sizeof(struct TTL)); // allocate TTL struct in heap
    new_ttl->previous_ttl = s->last_ttl;
    new_ttl->val = new_packet->ttl;
    s->last_ttl = new_ttl;
  }
}

void analysis() {
  /*
   * Once all packets have been parsed, this analyzes all of them to find ambiguities
   * TODO
   */
  if (DEBUG_ON) print_sessions(previous_session);
  printf(GRN "\n[INFO]" RESET " Launching analysis...\n");
  int counter_sessions=0;
  int counter_mac_src, counter_mac_dst, counter_ttl;
  bool session_printed, packet_printed;
  bool ret_found, ttl_found; // ambiguities found for a given session
  struct MAC_address* m_src;
  struct MAC_address* m_dst;
  struct TTL* ttl;
  struct Session* s = previous_session;
  struct TCP_Packet *p, *p2;
  while (s != NULL) {
    counter_sessions++;
    counter_mac_src = 0;
    counter_mac_dst = 0;
    counter_ttl = 0;
    session_printed = false;
    ttl_found = false;
    ret_found = false;
    m_dst = s->last_mac_dst;
    m_src = s->last_mac_src;
    ttl = s->last_ttl;
    while (m_src != NULL) {
      counter_mac_src++;
      m_src = m_src->previous_mac;
    }
    while (m_dst != NULL) {
      counter_mac_dst++;
      m_dst = m_dst->previous_mac;
    }
    while (ttl != NULL) {
      counter_ttl++;
      ttl = ttl->previous_ttl;
    }
    // Different MAC addresses for one IP
    if (counter_mac_dst!=1 && !EXCLUDE_MAC) {
      if (!session_printed) {
        print_session(s);
        session_printed=true;
      }
      m_dst = s->last_mac_dst;
      if (VERBOSE_ON) {
        printf(RED "\tMultiple MAC addresses associated to %s:\n" RESET, s->ip_dst);
        while (m_dst!=NULL) {
          printf(RED "\t\t%s\n" RESET, m_dst->address);
          m_dst = m_dst->previous_mac;
        }
      } else {
        printf(RED "[MAC]" RESET);
      }
    }
    if (counter_mac_src!=1 && !EXCLUDE_MAC) {
      if (!session_printed) {
        print_session(s);
        session_printed=true;
      }
      m_src = s->last_mac_src;
      if (VERBOSE_ON) {
        printf(RED "\tMultiple MAC addresses associated to %s:\n" RESET, s->ip_src);
        while (m_src!=NULL) {
          printf(RED "\t\t%s\n" RESET, m_src->address);
          m_src = m_src->previous_mac;
        }
      } else {
        printf(RED "[MAC]" RESET);
      }
    }
    // Different TTLs in one session
    if (counter_ttl>2 && !EXCLUDE_TTL) {
      if (!session_printed) {
        print_session(s);
        session_printed=true;
      }
      ttl = s->last_ttl;
      if (VERBOSE_ON || DEBUG_ON) {
        printf(YLW "\tMultiple TTLs found in this session: " RESET);
        while (ttl!=NULL) {
          printf(YLW "%d " RESET, ttl->val);
          ttl = ttl->previous_ttl;
        }
        printf("\n");
      } else if (!DEBUG_ON){
        printf(YLW "[TTL]" RESET);
      }
    }
    // Low TTL & retransmissions
    p = s->first_p;
    while (p != NULL) {
      // Low TTL
      if (p->ttl < TTL_THRESHOLD && !EXCLUDE_TTL) {
        if (!session_printed) {
          print_session(s);
          session_printed=true;
        }
        if (VERBOSE_ON) {
          printf(RED "\tLow TTL encountered in Packet %d\n" RESET, p->number);
          printf("\tSEQ = %ld\n\tACK = %ld\n\tTTL = %d\n", p->seq, p->ack, p->ttl);
          print_flag(p->flags);
        } else if (!ttl_found) {
          printf(RED "[TTL]" RESET);
          ttl_found = true;
        }
      }
      // Retransmissions
      if (!p->retransmitted && !EXCLUDE_RET) {
        p2 = p->next_p;
        packet_printed = false;
        while (p2 != NULL) {
          if (p2->keepalive == false && strcmp(p->hash_src, p2->hash_src)==0 && p->seq==p2->seq && p->ack==p2->ack && p->flags==p2->flags && p->flags!=TH_RST) {
            if (p->len==0 && p->flags==TH_ACK && p2->len!=0) {
              // normal
              break;
            } else {
              if (!session_printed) {
                print_session(s);
                session_printed=true;
              }
              if (!packet_printed) {
                if (DEBUG_ON || VERBOSE_ON) {
                  printf(RED "\tTCP retransmission:\n" RESET);
                  printf("\tPacket %d\n\t\tSEQ = %ld | ACK = %ld\n\t\tLEN = %d\n\t", p->number, p->seq, p->ack, p->len);
                  print_flag(p->flags);
                } else if (!ret_found) {
                    printf(RED "[RET]" RESET);
                    ret_found = true;
                }
                packet_printed = true;
                p->retransmitted=true;
              }
              if (VERBOSE_ON || DEBUG_ON) printf("\tPacket %d | LEN = %d\n", p2->number, p2->len);
              p2->retransmitted=true;
            }
          }
          p2 = p2->next_p;
        }
      }
      p = p->next_p;
    }
    s = s->previous_s;
  }
  if (!VERBOSE_ON) printf("\n");
  printf(GRN "\n[DONE]" RESET " Processed %d connection(s).\n", counter_sessions);
}

void print_session(struct Session *s) {
  printf("\n");
  if (DEBUG_ON) printf("Session IDs: %s %s\n", s->hash_src, s->hash_dst);
  printf(STRG "%15s:%-5d --> %15s:%-5d" RESET, s->ip_src, s->port_src, s->ip_dst, s->port_dst);
  if (DEBUG_ON || VERBOSE_ON) {
    printf("\n");
  } else {
    printf("\t");
  }
}

void print_flag(int flag) {
  switch (flag) {
    case TH_SYN:
      printf("\tFlag = SYN\n");
      break;
    case TH_PHACK:
      printf("\tFlag = PUSH-ACK\n");
      break;
    case TH_ACK:
      printf("\tFlag = ACK\n");
      break;
    case TH_RST:
      printf("\tFlag = RST\n");
      break;
    case TH_SYNACK:
      printf("\tFlag = SYN-ACK\n");
      break;
    case TH_RSTACK:
      printf("\tFlag = RST-ACK\n");
      break;
    case TH_FIN:
      printf("\tFlag = FIN\n");
      break;
    case TH_FINACK:
      printf("\tFlag = FIN-ACK\n");
      break;
    case TH_PHFINACK:
      printf("\tFlag = PUSH-FIN-ACK\n");
      break;
    default:
      printf(RED "\tUnknown Flag = %d\n" RESET "\t(-> Contribute to the project and add it in <utils.h>?)\n", flag);
  }
}

void exclude(char* excl) {
  /*
   * Called with the "--exlude" argument.
   * For example, argument should be like "ret,mac" to exclude TCP retransmissions and MAC ambiguities.
   * Source: adapted from https://stackoverflow.com/questions/15822660/how-to-parse-a-string-separated-by-commas
   */
  char *pt;
  pt = strtok(excl,",");
  while (pt != NULL) {
    if (strcmp(pt, "ret")==0) {
      EXCLUDE_RET=true;
      printf(GRN "[INFO]" RESET " Excluding RET ambiguities\n");
    } else if (strcmp(pt, "ttl")==0) {
      EXCLUDE_TTL=true;
      printf(GRN "[INFO]" RESET " Excluding TTL ambiguities\n");
    } else if (strcmp(pt, "mac")==0) {
      EXCLUDE_MAC=true;
      printf(GRN "[INFO]" RESET " Excluding MAC ambiguities\n");
    } else {
      printf(RED "[ERROR]" RESET " Unexpected 'exclude' value: %s\n", pt);
      help();
      exit(1);
    }
    pt = strtok (NULL, ",");
  }
}
