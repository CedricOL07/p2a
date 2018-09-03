#ifndef UTILS_H
#define UTILS_H

#include <netinet/in.h>
#include <openssl/sha.h>   // for SHA_DIGEST_LENGTH

#define D_HOST_MAC_ADDR 6

#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FINACK 0x11
#define TH_SYNACK 0x12
#define TH_RSTACK 0x14
#define TH_PHACK 0x18
#define TH_PHFINACK 0x19
#define TH_FLAGS (TH_PHACK |TH_RSTACK| TH_SYNACK|TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR|TH_FINACK|TH_PHFINACK)
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)

#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

#define RED   "\033[1m\033[31m"
#define GRN   "\033[1m\033[32m"
#define YLW   "\033[1m\033[33m"
#define RESET "\x1B[0m"
#define STRG  "\x1B[1m"

void my_packet_handler(u_char *args,const struct pcap_pkthdr *header,const u_char *packet);
int help();
void activate_verbose();
void activate_debug();
void activate_linux_cooked();
void analysis(char* file_in, char* file_out);
void print_flag(int flag);
void print_flag_json(FILE *fp, int flag);
void exclude(char* excl);
void save_json(char* filename);

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[D_HOST_MAC_ADDR];    /* destination host address */
        u_char  ether_shost;    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
const struct sniff_ip *ip_layer;
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};


typedef uint32_t tcp_seq;

struct sniff_tcp {
  u_short th_sport;	/* source port */
  u_short th_dport;	/* destination port */
  tcp_seq th_seq;   /* sequence number */
  tcp_seq th_ack;		/* acknowledgement number */
  u_char th_offx2;	/* data offset, rsvd */
  u_char th_flags;  /* flags */
  u_short th_win;		/* window */
  u_short th_sum;		/* checksum */
  u_short th_urp;		/* urgent pointer */
};

struct Session {
  struct MAC_address *last_mac_src, *last_mac_dst;
  char ip_src[20], ip_dst[20];
  int port_src, port_dst;
  long int seq_keepalive;
  char hash_src[SHA_DIGEST_LENGTH*2+1];
  char hash_dst[SHA_DIGEST_LENGTH*2+1];
  struct TCP_Packet *last_p;
  struct TCP_Packet *first_p;
  struct Session *previous_s;
  struct TTL *last_ttl;
};

struct TCP_Packet {
  char hash_src[SHA_DIGEST_LENGTH*2+1];
  char hash_dst[SHA_DIGEST_LENGTH*2+1];
  long int ack, seq;
  int number, flags, len, ttl;
  bool keepalive, retransmitted;
  struct TCP_Packet *next_p;
};

struct MAC_address {
  char address[20];
  struct MAC_address *previous_mac;
};

struct TTL {
  int val;
  struct TTL *previous_ttl;
};

#endif
